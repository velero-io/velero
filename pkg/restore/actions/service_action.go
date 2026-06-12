/*
Copyright 2017 the Velero contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package actions

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	"github.com/vmware-tanzu/velero/pkg/util/boolptr"
)

const annotationLastAppliedConfig = "kubectl.kubernetes.io/last-applied-configuration"

type ServiceAction struct {
	log logrus.FieldLogger
}

func NewServiceAction(logger logrus.FieldLogger) *ServiceAction {
	return &ServiceAction{log: logger}
}

func (a *ServiceAction) AppliesTo() (velero.ResourceSelector, error) {
	return velero.ResourceSelector{
		IncludedResources: []string{"services"},
	}, nil
}

func (a *ServiceAction) Execute(input *velero.RestoreItemActionExecuteInput) (*velero.RestoreItemActionExecuteOutput, error) {
	service := new(corev1api.Service)
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(input.Item.UnstructuredContent(), service); err != nil {
		return nil, errors.WithStack(err)
	}

	if service.Spec.ClusterIP != "None" {
		service.Spec.ClusterIP = ""
		service.Spec.ClusterIPs = nil
	}

	/* Do not delete NodePorts if restore triggered with "--preserve-nodeports" flag */
	if boolptr.IsSetToTrue(input.Restore.Spec.PreserveNodePorts) {
		a.log.Info("Restoring Services with original NodePort(s)")
	} else {
		if err := deleteNodePorts(service); err != nil {
			return nil, err
		}
		if err := deleteHealthCheckNodePort(service); err != nil {
			return nil, err
		}
	}

	res, err := runtime.DefaultUnstructuredConverter.ToUnstructured(service)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return velero.NewRestoreItemActionExecuteOutput(&unstructured.Unstructured{Object: res}), nil
}

func deleteHealthCheckNodePort(service *corev1api.Service) error {
	// Check service type and external traffic policy setting,
	// if the setting is not applicable for HealthCheckNodePort, return early.
	if service.Spec.ExternalTrafficPolicy != corev1api.ServiceExternalTrafficPolicyTypeLocal ||
		service.Spec.Type != corev1api.ServiceTypeLoadBalancer {
		return nil
	}

	// HealthCheckNodePort is already 0, return.
	if service.Spec.HealthCheckNodePort == 0 {
		return nil
	}

	// Search HealthCheckNodePort from server's last-applied-configuration
	// annotation(HealthCheckNodePort is specified by `kubectl apply` command)
	lastAppliedConfig, ok := service.Annotations[annotationLastAppliedConfig]
	if ok {
		appliedServiceUnstructured := new(map[string]any)
		if err := json.Unmarshal([]byte(lastAppliedConfig), appliedServiceUnstructured); err != nil {
			return errors.WithStack(err)
		}

		healthCheckNodePort, exist, err := unstructured.NestedFloat64(*appliedServiceUnstructured, "spec", "healthCheckNodePort")
		if err != nil {
			return errors.WithStack(err)
		}

		// Found healthCheckNodePort in lastAppliedConfig annotation,
		// and the value is not 0. No need to delete, return.
		if exist && healthCheckNodePort != 0 {
			return nil
		}
	}

	// Search HealthCheckNodePort from ManagedFields(HealthCheckNodePort
	// is specified by `kubectl apply --server-side` command).
	for _, entry := range service.GetManagedFields() {
		if entry.FieldsV1 == nil {
			continue
		}
		fields := new(map[string]any)
		if err := json.Unmarshal(entry.FieldsV1.Raw, fields); err != nil {
			return errors.WithStack(err)
		}

		_, exist, err := unstructured.NestedMap(*fields, "f:spec", "f:healthCheckNodePort")
		if err != nil {
			return errors.WithStack(err)
		}
		if !exist {
			continue
		}
		// Because the format in ManagedFields is `f:healthCheckNodePort: {}`,
		// cannot get the value, check whether exists is enough.
		// Found healthCheckNodePort in ManagedFields.
		// No need to delete. Return.
		return nil
	}

	// Cannot find HealthCheckNodePort from Annotation and
	// ManagedFields, which means it's auto-generated. Delete it.
	service.Spec.HealthCheckNodePort = 0

	return nil
}

func deleteNodePorts(service *corev1api.Service) error {
	if service.Spec.Type == corev1api.ServiceTypeExternalName {
		return nil
	}

	// find any NodePorts whose values were explicitly specified according
	// to the last-applied-config annotation. We'll retain these values, and
	// clear out any other (presumably auto-assigned) NodePort values.
	lastAppliedConfig, ok := service.Annotations[annotationLastAppliedConfig]
	if ok {
		explicitNodePorts := sets.NewString()
		unnamedPortInts := sets.NewInt()
		appliedServiceUnstructured := new(map[string]any)
		if err := json.Unmarshal([]byte(lastAppliedConfig), appliedServiceUnstructured); err != nil {
			return errors.WithStack(err)
		}

		ports, bool, err := unstructured.NestedSlice(*appliedServiceUnstructured, "spec", "ports")

		if err != nil {
			return errors.WithStack(err)
		}

		if bool {
			for _, port := range ports {
				p, ok := port.(map[string]any)
				if !ok {
					continue
				}
				nodePort, nodePortBool, err := unstructured.NestedFieldNoCopy(p, "nodePort")
				if err != nil {
					return errors.WithStack(err)
				}
				if nodePortBool {
					nodePortInt := 0
					switch nodePort := nodePort.(type) {
					case int32:
						nodePortInt = int(nodePort)
					case float64:
						nodePortInt = int(nodePort)
					case string:
						nodePortInt, err = strconv.Atoi(nodePort)
						if err != nil {
							return errors.WithStack(err)
						}
					}
					if nodePortInt > 0 {
						portName, ok := p["name"]
						if !ok {
							// unnamed port
							unnamedPortInts.Insert(nodePortInt)
						} else {
							explicitNodePorts.Insert(portName.(string))
						}
					}
				}
			}
		}

		for i, port := range service.Spec.Ports {
			if port.Name != "" {
				if !explicitNodePorts.Has(port.Name) {
					service.Spec.Ports[i].NodePort = 0
				}
			} else {
				if !unnamedPortInts.Has(int(port.NodePort)) {
					service.Spec.Ports[i].NodePort = 0
				}
			}
		}

		return nil
	}

	explicitNodePorts := sets.NewString()
	for _, entry := range service.GetManagedFields() {
		if entry.FieldsV1 == nil {
			continue
		}
		fields := new(map[string]any)
		if err := json.Unmarshal(entry.FieldsV1.Raw, fields); err != nil {
			return errors.WithStack(err)
		}

		ports, exist, err := unstructured.NestedMap(*fields, "f:spec", "f:ports")
		if err != nil {
			return errors.WithStack(err)
		}
		if !exist {
			continue
		}
		for key, port := range ports {
			p, ok := port.(map[string]any)
			if !ok {
				continue
			}
			if _, exist := p["f:nodePort"]; exist {
				explicitNodePorts.Insert(key)
			}
		}
	}
	for i, port := range service.Spec.Ports {
		k := portKey(port)
		if !explicitNodePorts.Has(k) {
			service.Spec.Ports[i].NodePort = 0
		}
	}
	return nil
}

func portKey(port corev1api.ServicePort) string {
	return fmt.Sprintf(`k:{"port":%d,"protocol":"%s"}`, port.Port, port.Protocol)
}
