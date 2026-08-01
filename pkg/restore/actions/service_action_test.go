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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
)

func svcJSON(ports ...corev1api.ServicePort) string {
	svc := corev1api.Service{
		Spec: corev1api.ServiceSpec{
			HealthCheckNodePort: 8080,
			Ports:               ports,
		},
	}

	data, err := json.Marshal(svc)
	if err != nil {
		panic(err)
	}

	return string(data)
}

func svcJSONFromUnstructured(ports ...map[string]any) string {
	svc := map[string]any{
		"spec": map[string]any{
			"ports": ports,
		},
	}

	data, err := json.Marshal(svc)
	if err != nil {
		panic(err)
	}

	return string(data)
}

func TestServiceActionExecute(t *testing.T) {
	tests := []struct {
		name        string
		obj         corev1api.Service
		restore     *api.Restore
		expectedErr bool
		expectedRes corev1api.Service
	}{
		{
			name: "clusterIP/clusterIPs should be deleted from spec",
			obj: corev1api.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name: "svc-1",
				},
				Spec: corev1api.ServiceSpec{
					ClusterIP:      "should-be-removed",
					ClusterIPs:     []string{"should-be-removed"},
					LoadBalancerIP: "should-be-kept",
				},
			},
			restore:     builder.ForRestore(api.DefaultNamespace, "").Result(),
			expectedErr: false,
			expectedRes: corev1api.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name: "svc-1",
				},
				Spec: corev1api.ServiceSpec{
					LoadBalancerIP: "should-be-kept",
				},
			},
		},
		{
			name: "headless clusterIP should not be deleted from spec",
			obj: corev1api.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name: "svc-1",
				},
				Spec: corev1api.ServiceSpec{
					ClusterIP: "None",
				},
			},
			restore: builder.ForRestore(api.DefaultNamespace, "").Result(),
			expectedRes: corev1api.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name: "svc-1",
				},
				Spec: corev1api.ServiceSpec{
					ClusterIP: "None",
				},
			},
		},
		{
			name: "nodePort (only) should be deleted from all spec.ports",
			obj: corev1api.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name: "svc-1",
				},
				Spec: corev1api.ServiceSpec{
					Ports: []corev1api.ServicePort{
						{
							Port:     32000,
							NodePort: 32000,
						},
						{
							Port:     32001,
							NodePort: 32001,
						},
					},
				},
			},
			restore: builder.ForRestore(api.DefaultNamespace, "").Result(),
			expectedRes: corev1api.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name: "svc-1",
				},
				Spec: corev1api.ServiceSpec{
					Ports: []corev1api.ServicePort{
						{
							Port: 32000,
						},
						{
							Port: 32001,
						},
					},
				},
			},
		},
		{
			name: "unnamed nodePort should be deleted when missing in annotation",
			obj: corev1api.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name: "svc-1",
					Annotations: map[string]string{
						annotationLastAppliedConfig: svcJSON(),
					},
				},
				Spec: corev1api.ServiceSpec{
					Ports: []corev1api.ServicePort{
						{
							NodePort: 8080,
						},
					},
				},
			},
			restore: builder.ForRestore(api.DefaultNamespace, "").Result(),
			expectedRes: corev1api.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name: "svc-1",
					Annotations: map[string]string{
						annotationLastAppliedConfig: svcJSON(),
					},
				},
				Spec: corev1api.ServiceSpec{
					Ports: []corev1api.ServicePort{
						{},
					},
				},
			},
		},
		{
			name: "unnamed nodePort should be preserved when specified in annotation",
			obj: corev1api.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name: "svc-1",
					Annotations: map[string]string{
						annotationLastAppliedConfig: svcJSON(corev1api.ServicePort{NodePort: 8080}),
					},
				},
				Spec: corev1api.ServiceSpec{
					Ports: []corev1api.ServicePort{
						{
							NodePort: 8080,
						},
						{
							NodePort: 9090,
						},
					},
				},
			},
			restore: builder.ForRestore(api.DefaultNamespace, "").Result(),
			expectedRes: corev1api.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name: "svc-1",
					Annotations: map[string]string{
						annotationLastAppliedConfig: svcJSON(corev1api.ServicePort{NodePort: 8080}),
					},
				},
				Spec: corev1api.ServiceSpec{
					Ports: []corev1api.ServicePort{
						{
							NodePort: 8080,
						},
						{},
					},
				},
			},
		},
		{
			name: "unnamed nodePort should be deleted when named nodePort specified in annotation",
			obj: corev1api.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name: "svc-1",
					Annotations: map[string]string{
						annotationLastAppliedConfig: svcJSON(corev1api.ServicePort{Name: "http", NodePort: 8080}),
					},
				},
				Spec: corev1api.ServiceSpec{
					Ports: []corev1api.ServicePort{
						{
							NodePort: 8080,
						},
					},
				},
			},
			restore: builder.ForRestore(api.DefaultNamespace, "").Result(),
			expectedRes: corev1api.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name: "svc-1",
					Annotations: map[string]string{
						annotationLastAppliedConfig: svcJSON(corev1api.ServicePort{Name: "http", NodePort: 8080}),
					},
				},
				Spec: corev1api.ServiceSpec{
					Ports: []corev1api.ServicePort{
						{},
					},
				},
			},
		},
		{
			name: "unnamed nodePort should be deleted when named a string nodePort specified in annotation",
			obj: corev1api.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name: "svc-1",
					Annotations: map[string]string{
						annotationLastAppliedConfig: svcJSONFromUnstructured(map[string]any{"name": "http", "nodePort": "8080"}),
					},
				},
				Spec: corev1api.ServiceSpec{
					Ports: []corev1api.ServicePort{
						{
							NodePort: 8080,
						},
					},
				},
			},
			restore: builder.ForRestore(api.DefaultNamespace, "").Result(),
			expectedRes: corev1api.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name: "svc-1",
					Annotations: map[string]string{
						annotationLastAppliedConfig: svcJSONFromUnstructured(map[string]any{"name": "http", "nodePort": "8080"}),
					},
				},
				Spec: corev1api.ServiceSpec{
					Ports: []corev1api.ServicePort{
						{},
					},
				},
			},
		},
		{
			name: "named nodePort should be preserved when specified in annotation",
			obj: corev1api.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name: "svc-1",
					Annotations: map[string]string{
						annotationLastAppliedConfig: svcJSON(corev1api.ServicePort{Name: "http", NodePort: 8080}),
					},
				},
				Spec: corev1api.ServiceSpec{
					Ports: []corev1api.ServicePort{
						{
							Name:     "http",
							NodePort: 8080,
						},
						{
							Name:     "admin",
							NodePort: 9090,
						},
					},
				},
			},
			restore: builder.ForRestore(api.DefaultNamespace, "").Result(),
			expectedRes: corev1api.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name: "svc-1",
					Annotations: map[string]string{
						annotationLastAppliedConfig: svcJSON(corev1api.ServicePort{Name: "http", NodePort: 8080}),
					},
				},
				Spec: corev1api.ServiceSpec{
					Ports: []corev1api.ServicePort{
						{
							Name:     "http",
							NodePort: 8080,
						},
						{
							Name: "admin",
						},
					},
				},
			},
		},
		{
			name: "If PreserveNodePorts is True in restore spec then nodePort always preserved.",
			obj: corev1api.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name: "svc-1",
				},
				Spec: corev1api.ServiceSpec{
					Ports: []corev1api.ServicePort{
						{
							Name:     "http",
							Port:     80,
							NodePort: 8080,
						},
						{
							Name:     "hepsiburada",
							NodePort: 9025,
						},
					},
				},
			},
			restore: builder.ForRestore(api.DefaultNamespace, "").PreserveNodePorts(true).Result(),
			expectedRes: corev1api.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name: "svc-1",
				},
				Spec: corev1api.ServiceSpec{
					Ports: []corev1api.ServicePort{
						{
							Name:     "http",
							Port:     80,
							NodePort: 8080,
						},
						{
							Name:     "hepsiburada",
							NodePort: 9025,
						},
					},
				},
			},
		},
		{
			name: "nodePort should be delete when not specified in managedFields",
			obj: corev1api.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name: "svc-1",
					ManagedFields: []metav1.ManagedFieldsEntry{
						{
							FieldsV1: &metav1.FieldsV1{
								Raw: []byte(`{"f:spec":{"f:ports":{"k:{\"port\":443,\"protocol\":\"TCP\"}":{".":{},"f:name":{},"f:port":{}},"k:{\"port\":80,\"protocol\":\"TCP\"}":{".":{},"f:name":{},"f:port":{}}},"f:selector":{},"f:type":{}}}`),
							},
						},
					},
				},
				Spec: corev1api.ServiceSpec{
					Ports: []corev1api.ServicePort{
						{
							Name:     "http",
							Port:     80,
							Protocol: "TCP",
						},
						{
							Name:     "https",
							Port:     443,
							Protocol: "TCP",
						},
					},
				},
			},
			restore: builder.ForRestore(api.DefaultNamespace, "").Result(),
			expectedRes: corev1api.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name: "svc-1",
					ManagedFields: []metav1.ManagedFieldsEntry{
						{
							FieldsV1: &metav1.FieldsV1{
								Raw: []byte(`{"f:spec":{"f:ports":{"k:{\"port\":443,\"protocol\":\"TCP\"}":{".":{},"f:name":{},"f:port":{}},"k:{\"port\":80,\"protocol\":\"TCP\"}":{".":{},"f:name":{},"f:port":{}}},"f:selector":{},"f:type":{}}}`),
							},
						},
					},
				},
				Spec: corev1api.ServiceSpec{
					Ports: []corev1api.ServicePort{
						{
							Name:     "http",
							Port:     80,
							NodePort: 0,
							Protocol: "TCP",
						},
						{
							Name:     "https",
							Port:     443,
							NodePort: 0,
							Protocol: "TCP",
						},
					},
				},
			},
		},
		{
			name: "nodePort should be preserved when specified in managedFields",
			obj: corev1api.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name: "svc-1",
					ManagedFields: []metav1.ManagedFieldsEntry{
						{
							FieldsV1: &metav1.FieldsV1{
								Raw: []byte(`{"f:spec":{"f:ports":{"k:{\"port\":443,\"protocol\":\"TCP\"}":{".":{},"f:name":{},"f:nodePort":{},"f:port":{}},"k:{\"port\":80,\"protocol\":\"TCP\"}":{".":{},"f:name":{},"f:nodePort":{},"f:port":{}}},"f:selector":{},"f:type":{}}}`),
							},
						},
					},
				},
				Spec: corev1api.ServiceSpec{
					Ports: []corev1api.ServicePort{
						{
							Name:     "http",
							Port:     80,
							NodePort: 30000,
							Protocol: "TCP",
						},
						{
							Name:     "https",
							Port:     443,
							NodePort: 30002,
							Protocol: "TCP",
						},
					},
				},
			},
			restore: builder.ForRestore(api.DefaultNamespace, "").Result(),
			expectedRes: corev1api.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name: "svc-1",
					ManagedFields: []metav1.ManagedFieldsEntry{
						{
							FieldsV1: &metav1.FieldsV1{
								Raw: []byte(`{"f:spec":{"f:ports":{"k:{\"port\":443,\"protocol\":\"TCP\"}":{".":{},"f:name":{},"f:nodePort":{},"f:port":{}},"k:{\"port\":80,\"protocol\":\"TCP\"}":{".":{},"f:name":{},"f:nodePort":{},"f:port":{}}},"f:selector":{},"f:type":{}}}`),
							},
						},
					},
				},
				Spec: corev1api.ServiceSpec{
					Ports: []corev1api.ServicePort{
						{
							Name:     "http",
							Port:     80,
							NodePort: 30000,
							Protocol: "TCP",
						},
						{
							Name:     "https",
							Port:     443,
							NodePort: 30002,
							Protocol: "TCP",
						},
					},
				},
			},
		},
		{
			name: "If PreserveNodePorts is True in restore spec then HealthCheckNodePort always preserved.",
			obj: corev1api.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name: "svc-1",
				},
				Spec: corev1api.ServiceSpec{
					HealthCheckNodePort:   8080,
					ExternalTrafficPolicy: corev1api.ServiceExternalTrafficPolicyTypeLocal,
					Type:                  corev1api.ServiceTypeLoadBalancer,
					Ports: []corev1api.ServicePort{
						{
							Name:     "http",
							Port:     80,
							NodePort: 8080,
						},
						{
							Name:     "hepsiburada",
							NodePort: 9025,
						},
					},
				},
			},
			restore: builder.ForRestore(api.DefaultNamespace, "").PreserveNodePorts(true).Result(),
			expectedRes: corev1api.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name: "svc-1",
				},
				Spec: corev1api.ServiceSpec{
					HealthCheckNodePort:   8080,
					ExternalTrafficPolicy: corev1api.ServiceExternalTrafficPolicyTypeLocal,
					Type:                  corev1api.ServiceTypeLoadBalancer,
					Ports: []corev1api.ServicePort{
						{
							Name:     "http",
							Port:     80,
							NodePort: 8080,
						},
						{
							Name:     "hepsiburada",
							NodePort: 9025,
						},
					},
				},
			},
		},
		{
			name: "If PreserveNodePorts is False in restore spec then HealthCheckNodePort should be cleaned.",
			obj: corev1api.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name: "svc-1",
				},
				Spec: corev1api.ServiceSpec{
					HealthCheckNodePort:   8080,
					ExternalTrafficPolicy: corev1api.ServiceExternalTrafficPolicyTypeLocal,
					Type:                  corev1api.ServiceTypeLoadBalancer,
				},
			},
			restore: builder.ForRestore(api.DefaultNamespace, "").PreserveNodePorts(false).Result(),
			expectedRes: corev1api.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name: "svc-1",
				},
				Spec: corev1api.ServiceSpec{
					HealthCheckNodePort:   0,
					ExternalTrafficPolicy: corev1api.ServiceExternalTrafficPolicyTypeLocal,
					Type:                  corev1api.ServiceTypeLoadBalancer,
				},
			},
		},
		{
			name: "If PreserveNodePorts is false in restore spec, but service is not expected, then HealthCheckNodePort should be kept.",
			obj: corev1api.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name: "svc-1",
				},
				Spec: corev1api.ServiceSpec{
					HealthCheckNodePort:   8080,
					ExternalTrafficPolicy: corev1api.ServiceExternalTrafficPolicyTypeCluster,
					Type:                  corev1api.ServiceTypeLoadBalancer,
				},
			},
			restore: builder.ForRestore(api.DefaultNamespace, "").PreserveNodePorts(false).Result(),
			expectedRes: corev1api.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name: "svc-1",
				},
				Spec: corev1api.ServiceSpec{
					HealthCheckNodePort:   8080,
					ExternalTrafficPolicy: corev1api.ServiceExternalTrafficPolicyTypeCluster,
					Type:                  corev1api.ServiceTypeLoadBalancer,
				},
			},
		},
		{
			name: "If PreserveNodePorts is false in restore spec, but HealthCheckNodePort can be found in Annotation, then it should be kept.",
			obj: corev1api.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "svc-1",
					Annotations: map[string]string{annotationLastAppliedConfig: svcJSON()},
				},
				Spec: corev1api.ServiceSpec{
					HealthCheckNodePort:   8080,
					ExternalTrafficPolicy: corev1api.ServiceExternalTrafficPolicyTypeLocal,
					Type:                  corev1api.ServiceTypeLoadBalancer,
				},
			},
			restore: builder.ForRestore(api.DefaultNamespace, "").PreserveNodePorts(false).Result(),
			expectedRes: corev1api.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "svc-1",
					Annotations: map[string]string{annotationLastAppliedConfig: svcJSON()},
				},
				Spec: corev1api.ServiceSpec{
					HealthCheckNodePort:   8080,
					ExternalTrafficPolicy: corev1api.ServiceExternalTrafficPolicyTypeLocal,
					Type:                  corev1api.ServiceTypeLoadBalancer,
				},
			},
		},
		{
			name: "If PreserveNodePorts is false in restore spec, but HealthCheckNodePort can be found in ManagedFields, then it should be kept.",
			obj: corev1api.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name: "svc-1",
					ManagedFields: []metav1.ManagedFieldsEntry{
						{
							FieldsV1: &metav1.FieldsV1{
								Raw: []byte(`{"f:spec":{"f:healthCheckNodePort":{}}}`),
							},
						},
					},
				},
				Spec: corev1api.ServiceSpec{
					HealthCheckNodePort:   8080,
					ExternalTrafficPolicy: corev1api.ServiceExternalTrafficPolicyTypeLocal,
					Type:                  corev1api.ServiceTypeLoadBalancer,
				},
			},
			restore: builder.ForRestore(api.DefaultNamespace, "").PreserveNodePorts(false).Result(),
			expectedRes: corev1api.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name: "svc-1",
					ManagedFields: []metav1.ManagedFieldsEntry{
						{
							FieldsV1: &metav1.FieldsV1{
								Raw: []byte(`{"f:spec":{"f:healthCheckNodePort":{}}}`),
							},
						},
					},
				},
				Spec: corev1api.ServiceSpec{
					HealthCheckNodePort:   8080,
					ExternalTrafficPolicy: corev1api.ServiceExternalTrafficPolicyTypeLocal,
					Type:                  corev1api.ServiceTypeLoadBalancer,
				},
			},
		},
		{
			name: "If PreserveNodePorts is false and HealthCheckNodePort is null in last-applied-configuration, it should not crash and the port should be cleared.",
			obj: corev1api.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name: "svc-1",
					Annotations: map[string]string{
						"kubectl.kubernetes.io/last-applied-configuration": `{"spec":{"healthCheckNodePort":null}}`,
					},
				},
				Spec: corev1api.ServiceSpec{
					HealthCheckNodePort:   8080,
					ExternalTrafficPolicy: corev1api.ServiceExternalTrafficPolicyTypeLocal,
					Type:                  corev1api.ServiceTypeLoadBalancer,
				},
			},
			restore: builder.ForRestore(api.DefaultNamespace, "").PreserveNodePorts(false).Result(),
			expectedRes: corev1api.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name: "svc-1",
					Annotations: map[string]string{
						"kubectl.kubernetes.io/last-applied-configuration": `{"spec":{"healthCheckNodePort":null}}`,
					},
				},
				Spec: corev1api.ServiceSpec{
					HealthCheckNodePort:   0,
					ExternalTrafficPolicy: corev1api.ServiceExternalTrafficPolicyTypeLocal,
					Type:                  corev1api.ServiceTypeLoadBalancer,
				},
			},
		},
		{
			name: "If a port name in last-applied-configuration is not a string, it should not crash.",
			obj: corev1api.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name: "svc-1",
					Annotations: map[string]string{
						"kubectl.kubernetes.io/last-applied-configuration": `{"spec":{"ports":[{"nodePort":30001,"name":123}]}}`,
					},
				},
				Spec: corev1api.ServiceSpec{
					Type: corev1api.ServiceTypeNodePort,
					Ports: []corev1api.ServicePort{
						{
							Name:     "http",
							NodePort: 30001,
						},
					},
				},
			},
			restore: builder.ForRestore(api.DefaultNamespace, "").PreserveNodePorts(false).Result(),
			expectedRes: corev1api.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name: "svc-1",
					Annotations: map[string]string{
						"kubectl.kubernetes.io/last-applied-configuration": `{"spec":{"ports":[{"nodePort":30001,"name":123}]}}`,
					},
				},
				Spec: corev1api.ServiceSpec{
					Type: corev1api.ServiceTypeNodePort,
					Ports: []corev1api.ServicePort{
						{
							Name:     "http",
							NodePort: 0,
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			action := NewServiceAction(velerotest.NewLogger())

			unstructuredSvc, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&test.obj)
			require.NoError(t, err)

			res, err := action.Execute(&velero.RestoreItemActionExecuteInput{
				Item:           &unstructured.Unstructured{Object: unstructuredSvc},
				ItemFromBackup: &unstructured.Unstructured{Object: unstructuredSvc},
				Restore:        test.restore,
			})

			if assert.Equal(t, test.expectedErr, err != nil) && !test.expectedErr {
				var svc corev1api.Service
				require.NoError(t, runtime.DefaultUnstructuredConverter.FromUnstructured(res.UpdatedItem.UnstructuredContent(), &svc))

				assert.Equal(t, test.expectedRes, svc)
			}
		})
	}
}
