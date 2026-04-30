/*
Copyright the Velero contributors.

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

package install

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/pkg/errors"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/vmware-tanzu/velero/pkg/client"
	"github.com/vmware-tanzu/velero/pkg/util/kube"
)

// kindToResource translates a Kind (mixed case, singular) to a Resource (lowercase, plural) string.
// This is to accommodate the dynamic client's need for an APIResource, as the Unstructured objects do not have easy helpers for this information.
var kindToResource = map[string]string{
	"CustomResourceDefinition": "customresourcedefinitions",
	"Namespace":                "namespaces",
	"ClusterRoleBinding":       "clusterrolebindings",
	"ServiceAccount":           "serviceaccounts",
	"Deployment":               "deployments",
	"DaemonSet":                "daemonsets",
	"Secret":                   "secrets",
	"ConfigMap":                "configmaps",
	"BackupStorageLocation":    "backupstoragelocations",
	"VolumeSnapshotLocation":   "volumesnapshotlocations",
}

// ResourceGroup represents a collection of Kubernetes objects with a common ready condition
type ResourceGroup struct {
	CRDResources   []*unstructured.Unstructured
	OtherResources []*unstructured.Unstructured
}

// crdV1Beta1ReadinessFn returns a function that can be used for polling to check
// if the provided unstructured v1beta1 CRDs are ready for use in the cluster.
func crdV1Beta1ReadinessFn(kbClient kbclient.Client, unstructuredCrds []*unstructured.Unstructured) func() (bool, error) {
	// Track all the CRDs that have been found and in ready state.
	// len should be equal to len(unstructuredCrds) in the happy path.
	return func() (bool, error) {
		foundCRDs := make([]*apiextv1beta1.CustomResourceDefinition, 0)
		for _, unstructuredCrd := range unstructuredCrds {
			crd := &apiextv1beta1.CustomResourceDefinition{}
			key := kbclient.ObjectKey{Name: unstructuredCrd.GetName()}
			err := kbClient.Get(context.Background(), key, crd)
			if apierrors.IsNotFound(err) {
				return false, nil
			} else if err != nil {
				return false, errors.Wrapf(err, "error waiting for %s to be ready", crd.GetName())
			}
			foundCRDs = append(foundCRDs, crd)
		}

		if len(foundCRDs) != len(unstructuredCrds) {
			return false, nil
		}

		for _, crd := range foundCRDs {
			ready := kube.IsV1Beta1CRDReady(crd)
			if !ready {
				return false, nil
			}
		}
		return true, nil
	}
}

// crdV1ReadinessFn returns a function that can be used for polling to check
// if the provided unstructured v1 CRDs are ready for use in the cluster.
func crdV1ReadinessFn(kbClient kbclient.Client, unstructuredCrds []*unstructured.Unstructured) func() (bool, error) {
	return func() (bool, error) {
		foundCRDs := make([]*apiextv1.CustomResourceDefinition, 0)
		for _, unstructuredCrd := range unstructuredCrds {
			crd := &apiextv1.CustomResourceDefinition{}
			key := kbclient.ObjectKey{Name: unstructuredCrd.GetName()}
			err := kbClient.Get(context.Background(), key, crd)
			if apierrors.IsNotFound(err) {
				return false, nil
			} else if err != nil {
				return false, errors.Wrapf(err, "error waiting for %s to be ready", crd.GetName())
			}
			foundCRDs = append(foundCRDs, crd)
		}

		if len(foundCRDs) != len(unstructuredCrds) {
			return false, nil
		}

		for _, crd := range foundCRDs {
			ready := kube.IsV1CRDReady(crd)
			if !ready {
				return false, nil
			}
		}
		return true, nil
	}
}

// crdsAreReady polls the API server to see if the Velero CRDs are ready to create objects.
func crdsAreReady(kbClient kbclient.Client, crds []*unstructured.Unstructured) (bool, error) {
	if len(crds) == 0 {
		// no CRDs to check so return
		return true, nil
	}

	// We assume that all Velero CRDs have the same GVK so we can use the GVK of the
	// first CRD to determine whether to use the v1beta1 or v1 API during polling.
	gvk := crds[0].GroupVersionKind()

	var crdReadinessFn func() (bool, error)
	switch gvk.Version {
	case "v1beta1":
		crdReadinessFn = crdV1Beta1ReadinessFn(kbClient, crds)
	case "v1":
		crdReadinessFn = crdV1ReadinessFn(kbClient, crds)
	default:
		return false, fmt.Errorf("unsupported CRD version %q", gvk.Version)
	}

	err := wait.PollImmediate(time.Second, time.Minute, crdReadinessFn)
	if err != nil {
		return false, errors.Wrap(err, "Error polling for CRDs")
	}
	return true, nil
}

func isAvailable(c appsv1.DeploymentCondition) bool {
	// Make sure that the deployment has been available for at least 10 seconds.
	// This is because the deployment can show as Ready momentarily before the pods fall into a CrashLoopBackOff.
	// See podutils.IsPodAvailable upstream for similar logic with pods
	if c.Type == appsv1.DeploymentAvailable && c.Status == corev1.ConditionTrue {
		if !c.LastTransitionTime.IsZero() && c.LastTransitionTime.Add(10*time.Second).Before(time.Now()) {
			return true
		}
	}
	return false
}

// DeploymentIsReady will poll the Kubernetes API server to see if the velero deployment is ready to service user requests.
func DeploymentIsReady(factory client.DynamicFactory, namespace string) (bool, error) {
	gvk := schema.FromAPIVersionAndKind(appsv1.SchemeGroupVersion.String(), "Deployment")
	apiResource := metav1.APIResource{
		Name:       "deployments",
		Namespaced: true,
	}
	c, err := factory.ClientForGroupVersionResource(gvk.GroupVersion(), apiResource, namespace)
	if err != nil {
		return false, errors.Wrapf(err, "Error creating client for deployment polling")
	}
	// declare this variable out of scope so we can return it
	var isReady bool
	var readyObservations int32
	err = wait.PollImmediate(time.Second, 3*time.Minute, func() (bool, error) {
		unstructuredDeployment, err := c.Get("velero", metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return false, nil
		} else if err != nil {
			return false, errors.Wrap(err, "error waiting for deployment to be ready")
		}

		deploy := new(appsv1.Deployment)
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(unstructuredDeployment.Object, deploy); err != nil {
			return false, errors.Wrap(err, "error converting deployment from unstructured")
		}

		for _, cond := range deploy.Status.Conditions {
			if isAvailable(cond) {
				readyObservations++
			}
		}
		// Make sure we query the deployment enough times to see the state change, provided there is one.
		if readyObservations > 4 {
			isReady = true
			return true, nil
		}
		return false, nil
	})
	return isReady, err
}

// DaemonSetIsReady will poll the Kubernetes API server to ensure the node-agent daemonset is ready, i.e. that
// pods are scheduled and available on all of the desired nodes.
func DaemonSetIsReady(factory client.DynamicFactory, namespace string) (bool, error) {
	gvk := schema.FromAPIVersionAndKind(appsv1.SchemeGroupVersion.String(), "DaemonSet")
	apiResource := metav1.APIResource{
		Name:       "daemonsets",
		Namespaced: true,
	}

	c, err := factory.ClientForGroupVersionResource(gvk.GroupVersion(), apiResource, namespace)
	if err != nil {
		return false, errors.Wrapf(err, "Error creating client for daemonset polling")
	}

	// declare this variable out of scope so we can return it
	var isReady bool
	var readyObservations int32

	err = wait.PollImmediate(time.Second, time.Minute, func() (bool, error) {
		unstructuredDaemonSet, err := c.Get("node-agent", metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return false, nil
		} else if err != nil {
			return false, errors.Wrap(err, "error waiting for daemonset to be ready")
		}

		daemonSet := new(appsv1.DaemonSet)
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(unstructuredDaemonSet.Object, daemonSet); err != nil {
			return false, errors.Wrap(err, "error converting daemonset from unstructured")
		}

		if daemonSet.Status.NumberAvailable == daemonSet.Status.DesiredNumberScheduled {
			readyObservations++
		}

		// Wait for 5 observations of the daemonset being "ready" to be consistent with our check for
		// the deployment being ready.
		if readyObservations > 4 {
			isReady = true
			return true, nil
		}
		return false, nil
	})
	return isReady, err
}

// GroupResources groups resources based on whether the resources are CustomResourceDefinitions or other types of Kubernetes objects
// This is useful to wait for readiness before creating CRD objects
func GroupResources(resources *unstructured.UnstructuredList) *ResourceGroup {
	rg := new(ResourceGroup)

	for i, r := range resources.Items {
		if r.GetKind() == "CustomResourceDefinition" {
			rg.CRDResources = append(rg.CRDResources, &resources.Items[i])
			continue
		}
		rg.OtherResources = append(rg.OtherResources, &resources.Items[i])
	}

	return rg
}

// createResource attempts to create a resource in the cluster.
// If the resource already exists in the cluster, it's merely logged.
func createResource(r *unstructured.Unstructured, factory client.DynamicFactory, w io.Writer) error {
	id := fmt.Sprintf("%s/%s", r.GetKind(), r.GetName())

	// Helper to reduce boilerplate message about the same object
	log := func(f string, a ...interface{}) {
		format := strings.Join([]string{id, ": ", f, "\n"}, "")
		fmt.Fprintf(w, format, a...)
	}
	log("attempting to create resource")

	c, err := CreateClient(r, factory, w)
	if err != nil {
		return err
	}

	if _, err := c.Create(r); apierrors.IsAlreadyExists(err) {
		log("already exists, proceeding")
	} else if err != nil {
		return errors.Wrapf(err, "Error creating resource %s", id)
	}

	log("created")
	return nil
}

// CreateClient creates a client for an unstructured resource
func CreateClient(r *unstructured.Unstructured, factory client.DynamicFactory, w io.Writer) (client.Dynamic, error) {
	id := fmt.Sprintf("%s/%s", r.GetKind(), r.GetName())

	// Helper to reduce boilerplate message about the same object
	log := func(f string, a ...interface{}) {
		format := strings.Join([]string{id, ": ", f, "\n"}, "")
		fmt.Fprintf(w, format, a...)
	}
	log("attempting to create resource client")

	gvk := schema.FromAPIVersionAndKind(r.GetAPIVersion(), r.GetKind())

	apiResource := metav1.APIResource{
		Name:       kindToResource[r.GetKind()],
		Namespaced: (r.GetNamespace() != ""),
	}

	c, err := factory.ClientForGroupVersionResource(gvk.GroupVersion(), apiResource, r.GetNamespace())
	if err != nil {
		return nil, errors.Wrapf(err, "Error creating client for resource %s", id)
	}

	return c, nil
}

// Install creates resources on the Kubernetes cluster.
// An unstructured list of resources is sent, one at a time, to the server. These are assumed to be in the preferred order already.
// Resources will be sorted into CustomResourceDefinitions and any other resource type, and the function will wait up to 1 minute
// for CRDs to be ready before proceeding.
// An io.Writer can be used to output to a log or the console.
func Install(dynamicFactory client.DynamicFactory, kbClient kbclient.Client, resources *unstructured.UnstructuredList, w io.Writer) error {
	rg := GroupResources(resources)

	//Install CRDs first
	for _, r := range rg.CRDResources {
		if err := createResource(r, dynamicFactory, w); err != nil {
			return err
		}
	}

	// Wait for CRDs to be ready before proceeding
	fmt.Fprint(w, "Waiting for resources to be ready in cluster...\n")
	_, err := crdsAreReady(kbClient, rg.CRDResources)
	if err == wait.ErrWaitTimeout {
		return errors.Errorf("timeout reached, CRDs not ready")
	} else if err != nil {
		return err
	}

	// Install all other resources
	for _, r := range rg.OtherResources {
		if err = createResource(r, dynamicFactory, w); err != nil {
			return err
		}
	}

	return nil
}
