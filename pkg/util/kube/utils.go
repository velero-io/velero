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

package kube

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/label"
	"github.com/vmware-tanzu/velero/pkg/uploader"
	"github.com/vmware-tanzu/velero/pkg/util/filesystem"
)

// These annotations are taken from the Kubernetes persistent volume/persistent volume claim controller.
// They cannot be directly importing because they are part of the kubernetes/kubernetes package, and importing that package is unsupported.
// Their values are well-known and slow changing. They're duplicated here as constants to provide compile-time checking.
// Originals can be found in kubernetes/kubernetes/pkg/controller/volume/persistentvolume/util/util.go.
const (
	KubeAnnBindCompleted          = "pv.kubernetes.io/bind-completed"
	KubeAnnBoundByController      = "pv.kubernetes.io/bound-by-controller"
	KubeAnnDynamicallyProvisioned = "pv.kubernetes.io/provisioned-by"
	KubeAnnMigratedTo             = "pv.kubernetes.io/migrated-to"
	KubeAnnSelectedNode           = "volume.kubernetes.io/selected-node"
)

// VolumeSnapshotContentManagedByLabel is applied by the snapshot controller
// to the VolumeSnapshotContent object in case distributed snapshotting is enabled.
// The value contains the name of the node that handles the snapshot for the volume local to that node.
const VolumeSnapshotContentManagedByLabel = "snapshot.storage.kubernetes.io/managed-by"

var ErrorPodVolumeIsNotPVC = errors.New("pod volume is not a PVC")

// NamespaceAndName returns a string in the format <namespace>/<name>
func NamespaceAndName(objMeta metav1.Object) string {
	if objMeta.GetNamespace() == "" {
		return objMeta.GetName()
	}
	return fmt.Sprintf("%s/%s", objMeta.GetNamespace(), objMeta.GetName())
}

// EnsureNamespaceExistsAndIsReady attempts to create the provided Kubernetes namespace.
// It returns three values:
//   - a bool indicating whether or not the namespace is ready,
//   - a bool indicating whether or not the namespace was created
//   - an error if one occurred.
//
// examples:
//
//	namespace already exists and is not ready, this function will return (false, false, nil).
//	If the namespace exists and is marked for deletion, this function will wait up to the timeout for it to fully delete.
func EnsureNamespaceExistsAndIsReady(namespace *corev1api.Namespace, client corev1client.NamespaceInterface, timeout time.Duration, resourceDeletionStatusTracker ResourceDeletionStatusTracker) (ready bool, nsCreated bool, err error) {
	// nsCreated tells whether the namespace was created by this method
	// required for keeping track of number of restored items
	// if namespace is marked for deletion, and we timed out, report an error
	var terminatingNamespace bool

	var namespaceAlreadyInDeletionTracker bool

	err = wait.PollUntilContextTimeout(context.Background(), time.Second, timeout, true, func(ctx context.Context) (bool, error) {
		clusterNS, err := client.Get(ctx, namespace.Name, metav1.GetOptions{})
		// if namespace is marked for deletion, and we timed out, report an error

		if apierrors.IsNotFound(err) {
			// Namespace isn't in cluster, we're good to create.
			return true, nil
		}

		if err != nil {
			// Return the err and exit the loop.
			return true, err
		}
		if clusterNS != nil && (clusterNS.GetDeletionTimestamp() != nil || clusterNS.Status.Phase == corev1api.NamespaceTerminating) {
			if resourceDeletionStatusTracker.Contains(clusterNS.Kind, clusterNS.Name, clusterNS.Name) {
				namespaceAlreadyInDeletionTracker = true
				return true, errors.Errorf("namespace %s is already present in the polling set, skipping execution", namespace.Name)
			}

			// Marked for deletion, keep waiting
			terminatingNamespace = true
			return false, nil
		}

		// clusterNS found, is not nil, and not marked for deletion, therefore we shouldn't create it.
		ready = true
		return true, nil
	})

	// err will be set if we timed out or encountered issues retrieving the namespace,
	if err != nil {
		if terminatingNamespace {
			// If the namespace is marked for deletion, and we timed out, adding it in tracker
			resourceDeletionStatusTracker.Add(namespace.Kind, namespace.Name, namespace.Name)
			return false, nsCreated, errors.Wrapf(err, "timed out waiting for terminating namespace %s to disappear before restoring", namespace.Name)
		} else if namespaceAlreadyInDeletionTracker {
			// If the namespace is already in the tracker, return an error.
			return false, nsCreated, errors.Wrapf(err, "skipping polling for terminating namespace %s", namespace.Name)
		}
		return false, nsCreated, errors.Wrapf(err, "error getting namespace %s", namespace.Name)
	}

	// In the case the namespace already exists and isn't marked for deletion, assume it's ready for use.
	if ready {
		return true, nsCreated, nil
	}

	clusterNS, err := client.Create(context.TODO(), namespace, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		if clusterNS != nil && (clusterNS.GetDeletionTimestamp() != nil || clusterNS.Status.Phase == corev1api.NamespaceTerminating) {
			// Somehow created after all our polling and marked for deletion, return an error
			return false, nsCreated, errors.Errorf("namespace %s created and marked for termination after timeout", namespace.Name)
		}
	} else if err != nil {
		return false, nsCreated, errors.Wrapf(err, "error creating namespace %s", namespace.Name)
	} else {
		nsCreated = true
	}

	// The namespace created successfully
	return true, nsCreated, nil
}

// GetVolumeDirectory gets the name of the directory on the host, under /var/lib/kubelet/pods/<podUID>/volumes/,
// where the specified volume lives.
// For volumes with a CSIVolumeSource, append "/mount" to the directory name.
func GetVolumeDirectory(ctx context.Context, log logrus.FieldLogger, pod *corev1api.Pod, volumeName string, kubeClient kubernetes.Interface) (string, error) {
	pvc, pv, volume, err := GetPodPVCVolume(ctx, log, pod, volumeName, kubeClient)
	if err != nil {
		// This case implies the administrator created the PV and attached it directly, without PVC.
		// Note that only one VolumeSource can be populated per Volume on a pod
		if err == ErrorPodVolumeIsNotPVC {
			if volume.VolumeSource.CSI != nil {
				return volume.Name + "/mount", nil
			}
			return volume.Name, nil
		}
		return "", errors.WithStack(err)
	}

	// Most common case is that we have a PVC VolumeSource, and we need to check the PV it points to for a CSI source.
	// PV's been created with a CSI source.
	isProvisionedByCSI, err := isProvisionedByCSI(log, pv, kubeClient)
	if err != nil {
		return "", errors.WithStack(err)
	}
	if isProvisionedByCSI {
		if pv.Spec.VolumeMode != nil && *pv.Spec.VolumeMode == corev1api.PersistentVolumeBlock {
			return pvc.Spec.VolumeName, nil
		}
		return pvc.Spec.VolumeName + "/mount", nil
	}

	return pvc.Spec.VolumeName, nil
}

// GetVolumeMode gets the uploader.PersistentVolumeMode of the volume.
func GetVolumeMode(ctx context.Context, log logrus.FieldLogger, pod *corev1api.Pod, volumeName string, kubeClient kubernetes.Interface) (
	uploader.PersistentVolumeMode, error) {
	_, pv, _, err := GetPodPVCVolume(ctx, log, pod, volumeName, kubeClient)

	if err != nil {
		if err == ErrorPodVolumeIsNotPVC {
			return uploader.PersistentVolumeFilesystem, nil
		}
		return "", errors.WithStack(err)
	}

	if pv.Spec.VolumeMode != nil && *pv.Spec.VolumeMode == corev1api.PersistentVolumeBlock {
		return uploader.PersistentVolumeBlock, nil
	}
	return uploader.PersistentVolumeFilesystem, nil
}

// GetPodPVCVolume gets the PVC, PV and volume for a pod volume name.
// Returns pod volume in case of ErrorPodVolumeIsNotPVC error
func GetPodPVCVolume(ctx context.Context, log logrus.FieldLogger, pod *corev1api.Pod, volumeName string, kubeClient kubernetes.Interface) (
	*corev1api.PersistentVolumeClaim, *corev1api.PersistentVolume, *corev1api.Volume, error) {
	var volume *corev1api.Volume

	for i := range pod.Spec.Volumes {
		if pod.Spec.Volumes[i].Name == volumeName {
			volume = &pod.Spec.Volumes[i]
			break
		}
	}

	if volume == nil {
		return nil, nil, nil, errors.New("volume not found in pod")
	}

	if volume.VolumeSource.PersistentVolumeClaim == nil {
		return nil, nil, volume, ErrorPodVolumeIsNotPVC // There is a pod volume but it is not a PVC
	}

	pvc, err := kubeClient.CoreV1().PersistentVolumeClaims(pod.Namespace).Get(ctx, volume.VolumeSource.PersistentVolumeClaim.ClaimName, metav1.GetOptions{})
	if err != nil {
		return nil, nil, nil, errors.WithStack(err)
	}

	pv, err := kubeClient.CoreV1().PersistentVolumes().Get(ctx, pvc.Spec.VolumeName, metav1.GetOptions{})
	if err != nil {
		return nil, nil, nil, errors.WithStack(err)
	}

	return pvc, pv, volume, nil
}

// isProvisionedByCSI function checks whether this is a CSI PV by annotation.
// Either "pv.kubernetes.io/provisioned-by" or "pv.kubernetes.io/migrated-to" indicates
// PV is provisioned by CSI.
func isProvisionedByCSI(log logrus.FieldLogger, pv *corev1api.PersistentVolume, kubeClient kubernetes.Interface) (bool, error) {
	if pv.Spec.CSI != nil {
		return true, nil
	}
	// Although the pv.Spec.CSI is nil, the volume could be provisioned by a CSI driver when enabling the CSI migration
	// Refer to https://github.com/vmware-tanzu/velero/issues/4496 for more details
	if pv.Annotations != nil {
		driverName := pv.Annotations[KubeAnnDynamicallyProvisioned]
		migratedDriver := pv.Annotations[KubeAnnMigratedTo]
		if len(driverName) > 0 || len(migratedDriver) > 0 {
			list, err := kubeClient.StorageV1().CSIDrivers().List(context.TODO(), metav1.ListOptions{})
			if err != nil {
				return false, err
			}

			for _, driver := range list.Items {
				if driverName == driver.Name || migratedDriver == driver.Name {
					log.Debugf("the annotation %s or %s equals to %s indicates the volume is provisioned by a CSI driver", KubeAnnDynamicallyProvisioned, KubeAnnMigratedTo, driver.Name)
					return true, nil
				}
			}
		}
	}
	return false, nil
}

// SinglePathMatch checks whether pass-in volume path is valid.
// Check whether there is only one match by the path's pattern.
func SinglePathMatch(path string, fs filesystem.Interface, log logrus.FieldLogger) (string, error) {
	matches, err := fs.Glob(path)
	if err != nil {
		return "", errors.WithStack(err)
	}
	if len(matches) != 1 {
		return "", errors.Errorf("expected one matching path: %s, got %d", path, len(matches))
	}

	log.Debugf("This is a valid volume path: %s.", matches[0])
	return matches[0], nil
}

// IsV1CRDReady checks a v1 CRD to see if it's ready, with both the Established and NamesAccepted conditions.
func IsV1CRDReady(crd *apiextv1.CustomResourceDefinition) bool {
	var isEstablished, namesAccepted bool
	for _, cond := range crd.Status.Conditions {
		if cond.Type == apiextv1.Established && cond.Status == apiextv1.ConditionTrue {
			isEstablished = true
		}
		if cond.Type == apiextv1.NamesAccepted && cond.Status == apiextv1.ConditionTrue {
			namesAccepted = true
		}
	}

	return (isEstablished && namesAccepted)
}

// IsV1Beta1CRDReady checks a v1beta1 CRD to see if it's ready, with both the Established and NamesAccepted conditions.
func IsV1Beta1CRDReady(crd *apiextv1beta1.CustomResourceDefinition) bool {
	var isEstablished, namesAccepted bool
	for _, cond := range crd.Status.Conditions {
		if cond.Type == apiextv1beta1.Established && cond.Status == apiextv1beta1.ConditionTrue {
			isEstablished = true
		}
		if cond.Type == apiextv1beta1.NamesAccepted && cond.Status == apiextv1beta1.ConditionTrue {
			namesAccepted = true
		}
	}

	return (isEstablished && namesAccepted)
}

// IsCRDReady triggers IsV1Beta1CRDReady/IsV1CRDReady according to the version of the input param
func IsCRDReady(crd *unstructured.Unstructured) (bool, error) {
	ver := crd.GroupVersionKind().Version
	switch ver {
	case "v1beta1":
		v1beta1crd := &apiextv1beta1.CustomResourceDefinition{}
		err := runtime.DefaultUnstructuredConverter.FromUnstructured(crd.Object, v1beta1crd)
		if err != nil {
			return false, err
		}
		return IsV1Beta1CRDReady(v1beta1crd), nil
	case "v1":
		v1crd := &apiextv1.CustomResourceDefinition{}
		err := runtime.DefaultUnstructuredConverter.FromUnstructured(crd.Object, v1crd)
		if err != nil {
			return false, err
		}
		return IsV1CRDReady(v1crd), nil
	default:
		return false, fmt.Errorf("unable to handle CRD with version %s", ver)
	}
}

// AddAnnotations adds the supplied key-values to the annotations on the object
func AddAnnotations(o *metav1.ObjectMeta, vals map[string]string) {
	if o.Annotations == nil {
		o.Annotations = make(map[string]string)
	}
	maps.Copy(o.Annotations, vals)
}

// AddLabels adds the supplied key-values to the labels on the object
func AddLabels(o *metav1.ObjectMeta, vals map[string]string) {
	if o.Labels == nil {
		o.Labels = make(map[string]string)
	}
	for k, v := range vals {
		o.Labels[k] = label.GetValidName(v)
	}
}

func HasBackupLabel(o *metav1.ObjectMeta, backupName string) bool {
	if o.Labels == nil || len(strings.TrimSpace(backupName)) == 0 {
		return false
	}
	return o.Labels[velerov1api.BackupNameLabel] == label.GetValidName(backupName)
}

func VerifyJSONConfigs(ctx context.Context, namespace string, crClient client.Client, configName string, configType any) error {
	cm := new(corev1api.ConfigMap)
	err := crClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: configName}, cm)
	if err != nil {
		return errors.Wrapf(err, "fail to find ConfigMap %s", configName)
	}

	if cm.Data == nil {
		return errors.Errorf("data is not available in ConfigMap %s", configName)
	}

	// Verify all the keys in ConfigMap's data.
	jsonString := ""
	for _, v := range cm.Data {
		jsonString = v

		configs := configType
		err = json.Unmarshal([]byte(jsonString), configs)
		if err != nil {
			return errors.Wrapf(err, "error to unmarshall data from ConfigMap %s", configName)
		}
	}

	return nil
}
