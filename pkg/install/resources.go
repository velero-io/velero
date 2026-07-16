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
	"fmt"
	"time"

	corev1api "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	v1crds "github.com/vmware-tanzu/velero/config/crd/v1/crds"
	v2alpha1crds "github.com/vmware-tanzu/velero/config/crd/v2alpha1/crds"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/util/kube"
)

const (
	defaultServiceAccountName = "velero"
	podSecurityLevel          = "privileged"
	podSecurityVersion        = "latest"
)

var (
	// default values for Velero server pod resource request/limit
	DefaultVeleroPodCPURequest = "500m"
	DefaultVeleroPodMemRequest = "128Mi"
	DefaultVeleroPodCPULimit   = "1000m"
	DefaultVeleroPodMemLimit   = "512Mi"

	// default values for node-agent pod resource request/limit,
	// "0" means no request/limit is set, so as to make the QoS as BestEffort
	DefaultNodeAgentPodCPURequest = "0"
	DefaultNodeAgentPodMemRequest = "0"
	DefaultNodeAgentPodCPULimit   = "0"
	DefaultNodeAgentPodMemLimit   = "0"

	DefaultVeleroNamespace = "velero"

	DefaultKubeletRootDir = "/var/lib/kubelet"
)

func Labels() map[string]string {
	return map[string]string{
		"component": "velero",
	}
}

func podLabels(userLabels ...map[string]string) map[string]string {
	// Use the default labels as a starting point
	base := Labels()

	// Merge base labels with user labels to enforce CLI precedence
	for _, labels := range userLabels {
		for k, v := range labels {
			base[k] = v
		}
	}

	return base
}

func podAnnotations(userAnnotations map[string]string) map[string]string {
	// Use the default annotations as a starting point
	base := map[string]string{
		"prometheus.io/scrape": "true",
		"prometheus.io/port":   "8085",
		"prometheus.io/path":   "/metrics",
	}

	// Merge base annotations with user annotations to enforce CLI precedence
	for k, v := range userAnnotations {
		base[k] = v
	}

	return base
}

func containerPorts() []corev1api.ContainerPort {
	return []corev1api.ContainerPort{
		{
			Name:          "metrics",
			ContainerPort: 8085,
		},
	}
}

func objectMeta(namespace, name string) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Name:      name,
		Namespace: namespace,
		Labels:    Labels(),
	}
}

func ServiceAccount(namespace string, annotations map[string]string) *corev1api.ServiceAccount {
	objMeta := objectMeta(namespace, defaultServiceAccountName)
	objMeta.Annotations = annotations
	return &corev1api.ServiceAccount{
		ObjectMeta: objMeta,
		TypeMeta: metav1.TypeMeta{
			Kind:       "ServiceAccount",
			APIVersion: corev1api.SchemeGroupVersion.String(),
		},
	}
}

func ClusterRoleBinding(namespace string) *rbacv1.ClusterRoleBinding {
	crbName := "velero"
	if namespace != DefaultVeleroNamespace {
		crbName = "velero-" + namespace
	}
	crb := &rbacv1.ClusterRoleBinding{
		ObjectMeta: objectMeta("", crbName),
		TypeMeta: metav1.TypeMeta{
			Kind:       "ClusterRoleBinding",
			APIVersion: rbacv1.SchemeGroupVersion.String(),
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Namespace: namespace,
				Name:      "velero",
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     "cluster-admin",
			APIGroup: "rbac.authorization.k8s.io",
		},
	}

	return crb
}

func Namespace(namespace string) *corev1api.Namespace {
	ns := &corev1api.Namespace{
		ObjectMeta: objectMeta("", namespace),
		TypeMeta: metav1.TypeMeta{
			Kind:       "Namespace",
			APIVersion: corev1api.SchemeGroupVersion.String(),
		},
	}

	ns.Labels["pod-security.kubernetes.io/enforce"] = podSecurityLevel
	ns.Labels["pod-security.kubernetes.io/enforce-version"] = podSecurityVersion
	ns.Labels["pod-security.kubernetes.io/audit"] = podSecurityLevel
	ns.Labels["pod-security.kubernetes.io/audit-version"] = podSecurityVersion
	ns.Labels["pod-security.kubernetes.io/warn"] = podSecurityLevel
	ns.Labels["pod-security.kubernetes.io/warn-version"] = podSecurityVersion

	return ns
}

func BackupStorageLocation(namespace, provider, bucket, prefix string, config map[string]string, caCert []byte) *velerov1api.BackupStorageLocation {
	return &velerov1api.BackupStorageLocation{
		ObjectMeta: objectMeta(namespace, "default"),
		TypeMeta: metav1.TypeMeta{
			Kind:       "BackupStorageLocation",
			APIVersion: velerov1api.SchemeGroupVersion.String(),
		},
		Spec: velerov1api.BackupStorageLocationSpec{
			Provider: provider,
			StorageType: velerov1api.StorageType{
				ObjectStorage: &velerov1api.ObjectStorageLocation{
					Bucket: bucket,
					Prefix: prefix,
					CACert: caCert,
				},
			},
			Config:  config,
			Default: true,
		},
	}
}

func VolumeSnapshotLocation(namespace, provider string, config map[string]string) *velerov1api.VolumeSnapshotLocation {
	return &velerov1api.VolumeSnapshotLocation{
		ObjectMeta: objectMeta(namespace, "default"),
		TypeMeta: metav1.TypeMeta{
			Kind:       "VolumeSnapshotLocation",
			APIVersion: velerov1api.SchemeGroupVersion.String(),
		},
		Spec: velerov1api.VolumeSnapshotLocationSpec{
			Provider: provider,
			Config:   config,
		},
	}
}

func Secret(namespace string, data []byte) *corev1api.Secret {
	return &corev1api.Secret{
		ObjectMeta: objectMeta(namespace, "cloud-credentials"),
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: corev1api.SchemeGroupVersion.String(),
		},
		Data: map[string][]byte{
			"cloud": data,
		},
		Type: corev1api.SecretTypeOpaque,
	}
}

func appendUnstructured(list *unstructured.UnstructuredList, obj runtime.Object) error {
	u, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&obj)

	// Remove the status field so we're not sending blank data to the server.
	// On CRDs, having an empty status is actually a validation error.
	delete(u, "status")
	if err != nil {
		return err
	}
	list.Items = append(list.Items, unstructured.Unstructured{Object: u})
	return nil
}

type VeleroOptions struct {
	Namespace                       string
	Image                           string
	ProviderName                    string
	Bucket                          string
	Prefix                          string
	PodAnnotations                  map[string]string
	PodLabels                       map[string]string
	ServiceAccountAnnotations       map[string]string
	ServiceAccountName              string
	VeleroPodResources              corev1api.ResourceRequirements
	NodeAgentPodResources           corev1api.ResourceRequirements
	SecretData                      []byte
	RestoreOnly                     bool
	UseNodeAgent                    bool
	UseNodeAgentWindows             bool
	PrivilegedNodeAgent             bool
	UseVolumeSnapshots              bool
	BSLConfig                       map[string]string
	VSLConfig                       map[string]string
	DefaultRepoMaintenanceFrequency time.Duration
	GarbageCollectionFrequency      time.Duration
	PodVolumeOperationTimeout       time.Duration
	Plugins                         []string
	NoDefaultBackupLocation         bool
	CACertData                      []byte
	Features                        []string
	DefaultVolumesToFsBackup        bool
	UploaderType                    string
	DefaultSnapshotMoveData         bool
	CSISnapshotEarlyFrequentPolling bool
	DisableInformerCache            bool
	ScheduleSkipImmediately         bool
	PodResources                    kube.PodResources
	KeepLatestMaintenanceJobs       int
	BackupRepoConfigMap             string
	RepoMaintenanceJobConfigMap     string
	NodeAgentConfigMap              string
	ItemBlockWorkerCount            int
	ConcurrentBackups               int
	KubeletRootDir                  string
	NodeAgentDisableHostPath        bool
	ServerPriorityClassName         string
	NodeAgentPriorityClassName      string
}

func AllCRDs() *unstructured.UnstructuredList {
	resources := new(unstructured.UnstructuredList)
	// Set the GVK so that the serialization framework outputs the list properly
	resources.SetGroupVersionKind(schema.GroupVersionKind{Group: "", Version: "v1", Kind: "List"})

	for _, crd := range v1crds.CRDs {
		crd.SetLabels(Labels())
		if err := appendUnstructured(resources, crd); err != nil {
			fmt.Printf("error appending v1 CRD %s: %s\n", crd.GetName(), err.Error())
		}
	}

	for _, crd := range v2alpha1crds.CRDs {
		crd.SetLabels(Labels())
		if err := appendUnstructured(resources, crd); err != nil {
			fmt.Printf("error appending v2alpha1 CRD %s: %s\n", crd.GetName(), err.Error())
		}
	}

	return resources
}

// AllResources returns a list of all resources necessary to install Velero, in the appropriate order, into a Kubernetes cluster.
// Items are unstructured, since there are different data types returned.
func AllResources(o *VeleroOptions) *unstructured.UnstructuredList {
	resources := AllCRDs()

	ns := Namespace(o.Namespace)
	if err := appendUnstructured(resources, ns); err != nil {
		fmt.Printf("error appending Namespace %s: %s\n", ns.GetName(), err.Error())
	}

	serviceAccountName := defaultServiceAccountName
	if o.ServiceAccountName == "" {
		crb := ClusterRoleBinding(o.Namespace)
		if err := appendUnstructured(resources, crb); err != nil {
			fmt.Printf("error appending ClusterRoleBinding %s: %s\n", crb.GetName(), err.Error())
		}
		sa := ServiceAccount(o.Namespace, o.ServiceAccountAnnotations)
		if err := appendUnstructured(resources, sa); err != nil {
			fmt.Printf("error appending ServiceAccount %s: %s\n", sa.GetName(), err.Error())
		}
	} else {
		serviceAccountName = o.ServiceAccountName
	}

	if o.SecretData != nil {
		sec := Secret(o.Namespace, o.SecretData)
		if err := appendUnstructured(resources, sec); err != nil {
			fmt.Printf("error appending Secret %s: %s\n", sec.GetName(), err.Error())
		}
	}

	if !o.NoDefaultBackupLocation {
		bsl := BackupStorageLocation(o.Namespace, o.ProviderName, o.Bucket, o.Prefix, o.BSLConfig, o.CACertData)
		if err := appendUnstructured(resources, bsl); err != nil {
			fmt.Printf("error appending BackupStorageLocation %s: %s\n", bsl.GetName(), err.Error())
		}
	}

	// A snapshot location may not be desirable for users relying on pod volume backup/restore
	if o.UseVolumeSnapshots {
		vsl := VolumeSnapshotLocation(o.Namespace, o.ProviderName, o.VSLConfig)
		if err := appendUnstructured(resources, vsl); err != nil {
			fmt.Printf("error appending VolumeSnapshotLocation %s: %s\n", vsl.GetName(), err.Error())
		}
	}

	secretPresent := o.SecretData != nil

	deployOpts := []podTemplateOption{
		WithAnnotations(o.PodAnnotations),
		WithLabels(o.PodLabels),
		WithImage(o.Image),
		WithResources(o.VeleroPodResources),
		WithSecret(secretPresent),
		WithDefaultRepoMaintenanceFrequency(o.DefaultRepoMaintenanceFrequency),
		WithServiceAccountName(serviceAccountName),
		WithGarbageCollectionFrequency(o.GarbageCollectionFrequency),
		WithPodVolumeOperationTimeout(o.PodVolumeOperationTimeout),
		WithUploaderType(o.UploaderType),
		WithScheduleSkipImmediately(o.ScheduleSkipImmediately),
		WithPodResources(o.PodResources),
		WithKeepLatestMaintenanceJobs(o.KeepLatestMaintenanceJobs),
		WithItemBlockWorkerCount(o.ItemBlockWorkerCount),
		WithConcurrentBackups(o.ConcurrentBackups),
	}

	if o.ServerPriorityClassName != "" {
		deployOpts = append(deployOpts, WithPriorityClassName(o.ServerPriorityClassName))
	}

	if len(o.Features) > 0 {
		deployOpts = append(deployOpts, WithFeatures(o.Features))
	}

	if o.RestoreOnly {
		deployOpts = append(deployOpts, WithRestoreOnly(true))
	}

	if len(o.Plugins) > 0 {
		deployOpts = append(deployOpts, WithPlugins(o.Plugins))
	}

	if o.DefaultVolumesToFsBackup {
		deployOpts = append(deployOpts, WithDefaultVolumesToFsBackup(true))
	}

	if o.DefaultSnapshotMoveData {
		deployOpts = append(deployOpts, WithDefaultSnapshotMoveData(true))
	}

	if o.CSISnapshotEarlyFrequentPolling {
		deployOpts = append(deployOpts, WithCSISnapshotEarlyFrequentPolling(true))
	}

	if o.DisableInformerCache {
		deployOpts = append(deployOpts, WithDisableInformerCache(true))
	}

	if len(o.BackupRepoConfigMap) > 0 {
		deployOpts = append(deployOpts, WithBackupRepoConfigMap(o.BackupRepoConfigMap))
	}

	if len(o.RepoMaintenanceJobConfigMap) > 0 {
		deployOpts = append(deployOpts, WithRepoMaintenanceJobConfigMap(o.RepoMaintenanceJobConfigMap))
	}

	deploy := Deployment(o.Namespace, deployOpts...)

	if err := appendUnstructured(resources, deploy); err != nil {
		fmt.Printf("error appending Deployment %s: %s\n", deploy.GetName(), err.Error())
	}

	if o.UseNodeAgent || o.UseNodeAgentWindows {
		dsOpts := []podTemplateOption{
			WithAnnotations(o.PodAnnotations),
			WithLabels(o.PodLabels),
			WithImage(o.Image),
			WithResources(o.NodeAgentPodResources),
			WithSecret(secretPresent),
			WithServiceAccountName(serviceAccountName),
			WithNodeAgentDisableHostPath(o.NodeAgentDisableHostPath),
		}
		if len(o.Features) > 0 {
			dsOpts = append(dsOpts, WithFeatures(o.Features))
		}
		if o.PrivilegedNodeAgent {
			dsOpts = append(dsOpts, WithPrivilegedNodeAgent(true))
		}
		if len(o.NodeAgentConfigMap) > 0 {
			dsOpts = append(dsOpts, WithNodeAgentConfigMap(o.NodeAgentConfigMap))
		}

		if len(o.BackupRepoConfigMap) > 0 {
			dsOpts = append(dsOpts, WithBackupRepoConfigMap(o.BackupRepoConfigMap))
		}

		if len(o.KubeletRootDir) > 0 {
			dsOpts = append(dsOpts, WithKubeletRootDir(o.KubeletRootDir))
		}

		if o.NodeAgentPriorityClassName != "" {
			dsOpts = append(dsOpts, WithPriorityClassName(o.NodeAgentPriorityClassName))
		}

		if o.UseNodeAgent {
			ds := DaemonSet(o.Namespace, dsOpts...)
			if err := appendUnstructured(resources, ds); err != nil {
				fmt.Printf("error appending DaemonSet %s: %s\n", ds.GetName(), err.Error())
			}
		}

		if o.UseNodeAgentWindows {
			dsOpts = append(dsOpts, WithForWindows())

			dsWin := DaemonSet(o.Namespace, dsOpts...)
			if err := appendUnstructured(resources, dsWin); err != nil {
				fmt.Printf("error appending DaemonSet %s: %s\n", dsWin.GetName(), err.Error())
			}
		}
	}

	return resources
}
