/*
Copyright The Velero Contributors.

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

package types

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/vmware-tanzu/velero/pkg/util/kube"
)

type LoadConcurrency struct {
	// GlobalConfig specifies the concurrency number to all nodes for which per-node config is not specified
	GlobalConfig int `json:"globalConfig,omitempty"`

	// PerNodeConfig specifies the concurrency number to nodes matched by rules
	PerNodeConfig []RuledConfigs `json:"perNodeConfig,omitempty"`

	// PrepareQueueLength specifies the max number of loads that are under expose
	PrepareQueueLength int `json:"prepareQueueLength,omitempty"`
}

type LoadAffinity struct {
	// NodeSelector specifies the label selector to match nodes
	NodeSelector metav1.LabelSelector `json:"nodeSelector"`
}

type RuledConfigs struct {
	// NodeSelector specifies the label selector to match nodes
	NodeSelector metav1.LabelSelector `json:"nodeSelector"`

	// Number specifies the number value associated to the matched nodes
	Number int `json:"number"`
}

type BackupPVC struct {
	// StorageClass is the name of storage class to be used by the backupPVC
	StorageClass string `json:"storageClass,omitempty"`

	// ReadOnly sets the backupPVC's access mode as read only
	ReadOnly bool `json:"readOnly,omitempty"`

	// SPCNoRelabeling sets Spec.SecurityContext.SELinux.Type to "spc_t" for the pod mounting the backupPVC
	// ignored if ReadOnly is false
	SPCNoRelabeling bool `json:"spcNoRelabeling,omitempty"`

	// Annotations permits setting annotations for the backupPVC
	Annotations map[string]string `json:"annotations,omitempty"`

	// SecretNames is a list of secret names to copy from the source PVC namespace
	// to the Velero namespace before creating the backupPVC. The secrets are deleted
	// after the DataUpload completes. This is needed for CSI drivers that require
	// namespace-scoped secrets for volume provisioning (e.g., encrypted volumes).
	SecretNames []string `json:"secretNames,omitempty"`
}

type RestorePVC struct {
	// IgnoreDelayBinding indicates to ignore delay binding the restorePVC when it is in WaitForFirstConsumer mode
	IgnoreDelayBinding bool `json:"ignoreDelayBinding,omitempty"`
}

type CachePVC struct {
	// StorageClass specifies the storage class for cache PVC
	StorageClass string `json:"storageClass,omitempty"`

	// ResidentThresholdInMB specifies the minimum size of the backup data to create cache PVC
	ResidentThresholdInMB int64 `json:"residentThresholdInMB,omitempty"`
}

type CSISnapshotMetadataService struct {
	SAName string `json:"saName,omitempty"`
}

type NodeAgentConfigs struct {
	// LoadConcurrency is the config for data path load concurrency per node.
	LoadConcurrency *LoadConcurrency `json:"loadConcurrency,omitempty"`

	// LoadAffinity is the config for data path load affinity.
	LoadAffinity []*kube.LoadAffinity `json:"loadAffinity,omitempty"`

	// BackupPVCConfig is the config for backupPVC (intermediate PVC) of snapshot data movement
	BackupPVCConfig map[string]BackupPVC `json:"backupPVC,omitempty"`

	// RestoreVCConfig is the config for restorePVC (intermediate PVC) of generic restore
	RestorePVCConfig *RestorePVC `json:"restorePVC,omitempty"`

	// PodResources is the resource config for various types of pods launched by node-agent, i.e., data mover pods.
	PodResources *kube.PodResources `json:"podResources,omitempty"`

	// PriorityClassName is the priority class name for data mover pods created by the node agent
	PriorityClassName string `json:"priorityClassName,omitempty"`

	// PrivilegedFsBackup determines whether to create fs-backup pods as privileged pods
	PrivilegedFsBackup bool `json:"privilegedFsBackup,omitempty"`

	// CachePVCConfig is the config for cachePVC
	CachePVCConfig *CachePVC `json:"cachePVC,omitempty"`

	// PodAnnotations are annotations to be added to pods created by node-agent, i.e., data mover pods.
	PodAnnotations map[string]string `json:"podAnnotations,omitempty"`

	// PodLabels are labels to be added to pods created by node-agent, i.e., data mover pods.
	PodLabels map[string]string `json:"podLabels,omitempty"`

	// CSISnapshotMetadataServiceConfigs is the config for CSI snapshot metadata service
	CSISnapshotMetadataServiceConfigs *CSISnapshotMetadataService `json:"csiSnapshotMetadataServiceConfigs,omitempty"`
}
