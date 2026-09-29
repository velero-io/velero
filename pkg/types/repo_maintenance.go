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
	corev1api "k8s.io/api/core/v1"

	"github.com/vmware-tanzu/velero/pkg/util/kube"
)

type JobConfigs struct {
	// LoadAffinities is the config for repository maintenance job load affinity.
	LoadAffinities []*kube.LoadAffinity `json:"loadAffinity,omitempty"`

	// PodResources is the config for the CPU and memory resources setting.
	PodResources *kube.PodResources `json:"podResources,omitempty"`

	// KeepLatestMaintenanceJobs is the number of latest maintenance jobs to keep for the repository.
	KeepLatestMaintenanceJobs *int `json:"keepLatestMaintenanceJobs,omitempty"`

	// PriorityClassName is the priority class name for the maintenance job pod
	// Note: This is only read from the global configuration, not per-repository
	PriorityClassName string `json:"priorityClassName,omitempty"`

	// PodAnnotations are annotations to be added to maintenance job pods.
	// Note: This is only read from the global configuration, not per-repository
	PodAnnotations map[string]string `json:"podAnnotations,omitempty"`

	// PodLabels are labels to be added to maintenance job pods.
	// Note: This is only read from the global configuration, not per-repository
	PodLabels map[string]string `json:"podLabels,omitempty"`

	// Tolerations are tolerations to be added to repository maintenance job pods.
	// Note: This is only read from the global configuration, not per-repository
	// These are merged with (and deduplicated against) any Velero deployment tolerations
	// whose key is in the in-tree third-party toleration allowlist, and the default Windows toleration.
	Tolerations []corev1api.Toleration `json:"tolerations,omitempty"`
}
