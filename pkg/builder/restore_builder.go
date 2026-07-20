/*
Copyright 2019 the Velero contributors.

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

package builder

import (
	"time"

	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
)

// RestoreBuilder builds Restore objects.
type RestoreBuilder struct {
	object *velerov1api.Restore
}

// ForRestore is the constructor for a RestoreBuilder.
func ForRestore(ns, name string) *RestoreBuilder {
	return &RestoreBuilder{
		object: &velerov1api.Restore{
			TypeMeta: metav1.TypeMeta{
				APIVersion: velerov1api.SchemeGroupVersion.String(),
				Kind:       "Restore",
			},
			ObjectMeta: metav1.ObjectMeta{
				Namespace: ns,
				Name:      name,
			},
		},
	}
}

// Result returns the built Restore.
func (b *RestoreBuilder) Result() *velerov1api.Restore {
	return b.object
}

// ObjectMeta applies functional options to the Restore's ObjectMeta.
func (b *RestoreBuilder) ObjectMeta(opts ...ObjectMetaOpt) *RestoreBuilder {
	for _, opt := range opts {
		opt(b.object)
	}

	return b
}

// Backup sets the Restore's backup name.
func (b *RestoreBuilder) Backup(name string) *RestoreBuilder {
	b.object.Spec.BackupName = name
	return b
}

// Schedule sets the Restore's schedule name.
func (b *RestoreBuilder) Schedule(name string) *RestoreBuilder {
	b.object.Spec.ScheduleName = name
	return b
}

// IncludedNamespaces appends to the Restore's included namespaces.
func (b *RestoreBuilder) IncludedNamespaces(namespaces ...string) *RestoreBuilder {
	b.object.Spec.IncludedNamespaces = append(b.object.Spec.IncludedNamespaces, namespaces...)
	return b
}

// ExcludedNamespaces appends to the Restore's excluded namespaces.
func (b *RestoreBuilder) ExcludedNamespaces(namespaces ...string) *RestoreBuilder {
	b.object.Spec.ExcludedNamespaces = append(b.object.Spec.ExcludedNamespaces, namespaces...)
	return b
}

// IncludedResources appends to the Restore's included resources.
func (b *RestoreBuilder) IncludedResources(resources ...string) *RestoreBuilder {
	b.object.Spec.IncludedResources = append(b.object.Spec.IncludedResources, resources...)
	return b
}

// ExcludedResources appends to the Restore's excluded resources.
func (b *RestoreBuilder) ExcludedResources(resources ...string) *RestoreBuilder {
	b.object.Spec.ExcludedResources = append(b.object.Spec.ExcludedResources, resources...)
	return b
}

// ExistingResourcePolicy sets the Restore's resource policy.
func (b *RestoreBuilder) ExistingResourcePolicy(policy string) *RestoreBuilder {
	b.object.Spec.ExistingResourcePolicy = velerov1api.ResourcePolicyType(policy)
	return b
}

// ExistingVolumeDataPolicy sets the Restore's volume data policy.
func (b *RestoreBuilder) ExistingVolumeDataPolicy(policy string) *RestoreBuilder {
	b.object.Spec.ExistingVolumeDataPolicy = velerov1api.VolumeDataPolicyType(policy)
	return b
}

// IncludeClusterResources sets the Restore's "include cluster resources" flag.
func (b *RestoreBuilder) IncludeClusterResources(val bool) *RestoreBuilder {
	b.object.Spec.IncludeClusterResources = &val
	return b
}

// LabelSelector sets the Restore's label selector.
func (b *RestoreBuilder) LabelSelector(selector *metav1.LabelSelector) *RestoreBuilder {
	b.object.Spec.LabelSelector = selector
	return b
}

// OrLabelSelector sets the Restore's orLabelSelector set.
func (b *RestoreBuilder) OrLabelSelector(orSelectors []*metav1.LabelSelector) *RestoreBuilder {
	b.object.Spec.OrLabelSelectors = orSelectors
	return b
}

// NamespaceMappings sets the Restore's namespace mappings.
func (b *RestoreBuilder) NamespaceMappings(mapping ...string) *RestoreBuilder {
	if b.object.Spec.NamespaceMapping == nil {
		b.object.Spec.NamespaceMapping = make(map[string]string)
	}

	if len(mapping)%2 != 0 {
		panic("mapping must contain an even number of values")
	}

	for i := 0; i < len(mapping); i += 2 {
		b.object.Spec.NamespaceMapping[mapping[i]] = mapping[i+1]
	}

	return b
}

// Phase sets the Restore's phase.
func (b *RestoreBuilder) Phase(phase velerov1api.RestorePhase) *RestoreBuilder {
	b.object.Status.Phase = phase
	return b
}

// RestorePVs sets the Restore's restore PVs.
func (b *RestoreBuilder) RestorePVs(val bool) *RestoreBuilder {
	b.object.Spec.RestorePVs = &val
	return b
}

// PreserveNodePorts sets the Restore's preserved NodePorts.
func (b *RestoreBuilder) PreserveNodePorts(val bool) *RestoreBuilder {
	b.object.Spec.PreserveNodePorts = &val
	return b
}

// StartTimestamp sets the Restore's start timestamp.
func (b *RestoreBuilder) StartTimestamp(val time.Time) *RestoreBuilder {
	b.object.Status.StartTimestamp = &metav1.Time{Time: val}
	return b
}

// CompletionTimestamp sets the Restore's completion timestamp.
func (b *RestoreBuilder) CompletionTimestamp(val time.Time) *RestoreBuilder {
	b.object.Status.CompletionTimestamp = &metav1.Time{Time: val}
	return b
}

// ItemOperationTimeout sets the Restore's ItemOperationTimeout
func (b *RestoreBuilder) ItemOperationTimeout(timeout time.Duration) *RestoreBuilder {
	b.object.Spec.ItemOperationTimeout.Duration = timeout
	return b
}

// ResourcePoliciesConfigmap sets the Restore's resource policies configmap.
func (b *RestoreBuilder) ResourcePoliciesConfigmap(name string) *RestoreBuilder {
	b.object.Spec.ResourcePolicy = &corev1api.TypedLocalObjectReference{
		Kind: "configmap",
		Name: name,
	}
	return b
}
