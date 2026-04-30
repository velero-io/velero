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

package resourcepolicies

import (
	"context"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
)

type VolumeActionType string

const (
	// currently only support configmap type of resource config
	ConfigmapRefType string = "configmap"
	// skip action implies the volume would be skipped from the backup operation
	Skip VolumeActionType = "skip"
	// fs-backup action implies that the volume would be backed up via file system copy method using the uploader(kopia) configured by the user
	FSBackup VolumeActionType = "fs-backup"
	// snapshot action can have 3 different meaning based on velero configuration and backup spec - cloud provider based snapshots, local csi snapshots and datamover snapshots
	Snapshot VolumeActionType = "snapshot"
	// custom action is used to identify a volume that will be handled by an external plugin. Velero will not snapshot or use fs-backup if action=="custom"
	Custom VolumeActionType = "custom"
)

// Action defined as one action for a specific way of backup
type Action struct {
	// Type defined specific type of action, currently only support 'skip'
	Type VolumeActionType `yaml:"type"`
	// Parameters defined map of parameters when executing a specific action
	Parameters map[string]any `yaml:"parameters,omitempty"`
}

// IncludeExcludePolicy defined policy to include or exclude resources based on the names
type IncludeExcludePolicy struct {
	// The following fields have the same semantics as those from the spec of backup.
	// Refer to the comment in the velerov1api.BackupSpec for more details.
	IncludedClusterScopedResources   []string `yaml:"includedClusterScopedResources"`
	ExcludedClusterScopedResources   []string `yaml:"excludedClusterScopedResources"`
	IncludedNamespaceScopedResources []string `yaml:"includedNamespaceScopedResources"`
	ExcludedNamespaceScopedResources []string `yaml:"excludedNamespaceScopedResources"`
}

func (p *IncludeExcludePolicy) Validate() error {
	if err := p.validateIncludeExclude(p.IncludedClusterScopedResources, p.ExcludedClusterScopedResources); err != nil {
		return err
	}
	return p.validateIncludeExclude(p.IncludedNamespaceScopedResources, p.ExcludedNamespaceScopedResources)
}

func (p *IncludeExcludePolicy) validateIncludeExclude(includesList, excludesList []string) error {
	includes := sets.NewString(includesList...)
	excludes := sets.NewString(excludesList...)

	if includes.Has("*") || excludes.Has("*") {
		return fmt.Errorf("cannot use '*' in includes or excludes filters in the policy")
	}
	for _, itm := range excludes.List() {
		if includes.Has(itm) {
			return fmt.Errorf("excludes list cannot contain an item in the includes list: %s", itm)
		}
	}
	return nil
}

// VolumePolicy defined policy to conditions to match Volumes and related action to handle matched Volumes
type VolumePolicy struct {
	// Conditions defined list of conditions to match Volumes
	Conditions map[string]any `yaml:"conditions"`
	Action     Action         `yaml:"action"`
}

// ResourcePolicies currently defined slice of volume policies to handle backup
type ResourcePolicies struct {
	Version              string                `yaml:"version"`
	VolumePolicies       []VolumePolicy        `yaml:"volumePolicies"`
	IncludeExcludePolicy *IncludeExcludePolicy `yaml:"includeExcludePolicy"`
	// we may support other resource policies in the future, and they could be added separately
	// OtherResourcePolicies []OtherResourcePolicy
}

type Policies struct {
	version              string
	volumePolicies       []volPolicy
	includeExcludePolicy *IncludeExcludePolicy
	// OtherPolicies
}

func unmarshalResourcePolicies(yamlData *string) (*ResourcePolicies, error) {
	resPolicies := &ResourcePolicies{}
	err := decodeStruct(strings.NewReader(*yamlData), resPolicies)
	if err != nil {
		return nil, fmt.Errorf("failed to decode yaml data into resource policies  %v", err)
	}

	for _, vp := range resPolicies.VolumePolicies {
		if raw, ok := vp.Conditions["pvcLabels"]; ok {
			switch raw.(type) {
			case map[string]any, map[string]string:
			default:
				return nil, fmt.Errorf("pvcLabels must be a map of string to string, got %T", raw)
			}
		}
	}
	return resPolicies, nil
}

func (p *Policies) BuildPolicy(resPolicies *ResourcePolicies) error {
	for _, vp := range resPolicies.VolumePolicies {
		con, err := unmarshalVolConditions(vp.Conditions)
		if err != nil {
			return errors.WithStack(err)
		}
		volCap, err := parseCapacity(con.Capacity)
		if err != nil {
			return errors.WithStack(err)
		}
		var volP volPolicy
		volP.action = vp.Action
		volP.conditions = append(volP.conditions, &capacityCondition{capacity: *volCap})
		volP.conditions = append(volP.conditions, &storageClassCondition{storageClass: con.StorageClass})
		volP.conditions = append(volP.conditions, &nfsCondition{nfs: con.NFS})
		volP.conditions = append(volP.conditions, &csiCondition{csi: con.CSI})
		volP.conditions = append(volP.conditions, &volumeTypeCondition{volumeTypes: con.VolumeTypes})
		if len(con.PVCLabels) > 0 {
			volP.conditions = append(volP.conditions, &pvcLabelsCondition{labels: con.PVCLabels})
		}
		if len(con.PVCPhase) > 0 {
			volP.conditions = append(volP.conditions, &pvcPhaseCondition{phases: con.PVCPhase})
		}
		p.volumePolicies = append(p.volumePolicies, volP)
	}

	// Other resource policies

	p.version = resPolicies.Version
	p.includeExcludePolicy = resPolicies.IncludeExcludePolicy
	return nil
}

func (p *Policies) match(res *structuredVolume) *Action {
	for _, policy := range p.volumePolicies {
		isAllMatch := false
		for _, con := range policy.conditions {
			if !con.match(res) {
				isAllMatch = false
				break
			}
			isAllMatch = true
		}
		if isAllMatch {
			return &policy.action
		}
	}
	return nil
}

func (p *Policies) GetMatchAction(res any) (*Action, error) {
	data, ok := res.(VolumeFilterData)
	if !ok {
		return nil, errors.New("failed to convert input to VolumeFilterData")
	}

	volume := &structuredVolume{}
	switch {
	case data.PersistentVolume != nil:
		volume.parsePV(data.PersistentVolume)
		if data.PVC != nil {
			volume.parsePVC(data.PVC)
		}
	case data.PodVolume != nil:
		volume.parsePodVolume(data.PodVolume)
		if data.PVC != nil {
			volume.parsePVC(data.PVC)
		}
	case data.PVC != nil:
		// Handle PVC-only scenarios (e.g., unbound PVCs)
		volume.parsePVC(data.PVC)
	default:
		return nil, errors.New("failed to convert object")
	}

	return p.match(volume), nil
}

func (p *Policies) Validate() error {
	if p.version != currentSupportDataVersion {
		return fmt.Errorf("incompatible version number %s with supported version %s", p.version, currentSupportDataVersion)
	}

	for _, policy := range p.volumePolicies {
		if err := policy.action.validate(); err != nil {
			return errors.WithStack(err)
		}
		for _, con := range policy.conditions {
			if err := con.validate(); err != nil {
				return errors.WithStack(err)
			}
		}
	}

	if p.GetIncludeExcludePolicy() != nil {
		if err := p.GetIncludeExcludePolicy().Validate(); err != nil {
			return errors.WithStack(err)
		}
	}

	return nil
}

func (p *Policies) GetIncludeExcludePolicy() *IncludeExcludePolicy {
	return p.includeExcludePolicy
}

func GetResourcePoliciesFromBackup(
	backup velerov1api.Backup,
	client crclient.Client,
	logger logrus.FieldLogger,
) (resourcePolicies *Policies, err error) {
	if backup.Spec.ResourcePolicy != nil &&
		strings.EqualFold(backup.Spec.ResourcePolicy.Kind, ConfigmapRefType) {
		policiesConfigMap := &corev1api.ConfigMap{}
		err = client.Get(
			context.Background(),
			crclient.ObjectKey{Namespace: backup.Namespace, Name: backup.Spec.ResourcePolicy.Name},
			policiesConfigMap,
		)
		if err != nil {
			logger.Errorf("Fail to get ResourcePolicies %s ConfigMap with error %s.",
				backup.Namespace+"/"+backup.Spec.ResourcePolicy.Name, err.Error())
			return nil, fmt.Errorf("fail to get ResourcePolicies %s ConfigMap with error %s",
				backup.Namespace+"/"+backup.Spec.ResourcePolicy.Name, err.Error())
		}
		resourcePolicies, err = getResourcePoliciesFromConfig(policiesConfigMap)
		if err != nil {
			logger.Errorf("Fail to read ResourcePolicies from ConfigMap %s with error %s.",
				backup.Namespace+"/"+backup.Name, err.Error())
			return nil, fmt.Errorf("fail to read the ResourcePolicies from ConfigMap %s with error %s",
				backup.Namespace+"/"+backup.Name, err.Error())
		} else if err = resourcePolicies.Validate(); err != nil {
			logger.Errorf("Fail to validate ResourcePolicies in ConfigMap %s with error %s.",
				backup.Namespace+"/"+backup.Name, err.Error())
			return nil, fmt.Errorf("fail to validate ResourcePolicies in ConfigMap %s with error %s",
				backup.Namespace+"/"+backup.Name, err.Error())
		}
	}

	return resourcePolicies, nil
}

func getResourcePoliciesFromConfig(cm *corev1api.ConfigMap) (*Policies, error) {
	if cm == nil {
		return nil, fmt.Errorf("could not parse config from nil configmap")
	}
	if len(cm.Data) != 1 {
		return nil, fmt.Errorf("illegal resource policies %s/%s configmap", cm.Namespace, cm.Name)
	}

	var yamlData string
	for _, v := range cm.Data {
		yamlData = v
	}

	resPolicies, err := unmarshalResourcePolicies(&yamlData)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	policies := &Policies{}
	if err := policies.BuildPolicy(resPolicies); err != nil {
		return nil, errors.WithStack(err)
	}

	return policies, nil
}
