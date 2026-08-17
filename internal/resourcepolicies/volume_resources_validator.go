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
	"fmt"
	"io"
	"strings"

	"github.com/cockroachdb/errors"
	"go.yaml.in/yaml/v3"

	datamover "github.com/velero-io/velero/pkg/util/datamover"
)

const currentSupportDataVersion = "v1"

type csiVolumeSource struct {
	Driver string `yaml:"driver,omitempty"`
	// CSI volume attributes
	VolumeAttributes map[string]string `yaml:"volumeAttributes,omitempty"`
}

type nFSVolumeSource struct {
	// Server is the hostname or IP address of the NFS server
	Server string `yaml:"server,omitempty"`
	// Path is the exported NFS share
	Path string `yaml:"path,omitempty"`
}

// volumeConditions defined the current format of conditions we parsed
type volumeConditions struct {
	Capacity       string            `yaml:"capacity,omitempty"`
	StorageClass   []string          `yaml:"storageClass,omitempty"`
	NFS            *nFSVolumeSource  `yaml:"nfs,omitempty"`
	CSI            *csiVolumeSource  `yaml:"csi,omitempty"`
	VolumeTypes    []SupportedVolume `yaml:"volumeTypes,omitempty"`
	PVCLabels      map[string]string `yaml:"pvcLabels,omitempty"`
	PVCPhase       []string          `yaml:"pvcPhase,omitempty"`
	PVCVolumeMode  string            `yaml:"pvcVolumeMode,omitempty"`
	PVCAccessModes []string          `yaml:"pvcAccessModes,omitempty"`
}

func (c *capacityCondition) validate() error {
	// [0, a]
	// [a, b]
	// [b, 0]
	// ==> low <= upper or upper is zero
	if (c.capacity.upper.Cmp(c.capacity.lower) >= 0) ||
		(!c.capacity.lower.IsZero() && c.capacity.upper.IsZero()) {
		return nil
	}
	return errors.Errorf("illegal values for capacity %v", c.capacity)
}

func (s *storageClassCondition) validate() error {
	// validate by yamlv3
	return nil
}

func (c *nfsCondition) validate() error {
	// validate by yamlv3
	return nil
}

func (c *csiCondition) validate() error {
	if c != nil && c.csi != nil && c.csi.Driver == "" && c.csi.VolumeAttributes != nil {
		return errors.New("csi driver should not be empty when filtering by volume attributes")
	}

	return nil
}

// decodeStruct restric validate the keys in decoded mappings to exist as fields in the struct being decoded into
func decodeStruct(r io.Reader, s any) error {
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	return dec.Decode(s)
}

// validate check action format
func (a *Action) validate() error {
	// validate Type
	valid := false
	if a.Type == Skip || a.Type == Snapshot || a.Type == FSBackup || a.Type == Custom {
		valid = true
	}
	if !valid {
		return fmt.Errorf("invalid action type %s", a.Type)
	}

	// validate parameters
	if raw, ok := a.Parameters[DataMoverParameter]; ok {
		// the dataMover parameter is only meaningful for the snapshot action
		if a.Type != Snapshot {
			return fmt.Errorf("parameter %q is only supported for the %q action, but the action type is %q",
				DataMoverParameter, Snapshot, a.Type)
		}
		dataMover, ok := raw.(string)
		if !ok {
			return fmt.Errorf("parameter %q must be a string, got %T", DataMoverParameter, raw)
		}
		if _, ok := validDataMovers[dataMover]; !ok {
			return fmt.Errorf("invalid %q value %q, valid values are %q, %q, %q",
				DataMoverParameter, dataMover, datamover.DataMoverTypeVelero, datamover.DataMoverTypeVeleroFs, datamover.DataMoverTypeVeleroBlock)
		}
	}

	if raw, ok := a.Parameters[SnapshotClassParameter]; ok {
		if a.Type != Snapshot {
			return fmt.Errorf("parameter %q is only supported for the %q action, but the action type is %q",
				SnapshotClassParameter, Snapshot, a.Type)
		}
		snapshotClass, ok := raw.(string)
		if !ok {
			return fmt.Errorf("parameter %q must be a string, got %T", SnapshotClassParameter, raw)
		}
		if snapshotClass == "" {
			return fmt.Errorf("parameter %q must not be empty", SnapshotClassParameter)
		}
	}

	if _, ok := a.Parameters[ExcludeParameter]; ok {
		return fmt.Errorf("parameter %q is not supported in action.parameters; declare %q at the volume policy rule level", ExcludeParameter, ExcludeParameter)
	}

	if _, ok := a.Parameters[InheritExcludesParameter]; ok {
		return fmt.Errorf("parameter %q is not supported in action.parameters; declare %q at the volume policy rule level", InheritExcludesParameter, InheritExcludesParameter)
	}

	return nil
}

func (v *volPolicy) validate() error {
	if v.exclude != nil {
		for _, pat := range v.exclude {
			if strings.TrimSpace(pat) == "" {
				return fmt.Errorf("%s must not contain empty entries", ExcludeParameter)
			}
		}
		if err := v.validateExcludeForAction(); err != nil {
			return err
		}
	}
	if v.inheritExcludes != nil {
		if err := v.validateInheritExcludesForAction(); err != nil {
			return err
		}
	}
	return nil
}

func (v *volPolicy) validateExcludeForAction() error {
	switch v.action.Type {
	case Skip, Custom:
		return fmt.Errorf("%s is not supported for action type %q", ExcludeParameter, v.action.Type)
	case FSBackup:
		return nil
	case Snapshot:
		dataMover, err := v.action.GetDataMover()
		if err != nil {
			return err
		}
		// GetDataMover already maps empty/"velero" to the default built-in (FS today).
		if dataMover == datamover.DataMoverTypeVeleroBlock {
			return fmt.Errorf("%s is not supported for data mover %q", ExcludeParameter, dataMover)
		}
		return nil
	default:
		return fmt.Errorf("%s is not supported for action type %q", ExcludeParameter, v.action.Type)
	}
}

func (v *volPolicy) validateInheritExcludesForAction() error {
	switch v.action.Type {
	case Skip, Custom:
		return fmt.Errorf("%s is not supported for action type %q", InheritExcludesParameter, v.action.Type)
	case FSBackup:
		return nil
	case Snapshot:
		dataMover, err := v.action.GetDataMover()
		if err != nil {
			return err
		}
		if dataMover == datamover.DataMoverTypeVeleroBlock {
			return fmt.Errorf("%s is not supported for data mover %q", InheritExcludesParameter, dataMover)
		}
		return nil
	default:
		return fmt.Errorf("%s is not supported for action type %q", InheritExcludesParameter, v.action.Type)
	}
}
