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

	"github.com/cockroachdb/errors"
	"go.yaml.in/yaml/v3"
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
	Capacity     string            `yaml:"capacity,omitempty"`
	StorageClass []string          `yaml:"storageClass,omitempty"`
	NFS          *nFSVolumeSource  `yaml:"nfs,omitempty"`
	CSI          *csiVolumeSource  `yaml:"csi,omitempty"`
	VolumeTypes  []SupportedVolume `yaml:"volumeTypes,omitempty"`
	PVCLabels    map[string]string `yaml:"pvcLabels,omitempty"`
	PVCPhase     []string          `yaml:"pvcPhase,omitempty"`
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

	// TODO validate parameters
	return nil
}
