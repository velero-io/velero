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
	"bytes"
	"fmt"
	"slices"
	"strings"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cockroachdb/errors"
	"go.yaml.in/yaml/v3"
	corev1api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

type volPolicy struct {
	action     Action
	conditions []volumeCondition
}

type volumeCondition interface {
	match(v *structuredVolume) bool
	validate() error
}

// capacity consist of the lower and upper boundary
type capacity struct {
	lower resource.Quantity
	upper resource.Quantity
}

type structuredVolume struct {
	capacity       resource.Quantity
	storageClass   string
	nfs            *nFSVolumeSource
	csi            *csiVolumeSource
	volumeType     SupportedVolume
	pvcLabels      map[string]string
	pvcPhase       string
	pvcVolumeMode  string
	pvcAccessModes []string
}

func (s *structuredVolume) parsePV(pv *corev1api.PersistentVolume) {
	s.capacity = *pv.Spec.Capacity.Storage()
	s.storageClass = pv.Spec.StorageClassName
	nfs := pv.Spec.NFS
	if nfs != nil {
		s.nfs = &nFSVolumeSource{Server: nfs.Server, Path: nfs.Path}
	}

	csi := pv.Spec.CSI
	if csi != nil {
		s.csi = &csiVolumeSource{Driver: csi.Driver, VolumeAttributes: csi.VolumeAttributes}
	}

	s.volumeType = getVolumeTypeFromPV(pv)
}

func (s *structuredVolume) parsePVC(pvc *corev1api.PersistentVolumeClaim) {
	if pvc != nil {
		if len(pvc.GetLabels()) > 0 {
			s.pvcLabels = pvc.Labels
		}
		s.pvcPhase = string(pvc.Status.Phase)
		if pvc.Spec.VolumeMode != nil {
			s.pvcVolumeMode = string(*pvc.Spec.VolumeMode)
		}
		if len(pvc.Spec.AccessModes) > 0 {
			s.pvcAccessModes = make([]string, 0, len(pvc.Spec.AccessModes))
			for _, accessMode := range pvc.Spec.AccessModes {
				s.pvcAccessModes = append(s.pvcAccessModes, string(accessMode))
			}
		}
	}
}

func (s *structuredVolume) parsePodVolume(vol *corev1api.Volume) {
	nfs := vol.NFS
	if nfs != nil {
		s.nfs = &nFSVolumeSource{Server: nfs.Server, Path: nfs.Path}
	}

	csi := vol.CSI
	if csi != nil {
		s.csi = &csiVolumeSource{Driver: csi.Driver, VolumeAttributes: csi.VolumeAttributes}
	}

	s.volumeType = getVolumeTypeFromVolume(vol)
}

// pvcLabelsCondition defines a condition that matches if the PVC's labels contain all the provided key/value pairs.
type pvcLabelsCondition struct {
	labels map[string]string
}

func (c *pvcLabelsCondition) match(v *structuredVolume) bool {
	// No labels specified: always match.
	if len(c.labels) == 0 {
		return true
	}
	if v.pvcLabels == nil {
		return false
	}
	selector := labels.SelectorFromSet(c.labels)
	return selector.Matches(labels.Set(v.pvcLabels))
}

func (c *pvcLabelsCondition) validate() error {
	return nil
}

// pvcPhaseCondition defines a condition that matches if the PVC's phase matches any of the provided phases.
type pvcPhaseCondition struct {
	phases []string
}

func (c *pvcPhaseCondition) match(v *structuredVolume) bool {
	// No phases specified: always match.
	if len(c.phases) == 0 {
		return true
	}
	if v.pvcPhase == "" {
		return false
	}
	return slices.Contains(c.phases, v.pvcPhase)
}

func (c *pvcPhaseCondition) validate() error {
	return nil
}

// pvcVolumeModeCondition defines a condition that matches if the PVC's volume mode matches the provided volume mode.
type pvcVolumeModeCondition struct {
	volumeMode string
}

func (c *pvcVolumeModeCondition) match(v *structuredVolume) bool {
	// No volume mode specified: always match.
	if c.volumeMode == "" {
		return true
	}

	// Here allows unknown strings for forward compatibility. If Kubernetes adds another volume mode later,
	// Velero would not reject the policy just because the string is unfamiliar.
	return v.pvcVolumeMode == c.volumeMode
}

func (c *pvcVolumeModeCondition) validate() error {
	return nil
}

// pvcAccessModesCondition defines a condition that matches if the PVC has exactly the provided access modes.
type pvcAccessModesCondition struct {
	accessModes []string
}

func (c *pvcAccessModesCondition) match(v *structuredVolume) bool {
	// No access modes specified: always match.
	if len(c.accessModes) == 0 {
		return true
	}

	if len(v.pvcAccessModes) != len(c.accessModes) {
		return false
	}

	return sets.New(c.accessModes...).Equal(sets.New(v.pvcAccessModes...))
}

func (c *pvcAccessModesCondition) validate() error {
	return nil
}

type capacityCondition struct {
	capacity capacity
}

func (c *capacityCondition) match(v *structuredVolume) bool {
	return c.capacity.isInRange(v.capacity)
}

type storageClassCondition struct {
	storageClass []string
}

func (s *storageClassCondition) match(v *structuredVolume) bool {
	if len(s.storageClass) == 0 {
		return true
	}

	if v.storageClass == "" {
		return false
	}

	for _, sc := range s.storageClass {
		if v.storageClass == sc {
			return true
		}
	}

	return false
}

type nfsCondition struct {
	nfs *nFSVolumeSource
}

func (c *nfsCondition) match(v *structuredVolume) bool {
	if c.nfs == nil {
		return true
	}
	if v.nfs == nil {
		return false
	}

	if c.nfs.Path == "" {
		if c.nfs.Server == "" { // match nfs: {}
			return v.nfs != nil
		}
		if c.nfs.Server != v.nfs.Server {
			return false
		}
		return true
	}
	if c.nfs.Path != v.nfs.Path {
		return false
	}
	if c.nfs.Server == "" {
		return true
	}
	if c.nfs.Server != v.nfs.Server {
		return false
	}
	return true
}

type csiCondition struct {
	csi *csiVolumeSource
}

func (c *csiCondition) match(v *structuredVolume) bool {
	if c.csi == nil {
		return true
	}

	if c.csi.Driver == "" { // match csi: {}
		return v.csi != nil
	}

	if v.csi == nil {
		return false
	}

	if c.csi.Driver != v.csi.Driver {
		return false
	}

	if len(c.csi.VolumeAttributes) == 0 {
		return true
	}

	if len(v.csi.VolumeAttributes) == 0 {
		return false
	}

	for key, value := range c.csi.VolumeAttributes {
		if value != v.csi.VolumeAttributes[key] {
			return false
		}
	}

	return true
}

// parseCapacity parse string into capacity format
func parseCapacity(cap string) (*capacity, error) {
	if cap == "" {
		cap = ","
	}
	capacities := strings.Split(cap, ",")
	var quantities []resource.Quantity
	if len(capacities) != 2 {
		return nil, fmt.Errorf("wrong format of Capacity %v", cap)
	}

	for _, v := range capacities {
		if strings.TrimSpace(v) == "" {
			// case similar "10Gi,"
			// if empty, the quantity will assigned with 0
			quantities = append(quantities, *resource.NewQuantity(int64(0), resource.DecimalSI))
		} else {
			quantity, err := resource.ParseQuantity(strings.TrimSpace(v))
			if err != nil {
				return nil, fmt.Errorf("wrong format of Capacity %v with err %v", v, err)
			}
			quantities = append(quantities, quantity)
		}
	}

	return &capacity{lower: quantities[0], upper: quantities[1]}, nil
}

// isInRange returns true if the quantity y is in range of capacity, or it returns false
func (c *capacity) isInRange(y resource.Quantity) bool {
	if c.lower.IsZero() && c.upper.Cmp(y) >= 0 {
		// [0, a] y
		return true
	}
	if c.upper.IsZero() && c.lower.Cmp(y) <= 0 {
		// [b, 0] y
		return true
	}
	if !c.lower.IsZero() && !c.upper.IsZero() {
		// [a, b] y
		return c.lower.Cmp(y) <= 0 && c.upper.Cmp(y) >= 0
	}
	return false
}

// unmarshalVolConditions parse map[string]any into volumeConditions format
// and validate key fields of the map.
func unmarshalVolConditions(con map[string]any) (*volumeConditions, error) {
	volConditons := &volumeConditions{}
	buffer := new(bytes.Buffer)
	err := yaml.NewEncoder(buffer).Encode(con)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encode volume conditions")
	}

	if err := decodeStruct(buffer, volConditons); err != nil {
		return nil, errors.Wrap(err, "failed to decode volume conditions")
	}
	return volConditons, nil
}
