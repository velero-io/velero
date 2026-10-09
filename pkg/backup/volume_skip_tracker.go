/*
Copyright 2018 the Velero contributors.

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

package backup

import (
	"sort"
	"sync"
)

type SkippedVolume struct {
	PVName       string   `json:"pvName"`
	PVCName      string   `json:"pvcName,omitempty"`
	PVCNamespace string   `json:"pvcNamespace,omitempty"`
	Reasons      []Reason `json:"reasons"`
}

func (s *SkippedVolume) SerializeSkipReasons() string {
	ret := ""
	for _, reason := range s.Reasons {
		ret = ret + reason.Approach + ": " + reason.Reason + ";"
	}
	return ret
}

type Reason struct {
	Approach string `json:"approach"`
	Reason   string `json:"reason"`
}

// skipVolumeTracker keeps track of volumes (PV/PVC) that have been skipped and the reason why they are skipped.
type skipVolumeTracker struct {
	*sync.RWMutex
	// volumes is a map of volume(PV/PVC) key to the list of reasons why it is skipped.
	// The reasons are stored in a map each key of the map is the backup approach, each approach can have one reason
	volumes map[string]map[string]string
	// includedVolumes is a set of volume key to be included in the backup, the element in this set should not be in the "volumes" map
	includedVolumes map[string]struct{}
	// volumeInfo is a map of volume key to SkippedVolume info
	volumeInfo map[string]SkippedVolume
}

const (
	podVolumeApproach       = "podvolume"
	csiSnapshotApproach     = "csiSnapshot"
	volumeSnapshotApproach  = "volumeSnapshot"
	vsphereSnapshotApproach = "vsphereSnapshot"
	anyApproach             = "any"
)

func NewSkipVolumeTracker() *skipVolumeTracker {
	return &skipVolumeTracker{
		RWMutex:         &sync.RWMutex{},
		volumes:         make(map[string]map[string]string),
		includedVolumes: make(map[string]struct{}),
		volumeInfo:      make(map[string]SkippedVolume),
	}
}

func getVolumeKey(pvName, pvcName, pvcNamespace string) string {
	if pvName != "" {
		return "pv:" + pvName
	}
	if pvcName != "" && pvcNamespace != "" {
		return "pvc:" + pvcNamespace + "/" + pvcName
	}
	return ""
}

// Track tracks the Volume(PV/PVC) with the specified name and the reason why it is skipped
func (pt *skipVolumeTracker) Track(pvName, pvcName, pvcNamespace, approach, reason string) {
	pt.Lock()
	defer pt.Unlock()
	key := getVolumeKey(pvName, pvcName, pvcNamespace)
	if key == "" || reason == "" {
		return
	}
	if _, ok := pt.includedVolumes[key]; ok {
		return
	}
	skipReasons := pt.volumes[key]
	if skipReasons == nil {
		skipReasons = make(map[string]string)
		pt.volumes[key] = skipReasons
	}
	if approach == "" {
		approach = anyApproach
	}
	skipReasons[approach] = reason
	pt.volumeInfo[key] = SkippedVolume{
		PVName:       pvName,
		PVCName:      pvcName,
		PVCNamespace: pvcNamespace,
	}
}

// Untrack removes the volume(pv/pvc) with the specified namespace and name.
// This func should be called when the volume is taken for snapshot, regardless native snapshot, CSI snapshot or fsb backup
// therefore, in one backup processed if a volume is Untracked once, it will not be tracked again.
func (pt *skipVolumeTracker) Untrack(pvName, pvcName, pvcNamespace string) {
	pt.Lock()
	defer pt.Unlock()
	key := getVolumeKey(pvName, pvcName, pvcNamespace)
	if key == "" {
		return
	}
	pt.includedVolumes[key] = struct{}{}
	delete(pt.volumes, key)
	delete(pt.volumeInfo, key)
}

// Summary returns the summary of the tracked volumes.
func (pt *skipVolumeTracker) Summary() []SkippedVolume {
	pt.RLock()
	defer pt.RUnlock()
	keys := make([]string, 0, len(pt.volumes))
	for key := range pt.volumes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	res := make([]SkippedVolume, 0, len(keys))
	for _, key := range keys {
		if skipReasons := pt.volumes[key]; len(skipReasons) > 0 {
			info := pt.volumeInfo[key]
			entry := SkippedVolume{
				PVName:       info.PVName,
				PVCName:      info.PVCName,
				PVCNamespace: info.PVCNamespace,
				Reasons:      make([]Reason, 0, len(skipReasons)),
			}
			approaches := make([]string, 0, len(skipReasons))
			for a := range skipReasons {
				approaches = append(approaches, a)
			}
			sort.Strings(approaches)
			for _, a := range approaches {
				entry.Reasons = append(entry.Reasons, Reason{
					Approach: a,
					Reason:   skipReasons[a],
				})
			}
			res = append(res, entry)
		}
	}
	return res
}
