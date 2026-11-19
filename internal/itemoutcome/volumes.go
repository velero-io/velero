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

package itemoutcome

import (
	"fmt"
	"sort"
	"strings"

	"github.com/velero-io/velero/pkg/kuberesource"
)

// ApplyVolumes folds the authoritative volume verdict into every item row that
// shares the volume identity.
func ApplyVolumes(items *ItemOutcomes, vols []VolumeOutcome) {
	if items == nil {
		return
	}

	grouped := make(map[volumeIdentity][]VolumeAttempt, len(vols))
	for _, vol := range vols {
		if vol.Result == "" && !vol.Skipped {
			// Nothing was concluded about this volume; recording it would only
			// add a row field with no verdict.
			continue
		}
		key := identityOf(vol)
		grouped[key] = append(grouped[key], VolumeAttempt{
			Method:        vol.Method,
			Result:        vol.Result,
			Skipped:       vol.Skipped,
			SkippedReason: vol.SkippedReason,
		})
	}

	pvcRows := make(map[Key]*ItemOutcome)
	pvRows := make(map[string]*ItemOutcome)
	for i := range items.Items {
		row := &items.Items[i]
		switch row.GroupResource {
		case kuberesource.PersistentVolumeClaims.String():
			pvcRows[KeyOf(*row)] = row
		case kuberesource.PersistentVolumes.String():
			pvRows[row.Name] = row
		}
	}

	// Sorted so two runs against the same input append messages in the same
	// order; the map above has no order of its own.
	keys := make([]volumeIdentity, 0, len(grouped))
	for key := range grouped {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })

	for _, key := range keys {
		// One disk can back both a PVC item and a PV item. The structured
		// summary belongs to one of them, but the verdict belongs to both: a
		// consumer must never see the PVC say Succeeded while its PV says
		// Skipped, or the reverse.
		var owner *ItemOutcome
		var rows []*ItemOutcome
		if key.pvcName != "" {
			if row := pvcRows[Key{
				GroupResource: kuberesource.PersistentVolumeClaims.String(),
				Namespace:     key.pvcNamespace,
				Name:          key.pvcName,
			}]; row != nil {
				owner = row
				rows = append(rows, row)
			}
		}
		if key.pvName != "" {
			if row := pvRows[key.pvName]; row != nil {
				if owner == nil {
					owner = row
				}
				rows = append(rows, row)
			}
		}
		if owner == nil {
			continue
		}

		// Capture-time attempts can sit on either row. They are evidence about
		// the same disk, so collect all of them for the summary and clear them
		// from every row the fold covers.
		var captureAttempts []VolumeAttempt
		for _, row := range rows {
			captureAttempts = append(captureAttempts, row.VolumeAttempts...)
			row.VolumeAttempts = nil
		}

		attempts := dedupeVolumeAttempts(grouped[key])
		if len(captureAttempts) > 0 {
			attempts = mergeVolumeAttemptLists(attempts, captureAttempts)
		}
		sortVolumeAttempts(attempts)
		attempts, dropped := capVolumeAttempts(attempts)
		vol := summarizeVolumeAttempts(key, attempts, dropped)

		final := vol
		owner.Volume = &final

		switch vol.Result {
		case VolumeResultFailed:
			msg := volumeFailureMessage(vol)
			for _, row := range rows {
				row.Outcome = OutcomeFailed
				row.Messages = appendTerminalMessage(row.Messages, msg)
			}
		case VolumeResultSucceeded:
			// A skipped row is the normal shape when the fs path opted out and
			// another method, usually a CSI snapshot, captured the same volume.
			// The summary says the disk was captured, so keep the row from
			// reading as "not backed up". Only a skip recorded by a volume path
			// is eligible: an item excluded by a BIA or a filter did not become
			// backed up because its disk was captured elsewhere.
			for _, row := range rows {
				if row.Outcome == OutcomeSkipped && row.SkippedByVolume {
					row.Outcome = OutcomeSucceeded
				}
			}
		}
	}
}

// volumeIdentity identifies one volume across its PVC and PV rows.
type volumeIdentity struct {
	pvcNamespace string
	pvcName      string
	pvName       string
}

func identityOf(vol VolumeOutcome) volumeIdentity {
	return volumeIdentity{pvcNamespace: vol.PVCNamespace, pvcName: vol.PVCName, pvName: vol.PVName}
}

func (k volumeIdentity) String() string {
	return k.pvcNamespace + "/" + k.pvcName + "/" + k.pvName
}

// dedupeVolumeAttempts removes exact duplicate attempts.
func dedupeVolumeAttempts(attempts []VolumeAttempt) []VolumeAttempt {
	seen := make(map[VolumeAttempt]struct{}, len(attempts))
	out := make([]VolumeAttempt, 0, len(attempts))
	for _, attempt := range attempts {
		if _, ok := seen[attempt]; ok {
			continue
		}
		seen[attempt] = struct{}{}
		out = append(out, attempt)
	}
	return out
}

// mergeVolumeAttemptLists folds capture-time attempts into volume-info attempts.
func mergeVolumeAttemptLists(base, extra []VolumeAttempt) []VolumeAttempt {
	out := dedupeVolumeAttempts(base)
	for _, attempt := range dedupeVolumeAttempts(extra) {
		if attempt.Result == "" && attempt.Skipped && attempt.Method != "" {
			replaced := false
			for i := range out {
				if out[i].Result == "" && out[i].Skipped && out[i].Method == "" && out[i].SkippedReason == attempt.SkippedReason {
					out[i] = attempt
					replaced = true
					break
				}
			}
			if replaced {
				continue
			}
		}
		if attempt.Result == "" && attempt.Skipped && attempt.Method == "" {
			named := false
			for _, existing := range out {
				if existing.Result == "" && existing.Skipped && existing.Method != "" && existing.SkippedReason == attempt.SkippedReason {
					named = true
					break
				}
			}
			if named {
				continue
			}
		}
		out = append(out, attempt)
	}
	return dedupeVolumeAttempts(out)
}

// sortVolumeAttempts orders attempts worst first, then by method and reason.
func sortVolumeAttempts(attempts []VolumeAttempt) {
	sort.Slice(attempts, func(i, j int) bool {
		ri, rj := volumeResultRank(attempts[i].Result), volumeResultRank(attempts[j].Result)
		if ri != rj {
			return ri > rj
		}
		if attempts[i].Method != attempts[j].Method {
			return attempts[i].Method < attempts[j].Method
		}
		if attempts[i].Skipped != attempts[j].Skipped {
			return attempts[i].Skipped
		}
		return attempts[i].SkippedReason < attempts[j].SkippedReason
	})
}

// capVolumeAttempts bounds attempts to MaxVolumeAttempts.
func capVolumeAttempts(attempts []VolumeAttempt) ([]VolumeAttempt, int) {
	if len(attempts) <= MaxVolumeAttempts {
		return attempts, 0
	}
	return attempts[:MaxVolumeAttempts], len(attempts) - MaxVolumeAttempts
}

// summarizeVolumeAttempts derives the verdict from the attempts.
func summarizeVolumeAttempts(key volumeIdentity, attempts []VolumeAttempt, dropped int) VolumeOutcome {
	out := VolumeOutcome{
		PVCNamespace:    key.pvcNamespace,
		PVCName:         key.pvcName,
		PVName:          key.pvName,
		DroppedAttempts: dropped,
	}
	if len(attempts) > 1 || dropped > 0 {
		out.Attempts = attempts
	}

	if hasResult(attempts, VolumeResultFailed) {
		out.Result = VolumeResultFailed
		out.Method = uniqueMethod(methodsAtRank(attempts, VolumeResultFailed))
		return out
	}
	if hasResult(attempts, VolumeResultSucceeded) {
		out.Result = VolumeResultSucceeded
		out.Method = uniqueMethod(methodsAtRank(attempts, VolumeResultSucceeded))
		return out
	}

	out.Skipped = true
	out.Method = uniqueMethod(methodsAtRank(attempts, ""))
	out.SkippedReason = joinSkipReasons(attempts)
	return out
}

// hasResult reports whether any attempt produced result.
func hasResult(attempts []VolumeAttempt, result VolumeResult) bool {
	for _, attempt := range attempts {
		if attempt.Result != result {
			continue
		}
		if result == "" && !attempt.Skipped {
			continue
		}
		return true
	}
	return false
}

// methodsAtRank returns the distinct non-empty methods that produced result.
func methodsAtRank(attempts []VolumeAttempt, result VolumeResult) []string {
	seen := make(map[string]struct{}, len(attempts))
	methods := make([]string, 0, len(attempts))
	for _, attempt := range attempts {
		if attempt.Result != result {
			continue
		}
		if result == "" && !attempt.Skipped {
			continue
		}
		if attempt.Method == "" {
			continue
		}
		if _, ok := seen[attempt.Method]; ok {
			continue
		}
		seen[attempt.Method] = struct{}{}
		methods = append(methods, attempt.Method)
	}
	sort.Strings(methods)
	return methods
}

// uniqueMethod returns the method only when the rank has exactly one method.
func uniqueMethod(methods []string) string {
	if len(methods) == 1 {
		return methods[0]
	}
	return ""
}

// joinSkipReasons joins the distinct skip reasons in sorted order.
func joinSkipReasons(attempts []VolumeAttempt) string {
	seen := make(map[string]struct{}, len(attempts))
	reasons := make([]string, 0, len(attempts))
	for _, attempt := range attempts {
		if !attempt.Skipped || attempt.Result != "" || attempt.SkippedReason == "" {
			continue
		}
		if _, ok := seen[attempt.SkippedReason]; ok {
			continue
		}
		seen[attempt.SkippedReason] = struct{}{}
		reasons = append(reasons, attempt.SkippedReason)
	}
	sort.Strings(reasons)
	return strings.Join(reasons, "; ")
}

func volumeResultRank(result VolumeResult) int {
	switch result {
	case VolumeResultFailed:
		return 2
	case VolumeResultSucceeded:
		return 1
	default:
		return 0
	}
}

// volumeFailureMessage names the failed methods in the row message.
func volumeFailureMessage(vol VolumeOutcome) string {
	ref := "unknown volume"
	switch {
	case vol.PVCName != "" && vol.PVName != "":
		ref = fmt.Sprintf("pvc=%s/%s pv=%s", vol.PVCNamespace, vol.PVCName, vol.PVName)
	case vol.PVCName != "":
		ref = fmt.Sprintf("pvc=%s/%s", vol.PVCNamespace, vol.PVCName)
	case vol.PVName != "":
		ref = fmt.Sprintf("pv=%s", vol.PVName)
	}

	methods := methodsAtRank(vol.Attempts, VolumeResultFailed)
	if len(methods) == 0 && vol.Method != "" {
		methods = []string{vol.Method}
	}

	switch len(methods) {
	case 0:
		return fmt.Sprintf("volume %s failed", ref)
	case 1:
		return fmt.Sprintf("volume %s (%s) failed", ref, methods[0])
	default:
		return fmt.Sprintf("volume %s (%s) failed", ref, strings.Join(methods, ", "))
	}
}
