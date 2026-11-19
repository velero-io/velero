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

// Merge folds the finalize-pass rows into the stored artifact.
func Merge(dst, src *ItemOutcomes) {
	if dst == nil || src == nil || len(src.Items) == 0 {
		return
	}

	index := make(map[Key]int, len(dst.Items))
	for i := range dst.Items {
		index[KeyOf(dst.Items[i])] = i
	}

	for _, item := range src.Items {
		key := KeyOf(item)
		idx, ok := index[key]
		if !ok {
			dst.Items = append(dst.Items, item)
			index[key] = len(dst.Items) - 1
			continue
		}

		row := &dst.Items[idx]
		// The finalize pass is newer than the stored artifact, so a skip it
		// records replaces the stored marker. This lets an item-level skip clear
		// a volume marker and lets a volume-path skip supply a marker an older
		// artifact did not have.
		if item.Outcome == OutcomeSkipped {
			row.SkippedByVolume = item.SkippedByVolume
		} else if item.SkippedByVolume {
			row.SkippedByVolume = true
		}
		if precedence[item.Outcome] > precedence[row.Outcome] {
			row.Outcome = item.Outcome
		}
		row.Messages = mergeMessages(row.Messages, item.Messages)
		row.VolumeAttempts = dedupeVolumeAttempts(append(row.VolumeAttempts, item.VolumeAttempts...))
		if row.Owner == nil && item.Owner != nil {
			owner := *item.Owner
			row.Owner = &owner
		}
		row.ReportedBy = mergeReportedBy(row.ReportedBy, item.ReportedBy)

		if row.Volume == nil && item.Volume != nil {
			volume := *item.Volume
			row.Volume = &volume
		}
	}

	sortItems(dst.Items)
}

func mergeReportedBy(dst, src []ItemRef) []ItemRef {
	merged := make(map[Key]ItemRef, len(dst)+len(src))
	for _, reporter := range dst {
		merged[KeyOfRef(&reporter)] = reporter
	}
	for _, reporter := range src {
		key := KeyOfRef(&reporter)
		if _, ok := merged[key]; ok {
			continue
		}
		merged[key] = reporter
	}
	out := make([]ItemRef, 0, len(merged))
	for _, reporter := range merged {
		out = append(out, reporter)
	}
	sortReportedBy(out)
	return out
}

// mergeMessages combines two capped message lists without losing the count of
// messages already represented by a marker.
func mergeMessages(groups ...[]string) []string {
	seen := make(map[string]bool)
	visible := make([]string, 0, MaxMessagesPerItem)
	hidden := 0

	for _, msgs := range groups {
		for _, msg := range msgs {
			if n, ok := moreMarkerCount(msg); ok {
				hidden += n
				continue
			}
			if seen[msg] {
				continue
			}
			seen[msg] = true
			visible = append(visible, msg)
		}
	}

	return capMessagesWithHidden(visible, hidden)
}
