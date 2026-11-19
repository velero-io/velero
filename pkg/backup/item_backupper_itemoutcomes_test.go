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

package backup

import (
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/velero-io/velero/internal/itemoutcome"
	"github.com/velero-io/velero/pkg/builder"
	"github.com/velero-io/velero/pkg/kuberesource"
	"github.com/velero-io/velero/pkg/plugin/velero"
	"github.com/velero-io/velero/pkg/podvolume"
)

// getFileForArchive rejects a name that walks out of the backup directory, so
// this failure is reachable from an ordinary backup and not only from a test
// fixture. When the archive path cannot be built the item was not backed up, so
// the row must record the failure rather than keep the outcome it was minted at.
// This is the attribution the path-safety change (0f8652173) left at a bare
// return, through no fault of its own: until that change the call could not fail.
//
// There are two calls to getFileForArchive, and the first only runs when the
// object's version is the preferred one. Both are covered because fixing one
// without the other would still leave a failing item reading BackedUp.
func TestBackupItemInternalRecordsFileArchiveFailure(t *testing.T) {
	gr := schema.GroupResource{Group: "apps", Resource: "deployments"}
	const escaping = "../../../../../../escape"

	tests := []struct {
		name        string
		objectVer   string
		preferredV  string
		whichReturn string
	}{
		{
			name:        "preferred version matches, so the first call fails",
			objectVer:   "v1",
			preferredV:  "v1",
			whichReturn: "first",
		},
		{
			name:        "version differs, so only the second call runs and fails",
			objectVer:   "v1beta1",
			preferredV:  "v1",
			whichReturn: "second",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			obj := &unstructured.Unstructured{Object: map[string]any{
				"apiVersion": "apps/" + tc.objectVer,
				"kind":       "Deployment",
				"metadata": map[string]any{
					"namespace": "ns1",
					"name":      escaping,
				},
			}}
			// backupItemInternal reads the version off the object's kind, which
			// the unstructured literal above does not carry.
			obj.SetGroupVersionKind(schema.GroupVersionKind{Group: "apps", Version: tc.objectVer, Kind: "Deployment"})

			ib := &itemBackupper{
				backupRequest: &Request{
					BackedUpItems:        NewBackedUpItemsMap(),
					ItemOutcomes:         itemoutcome.NewRecorder(),
					SkippedVolumeTracker: NewSkipVolumeTracker(),
				},
				podVolumeSnapshotTracker: podvolume.NewTracker(),
			}

			// mustInclude skips the inclusion filters, whose ShouldInclude needs a
			// discovery helper. The filters are not what this test is about.
			preferredGVR := schema.GroupVersionResource{Group: "apps", Version: tc.preferredV, Resource: "deployments"}
			backedUp, _, err := ib.backupItemInternal(logrus.New(), obj, gr, preferredGVR, true, false, nil)

			require.Error(t, err, "the archive path is rejected")
			assert.False(t, backedUp)

			var row *itemoutcome.ItemOutcome
			for _, item := range ib.backupRequest.ItemOutcomes.Result().Items {
				if item.GroupResource == gr.String() && item.Name == escaping {
					item := item
					row = &item
				}
			}
			require.NotNil(t, row, "the item must still have a row")
			assert.Equal(t, itemoutcome.OutcomeFailed, row.Outcome,
				"an item whose archive entry could not be built was not backed up")
			require.NotEmpty(t, row.Messages, "the reason must be attached to the row")
		})
	}
}

// A skipped volume was only ever recorded in the skipped-volume tracker, which
// feeds the separate volumeinfo artifact and carries no back-reference to the
// item that owned the volume. Recording the skip against the item too is what
// lets a reader tell, from the item-outcomes artifact alone, which VM a skipped
// disk belonged to.
func TestTrackSkippedVolume_RecordsItemOutcome(t *testing.T) {
	ib := &itemBackupper{
		backupRequest: &Request{
			SkippedVolumeTracker: NewSkipVolumeTracker(),
			ItemOutcomes:         itemoutcome.NewRecorder(),
		},
	}

	pvc := builder.ForPersistentVolumeClaim("vm-ns", "disk-0").
		Phase(corev1api.ClaimBound).
		VolumeName("pv-disk-0").
		Result()

	pvcData, err := runtime.DefaultUnstructuredConverter.ToUnstructured(pvc)
	require.NoError(t, err)
	obj := &unstructured.Unstructured{Object: pvcData}

	ib.trackSkippedVolume(obj, kuberesource.PersistentVolumeClaims, csiSnapshotApproach, "skipped b/c it's not a CSI volume", logrus.New())

	result := ib.backupRequest.ItemOutcomes.Result()
	require.Len(t, result.Items, 1)

	item := result.Items[0]
	assert.Equal(t, kuberesource.PersistentVolumeClaims.String(), item.GroupResource)
	assert.Equal(t, "vm-ns", item.Namespace)
	assert.Equal(t, "disk-0", item.Name)
	assert.Equal(t, itemoutcome.OutcomeSkipped, item.Outcome)
	assert.True(t, item.SkippedByVolume, "a volume-path skip must be rescuable at finalize")
	require.Len(t, item.Messages, 1)
	assert.Contains(t, item.Messages[0], "pvc=disk-0 pv=pv-disk-0")
	assert.Contains(t, item.Messages[0], "skipped b/c it's not a CSI volume")
	assert.Contains(t, item.Messages[0], "CSISnapshot volume skipped",
		"the row message must use the same method vocabulary as the attempt")
	require.Len(t, item.VolumeAttempts, 1)
	assert.Equal(t, itemoutcome.VolumeMethodCSISnapshot, item.VolumeAttempts[0].Method,
		"the capture-time approach is normalized to the volume-info method name")
	assert.True(t, item.VolumeAttempts[0].Skipped)
	assert.Equal(t, "skipped b/c it's not a CSI volume", item.VolumeAttempts[0].SkippedReason)
}

// An item excluded by the user is not rescuable by a volume verdict: the disk
// may have been captured, but the item itself was never backed up.
func TestTrackSkippedItemVolume_DoesNotSetVolumeProvenance(t *testing.T) {
	ib := &itemBackupper{
		backupRequest: &Request{
			SkippedVolumeTracker: NewSkipVolumeTracker(),
			ItemOutcomes:         itemoutcome.NewRecorder(),
		},
	}

	obj := unstructuredFor(t, builder.ForPersistentVolumeClaim("vm-ns", "disk-0").
		Phase(corev1api.ClaimBound).
		VolumeName("pv-disk-0").
		Result())

	ib.trackSkippedItemVolume(obj, kuberesource.PersistentVolumeClaims, "item has label velero.io/exclude-from-backup=true", logrus.New())

	result := ib.backupRequest.ItemOutcomes.Result()
	require.Len(t, result.Items, 1)
	assert.Equal(t, itemoutcome.OutcomeSkipped, result.Items[0].Outcome)
	assert.False(t, result.Items[0].SkippedByVolume)
	assert.Empty(t, result.Items[0].VolumeAttempts)
	assert.Len(t, ib.backupRequest.SkippedVolumeTracker.Summary(), 1)
}

// A skip must never downgrade an item that already failed: a volume skip is a
// weaker signal than the failure, and the recorder's precedence order enforces
// that. This pins the behaviour the trackSkippedVolume comment relies on.
func TestTrackSkippedVolume_DoesNotMaskFailure(t *testing.T) {
	recorder := itemoutcome.NewRecorder()
	recorder.Fail(velero.ResourceIdentifier{
		GroupResource: kuberesource.PersistentVolumeClaims,
		Namespace:     "vm-ns",
		Name:          "disk-0",
	}, "snapshot failed")

	ib := &itemBackupper{
		backupRequest: &Request{
			SkippedVolumeTracker: NewSkipVolumeTracker(),
			ItemOutcomes:         recorder,
		},
	}

	obj := unstructuredFor(t, builder.ForPersistentVolumeClaim("vm-ns", "disk-0").
		Phase(corev1api.ClaimBound).
		VolumeName("pv-disk-0").
		Result())
	ib.trackSkippedVolume(obj, kuberesource.PersistentVolumeClaims, "CSI", "reason", logrus.New())

	result := ib.backupRequest.ItemOutcomes.Result()
	require.Len(t, result.Items, 1)
	assert.Equal(t, itemoutcome.OutcomeFailed, result.Items[0].Outcome)
}

func TestTrackSkippedVolume_NoItemOutcomesRecorder(t *testing.T) {
	// ItemOutcomes is nil when the backup did not opt in to collection; the
	// tracker must still be populated and nothing should panic.
	ib := &itemBackupper{
		backupRequest: &Request{
			SkippedVolumeTracker: NewSkipVolumeTracker(),
		},
	}

	obj := unstructuredFor(t, builder.ForPersistentVolumeClaim("vm-ns", "disk-0").
		Phase(corev1api.ClaimBound).
		VolumeName("pv-disk-0").
		Result())

	assert.NotPanics(t, func() {
		ib.trackSkippedVolume(obj, kuberesource.PersistentVolumeClaims, "CSI", "reason", logrus.New())
	})
	assert.Len(t, ib.backupRequest.SkippedVolumeTracker.Summary(), 1)
}

func TestVolumeRef(t *testing.T) {
	tests := []struct {
		name     string
		pvName   string
		pvcName  string
		expected string
	}{
		{name: "both", pvName: "pv-0", pvcName: "pvc-0", expected: "pvc=pvc-0 pv=pv-0"},
		{name: "pvc only", pvcName: "pvc-0", expected: "pvc=pvc-0"},
		{name: "pv only", pvName: "pv-0", expected: "pv=pv-0"},
		{name: "neither", expected: "unknown volume"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, volumeRef(tc.pvName, tc.pvcName))
		})
	}
}

func unstructuredFor(t *testing.T, obj interface{}) *unstructured.Unstructured {
	t.Helper()
	data, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	require.NoError(t, err)
	return &unstructured.Unstructured{Object: data}
}

// The archive write happens after Observe. A write failure means the item is
// not in the backup, so the row must not keep the Succeeded it was minted at.
func TestRecordArchiveFailureRecordsFailedRow(t *testing.T) {
	recorder := itemoutcome.NewRecorder()
	ib := &itemBackupper{backupRequest: &Request{ItemOutcomes: recorder}}
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"namespace": "ns", "name": "pod1"},
	}}

	ib.recordArchiveFailure(obj, schema.GroupResource{Resource: "pods"}, errors.New("archive write failed"))

	items := recorder.Result().Items
	require.Len(t, items, 1)
	assert.Equal(t, itemoutcome.OutcomeFailed, items[0].Outcome)
	require.Len(t, items[0].Messages, 1)
	assert.Contains(t, items[0].Messages[0], "failed to write item to backup archive")
	assert.Contains(t, items[0].Messages[0], "archive write failed")
}
