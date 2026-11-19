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
	"bytes"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/velero-io/velero/internal/hook"
	"github.com/velero-io/velero/internal/itemoutcome"
	"github.com/velero-io/velero/pkg/builder"
	"github.com/velero-io/velero/pkg/discovery/mocks"
	"github.com/velero-io/velero/pkg/itemblock"
	"github.com/velero-io/velero/pkg/kuberesource"
	"github.com/velero-io/velero/pkg/plugin/velero"
	biav2 "github.com/velero-io/velero/pkg/plugin/velero/backupitemaction/v2"
	"github.com/velero-io/velero/pkg/test"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestItemOutcomesCapture(t *testing.T) {
	itemBlockPool := StartItemBlockWorkerPool(t.Context(), 1, logrus.StandardLogger())
	defer itemBlockPool.Stop()

	h := newHarness(t, itemBlockPool)
	req := &Request{
		Backup:               defaultBackup().Result(),
		SkippedVolumeTracker: NewSkipVolumeTracker(),
		BackedUpItems:        NewBackedUpItemsMap(),
		WorkerPool:           itemBlockPool,
		ItemOutcomes:         itemoutcome.NewRecorder(),
	}
	backupFile := bytes.NewBuffer([]byte{})

	h.addItems(t, test.Pods(
		builder.ForPod("ns-1", "pod-1").Result(),
	))
	h.addItems(t, test.PVCs(
		builder.ForPersistentVolumeClaim("ns-1", "pvc-1").Result(),
	))

	action := new(recordResourcesAction).ForResource("pods").WithAdditionalItems([]velero.ResourceIdentifier{
		{
			GroupResource: kuberesource.PersistentVolumeClaims,
			Namespace:     "ns-1",
			Name:          "pvc-1",
		},
	})

	err := h.backupper.Backup(h.log, req, backupFile, []biav2.BackupItemAction{action}, nil, nil)
	require.NoError(t, err)

	result := req.ItemOutcomes.Result()
	byKey := map[string]itemoutcome.ItemOutcome{}
	for _, item := range result.Items {
		byKey[item.GroupResource+"/"+item.Namespace+"/"+item.Name] = item
	}

	pod, ok := byKey["pods/ns-1/pod-1"]
	require.True(t, ok)
	assert.Equal(t, itemoutcome.OutcomeSucceeded, pod.Outcome)
	assert.Empty(t, pod.ReportedBy)

	pvc, ok := byKey[kuberesource.PersistentVolumeClaims.String()+"/ns-1/pvc-1"]
	require.True(t, ok)
	assert.Equal(t, itemoutcome.OutcomeSucceeded, pvc.Outcome)
	require.Len(t, pvc.ReportedBy, 1)
	assert.Equal(t, kuberesource.Pods.String(), pvc.ReportedBy[0].GroupResource)
	assert.Equal(t, "ns-1", pvc.ReportedBy[0].Namespace)
	assert.Equal(t, "pod-1", pvc.ReportedBy[0].Name)
}

// TestItemOutcomesCapturesSynchronousFailure verifies that an item whose
// BackupItemAction.Execute returns an error is recorded as OutcomeFailed,
// even though the only place that error is logged (kubernetesBackupper.backupItem)
// does not attach structured resource/namespace fields the log hook could
// otherwise have used to attribute it.
func TestItemOutcomesCapturesSynchronousFailure(t *testing.T) {
	itemBlockPool := StartItemBlockWorkerPool(t.Context(), 1, logrus.StandardLogger())
	defer itemBlockPool.Stop()

	h := newHarness(t, itemBlockPool)
	req := &Request{
		Backup:               defaultBackup().Result(),
		SkippedVolumeTracker: NewSkipVolumeTracker(),
		BackedUpItems:        NewBackedUpItemsMap(),
		WorkerPool:           itemBlockPool,
		ItemOutcomes:         itemoutcome.NewRecorder(),
	}
	backupFile := bytes.NewBuffer([]byte{})

	h.addItems(t, test.Pods(
		builder.ForPod("ns-1", "pod-1").Result(),
	))

	executionErr := errors.New("boom")
	action := new(recordResourcesAction).ForResource("pods").WithExecutionErr(executionErr)

	err := h.backupper.Backup(h.log, req, backupFile, []biav2.BackupItemAction{action}, nil, nil)
	require.NoError(t, err)

	result := req.ItemOutcomes.Result()
	require.Len(t, result.Items, 1)
	assert.Equal(t, itemoutcome.OutcomeFailed, result.Items[0].Outcome)
	require.Len(t, result.Items[0].Messages, 1)
	assert.Contains(t, result.Items[0].Messages[0], "boom")
}

// A failing pre-hook prevents the pod from being backed up, so the usual
// capture path (Observe in backupItem) never runs. The failure must still reach
// the artifact, or a pod that was skipped because its hook failed would read as
// absent rather than broken.
type failingHookHandler struct{ err error }

func (h failingHookHandler) HandleHooks(
	_ logrus.FieldLogger,
	_ schema.GroupResource,
	_ runtime.Unstructured,
	_ []hook.ResourceHook,
	_ hook.HookPhase,
	_ *hook.HookTracker,
) error {
	return h.err
}

func TestPreHookFailureIsRecordedAsItemOutcome(t *testing.T) {
	helper := new(mocks.Helper)
	helper.On("KindFor", schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "ReplicaSet"}).
		Return(schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "replicasets"}, metav1.APIResource{Name: "replicasets", Namespaced: true}, nil)

	recorder := itemoutcome.NewRecorder()
	ib := &itemBackupper{
		backupRequest:   &Request{ItemOutcomes: recorder},
		itemHookHandler: failingHookHandler{err: errors.New("pre hook boom")},
		discoveryHelper: helper,
	}
	block := NewBackupItemBlock(logrus.New(), ib)

	pod := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"namespace": "ns",
			"name":      "pod1",
			"ownerReferences": []any{map[string]any{
				"apiVersion": "apps/v1",
				"kind":       "ReplicaSet",
				"name":       "rs1",
				"controller": true,
				"uid":        "uid-1",
			}},
		},
	}}
	pods := []itemblock.ItemBlockItem{{Gr: schema.GroupResource{Resource: "pods"}, Item: pod}}

	_, failed, errs := (&kubernetesBackupper{}).handleItemBlockPreHooks(block, pods)

	require.Len(t, failed, 1)
	require.Len(t, errs, 1)

	items := recorder.Result().Items
	require.Len(t, items, 1)
	assert.Equal(t, itemoutcome.OutcomeFailed, items[0].Outcome)
	assert.Equal(t, "pod1", items[0].Name)
	require.Len(t, items[0].Messages, 1)
	assert.Contains(t, items[0].Messages[0], "pre hook boom")

	require.NotNil(t, items[0].Owner)
	assert.Equal(t, "replicasets.apps", items[0].Owner.GroupResource)
	assert.Equal(t, "ns", items[0].Owner.Namespace)
	assert.Equal(t, "rs1", items[0].Owner.Name)
	assert.Empty(t, items[0].ReportedBy)
}
