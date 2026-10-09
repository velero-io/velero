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

package controller

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	testclocks "k8s.io/utils/clock/testing"
	ctrl "sigs.k8s.io/controller-runtime"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1crds "github.com/vmware-tanzu/velero/config/crd/v1"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	persistencemocks "github.com/vmware-tanzu/velero/pkg/persistence/mocks"
	"github.com/vmware-tanzu/velero/pkg/plugin/clientmgmt"
	pluginmocks "github.com/vmware-tanzu/velero/pkg/plugin/mocks"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
)

// Expectations are declared once and reused by both the behavior tests and the coverage
// tests below, so a phase can only be tested by being classified here first.
var backupPhaseExpectations = map[velerov1api.BackupPhase]bool{
	// Pre-execution: nothing has been written for any target kind.
	velerov1api.BackupPhaseNew:              true,
	velerov1api.BackupPhaseQueued:           true,
	velerov1api.BackupPhaseReadyToStart:     true,
	velerov1api.BackupPhaseFailedValidation: true,

	// From here on there may be a partial log or other artifacts, and Deleting may
	// still have all of them, so these keep the behavior callers have today.
	velerov1api.BackupPhaseInProgress:                                false,
	velerov1api.BackupPhaseWaitingForPluginOperations:                false,
	velerov1api.BackupPhaseWaitingForPluginOperationsPartiallyFailed: false,
	velerov1api.BackupPhaseFinalizing:                                false,
	velerov1api.BackupPhaseFinalizingPartiallyFailed:                 false,
	velerov1api.BackupPhaseCompleted:                                 false,
	velerov1api.BackupPhasePartiallyFailed:                           false,
	velerov1api.BackupPhaseFailed:                                    false,
	velerov1api.BackupPhaseDeleting:                                  false,
}

var restorePhaseExpectations = map[velerov1api.RestorePhase]bool{
	velerov1api.RestorePhaseNew:              true,
	velerov1api.RestorePhaseFailedValidation: true,

	velerov1api.RestorePhaseInProgress:                                false,
	velerov1api.RestorePhaseWaitingForPluginOperations:                false,
	velerov1api.RestorePhaseWaitingForPluginOperationsPartiallyFailed: false,
	velerov1api.RestorePhaseFinalizing:                                false,
	velerov1api.RestorePhaseFinalizingPartiallyFailed:                 false,
	velerov1api.RestorePhaseCompleted:                                 false,
	velerov1api.RestorePhasePartiallyFailed:                           false,
	velerov1api.RestorePhaseFailed:                                    false,
}

func TestBackupPhaseHasNoArtifacts(t *testing.T) {
	for phase, want := range backupPhaseExpectations {
		t.Run(string(phase), func(t *testing.T) {
			assert.Equal(t, want, backupPhaseHasNoArtifacts(phase))
		})
	}

	// A backup that has not been reconciled yet has an empty phase. It is left alone
	// deliberately: the state is transient and the caller can retry.
	assert.False(t, backupPhaseHasNoArtifacts(velerov1api.BackupPhase("")))
}

func TestRestorePhaseHasNoArtifacts(t *testing.T) {
	for phase, want := range restorePhaseExpectations {
		t.Run(string(phase), func(t *testing.T) {
			assert.Equal(t, want, restorePhaseHasNoArtifacts(phase))
		})
	}

	assert.False(t, restorePhaseHasNoArtifacts(velerov1api.RestorePhase("")))
}

// The two tests below read the phase enum out of the generated CRDs, which come from the
// same kubebuilder markers as the Go constants. Adding a phase to the API without
// classifying it here fails, which a hand-written list of phases cannot do.
func TestBackupPhaseExpectationsCoverTheCRD(t *testing.T) {
	phases := statusPhaseEnum(t, "backups.velero.io")
	require.NotEmpty(t, phases, "no status.phase enum found in the Backup CRD")

	for _, phase := range phases {
		_, ok := backupPhaseExpectations[velerov1api.BackupPhase(phase)]
		assert.True(t, ok, "BackupPhase %q is served by the CRD but not classified by backupPhaseHasNoArtifacts", phase)
	}
	assert.Len(t, backupPhaseExpectations, len(phases), "backupPhaseExpectations and the CRD enum have drifted apart")
}

func TestRestorePhaseExpectationsCoverTheCRD(t *testing.T) {
	phases := statusPhaseEnum(t, "restores.velero.io")
	require.NotEmpty(t, phases, "no status.phase enum found in the Restore CRD")

	for _, phase := range phases {
		_, ok := restorePhaseExpectations[velerov1api.RestorePhase(phase)]
		assert.True(t, ok, "RestorePhase %q is served by the CRD but not classified by restorePhaseHasNoArtifacts", phase)
	}
	assert.Len(t, restorePhaseExpectations, len(phases), "restorePhaseExpectations and the CRD enum have drifted apart")
}

// statusPhaseEnum returns the allowed values of status.phase for a generated CRD.
func statusPhaseEnum(t *testing.T, crdName string) []string {
	t.Helper()

	for _, crd := range v1crds.CRDs {
		if crd.Name != crdName {
			continue
		}
		for _, version := range crd.Spec.Versions {
			if version.Schema == nil || version.Schema.OpenAPIV3Schema == nil {
				continue
			}
			status, ok := version.Schema.OpenAPIV3Schema.Properties["status"]
			if !ok {
				continue
			}
			phase, ok := status.Properties["phase"]
			if !ok {
				continue
			}

			values := make([]string, 0, len(phase.Enum))
			for _, raw := range phase.Enum {
				var value string
				require.NoError(t, json.Unmarshal(raw.Raw, &value))
				values = append(values, value)
			}
			return values
		}
	}

	t.Fatalf("CRD %q not found", crdName)
	return nil
}

// The guard is only useful if a caller can tell why it fired. These reconcile a real
// request against a fake client and assert on what a client would actually observe.
func TestGuardSetsFailedPhaseWithReason(t *testing.T) {
	tests := []struct {
		name        string
		targetKind  velerov1api.DownloadTargetKind
		backupPhase velerov1api.BackupPhase
		wantPhase   velerov1api.DownloadRequestPhase
		wantMessage string
	}{
		{
			name:        "backup that never ran fails with the phase named",
			targetKind:  velerov1api.DownloadTargetKindBackupLog,
			backupPhase: velerov1api.BackupPhaseFailedValidation,
			wantPhase:   velerov1api.DownloadRequestPhaseFailed,
			wantMessage: `backup "a-backup" is in phase "FailedValidation" and has not written any artifacts`,
		},
		{
			name:        "backup that ran is untouched by the guard",
			targetKind:  velerov1api.DownloadTargetKindBackupLog,
			backupPhase: velerov1api.BackupPhaseCompleted,
			wantPhase:   velerov1api.DownloadRequestPhaseProcessed,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			harness := newDownloadRequestHarness(t, tc.targetKind, tc.backupPhase)
			got := harness.reconcile(t)

			assert.Equal(t, tc.wantPhase, got.Status.Phase)
			assert.Equal(t, tc.wantMessage, got.Status.Message,
				"the message is the only thing telling a caller why no URL arrived")

			if tc.wantPhase == velerov1api.DownloadRequestPhaseFailed {
				assert.Empty(t, got.Status.DownloadURL,
					"a failed request must not carry a URL that would 404")
			}
		})
	}
}

// A message is set only on failure. An empty message alongside Failed would put the CLI
// back on its generic storage-location error, which is the thing this replaces.
func TestFailedPhaseAlwaysCarriesAMessage(t *testing.T) {
	harness := newDownloadRequestHarness(t,
		velerov1api.DownloadTargetKindBackupLog, velerov1api.BackupPhaseNew)

	got := harness.reconcile(t)

	require.Equal(t, velerov1api.DownloadRequestPhaseFailed, got.Status.Phase)
	assert.NotEmpty(t, got.Status.Message)
}

// downloadRequestHarness builds the smallest cluster a DownloadRequest reconcile needs:
// the request, its backup, and a storage location whose store returns a URL.
type downloadRequestHarness struct {
	client  kbclient.Client
	reqName string
	r       *downloadRequestReconciler
}

func newDownloadRequestHarness(
	t *testing.T,
	kind velerov1api.DownloadTargetKind,
	backupPhase velerov1api.BackupPhase,
) *downloadRequestHarness {
	t.Helper()

	s := runtime.NewScheme()
	require.NoError(t, velerov1api.AddToScheme(s))

	backup := builder.ForBackup(velerov1api.DefaultNamespace, "a-backup").
		StorageLocation("a-location").Phase(backupPhase).Result()
	location := builder.ForBackupStorageLocation(velerov1api.DefaultNamespace, "a-location").Result()
	request := builder.ForDownloadRequest(velerov1api.DefaultNamespace, "a-request").
		Target(kind, "a-backup").Result()

	c := fake.NewClientBuilder().WithScheme(s).
		WithObjects(request, backup, location).Build()

	store := &persistencemocks.BackupStore{}
	store.On("GetDownloadURL", request.Spec.Target).Return("a-url", nil)

	pluginManager := &pluginmocks.Manager{}
	pluginManager.On("CleanupClients").Return(nil)

	r := NewDownloadRequestReconciler(
		c,
		testclocks.NewFakeClock(time.Now()),
		func(logrus.FieldLogger) clientmgmt.Manager { return pluginManager },
		NewFakeObjectBackupStoreGetter(map[string]*persistencemocks.BackupStore{"a-location": store}),
		velerotest.NewLogger(),
		nil,
		nil,
	)

	return &downloadRequestHarness{client: c, reqName: request.Name, r: r}
}

func (h *downloadRequestHarness) reconcile(t *testing.T) *velerov1api.DownloadRequest {
	t.Helper()

	_, err := h.r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: kbclient.ObjectKey{
			Namespace: velerov1api.DefaultNamespace,
			Name:      h.reqName,
		},
	})
	require.NoError(t, err)

	got := &velerov1api.DownloadRequest{}
	require.NoError(t, h.client.Get(context.Background(), kbclient.ObjectKey{
		Namespace: velerov1api.DefaultNamespace, Name: h.reqName,
	}, got))
	return got
}
