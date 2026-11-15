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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"
	ctrlfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	velerov1api "github.com/velero-io/velero/pkg/apis/velero/v1"
	"github.com/velero-io/velero/pkg/builder"
)

func newCancellationTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, velerov1api.AddToScheme(scheme))
	return scheme
}

func cancellationTestBackup(phase velerov1api.BackupPhase, cancel bool) *velerov1api.Backup {
	backup := builder.ForBackup("velero", "b1").WithStatus(velerov1api.BackupStatus{
		Phase: phase,
	}).Result()
	backup.Spec.Cancel = cancel
	return backup
}

func getCancellationTestBackup(t *testing.T, client kbclient.Client) *velerov1api.Backup {
	t.Helper()
	backup := &velerov1api.Backup{}
	require.NoError(t, client.Get(context.Background(), types.NamespacedName{Namespace: "velero", Name: "b1"}, backup))
	return backup
}

func conflictError() error {
	return apierrors.NewConflict(schema.GroupResource{Group: "velero.io", Resource: "backups"}, "b1", errors.New("the object has been modified"))
}

func TestAcceptCancellation(t *testing.T) {
	ctx := context.Background()

	t.Run("transitions an acceptable phase with the signal set", func(t *testing.T) {
		client := ctrlfake.NewClientBuilder().
			WithScheme(newCancellationTestScheme(t)).
			WithObjects(cancellationTestBackup(velerov1api.BackupPhaseInProgress, true)).
			Build()

		ok, err := acceptCancellation(ctx, client, "velero", "b1",
			velerov1api.BackupPhaseReadyToStart, velerov1api.BackupPhaseInProgress)
		require.NoError(t, err)
		assert.True(t, ok)

		updated := getCancellationTestBackup(t, client)
		assert.Equal(t, velerov1api.BackupPhaseCanceling, updated.Status.Phase)
		require.NotNil(t, updated.Status.Cancellation)
		assert.Equal(t, velerov1api.BackupPhaseInProgress, updated.Status.Cancellation.AcceptedFromPhase)
		assert.NotNil(t, updated.Status.Cancellation.AcceptedAt)
	})

	t.Run("does nothing when the signal is not set", func(t *testing.T) {
		client := ctrlfake.NewClientBuilder().
			WithScheme(newCancellationTestScheme(t)).
			WithObjects(cancellationTestBackup(velerov1api.BackupPhaseInProgress, false)).
			Build()

		ok, err := acceptCancellation(ctx, client, "velero", "b1", velerov1api.BackupPhaseInProgress)
		require.NoError(t, err)
		assert.False(t, ok)
		assert.Equal(t, velerov1api.BackupPhaseInProgress, getCancellationTestBackup(t, client).Status.Phase)
	})

	t.Run("does nothing when the phase is not acceptable", func(t *testing.T) {
		client := ctrlfake.NewClientBuilder().
			WithScheme(newCancellationTestScheme(t)).
			WithObjects(cancellationTestBackup(velerov1api.BackupPhaseFinalizing, true)).
			Build()

		ok, err := acceptCancellation(ctx, client, "velero", "b1", velerov1api.BackupPhaseReadyToStart)
		require.NoError(t, err)
		assert.False(t, ok)
		assert.Equal(t, velerov1api.BackupPhaseFinalizing, getCancellationTestBackup(t, client).Status.Phase)
	})

	t.Run("does not clobber an already-Canceling backup", func(t *testing.T) {
		backup := cancellationTestBackup(velerov1api.BackupPhaseCanceling, true)
		backup.Status.Cancellation = &velerov1api.BackupCancellationStatus{
			AcceptedAt:        &metav1.Time{Time: metav1.Now().Add(-1)},
			AcceptedFromPhase: velerov1api.BackupPhaseQueued,
			ActionsAttempted:  2,
		}
		client := ctrlfake.NewClientBuilder().
			WithScheme(newCancellationTestScheme(t)).
			WithObjects(backup).
			Build()

		ok, err := acceptCancellation(ctx, client, "velero", "b1", velerov1api.BackupPhaseQueued)
		require.NoError(t, err)
		assert.False(t, ok)

		updated := getCancellationTestBackup(t, client)
		assert.Equal(t, velerov1api.BackupPhaseCanceling, updated.Status.Phase)
		require.NotNil(t, updated.Status.Cancellation)
		assert.Equal(t, 2, updated.Status.Cancellation.ActionsAttempted)
		assert.Equal(t, velerov1api.BackupPhaseQueued, updated.Status.Cancellation.AcceptedFromPhase)
	})

	t.Run("retries on conflict and recomputes against the fresh object", func(t *testing.T) {
		updateCalls := 0
		client := ctrlfake.NewClientBuilder().
			WithScheme(newCancellationTestScheme(t)).
			WithObjects(cancellationTestBackup(velerov1api.BackupPhaseReadyToStart, true)).
			WithInterceptorFuncs(interceptor.Funcs{
				Update: func(ctx context.Context, c kbclient.WithWatch, obj kbclient.Object, opts ...kbclient.UpdateOption) error {
					updateCalls++
					if updateCalls > 1 {
						return c.Update(ctx, obj, opts...)
					}
					// A concurrent writer wins the race: the stored backup
					// moves to Finalizing before our Update lands.
					stored := &velerov1api.Backup{}
					if err := c.Get(ctx, types.NamespacedName{Namespace: obj.GetNamespace(), Name: obj.GetName()}, stored); err != nil {
						return err
					}
					stored.Status.Phase = velerov1api.BackupPhaseFinalizing
					if err := c.Update(ctx, stored); err != nil {
						return err
					}
					return conflictError()
				},
			}).
			Build()

		ok, err := acceptCancellation(ctx, client, "velero", "b1", velerov1api.BackupPhaseReadyToStart)
		require.NoError(t, err)
		assert.False(t, ok, "precondition was lost to the concurrent writer, so no write should happen")
		assert.Equal(t, 1, updateCalls)
		assert.Equal(t, velerov1api.BackupPhaseFinalizing, getCancellationTestBackup(t, client).Status.Phase)
	})

	t.Run("returns an error when conflicts persist", func(t *testing.T) {
		updateCalls := 0
		client := ctrlfake.NewClientBuilder().
			WithScheme(newCancellationTestScheme(t)).
			WithObjects(cancellationTestBackup(velerov1api.BackupPhaseReadyToStart, true)).
			WithInterceptorFuncs(interceptor.Funcs{
				Update: func(ctx context.Context, c kbclient.WithWatch, obj kbclient.Object, opts ...kbclient.UpdateOption) error {
					updateCalls++
					return conflictError()
				},
			}).
			Build()

		ok, err := acceptCancellation(ctx, client, "velero", "b1", velerov1api.BackupPhaseReadyToStart)
		require.Error(t, err)
		assert.False(t, ok)
		assert.Equal(t, guardedBackupUpdateMaxAttempts, updateCalls)
		assert.Equal(t, velerov1api.BackupPhaseReadyToStart, getCancellationTestBackup(t, client).Status.Phase)
	})

	t.Run("returns an error for a missing backup", func(t *testing.T) {
		client := ctrlfake.NewClientBuilder().
			WithScheme(newCancellationTestScheme(t)).
			Build()

		ok, err := acceptCancellation(ctx, client, "velero", "missing", velerov1api.BackupPhaseInProgress)
		require.Error(t, err)
		assert.True(t, apierrors.IsNotFound(err))
		assert.False(t, ok)
	})
}

func TestCompleteCancellation(t *testing.T) {
	ctx := context.Background()

	t.Run("transitions Canceling to terminal Canceled, keeping counts", func(t *testing.T) {
		backup := cancellationTestBackup(velerov1api.BackupPhaseCanceling, true)
		backup.Status.Cancellation = &velerov1api.BackupCancellationStatus{
			AcceptedFromPhase:  velerov1api.BackupPhaseInProgress,
			ActionsAttempted:   3,
			ActionsConfirmed:   1,
			ActionsUnconfirmed: 2,
		}
		client := ctrlfake.NewClientBuilder().
			WithScheme(newCancellationTestScheme(t)).
			WithObjects(backup).
			Build()

		ok, err := completeCancellation(ctx, client, "velero", "b1", "teardown requested; 2 actions unconfirmed")
		require.NoError(t, err)
		assert.True(t, ok)

		updated := getCancellationTestBackup(t, client)
		assert.Equal(t, velerov1api.BackupPhaseCanceled, updated.Status.Phase)
		assert.NotNil(t, updated.Status.CompletionTimestamp)
		require.NotNil(t, updated.Status.Cancellation)
		assert.Equal(t, "teardown requested; 2 actions unconfirmed", updated.Status.Cancellation.Reason)
		assert.Equal(t, 3, updated.Status.Cancellation.ActionsAttempted)
		assert.Equal(t, 1, updated.Status.Cancellation.ActionsConfirmed)
		assert.Equal(t, 2, updated.Status.Cancellation.ActionsUnconfirmed)
	})

	t.Run("does nothing when the backup is not Canceling", func(t *testing.T) {
		client := ctrlfake.NewClientBuilder().
			WithScheme(newCancellationTestScheme(t)).
			WithObjects(cancellationTestBackup(velerov1api.BackupPhaseInProgress, true)).
			Build()

		ok, err := completeCancellation(ctx, client, "velero", "b1", "reason")
		require.NoError(t, err)
		assert.False(t, ok)
		assert.Equal(t, velerov1api.BackupPhaseInProgress, getCancellationTestBackup(t, client).Status.Phase)
		assert.Nil(t, getCancellationTestBackup(t, client).Status.CompletionTimestamp)
	})
}
