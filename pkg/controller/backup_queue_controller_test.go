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
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	//metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlClient "sigs.k8s.io/controller-runtime/pkg/client"

	//"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
)

func TestBackupQueueReconciler(t *testing.T) {
	scheme := runtime.NewScheme()
	velerov1api.AddToScheme(scheme)

	tests := []struct {
		name                string
		priorBackups        []*velerov1api.Backup
		namespaces          []string
		backup              *velerov1api.Backup
		concurrentBackups   int
		expectError         bool
		expectPhase         velerov1api.BackupPhase
		expectQueuePosition int
	}{
		{
			name:                "New Backup gets queued",
			backup:              builder.ForBackup(velerov1api.DefaultNamespace, "backup-11").Result(),
			expectPhase:         velerov1api.BackupPhaseQueued,
			expectQueuePosition: 1,
		},
		{
			name:        "InProgress Backup is ignored",
			backup:      builder.ForBackup(velerov1api.DefaultNamespace, "backup-11").Phase(velerov1api.BackupPhaseInProgress).Result(),
			expectPhase: velerov1api.BackupPhaseInProgress,
		},
		{
			name: "Second New Backup gets queued with queuePosition 2",
			priorBackups: []*velerov1api.Backup{
				builder.ForBackup(velerov1api.DefaultNamespace, "backup-11").Phase(velerov1api.BackupPhaseQueued).QueuePosition(1).Result(),
			},
			backup:              builder.ForBackup(velerov1api.DefaultNamespace, "backup-12").Result(),
			expectPhase:         velerov1api.BackupPhaseQueued,
			expectQueuePosition: 2,
		},
		{
			name:        "Queued Backup moves to ReadyToStart if no others are running",
			backup:      builder.ForBackup(velerov1api.DefaultNamespace, "backup-11").Phase(velerov1api.BackupPhaseQueued).Result(),
			expectPhase: velerov1api.BackupPhaseReadyToStart,
		},
		{
			name: "Queued Backup remains queued if no spaces available",
			priorBackups: []*velerov1api.Backup{
				builder.ForBackup(velerov1api.DefaultNamespace, "backup-11").Phase(velerov1api.BackupPhaseInProgress).Result(),
				builder.ForBackup(velerov1api.DefaultNamespace, "backup-12").Phase(velerov1api.BackupPhaseInProgress).Result(),
			},
			concurrentBackups:   2,
			backup:              builder.ForBackup(velerov1api.DefaultNamespace, "backup-20").Phase(velerov1api.BackupPhaseQueued).QueuePosition(1).Result(),
			expectPhase:         velerov1api.BackupPhaseQueued,
			expectQueuePosition: 1,
		},
		{
			name: "Queued Backup remains queued if no spaces available including ReadyToStart",
			priorBackups: []*velerov1api.Backup{
				builder.ForBackup(velerov1api.DefaultNamespace, "backup-11").Phase(velerov1api.BackupPhaseInProgress).Result(),
				builder.ForBackup(velerov1api.DefaultNamespace, "backup-12").Phase(velerov1api.BackupPhaseReadyToStart).Result(),
			},
			concurrentBackups:   2,
			backup:              builder.ForBackup(velerov1api.DefaultNamespace, "backup-20").Phase(velerov1api.BackupPhaseQueued).QueuePosition(1).Result(),
			expectPhase:         velerov1api.BackupPhaseQueued,
			expectQueuePosition: 1,
		},
		{
			name: "Queued Backup remains queued if earlier runnable backup is also queued",
			priorBackups: []*velerov1api.Backup{
				builder.ForBackup(velerov1api.DefaultNamespace, "backup-11").Phase(velerov1api.BackupPhaseInProgress).Result(),
				builder.ForBackup(velerov1api.DefaultNamespace, "backup-12").Phase(velerov1api.BackupPhaseQueued).QueuePosition(1).Result(),
			},
			concurrentBackups:   3,
			backup:              builder.ForBackup(velerov1api.DefaultNamespace, "backup-20").Phase(velerov1api.BackupPhaseQueued).QueuePosition(2).Result(),
			expectPhase:         velerov1api.BackupPhaseQueued,
			expectQueuePosition: 2,
		},
		{
			name: "Queued Backup remains queued if in conflict with running backup",
			priorBackups: []*velerov1api.Backup{
				builder.ForBackup(velerov1api.DefaultNamespace, "backup-11").Phase(velerov1api.BackupPhaseInProgress).IncludedNamespaces("foo").Result(),
			},
			namespaces:          []string{"foo"},
			concurrentBackups:   3,
			backup:              builder.ForBackup(velerov1api.DefaultNamespace, "backup-20").Phase(velerov1api.BackupPhaseQueued).QueuePosition(1).IncludedNamespaces("foo").Result(),
			expectPhase:         velerov1api.BackupPhaseQueued,
			expectQueuePosition: 1,
		},
		{
			name: "Queued Backup remains queued if in conflict with ReadyToStart backup",
			priorBackups: []*velerov1api.Backup{
				builder.ForBackup(velerov1api.DefaultNamespace, "backup-11").Phase(velerov1api.BackupPhaseReadyToStart).IncludedNamespaces("foo").Result(),
			},
			namespaces:          []string{"foo"},
			concurrentBackups:   3,
			backup:              builder.ForBackup(velerov1api.DefaultNamespace, "backup-20").Phase(velerov1api.BackupPhaseQueued).QueuePosition(1).IncludedNamespaces("foo").Result(),
			expectPhase:         velerov1api.BackupPhaseQueued,
			expectQueuePosition: 1,
		},
		{
			name: "Queued Backup remains queued if in conflict with earlier queued backup",
			priorBackups: []*velerov1api.Backup{
				builder.ForBackup(velerov1api.DefaultNamespace, "backup-11").Phase(velerov1api.BackupPhaseQueued).QueuePosition(1).IncludedNamespaces("foo").Result(),
			},
			namespaces:          []string{"foo", "bar"},
			concurrentBackups:   3,
			backup:              builder.ForBackup(velerov1api.DefaultNamespace, "backup-20").Phase(velerov1api.BackupPhaseQueued).QueuePosition(2).IncludedNamespaces("foo", "bar").Result(),
			expectPhase:         velerov1api.BackupPhaseQueued,
			expectQueuePosition: 2,
		},
		{
			name: "Queued Backup remains queued if earlier non-ns-conflict backup exists",
			priorBackups: []*velerov1api.Backup{
				builder.ForBackup(velerov1api.DefaultNamespace, "backup-11").Phase(velerov1api.BackupPhaseInProgress).IncludedNamespaces("bar").Result(),
				builder.ForBackup(velerov1api.DefaultNamespace, "backup-12").Phase(velerov1api.BackupPhaseQueued).QueuePosition(1).IncludedNamespaces("foo").Result(),
			},
			namespaces:          []string{"foo", "bar", "baz"},
			concurrentBackups:   3,
			backup:              builder.ForBackup(velerov1api.DefaultNamespace, "backup-20").Phase(velerov1api.BackupPhaseQueued).QueuePosition(2).IncludedNamespaces("baz").Result(),
			expectPhase:         velerov1api.BackupPhaseQueued,
			expectQueuePosition: 2,
		},
		{
			name: "Running all-namespace backup conflicts with queued one-namespace backup ",
			priorBackups: []*velerov1api.Backup{
				builder.ForBackup(velerov1api.DefaultNamespace, "backup-11").Phase(velerov1api.BackupPhaseInProgress).IncludedNamespaces("*").Result(),
			},
			namespaces:          []string{"foo", "bar"},
			concurrentBackups:   3,
			backup:              builder.ForBackup(velerov1api.DefaultNamespace, "backup-20").Phase(velerov1api.BackupPhaseQueued).QueuePosition(1).IncludedNamespaces("foo").Result(),
			expectPhase:         velerov1api.BackupPhaseQueued,
			expectQueuePosition: 1,
		},
		{
			name: "Running one-namespace backup conflicts with queued all-namespace backup ",
			priorBackups: []*velerov1api.Backup{
				builder.ForBackup(velerov1api.DefaultNamespace, "backup-11").Phase(velerov1api.BackupPhaseInProgress).IncludedNamespaces("bar").Result(),
			},
			namespaces:          []string{"foo", "bar"},
			concurrentBackups:   3,
			backup:              builder.ForBackup(velerov1api.DefaultNamespace, "backup-20").Phase(velerov1api.BackupPhaseQueued).QueuePosition(1).IncludedNamespaces("*").Result(),
			expectPhase:         velerov1api.BackupPhaseQueued,
			expectQueuePosition: 1,
		},
		{
			name: "Queued Backup moves to ReadyToStart if running count < concurrentBackups",
			priorBackups: []*velerov1api.Backup{
				builder.ForBackup(velerov1api.DefaultNamespace, "backup-11").Phase(velerov1api.BackupPhaseInProgress).Result(),
				builder.ForBackup(velerov1api.DefaultNamespace, "backup-12").Phase(velerov1api.BackupPhaseInProgress).Result(),
			},
			concurrentBackups: 3,
			backup:            builder.ForBackup(velerov1api.DefaultNamespace, "backup-20").Phase(velerov1api.BackupPhaseQueued).QueuePosition(1).Result(),
			expectPhase:       velerov1api.BackupPhaseReadyToStart,
		},
		{
			name: "Queued Backup moves to ReadyToStart if running count < concurrentBackups and no ns conflict found",
			priorBackups: []*velerov1api.Backup{
				builder.ForBackup(velerov1api.DefaultNamespace, "backup-11").Phase(velerov1api.BackupPhaseReadyToStart).IncludedNamespaces("foo").Result(),
			},
			namespaces:        []string{"foo", "bar"},
			concurrentBackups: 3,
			backup:            builder.ForBackup(velerov1api.DefaultNamespace, "backup-20").Phase(velerov1api.BackupPhaseQueued).QueuePosition(1).IncludedNamespaces("bar").Result(),
			expectPhase:       velerov1api.BackupPhaseReadyToStart,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.backup == nil {
				return
			}

			backupTracker := NewBackupTracker()
			initObjs := []runtime.Object{}
			for _, priorBackup := range test.priorBackups {
				initObjs = append(initObjs, priorBackup)
				if priorBackup.Status.Phase == velerov1api.BackupPhaseReadyToStart {
					backupTracker.AddReadyToStart(priorBackup.Namespace, priorBackup.Name)
				} else if priorBackup.Status.Phase == velerov1api.BackupPhaseInProgress {
					backupTracker.Add(priorBackup.Namespace, priorBackup.Name)
				}
			}
			for _, ns := range test.namespaces {
				initObjs = append(initObjs, builder.ForNamespace(ns).Result())
			}
			initObjs = append(initObjs, test.backup)

			fakeClient := velerotest.NewFakeControllerRuntimeClient(t, initObjs...)
			logger := logrus.New()
			log := logger.WithField("controller", "backup-queue-test")
			r := NewBackupQueueReconciler(fakeClient, scheme, log, test.concurrentBackups, backupTracker)
			req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: test.backup.Namespace, Name: test.backup.Name}}
			res, err := r.Reconcile(t.Context(), req)
			gotErr := err != nil
			require.NoError(t, err)
			assert.Equal(t, ctrl.Result{}, res)
			assert.Equal(t, test.expectError, gotErr)
			backupAfter := velerov1api.Backup{}
			err = fakeClient.Get(t.Context(), types.NamespacedName{
				Namespace: test.backup.Namespace,
				Name:      test.backup.Name,
			}, &backupAfter)

			require.NoError(t, err)
			assert.Equal(t, test.expectPhase, backupAfter.Status.Phase)
			assert.Equal(t, test.expectQueuePosition, backupAfter.Status.QueuePosition)
		})
	}
}

// TestBackupQueueReconcilerTrackerNotLeakedWhenBackupCompletesDuringPatch verifies the fix for
// https://github.com/velero-io/velero/issues/10519: if backupReconciler picks up the
// ReadyToStart phase change (e.g. because the backup fails validation immediately) and calls
// BackupTracker.Add/Delete before backupQueueReconciler reaches its own AddReadyToStart call,
// the queue controller must not re-insert a tracker entry nobody will ever delete.
func TestBackupQueueReconcilerTrackerNotLeakedWhenBackupCompletesDuringPatch(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, velerov1api.AddToScheme(scheme))

	backup := builder.ForBackup(velerov1api.DefaultNamespace, "backup-11").Phase(velerov1api.BackupPhaseQueued).QueuePosition(1).Result()
	backupTracker := NewBackupTracker()

	fakeClient := velerotest.NewFakeControllerRuntimeClientBuilder(t).
		WithRuntimeObjects(backup).
		WithInterceptorFuncs(interceptor.Funcs{
			Patch: func(ctx context.Context, c ctrlClient.WithWatch, obj ctrlClient.Object, patch ctrlClient.Patch, opts ...ctrlClient.PatchOption) error {
				if err := c.Patch(ctx, obj, patch, opts...); err != nil {
					return err
				}
				// Simulate backupReconciler racing ahead of this goroutine: it sees
				// the ReadyToStart patch land, runs, and immediately completes the
				// backup (e.g. FailedValidation), calling Add then its deferred
				// Delete before backupQueueReconciler's next statement executes.
				if b, ok := obj.(*velerov1api.Backup); ok && b.Status.Phase == velerov1api.BackupPhaseReadyToStart {
					backupTracker.Add(b.Namespace, b.Name)
					backupTracker.Delete(b.Namespace, b.Name)
				}
				return nil
			},
		}).
		Build()

	logger := logrus.New()
	log := logger.WithField("controller", "backup-queue-test")
	r := NewBackupQueueReconciler(fakeClient, scheme, log, 1, backupTracker)
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: backup.Namespace, Name: backup.Name}}
	_, err := r.Reconcile(t.Context(), req)
	require.NoError(t, err)

	assert.Equal(t, 0, backupTracker.RunningCount(),
		"tracker entry must not be leaked when a racing reconcile completes the backup before AddReadyToStart runs")
}
