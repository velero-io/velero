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
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/velero-io/velero/pkg/apis/velero/v1"
)

// Cancellation phase transitions must not use the replay-prone patch helpers
// (kube.PatchResource and friends apply JSON merge patches with no
// resourceVersion precondition, so a stale writer can overwrite an accepted
// cancellation). guardedBackupUpdate instead reads the Backup fresh, lets the
// apply closure compute the transition against that fresh object, and Updates
// it; the apiserver rejects the Update with a Conflict if the
// resourceVersion has moved, in which case it retries with another fresh
// read so exactly one transition wins.

const (
	guardedBackupUpdateMaxAttempts = 5
	guardedBackupUpdateBackoff     = 100 * time.Millisecond
)

// guardedBackupUpdate reads the Backup named ns/name fresh, lets apply
// compute changes against the fresh object, and Updates it. apply MUST
// re-validate its preconditions against the object it is given and return
// false when they no longer hold, in which case no write happens. On
// conflict, it retries with a fresh read, up to
// guardedBackupUpdateMaxAttempts attempts. It returns whether apply made a
// transition that was written.
func guardedBackupUpdate(ctx context.Context, kbClient kbclient.Client, ns, name string, apply func(fresh *velerov1api.Backup) bool) (bool, error) {
	for attempt := 1; ; attempt++ {
		fresh := &velerov1api.Backup{}
		if err := kbClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, fresh); err != nil {
			return false, err
		}

		if !apply(fresh) {
			return false, nil
		}

		if err := kbClient.Update(ctx, fresh); err != nil {
			if apierrors.IsConflict(err) && attempt < guardedBackupUpdateMaxAttempts {
				time.Sleep(guardedBackupUpdateBackoff)
				continue
			}
			return false, err
		}

		return true, nil
	}
}

// acceptCancellation transitions a Backup from one of acceptablePhases to
// Canceling when spec.cancel is set, recording acceptance time and the
// phase cancellation was accepted from. It returns true only when this call
// performed the transition; if the signal is absent, the phase is not
// acceptable (including already Canceling), or another writer won the race,
// it returns false and writes nothing.
func acceptCancellation(ctx context.Context, kbClient kbclient.Client, ns, name string, acceptablePhases ...velerov1api.BackupPhase) (bool, error) { //nolint:unparam // ns is always "velero" in current callers/tests, but the parameter is part of the general-purpose contract future phase owners will call with real namespaces.
	acceptable := sets.New(acceptablePhases...)
	now := metav1.Now()

	return guardedBackupUpdate(ctx, kbClient, ns, name, func(fresh *velerov1api.Backup) bool {
		if !fresh.Spec.Cancel || !acceptable.Has(fresh.Status.Phase) {
			return false
		}

		acceptedFrom := fresh.Status.Phase
		fresh.Status.Phase = velerov1api.BackupPhaseCanceling
		fresh.Status.Cancellation = &velerov1api.BackupCancellationStatus{
			AcceptedAt:        &now,
			AcceptedFromPhase: acceptedFrom,
		}
		return true
	})
}

// completeCancellation transitions a Canceling Backup to terminal Canceled,
// recording the completion timestamp and outcome reason. Counts already on
// status.cancellation are kept. It returns true only when this call performed
// the transition; a Backup in any other phase is left untouched.
func completeCancellation(ctx context.Context, kbClient kbclient.Client, ns, name, reason string) (bool, error) {
	now := metav1.Now()

	return guardedBackupUpdate(ctx, kbClient, ns, name, func(fresh *velerov1api.Backup) bool {
		if fresh.Status.Phase != velerov1api.BackupPhaseCanceling {
			return false
		}

		fresh.Status.Phase = velerov1api.BackupPhaseCanceled
		fresh.Status.CompletionTimestamp = &now
		if fresh.Status.Cancellation == nil {
			fresh.Status.Cancellation = &velerov1api.BackupCancellationStatus{}
		}
		if reason != "" {
			fresh.Status.Cancellation.Reason = reason
		}
		return true
	})
}
