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

package controller

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/metrics"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
)

// patchCountingClient wraps a client.Client and counts Patch calls so tests can
// observe how many patches each Reconcile actually issues.
type patchCountingClient struct {
	crclient.Client
	patches int
}

func (p *patchCountingClient) Patch(ctx context.Context, obj crclient.Object, patch crclient.Patch, opts ...crclient.PatchOption) error {
	p.patches++
	return p.Client.Patch(ctx, obj, patch, opts...)
}

// TestSchedulePatchThreshold pins the Patch frequency of the schedule
// reconciler around spec.SkipImmediately handling.
//
// Known defect under test (schedule_controller.go, "update spec.SkipImmediately
// if it's changed"): the comparison is a *bool POINTER comparison between the
// fetched schedule and its DeepCopy, so it is always unequal. Every Reconcile
// of an unchanged schedule therefore issues one Patch.
func TestSchedulePatchThreshold(t *testing.T) {
	require.NoError(t, velerov1api.AddToScheme(scheme.Scheme))

	ctx := context.Background()
	const (
		testCron     = "0 0 1 1 *"
		testLastBk   = "2026-09-06 00:00:00"
		testSchedule = "name" // newScheduleBuilder hardcodes ns/name (see schedule_controller_test.go)
	)

	// Same helper as schedule_controller_test.go's TestReconcileOfSchedule —
	// that one is closure-local, so this file needs its own identical copy.
	newScheduleBuilder := func(phase velerov1api.SchedulePhase) *builder.ScheduleBuilder {
		return builder.ForSchedule("ns", testSchedule).Phase(phase)
	}

	newReconciler := func(c crclient.Client, skip bool) *scheduleReconciler {
		return NewScheduleReconciler("namespace", velerotest.NewLogger(), c, metrics.NewServerMetrics(), skip)
	}

	t.Run("skip-once flip persists on first reconcile only", func(t *testing.T) {
		base := (&fake.ClientBuilder{}).Build()
		counting := &patchCountingClient{Client: base}

		schedule := newScheduleBuilder(velerov1api.SchedulePhaseEnabled).
			CronSchedule(testCron).
			LastBackupTime(testLastBk).
			SkipImmediately(ptr.To(true)).
			Result()
		require.NoError(t, counting.Create(ctx, schedule))

		reconciler := newReconciler(counting, true)

		req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns", Name: testSchedule}}
		_, err := reconciler.Reconcile(ctx, req)
		require.NoError(t, err)
		firstRound := counting.patches

		_, err = reconciler.Reconcile(ctx, req)
		require.NoError(t, err)
		secondRound := counting.patches - firstRound

		t.Logf("patches in reconcile #1: %d", firstRound)
		t.Logf("additional patches in reconcile #2: %d", secondRound)
		// Reconcile #1 legitimately persists the skip-once flip (spec.SkipImmediately
		// true -> false plus status.LastSkipped). Everything else (phase, cron,
		// LastBackup) is stable, so it must patch exactly once.
		assert.Equal(t, 1, firstRound, "reconcile #1 should persist the skip-once flip with exactly one patch")
		// Reconcile #2 runs against the already-persisted state: comparing the
		// *bool SkipImmediately and the *metav1.Time LastSkipped by pointer would
		// always report a change after DeepCopy and force a patch every cycle.
		assert.Equal(t, 0, secondRound, "reconcile #2 of a fully-persisted schedule should issue no patch")

		stored := &velerov1api.Schedule{}
		require.NoError(t, counting.Get(ctx, req.NamespacedName, stored))
		require.NotNil(t, stored.Spec.SkipImmediately)
		assert.False(t, *stored.Spec.SkipImmediately, "skip-once flag should stay false after the flip is persisted")
	})

	t.Run("explicit false is a no-op", func(t *testing.T) {
		base := (&fake.ClientBuilder{}).Build()
		counting := &patchCountingClient{Client: base}

		schedule := newScheduleBuilder(velerov1api.SchedulePhaseEnabled).
			CronSchedule(testCron).
			LastBackupTime(testLastBk).
			SkipImmediately(ptr.To(false)).
			Result()
		require.NoError(t, counting.Create(ctx, schedule))

		reconciler := newReconciler(counting, true)

		req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns", Name: testSchedule}}
		_, err := reconciler.Reconcile(ctx, req)
		require.NoError(t, err)

		// The reconciler only nil-fills and flips true->false; an explicit false
		// with a stable phase/LastSkipped changes nothing, so no patch is needed.
		// (A pointer comparison would patch here on every reconcile.)
		assert.Equal(t, 0, counting.patches, "an explicit spec.skipImmediately=false should not be patched when nothing changes")

		stored := &velerov1api.Schedule{}
		require.NoError(t, counting.Get(ctx, req.NamespacedName, stored))
		require.NotNil(t, stored.Spec.SkipImmediately)
		assert.False(t, *stored.Spec.SkipImmediately, "SkipImmediately=false survives reconcile unchanged")
	})

	t.Run("nil to set transitions once", func(t *testing.T) {
		base := (&fake.ClientBuilder{}).Build()
		counting := &patchCountingClient{Client: base}

		// SkipImmediately left nil (builder default).
		schedule := newScheduleBuilder(velerov1api.SchedulePhaseEnabled).
			CronSchedule(testCron).
			LastBackupTime(testLastBk).
			Result()
		require.NoError(t, counting.Create(ctx, schedule))

		reconciler := newReconciler(counting, true)

		req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "ns", Name: testSchedule}}
		_, err := reconciler.Reconcile(ctx, req)
		require.NoError(t, err)

		assert.Equal(t, 1, counting.patches, "the nil->set transition should be covered by exactly one patch")

		stored := &velerov1api.Schedule{}
		require.NoError(t, counting.Get(ctx, req.NamespacedName, stored))
		// Current implementation contract: nil is filled from the reconciler
		// default (true) and then immediately flipped to false by the
		// skip-immediately block, so the persisted value is false, not true.
		require.NotNil(t, stored.Spec.SkipImmediately)
		assert.False(t, *stored.Spec.SkipImmediately, "nil SkipImmediately is filled then flipped to false in one reconcile")
	})
}
