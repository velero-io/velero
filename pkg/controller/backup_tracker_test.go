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

package controller

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/velero-io/velero/pkg/metrics"
)

func TestBackupTracker(t *testing.T) {
	bt := NewBackupTracker()

	assert.False(t, bt.Contains("ns", "name"))

	bt.Add("ns", "name")
	assert.True(t, bt.Contains("ns", "name"))

	bt.Add("ns2", "name2")
	assert.True(t, bt.Contains("ns", "name"))
	assert.True(t, bt.Contains("ns2", "name2"))

	bt.Delete("ns", "name")
	assert.False(t, bt.Contains("ns", "name"))
	assert.True(t, bt.Contains("ns2", "name2"))

	bt.Delete("ns2", "name2")
	assert.False(t, bt.Contains("ns2", "name2"))
}

func TestBackupTrackerRecordsActive(t *testing.T) {
	m := metrics.NewServerMetrics()
	bt := NewBackupTrackerWithMetrics(m)

	phase := func(p string) float64 {
		g, ok := m.Metrics()["backup_active"].(*prometheus.GaugeVec)
		require.True(t, ok, "backup_active is not a registered GaugeVec")
		return testutil.ToFloat64(g.WithLabelValues(p))
	}
	inFlight := func() float64 {
		return phase(metrics.BackupActivePhaseReadyToStart) +
			phase(metrics.BackupActivePhaseInProgress) +
			phase(metrics.BackupActivePhasePostProcessing)
	}

	assert.Equal(t, float64(0), inFlight())

	bt.AddReadyToStart("ns", "name")
	assert.Equal(t, float64(1), phase(metrics.BackupActivePhaseReadyToStart))
	assert.Equal(t, float64(1), inFlight())

	bt.Add("ns", "name")
	assert.Equal(t, float64(0), phase(metrics.BackupActivePhaseReadyToStart))
	assert.Equal(t, float64(1), phase(metrics.BackupActivePhaseInProgress))
	assert.Equal(t, float64(1), inFlight(), "moving ReadyToStart to InProgress must not double count")

	// The case that matters: a data mover backup spends its DataUpload time in
	// WaitingForPluginOperations, which the tracker holds as post-processing.
	// It no longer occupies a concurrency slot, but it is very much running, so
	// the in-flight total must stay at 1.
	bt.AddPostProcessing("ns", "name")
	assert.Equal(t, float64(0), phase(metrics.BackupActivePhaseInProgress))
	assert.Equal(t, float64(1), phase(metrics.BackupActivePhasePostProcessing))
	assert.Equal(t, float64(1), inFlight(), "a backup in post-processing is still in flight")

	bt.AddReadyToStart("ns", "queued")
	assert.Equal(t, float64(2), inFlight())

	bt.Delete("ns", "queued")
	bt.Delete("ns", "name")
	assert.Equal(t, float64(0), inFlight())
	assert.Equal(t, float64(0), phase(metrics.BackupActivePhasePostProcessing))
}

func TestBackupTrackerWithoutMetricsDoesNotPanic(t *testing.T) {
	bt := NewBackupTracker()

	assert.NotPanics(t, func() {
		bt.AddReadyToStart("ns", "name")
		bt.Add("ns", "name")
		bt.AddPostProcessing("ns", "name")
		bt.Delete("ns", "name")
	})
}
