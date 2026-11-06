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

func TestBackupTrackerRecordsActiveTotal(t *testing.T) {
	m := metrics.NewServerMetrics()
	bt := NewBackupTrackerWithMetrics(m)

	activeTotal := func() float64 {
		g, ok := m.Metrics()["backup_active_total"].(prometheus.Gauge)
		require.True(t, ok, "backup_active_total gauge is not registered")
		return testutil.ToFloat64(g)
	}

	assert.Equal(t, float64(0), activeTotal())

	// ReadyToStart and InProgress both count as active, because together they
	// are what the queue controller limits concurrency on.
	bt.AddReadyToStart("ns", "name")
	assert.Equal(t, float64(1), activeTotal())

	bt.Add("ns", "name")
	assert.Equal(t, float64(1), activeTotal(), "moving ReadyToStart to InProgress must not double count")

	bt.AddReadyToStart("ns", "queued")
	assert.Equal(t, float64(2), activeTotal())

	// Post-processing backups are no longer occupying a slot.
	bt.AddPostProcessing("ns", "name")
	assert.Equal(t, float64(1), activeTotal())

	bt.Delete("ns", "queued")
	assert.Equal(t, float64(0), activeTotal())

	// Deleting a backup that is still post-processing leaves the count at zero
	// rather than going negative.
	bt.Delete("ns", "name")
	assert.Equal(t, float64(0), activeTotal())
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
