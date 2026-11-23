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

package podvolume

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/velero-io/velero/pkg/builder"
)

func TestOptoutVolume(t *testing.T) {
	pod := builder.ForPod("ns-1", "pod-1").Volumes(
		builder.ForVolume("pod-vol-1").PersistentVolumeClaimSource("pvc-1").Result(),
		builder.ForVolume("pod-vol-2").PersistentVolumeClaimSource("pvc-2").Result(),
	).Result()
	tracker := NewTracker()
	tracker.Optout(pod, "pod-vol-1")
	ok, pn := tracker.OptedoutByPod("ns-1", "pvc-1")
	assert.True(t, ok)
	assert.Equal(t, "pod-1", pn)
	// if a volume is tracked for opted out, it can't be tracked as "tracked" or "taken"
	tracker.Track(pod, "pod-vol-1")
	tracker.Track(pod, "pod-vol-2")
	assert.False(t, tracker.Has("ns-1", "pvc-1"))
	assert.True(t, tracker.Has("ns-1", "pvc-2"))
	tracker.Take(pod, "pod-vol-1")
	tracker.Take(pod, "pod-vol-2")
	ok1, _ := tracker.TakenForPodVolume(pod, "pod-vol-1")
	assert.False(t, ok1)
	ok2, _ := tracker.TakenForPodVolume(pod, "pod-vol-2")
	assert.True(t, ok2)
}

func TestABC(t *testing.T) {
	tracker := NewTracker()
	v1, v2 := tracker.OptedoutByPod("a", "b")
	t.Logf("v1: %v, v2: %v", v1, v2)
}
