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

package podvolume

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
)

const handlerTestRestoreUID = "handler-test-restore-uid"

// logCaptureHook records logrus entries so tests can assert which log paths
// the captured UpdateFunc handler exercised.
type logCaptureHook struct {
	mu      sync.Mutex
	entries []logrus.Entry
}

func (h *logCaptureHook) Levels() []logrus.Level { return logrus.AllLevels }

func (h *logCaptureHook) Fire(e *logrus.Entry) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.entries = append(h.entries, *e)
	return nil
}

func (h *logCaptureHook) messages() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	msgs := make([]string, 0, len(h.entries))
	for i := range h.entries {
		msgs = append(msgs, h.entries[i].Message)
	}
	return msgs
}

// containsMessage reports whether any captured entry's message contains sub.
// require.Contains cannot be used on messages() directly: it compares whole
// elements for equality, not substrings.
func (h *logCaptureHook) containsMessage(sub string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for i := range h.entries {
		if strings.Contains(h.entries[i].Message, sub) {
			return true
		}
	}
	return false
}

// newHandlerHarness builds a restorer through newRestorer with a fakeInformer
// (shared type from backupper_test.go), capturing the registered event
// handler. All repo/kube dependencies are nil: the captured UpdateFunc only
// touches the restorer's results map and its logger.
func newHandlerHarness(t *testing.T) (*fakeInformer, *restorer, *logCaptureHook) {
	t.Helper()

	logger := logrus.New()
	logger.Out = io.Discard
	hook := &logCaptureHook{}
	logger.AddHook(hook)

	informer := &fakeInformer{}
	r := newRestorer(
		context.Background(),
		nil, // repoLocker: not used by the UpdateFunc handler
		nil, // repoEnsurer: not used by the UpdateFunc handler
		informer,
		nil, // kubeClient
		nil, // crClient
		&velerov1api.Restore{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "velero",
				Name:      "restore-1",
				UID:       handlerTestRestoreUID,
			},
		},
		logger,
	)

	return informer, r, hook
}

// handlerTestPVR builds a PodVolumeRestore fixture for handler invocations.
// The results channel key is derived from Spec.Pod namespace/name
// (resultsKey), so the fixture pod is always ns-1/pod-1.
func handlerTestPVR(name, uidLabel string, phase velerov1api.PodVolumeRestorePhase) *velerov1api.PodVolumeRestore {
	pvr := &velerov1api.PodVolumeRestore{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "velero",
			Name:      name,
			UID:       types.UID("uid-" + name),
		},
		Spec: velerov1api.PodVolumeRestoreSpec{
			Pod: corev1api.ObjectReference{
				Kind:      "Pod",
				Namespace: "ns-1",
				Name:      "pod-1",
				UID:       "pod-uid-1",
			},
			Volume: "vol-1",
		},
		Status: velerov1api.PodVolumeRestoreStatus{
			Phase: phase,
		},
	}
	if uidLabel != "" {
		pvr.Labels = map[string]string{
			velerov1api.RestoreUIDLabel: uidLabel,
		}
	}
	return pvr
}

// registerResultsChannel installs a results channel under the fixture pod's
// key, mirroring how RestorePodVolumes registers one before spawning PVRs.
func registerResultsChannel(t *testing.T, r *restorer) chan *velerov1api.PodVolumeRestore {
	t.Helper()

	ch := make(chan *velerov1api.PodVolumeRestore, 1)
	r.resultsLock.Lock()
	r.results[resultsKey("ns-1", "pod-1")] = ch
	r.resultsLock.Unlock()
	return ch
}

// requireNoResultSend asserts the results channel carries no value. The
// captured handler runs synchronously on the test goroutine, so a filter
// leak would surface deterministically here.
func requireNoResultSend(t *testing.T, ch chan *velerov1api.PodVolumeRestore, scenario string) {
	t.Helper()
	select {
	case v := <-ch:
		t.Fatalf("%s: unexpected send on results channel: got PVR %s (phase %s)", scenario, v.Name, v.Status.Phase)
	default:
	}
}

// TestRestorerHandler pins the filter paths and the orphan results-key
// contract of the UpdateFunc captured by newRestorer:
//   - a PVR whose restore UID label does not match this restore is dropped
//     before any channel send;
//   - an update that does not change the phase is dropped;
//   - a phase transition to a non-terminal phase is dropped;
//   - a terminal transition when the results key is absent (e.g. after
//     RestorePodVolumes deletes it) logs an error, sends nothing, and never
//     blocks (if the !ok guard regressed into a nil-channel send, the
//     handler would block forever).
func TestRestorerHandler(t *testing.T) {
	t.Run("positive control: terminal transition sends once", func(t *testing.T) {
		informer, r, hook := newHandlerHarness(t)
		ch := registerResultsChannel(t, r)

		informer.handler.OnUpdate(
			handlerTestPVR("pvr-1", handlerTestRestoreUID, velerov1api.PodVolumeRestorePhaseNew),
			handlerTestPVR("pvr-1", handlerTestRestoreUID, velerov1api.PodVolumeRestorePhaseCompleted),
		)

		select {
		case got := <-ch:
			require.Equal(t, "pvr-1", got.Name)
			require.Equal(t, velerov1api.PodVolumeRestorePhaseCompleted, got.Status.Phase)
		default:
			t.Fatal("positive control failed: no send on results channel")
		}
		require.Empty(t, hook.messages(), "positive control must not log errors")
	})

	t.Run("restore UID label mismatch sends nothing", func(t *testing.T) {
		informer, r, _ := newHandlerHarness(t)
		ch := registerResultsChannel(t, r)

		// The new phase is terminal, so only the UID filter can stop the
		// send — isolates filter (1).
		informer.handler.OnUpdate(
			handlerTestPVR("pvr-1", "some-other-restore-uid", velerov1api.PodVolumeRestorePhaseNew),
			handlerTestPVR("pvr-1", "some-other-restore-uid", velerov1api.PodVolumeRestorePhaseCompleted),
		)

		requireNoResultSend(t, ch, "restore UID label mismatch")
	})

	t.Run("same non-terminal phase sends nothing", func(t *testing.T) {
		informer, r, _ := newHandlerHarness(t)
		ch := registerResultsChannel(t, r)

		informer.handler.OnUpdate(
			handlerTestPVR("pvr-1", handlerTestRestoreUID, velerov1api.PodVolumeRestorePhaseInProgress),
			handlerTestPVR("pvr-1", handlerTestRestoreUID, velerov1api.PodVolumeRestorePhaseInProgress),
		)

		requireNoResultSend(t, ch, "same phase")
	})

	t.Run("non-terminal phase transition sends nothing", func(t *testing.T) {
		informer, r, _ := newHandlerHarness(t)
		ch := registerResultsChannel(t, r)

		informer.handler.OnUpdate(
			handlerTestPVR("pvr-1", handlerTestRestoreUID, velerov1api.PodVolumeRestorePhaseNew),
			handlerTestPVR("pvr-1", handlerTestRestoreUID, velerov1api.PodVolumeRestorePhaseInProgress),
		)

		requireNoResultSend(t, ch, "non-terminal transition")
	})

	t.Run("orphan results key logs and never blocks", func(t *testing.T) {
		informer, _, hook := newHandlerHarness(t)
		// No channel registered: resultsKey("ns-1", "pod-1") is absent from
		// the results map, mirroring the state after RestorePodVolumes'
		// deferred delete.

		done := make(chan struct{})
		go func() {
			defer close(done)
			informer.handler.OnUpdate(
				handlerTestPVR("pvr-1", handlerTestRestoreUID, velerov1api.PodVolumeRestorePhaseNew),
				handlerTestPVR("pvr-1", handlerTestRestoreUID, velerov1api.PodVolumeRestorePhaseCompleted),
			)
		}()

		select {
		case <-done:
			// handler returned: nothing was sent and nothing is blocked.
		case <-time.After(2 * time.Second):
			t.Fatal("handler blocked on a missing results key: the !ok guard appears to have regressed into a nil-channel send")
		}

		require.True(t, hook.containsMessage("No results channel found for pod ns-1/pod-1"))
	})
}

// registerSizedResultsChannel installs a results channel with an explicit
// capacity, mirroring the real RestorePodVolumes geometry where the buffer is
// exactly len(volumesToRestore) wide (restorer.go:153).
func registerSizedResultsChannel(t *testing.T, r *restorer, bufferSize int) chan *velerov1api.PodVolumeRestore {
	t.Helper()

	ch := make(chan *velerov1api.PodVolumeRestore, bufferSize)
	r.resultsLock.Lock()
	r.results[resultsKey("ns-1", "pod-1")] = ch
	r.resultsLock.Unlock()
	return ch
}

// sendTerminalTransitions injects numRestores New -> Completed transitions,
// one per distinct PVR, mirroring the sends the receive loop in
// RestorePodVolumes consumes.
func sendTerminalTransitions(informer *fakeInformer, numRestores int) {
	for i := 0; i < numRestores; i++ {
		name := fmt.Sprintf("pvr-%d", i)
		informer.handler.OnUpdate(
			handlerTestPVR(name, handlerTestRestoreUID, velerov1api.PodVolumeRestorePhaseNew),
			handlerTestPVR(name, handlerTestRestoreUID, velerov1api.PodVolumeRestorePhaseCompleted),
		)
	}
}

// retransitionPVR0 injects the manual-edit scenario the restorer.go:263-265
// comment anticipates: pvr-0 flips between two terminal phases
// (Completed -> Canceled). The UpdateFunc has no per-PVR "already terminal"
// dedup, so the phase-change filter (restorer.go:106) and the terminal filter
// (restorer.go:110) both pass and the handler reaches resChan <- pvr
// (restorer.go:119). The handler runs on its own goroutine; the returned
// channel closes when OnUpdate returns.
func retransitionPVR0(informer *fakeInformer) chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		informer.handler.OnUpdate(
			handlerTestPVR("pvr-0", handlerTestRestoreUID, velerov1api.PodVolumeRestorePhaseCompleted),
			handlerTestPVR("pvr-0", handlerTestRestoreUID, velerov1api.PodVolumeRestorePhaseCanceled),
		)
	}()
	return done
}

// TestRestorerHandlerRetransitionOverflow pins the terminal re-transition
// behavior of the captured UpdateFunc under the real RestorePodVolumes channel
// geometry: the results buffer is exactly len(volumesToRestore) wide
// (restorer.go:153) while the receive loop consumes only numRestores results
// (restorer.go:245), and numRestores == len(volumesToRestore) when every
// volume yields a PodVolumeRestore.
//
// The handler dedups terminal results per PVR UID (terminalPVRs): a second
// terminal transition for the same PVR (e.g. a manual CR edit) is ignored
// before any channel interaction, so it can never block the handler and can
// never take a channel slot that belongs to another PVR's result — regardless
// of the buffer occupancy at the time.
func TestRestorerHandlerRetransitionOverflow(t *testing.T) {
	const numVolumes = 2

	t.Run("full buffer: re-transition is ignored without blocking", func(t *testing.T) {
		informer, r, hook := newHandlerHarness(t)
		ch := registerSizedResultsChannel(t, r, numVolumes)

		// numRestores == numVolumes normal terminal transitions from distinct
		// PVRs. With no consumer running, the buffer (capacity ==
		// numVolumes) fills deterministically.
		sendTerminalTransitions(informer, numVolumes)

		retransitionDone := retransitionPVR0(informer)
		select {
		case <-retransitionDone:
			// Handler returned promptly: the re-transition never touches the
			// channel, so a full buffer cannot park the informer's event
			// dispatch goroutine.
		case <-time.After(2 * time.Second):
			t.Fatal("re-transition blocked on the full buffer: the handler goroutine is parked on resChan <- pvr")
		}

		// The buffer still holds only the original numVolumes results.
		require.Len(t, ch, numVolumes)

		// The dedup is observable: the duplicate terminal result was
		// discarded deliberately rather than sent into the buffer.
		require.True(t, hook.containsMessage("Ignoring the terminal phase"))
	})

	t.Run("drained buffer: re-transition leaves the channel empty", func(t *testing.T) {
		informer, r, hook := newHandlerHarness(t)
		ch := registerSizedResultsChannel(t, r, numVolumes)

		sendTerminalTransitions(informer, numVolumes)
		// Drain everything, mirroring the receive loop having consumed all
		// numRestores results before the re-transition is observed.
		for i := 0; i < numVolumes; i++ {
			<-ch
		}

		require.True(t, notifyWithin(t, retransitionPVR0(informer), 2*time.Second),
			"re-transition must not block even on a drained buffer")

		select {
		case got := <-ch:
			t.Fatalf("re-transitioned result leaked into the drained channel: %s/%s", got.Name, got.Status.Phase)
		default:
			// The channel stays empty: the duplicate result never occupies a
			// slot and never surfaces as an orphaned result the receive loop
			// would misattribute.
		}
		require.True(t, hook.containsMessage("Ignoring the terminal phase"))
	})

	t.Run("buffer slack: re-transition still never sends", func(t *testing.T) {
		informer, r, _ := newHandlerHarness(t)
		// Real-path geometry when some volumes fail before their
		// PodVolumeRestore is created: the buffer stays
		// len(volumesToRestore)-wide while only numRestores == 1 PVR is
		// produced, leaving one free slot.
		ch := registerSizedResultsChannel(t, r, numVolumes)

		sendTerminalTransitions(informer, 1)

		require.True(t, notifyWithin(t, retransitionPVR0(informer), 2*time.Second),
			"re-transition must not block despite free buffer slack")

		count := 0
	drain:
		for {
			select {
			case <-ch:
				count++
			default:
				break drain
			}
		}
		require.Equal(t, 1, count,
			"only the original result may be buffered: the duplicate must not consume the spare slot")
	})
}

// notifyWithin reports whether done is closed within d, failing the test
// (with a blocking diagnosis) otherwise.
func notifyWithin(t *testing.T, done chan struct{}, d time.Duration) bool {
	t.Helper()
	select {
	case <-done:
		return true
	case <-time.After(d):
		t.Fatal("handler goroutine is parked: the send appears to block")
		return false
	}
}
