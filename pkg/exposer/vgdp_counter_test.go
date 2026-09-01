package exposer

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/vmware-tanzu/velero/pkg/builder"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	velerov2alpha1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v2alpha1"
)

func TestIsConstrained(t *testing.T) {
	tests := []struct {
		name          string
		counter       *VgdpCounter
		kubeClientObj []client.Object
		getErr        bool
		expected      bool
	}{
		{
			name:     "no change, constrained",
			counter:  &VgdpCounter{},
			expected: true,
		},
		{
			name:    "no change, not constrained",
			counter: &VgdpCounter{allowedQueueLength: 1},
		},
		{
			name: "change in du, get failed",
			counter: &VgdpCounter{
				allowedQueueLength: 1,
				duState:            dynamicQueueLength{0, 1},
			},
			getErr: true,
		},
		{
			name: "change in du, constrained",
			counter: &VgdpCounter{
				allowedQueueLength: 1,
				duState:            dynamicQueueLength{0, 1},
			},
			kubeClientObj: []client.Object{
				builder.ForDataUpload("velero", "test-1").Labels(map[string]string{ExposeOnGoingLabel: "true"}).Result(),
			},
			expected: true,
		},
		{
			name: "change in dd, get failed",
			counter: &VgdpCounter{
				allowedQueueLength: 1,
				ddState:            dynamicQueueLength{0, 1},
			},
			getErr: true,
		},
		{
			name: "change in dd, constrained",
			counter: &VgdpCounter{
				allowedQueueLength: 1,
				ddState:            dynamicQueueLength{0, 1},
			},
			kubeClientObj: []client.Object{
				builder.ForDataDownload("velero", "test-1").Labels(map[string]string{ExposeOnGoingLabel: "true"}).Result(),
			},
			expected: true,
		},
		{
			name: "change in pvb, get failed",
			counter: &VgdpCounter{
				allowedQueueLength: 1,
				pvbState:           dynamicQueueLength{0, 1},
			},
			getErr: true,
		},
		{
			name: "change in pvb, constrained",
			counter: &VgdpCounter{
				allowedQueueLength: 1,
				pvbState:           dynamicQueueLength{0, 1},
			},
			kubeClientObj: []client.Object{
				builder.ForPodVolumeBackup("velero", "test-1").Labels(map[string]string{ExposeOnGoingLabel: "true"}).Result(),
			},
			expected: true,
		},
		{
			name: "change in pvr, get failed",
			counter: &VgdpCounter{
				allowedQueueLength: 1,
				pvrState:           dynamicQueueLength{0, 1},
			},
			getErr: true,
		},
		{
			name: "change in pvr, constrained",
			counter: &VgdpCounter{
				allowedQueueLength: 1,
				pvrState:           dynamicQueueLength{0, 1},
			},
			kubeClientObj: []client.Object{
				builder.ForPodVolumeRestore("velero", "test-1").Labels(map[string]string{ExposeOnGoingLabel: "true"}).Result(),
			},
			expected: true,
		},
		{
			name: "change in du, pvb, not constrained",
			counter: &VgdpCounter{
				allowedQueueLength: 3,
				duState:            dynamicQueueLength{0, 1},
				pvbState:           dynamicQueueLength{0, 1},
			},
			kubeClientObj: []client.Object{
				builder.ForDataUpload("velero", "test-1").Labels(map[string]string{ExposeOnGoingLabel: "true"}).Result(),
				builder.ForPodVolumeBackup("velero", "test-1").Labels(map[string]string{ExposeOnGoingLabel: "true"}).Result(),
			},
		},
		{
			name: "change in dd, pvr, constrained",
			counter: &VgdpCounter{
				allowedQueueLength: 1,
				ddState:            dynamicQueueLength{0, 1},
				pvrState:           dynamicQueueLength{0, 1},
			},
			kubeClientObj: []client.Object{
				builder.ForDataDownload("velero", "test-1").Labels(map[string]string{ExposeOnGoingLabel: "true"}).Result(),
				builder.ForPodVolumeRestore("velero", "test-1").Labels(map[string]string{ExposeOnGoingLabel: "true"}).Result(),
			},
			expected: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scheme := runtime.NewScheme()

			if !test.getErr {
				err := velerov1api.AddToScheme(scheme)
				require.NoError(t, err)

				err = velerov2alpha1api.AddToScheme(scheme)
				require.NoError(t, err)
			}

			test.counter.client = fake.NewClientBuilder().WithScheme(scheme).WithObjects(test.kubeClientObj...).Build()

			result := test.counter.IsConstrained(t.Context(), velerotest.NewLogger())

			assert.Equal(t, test.expected, result)

			if !test.getErr {
				assert.Equal(t, test.counter.duState.changeID, test.counter.duCacheState.changeID)
				assert.Equal(t, test.counter.ddState.changeID, test.counter.ddCacheState.changeID)
				assert.Equal(t, test.counter.pvbState.changeID, test.counter.pvbCacheState.changeID)
				assert.Equal(t, test.counter.pvrState.changeID, test.counter.pvrCacheState.changeID)
			} else {
				or := test.counter.duState.changeID != test.counter.duCacheState.changeID
				if !or {
					or = test.counter.ddState.changeID != test.counter.ddCacheState.changeID
				}

				if !or {
					or = test.counter.pvbState.changeID != test.counter.pvbCacheState.changeID
				}

				if !or {
					or = test.counter.pvrState.changeID != test.counter.pvrCacheState.changeID
				}

				assert.True(t, or)
			}
		})
	}
}

// listProbeClient records whether more than one List call is ever in flight at
// the same time, so a test can tell serialized callers from concurrent ones
// without relying on the race detector.
type listProbeClient struct {
	client.Client

	inFlight atomic.Int32
	maxSeen  atomic.Int32
}

func (c *listProbeClient) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	inFlight := c.inFlight.Add(1)

	for {
		maxSeen := c.maxSeen.Load()
		if inFlight <= maxSeen || c.maxSeen.CompareAndSwap(maxSeen, inFlight) {
			break
		}
	}

	// widen the window so overlapping callers are observed reliably
	time.Sleep(time.Millisecond * 20)

	err := c.Client.List(ctx, list, opts...)

	c.inFlight.Add(-1)

	return err
}

// The node-agent shares one VgdpCounter across the DataUpload, DataDownload,
// PodVolumeBackup and PodVolumeRestore controllers, each of which calls
// IsConstrained from its own goroutine. The cache states it updates must not be
// read and written by two of them at once.
func TestIsConstrainedConcurrent(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, velerov1api.AddToScheme(scheme))
	require.NoError(t, velerov2alpha1api.AddToScheme(scheme))

	probe := &listProbeClient{
		Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(
			builder.ForDataUpload("velero", "du-1").Labels(map[string]string{ExposeOnGoingLabel: "true"}).Result(),
		).Build(),
	}

	counter := &VgdpCounter{
		client:             probe,
		allowedQueueLength: 100,
	}

	log := velerotest.NewLogger()

	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for range 10 {
				// stand in for the informer handlers, so every call re-lists
				atomic.AddUint64(&counter.duState.changeID, 1)

				counter.IsConstrained(t.Context(), log)
			}
		}()
	}

	wg.Wait()

	assert.Equal(t, int32(1), probe.maxSeen.Load(), "IsConstrained ran concurrently on a shared counter")
}
