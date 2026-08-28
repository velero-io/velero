package exposer

import (
	"testing"

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
