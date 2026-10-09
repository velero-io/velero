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

package schedule

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	factorymocks "github.com/vmware-tanzu/velero/pkg/client/mocks"
	"github.com/vmware-tanzu/velero/pkg/cmd/cli"
	cmdtest "github.com/vmware-tanzu/velero/pkg/cmd/test"
	"github.com/vmware-tanzu/velero/pkg/cmd/util/flag"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
)

func scheduleIsPaused(t *testing.T, crClient ctrlclient.Client, namespace, name string) bool {
	t.Helper()

	schedule := new(velerov1api.Schedule)
	require.NoError(t, crClient.Get(t.Context(), ctrlclient.ObjectKey{Namespace: namespace, Name: name}, schedule))
	return schedule.Spec.Paused
}

func TestRunPauseOnlyTouchesTheVeleroNamespace(t *testing.T) {
	labeled := func(s *velerov1api.Schedule) *velerov1api.Schedule {
		s.Labels = map[string]string{"foo": "bar"}
		return s
	}

	tests := []struct {
		name    string
		options func(o *cli.SelectOptions)
	}{
		{
			name:    "--all",
			options: func(o *cli.SelectOptions) { o.All = true },
		},
		{
			name: "--selector",
			options: func(o *cli.SelectOptions) {
				o.Selector = flag.LabelSelector{LabelSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"foo": "bar"}}}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ours := labeled(builder.ForSchedule(cmdtest.VeleroNameSpace, "ours").CronSchedule("@daily").Result())
			theirs := labeled(builder.ForSchedule("another-velero", "theirs").CronSchedule("@daily").Result())

			crClient := velerotest.NewFakeControllerRuntimeClient(t, ours, theirs)

			f := &factorymocks.Factory{}
			f.On("Namespace").Return(cmdtest.VeleroNameSpace)
			f.On("KubebuilderClient").Return(crClient, nil)

			o := cli.NewSelectOptions("pause", "schedule")
			tc.options(o)
			require.NoError(t, o.Validate())

			require.NoError(t, runPause(f, o, true, nil))

			assert.True(t, scheduleIsPaused(t, crClient, cmdtest.VeleroNameSpace, "ours"))
			assert.False(t, scheduleIsPaused(t, crClient, "another-velero", "theirs"))
		})
	}
}

func TestRunUnpauseOnlyTouchesTheVeleroNamespace(t *testing.T) {
	paused := func(ns, name string) *velerov1api.Schedule {
		s := builder.ForSchedule(ns, name).CronSchedule("@daily").Result()
		s.Spec.Paused = true
		return s
	}

	ours := paused(cmdtest.VeleroNameSpace, "ours")
	theirs := paused("another-velero", "theirs")

	crClient := velerotest.NewFakeControllerRuntimeClient(t, ours, theirs)

	f := &factorymocks.Factory{}
	f.On("Namespace").Return(cmdtest.VeleroNameSpace)
	f.On("KubebuilderClient").Return(crClient, nil)

	o := cli.NewSelectOptions("pause", "schedule")
	o.All = true

	require.NoError(t, runPause(f, o, false, nil))

	assert.False(t, scheduleIsPaused(t, crClient, cmdtest.VeleroNameSpace, "ours"))
	assert.True(t, scheduleIsPaused(t, crClient, "another-velero", "theirs"))
}
