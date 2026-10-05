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

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	factorymocks "github.com/vmware-tanzu/velero/pkg/client/mocks"
	cmdtest "github.com/vmware-tanzu/velero/pkg/cmd/test"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
)

// TestCreateScheduleAppliesAnnotations verifies that --annotations reaches the created
// Schedule object. Backups generated from a Schedule inherit schedule.Annotations (see
// BackupBuilder.FromSchedule), so dropping them here silently strips the annotations from
// every backup the schedule produces.
func TestCreateScheduleAppliesAnnotations(t *testing.T) {
	crClient := velerotest.NewFakeControllerRuntimeClient(t)

	f := &factorymocks.Factory{}
	f.On("Namespace").Return(cmdtest.VeleroNameSpace)
	f.On("KubebuilderClient").Return(crClient, nil)

	o := NewCreateOptions()
	o.Schedule = "@daily"
	o.BackupOptions.Name = "test-schedule"
	require.NoError(t, o.BackupOptions.Annotations.Set("owner=team-a,purpose=nightly"))
	require.NoError(t, o.BackupOptions.Labels.Set("env=prod"))

	require.NoError(t, o.Run(&cobra.Command{}, f))

	created := new(velerov1api.Schedule)
	require.NoError(t, crClient.Get(t.Context(), ctrlclient.ObjectKey{
		Namespace: cmdtest.VeleroNameSpace,
		Name:      "test-schedule",
	}, created))

	assert.Equal(t, map[string]string{"env": "prod"}, created.Labels)
	assert.Equal(t, map[string]string{"owner": "team-a", "purpose": "nightly"}, created.Annotations)
}
