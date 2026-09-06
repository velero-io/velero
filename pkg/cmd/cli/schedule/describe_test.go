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

	"github.com/vmware-tanzu/velero/pkg/builder"
	factorymocks "github.com/vmware-tanzu/velero/pkg/client/mocks"
	cmdtest "github.com/vmware-tanzu/velero/pkg/cmd/test"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
)

func TestNewDescribeCommandDescribesOnlyTheVeleroNamespace(t *testing.T) {
	ours := builder.ForSchedule(cmdtest.VeleroNameSpace, "ours").CronSchedule("@daily").Result()
	theirs := builder.ForSchedule("another-velero", "theirs").CronSchedule("@daily").Result()

	crClient := velerotest.NewFakeControllerRuntimeClient(t, ours, theirs)

	f := &factorymocks.Factory{}
	f.On("Namespace").Return(cmdtest.VeleroNameSpace)
	f.On("KubebuilderClient").Return(crClient, nil)

	c := NewDescribeCommand(f, "describe")
	c.SetArgs([]string{})

	out := captureStdout(t, func() {
		require.NoError(t, c.Execute())
	})

	assert.Contains(t, out, "ours")
	assert.NotContains(t, out, "theirs")
}
