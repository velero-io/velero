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

package snapshotlocation

import (
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/vmware-tanzu/velero/pkg/builder"
	factorymocks "github.com/vmware-tanzu/velero/pkg/client/mocks"
	cmdtest "github.com/vmware-tanzu/velero/pkg/cmd/test"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
	veleroexec "github.com/vmware-tanzu/velero/pkg/util/exec"
)

func TestNewGetCommand(t *testing.T) {
	vslList := []string{"vsl1", "vsl2"}

	f := &factorymocks.Factory{}
	kbclient := velerotest.NewFakeControllerRuntimeClient(t)
	f.On("Namespace").Return(mock.Anything)
	f.On("KubebuilderClient").Return(kbclient, nil)

	// get command
	c := NewGetCommand(f, "velero snapshot-location get")
	assert.Equal(t, "Get snapshot locations", c.Short)

	c.Execute()

	if os.Getenv(cmdtest.CaptureFlag) == "1" {
		c.SetArgs([]string{"vsl1", "vsl2"})
		c.Execute()
		return
	}
	cmd := exec.CommandContext(t.Context(), os.Args[0], []string{"-test.run=TestNewGetCommand"}...)
	cmd.Env = append(os.Environ(), fmt.Sprintf("%s=1", cmdtest.CaptureFlag))
	_, stderr, err := veleroexec.RunCommand(cmd)

	if err != nil {
		assert.Contains(t, stderr, fmt.Sprintf("volumesnapshotlocations.velero.io \"%s\" not found", vslList[0]))
		return
	}
	t.Fatalf("process ran with err %v, want snapshot location get to fail for non-existent VSL", err)
}

func TestNewGetCommand_SelectorFiltersVSLs(t *testing.T) {
	f := &factorymocks.Factory{}
	client := velerotest.NewFakeControllerRuntimeClient(t)

	vslLabeled := builder.ForVolumeSnapshotLocation(cmdtest.VeleroNameSpace, "vsl-labeled").
		ObjectMeta(builder.WithLabels("env", "test")).
		Result()
	err := client.Create(t.Context(), vslLabeled, &kbclient.CreateOptions{})
	require.NoError(t, err)

	vslUnlabeled := builder.ForVolumeSnapshotLocation(cmdtest.VeleroNameSpace, "vsl-unlabeled").
		Result()
	err = client.Create(t.Context(), vslUnlabeled, &kbclient.CreateOptions{})
	require.NoError(t, err)

	f.On("KubebuilderClient").Return(client, nil)
	f.On("Namespace").Return(cmdtest.VeleroNameSpace)

	// get command with selector
	c := NewGetCommand(f, "velero snapshot-location get")
	c.SetArgs([]string{"--selector", "env=test"})
	err = c.Execute()
	require.NoError(t, err)

	if os.Getenv(cmdtest.CaptureFlag) == "1" {
		return
	}

	cmd := exec.CommandContext(t.Context(), os.Args[0], []string{"-test.run=TestNewGetCommand_SelectorFiltersVSLs"}...)
	cmd.Env = append(os.Environ(), fmt.Sprintf("%s=1", cmdtest.CaptureFlag))
	stdout, _, err := veleroexec.RunCommand(cmd)
	require.NoError(t, err)

	// assert that the labeled VSL is returned
	assert.Contains(t, stdout, "vsl-labeled")
	// assert that the unlabeled VSL is not returned
	assert.NotContains(t, stdout, "vsl-unlabeled")
}
