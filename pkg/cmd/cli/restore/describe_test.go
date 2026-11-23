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

package restore

import (
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"
	controllerclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/velero-io/velero/pkg/builder"
	factorymocks "github.com/velero-io/velero/pkg/client/mocks"
	cmdtest "github.com/velero-io/velero/pkg/cmd/test"
	"github.com/velero-io/velero/pkg/features"
	"github.com/velero-io/velero/pkg/test"
	veleroexec "github.com/velero-io/velero/pkg/util/exec"
)

func TestNewDescribeCommand(t *testing.T) {
	// create a factory
	f := &factorymocks.Factory{}
	restoreName := "restore-describe-1"
	testRestore := builder.ForRestore(cmdtest.VeleroNameSpace, restoreName).Result()

	clientConfig := rest.Config{}
	kbClient := test.NewFakeControllerRuntimeClient(t)
	kbClient.Create(t.Context(), testRestore, &controllerclient.CreateOptions{})

	f.On("ClientConfig").Return(&clientConfig, nil)
	f.On("Namespace").Return(cmdtest.VeleroNameSpace)
	f.On("KubebuilderClient").Return(kbClient, nil)

	// create command
	c := NewDescribeCommand(f, "velero restore describe")
	assert.Equal(t, "Describe restores", c.Short)

	features.NewFeatureFlagSet("EnableCSI")
	defer features.NewFeatureFlagSet()

	c.SetArgs([]string{restoreName})
	e := c.Execute()
	require.NoError(t, e)

	if os.Getenv(cmdtest.CaptureFlag) == "1" {
		return
	}
	cmd := exec.CommandContext(t.Context(), os.Args[0], []string{"-test.run=TestNewDescribeCommand"}...)
	cmd.Env = append(os.Environ(), fmt.Sprintf("%s=1", cmdtest.CaptureFlag))
	stdout, _, err := veleroexec.RunCommand(cmd)

	if err == nil {
		assert.Contains(t, stdout, fmt.Sprintf("Name:         %s", restoreName))
		return
	}
	t.Fatalf("process ran with err %v, want backups by get()", err)
}
