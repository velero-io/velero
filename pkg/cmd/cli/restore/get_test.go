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
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/velero-io/velero/pkg/builder"
	factorymocks "github.com/velero-io/velero/pkg/client/mocks"
	cmdtest "github.com/velero-io/velero/pkg/cmd/test"
	velerotest "github.com/velero-io/velero/pkg/test"
	veleroexec "github.com/velero-io/velero/pkg/util/exec"
)

func TestNewGetCommand(t *testing.T) {
	args := []string{"b1", "b2", "b3"}

	// create a factory
	f := &factorymocks.Factory{}

	client := velerotest.NewFakeControllerRuntimeClient(t)

	for _, restoreName := range args {
		restore := builder.ForRestore(cmdtest.VeleroNameSpace, restoreName).ObjectMeta(builder.WithLabels("abc", "abc")).Result()
		err := client.Create(t.Context(), restore, &kbclient.CreateOptions{})
		require.NoError(t, err)
	}

	f.On("KubebuilderClient").Return(client, nil)
	f.On("Namespace").Return(cmdtest.VeleroNameSpace)

	// create command
	c := NewGetCommand(f, "velero restore get")
	require.Equal(t, "Get restores", c.Short)

	c.SetArgs(args)
	e := c.Execute()
	require.NoError(t, e)

	if os.Getenv(cmdtest.CaptureFlag) == "1" {
		return
	}

	cmd := exec.CommandContext(t.Context(), os.Args[0], []string{"-test.run=TestNewGetCommand"}...)
	cmd.Env = append(os.Environ(), fmt.Sprintf("%s=1", cmdtest.CaptureFlag))
	stdout, _, err := veleroexec.RunCommand(cmd)
	require.NoError(t, err)

	if err == nil {
		output := strings.Split(stdout, "\n")
		i := 0
		for _, line := range output {
			if strings.Contains(line, "New") {
				i++
			}
		}
		require.Len(t, args, i)
	}
}
