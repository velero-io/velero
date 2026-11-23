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

package backuplocation

import (
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	factorymocks "github.com/velero-io/velero/pkg/client/mocks"
	cmdtest "github.com/velero-io/velero/pkg/cmd/test"
	velerotest "github.com/velero-io/velero/pkg/test"
	veleroexec "github.com/velero-io/velero/pkg/util/exec"
)

func TestNewGetCommand(t *testing.T) {
	bkList := []string{"b1", "b2"}

	f := &factorymocks.Factory{}
	kbclient := velerotest.NewFakeControllerRuntimeClient(t)
	f.On("Namespace").Return(mock.Anything)
	f.On("KubebuilderClient").Return(kbclient, nil)

	// get command
	c := NewGetCommand(f, "velero backup-location get")
	assert.Equal(t, "Get backup storage locations", c.Short)

	c.Execute()

	if os.Getenv(cmdtest.CaptureFlag) == "1" {
		c.SetArgs([]string{"b1", "b2", "--default"})
		c.Execute()
		return
	}
	cmd := exec.CommandContext(t.Context(), os.Args[0], []string{"-test.run=TestNewGetCommand"}...)
	cmd.Env = append(os.Environ(), fmt.Sprintf("%s=1", cmdtest.CaptureFlag))
	_, stderr, err := veleroexec.RunCommand(cmd)

	if err != nil {
		assert.Contains(t, stderr, fmt.Sprintf("backupstoragelocations.velero.io \"%s\" not found", bkList[0]))
		return
	}
	t.Fatalf("process ran with err %v, want backup delete successfully", err)
}
