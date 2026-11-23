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

	flag "github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	velerov1api "github.com/velero-io/velero/pkg/apis/velero/v1"
	factorymocks "github.com/velero-io/velero/pkg/client/mocks"
	"github.com/velero-io/velero/pkg/cmd/cli"
	cmdtest "github.com/velero-io/velero/pkg/cmd/test"
	velerotest "github.com/velero-io/velero/pkg/test"
	veleroexec "github.com/velero-io/velero/pkg/util/exec"
)

func TestNewDeleteCommand(t *testing.T) {
	// create a factory
	f := &factorymocks.Factory{}
	kbclient := velerotest.NewFakeControllerRuntimeClient(t)
	f.On("Namespace").Return(mock.Anything)
	f.On("KubebuilderClient").Return(kbclient, nil)

	// create command
	c := NewDeleteCommand(f, "velero backup-location delete")
	assert.Equal(t, "Delete backup storage locations", c.Short)

	o := cli.NewDeleteOptions("backup")
	flags := new(flag.FlagSet)
	o.BindFlags(flags)
	flags.Parse([]string{"--confirm"})

	args := []string{"bk-loc-1", "bk-loc-2"}
	e := o.Complete(f, args)
	require.NoError(t, e)
	e = o.Validate(c, f, args)
	require.NoError(t, e)
	c.SetArgs([]string{"bk-1", "--confirm"})
	e = c.Execute()
	require.NoError(t, e)

	e = Run(f, o)
	require.NoError(t, e)
	if os.Getenv(cmdtest.CaptureFlag) == "1" {
		return
	}

	cmd := exec.CommandContext(t.Context(), os.Args[0], []string{"-test.run=TestNewDeleteCommand"}...)
	cmd.Env = append(os.Environ(), fmt.Sprintf("%s=1", cmdtest.CaptureFlag))
	stdout, _, err := veleroexec.RunCommand(cmd)

	if err == nil {
		assert.Contains(t, stdout, "No backup-locations found")
		return
	}
	t.Fatalf("process ran with err %v, want backups by get()", err)
}
func TestDeleteFunctions(t *testing.T) {
	//t.Run("create the other create command with fromSchedule option for Run() other branches", func(t *testing.T) {
	// create a factory
	f := &factorymocks.Factory{}
	kbclient := velerotest.NewFakeControllerRuntimeClient(t)
	f.On("Namespace").Return(mock.Anything)
	f.On("KubebuilderClient").Return(kbclient, nil)

	bkList := velerov1api.BackupList{}
	bkrepoList := velerov1api.BackupRepositoryList{}
	t.Run("findAssociatedBackups", func(t *testing.T) {
		bkList, e := findAssociatedBackups(kbclient, "bk-loc-1", "ns1")
		assert.Empty(t, bkList.Items)
		assert.NoError(t, e)
	})

	t.Run("findAssociatedBackupRepos", func(t *testing.T) {
		bkrepoList, e := findAssociatedBackupRepos(kbclient, "bk-loc-1", "ns1")
		assert.Empty(t, bkrepoList.Items)
		assert.NoError(t, e)
	})

	t.Run("deleteBackups", func(t *testing.T) {
		bk := velerov1api.Backup{}
		bk.Name = "bk-name-last"
		bkList.Items = append(bkList.Items, bk)
		errList := deleteBackups(kbclient, bkList)
		assert.Len(t, errList, 1)
		assert.ErrorContains(t, errList[0], fmt.Sprintf("delete backup \"%s\" associated with deleted BSL: backups.velero.io \"%s\" not found", bk.Name, bk.Name))
	})
	t.Run("deleteBackupRepos", func(t *testing.T) {
		bkrepo := velerov1api.BackupRepository{}
		bkrepo.Name = "bk-repo-name-last"
		bkrepoList.Items = append(bkrepoList.Items, bkrepo)
		errList := deleteBackupRepos(kbclient, bkrepoList)
		assert.Len(t, errList, 1)
		assert.ErrorContains(t, errList[0], fmt.Sprintf("delete backup repository \"%s\" associated with deleted BSL: backuprepositories.velero.io \"%s\" not found", bkrepo.Name, bkrepo.Name))
	})
}
