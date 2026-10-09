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

package repo

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	factorymocks "github.com/vmware-tanzu/velero/pkg/client/mocks"
	cmdtest "github.com/vmware-tanzu/velero/pkg/cmd/test"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
)

func backupRepository(namespace, name string) *velerov1api.BackupRepository {
	return &velerov1api.BackupRepository{
		TypeMeta: metav1.TypeMeta{
			APIVersion: velerov1api.SchemeGroupVersion.String(),
			Kind:       "BackupRepository",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Spec: velerov1api.BackupRepositorySpec{
			RepositoryType: velerov1api.BackupRepositoryTypeKopia,
		},
	}
}

// captureStdout runs execute and returns everything it wrote to os.Stdout. The
// output helpers write to os.Stdout directly rather than to the command's
// output writer, so the file has to be swapped to read them back.
func captureStdout(t *testing.T, execute func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	require.NoError(t, err)

	original := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = original }()

	execute()

	require.NoError(t, w.Close())

	var buf bytes.Buffer
	_, err = io.Copy(&buf, r)
	require.NoError(t, err)

	return buf.String()
}

func TestNewGetCommandListsOnlyTheVeleroNamespace(t *testing.T) {
	ours := backupRepository(cmdtest.VeleroNameSpace, "ours")
	theirs := backupRepository("another-velero", "theirs")

	crClient := velerotest.NewFakeControllerRuntimeClient(t, ours, theirs)

	f := &factorymocks.Factory{}
	f.On("Namespace").Return(cmdtest.VeleroNameSpace)
	f.On("KubebuilderClient").Return(crClient, nil)

	c := NewGetCommand(f, "get")
	c.SetArgs([]string{})

	out := captureStdout(t, func() {
		require.NoError(t, c.Execute())
	})

	assert.Contains(t, out, "ours")
	assert.NotContains(t, out, "theirs")
}
