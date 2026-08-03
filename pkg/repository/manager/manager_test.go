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

package repository

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
)

func TestGetRepositoryProvider(t *testing.T) {
	var fakeClient kbclient.Client
	mgr := NewManager("", fakeClient, nil, nil, nil, nil, nil).(*manager)
	repo := &velerov1.BackupRepository{}

	// empty repository type
	_, err := mgr.getRepositoryProvider(repo)
	require.Error(t, err)

	// invalid repository type
	repo.Spec.RepositoryType = "restic"
	_, err = mgr.getRepositoryProvider(repo)
	require.Error(t, err)

	// invalid repository type
	repo.Spec.RepositoryType = "unknown"
	_, err = mgr.getRepositoryProvider(repo)
	require.Error(t, err)
}

func TestGetRepositoryConfigProvider(t *testing.T) {
	mgr := NewConfigManager(nil).(*configManager)

	// empty repository type
	_, err := mgr.getRepositoryProvider("")
	require.Error(t, err)

	// valid repository type
	provider, err := mgr.getRepositoryProvider(velerov1.BackupRepositoryTypeKopia)
	require.NoError(t, err)
	assert.NotNil(t, provider)

	// invalid repository type
	_, err = mgr.getRepositoryProvider("restic")
	require.Error(t, err)
}
