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
	"context"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	velerov1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/repository"
	"github.com/vmware-tanzu/velero/pkg/repository/provider"
)

// fakeProvider is a minimal provider.Provider implementation used to
// observe the context passed by the manager into the provider calls.
type fakeProvider struct {
	provider.Provider

	gotConnectCtx context.Context
	gotForgetCtx  context.Context

	connectErr error
	forgetErr  error
	forgetErrs []error
}

func (f *fakeProvider) BoostRepoConnect(ctx context.Context, _ provider.RepoParam) error {
	f.gotConnectCtx = ctx
	return f.connectErr
}

func (f *fakeProvider) Forget(ctx context.Context, _ string, _ provider.RepoParam) error {
	f.gotForgetCtx = ctx
	return f.forgetErr
}

func (f *fakeProvider) BatchForget(ctx context.Context, _ []string, _ provider.RepoParam) []error {
	f.gotForgetCtx = ctx
	return f.forgetErrs
}

func newTestManager(t *testing.T, prd provider.Provider) *manager {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, velerov1.AddToScheme(scheme))

	bsl := &velerov1.BackupStorageLocation{}
	bsl.Namespace = "velero"
	bsl.Name = "fake-bsl"

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bsl).Build()

	mgr := NewManager("velero", fakeClient, repository.NewRepoLocker(), nil, nil, nil).(*manager)
	mgr.providers[velerov1.BackupRepositoryTypeKopia] = prd
	return mgr
}

func newTestRepo() *velerov1.BackupRepository {
	repo := &velerov1.BackupRepository{}
	repo.Spec.RepositoryType = velerov1.BackupRepositoryTypeKopia
	repo.Spec.BackupStorageLocation = "fake-bsl"
	return repo
}

func TestGetRepositoryProvider(t *testing.T) {
	var fakeClient kbclient.Client
	mgr := NewManager("", fakeClient, nil, nil, nil, nil).(*manager)
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

func TestForgetPropagatesCallerContext(t *testing.T) {
	prd := &fakeProvider{}
	mgr := newTestManager(t, prd)

	type ctxKeyType string
	key := ctxKeyType("test-key")
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), key, "test-value"))
	defer cancel()

	err := mgr.Forget(ctx, newTestRepo(), "snapshot-1")
	require.NoError(t, err)

	require.NotNil(t, prd.gotConnectCtx)
	require.NotNil(t, prd.gotForgetCtx)
	assert.Equal(t, "test-value", prd.gotConnectCtx.Value(key))
	assert.Equal(t, "test-value", prd.gotForgetCtx.Value(key))

	// canceling the caller's context must be observed by the provider calls,
	// proving the manager no longer substitutes context.Background().
	cancel()
	require.Error(t, prd.gotConnectCtx.Err())
	require.Error(t, prd.gotForgetCtx.Err())
}

func TestBatchForgetPropagatesCallerContext(t *testing.T) {
	prd := &fakeProvider{forgetErrs: []error{}}
	mgr := newTestManager(t, prd)

	type ctxKeyType string
	key := ctxKeyType("test-key")
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), key, "test-value"))
	defer cancel()

	errs := mgr.BatchForget(ctx, newTestRepo(), []string{"snapshot-1", "snapshot-2"})
	require.Empty(t, errs)

	require.NotNil(t, prd.gotConnectCtx)
	require.NotNil(t, prd.gotForgetCtx)
	assert.Equal(t, "test-value", prd.gotConnectCtx.Value(key))
	assert.Equal(t, "test-value", prd.gotForgetCtx.Value(key))
}

func TestBatchForgetReturnsConnectError(t *testing.T) {
	connectErr := errors.New("boom: connection refused")
	prd := &fakeProvider{connectErr: connectErr}
	mgr := newTestManager(t, prd)

	errs := mgr.BatchForget(context.Background(), newTestRepo(), []string{"snapshot-1"})

	require.Len(t, errs, 1)
	require.ErrorContains(t, errs[0], "boom: connection refused")
}
