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

package controller

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/velero-io/velero/pkg/persistence"
	persistencemocks "github.com/velero-io/velero/pkg/persistence/mocks"

	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	velerov1api "github.com/velero-io/velero/pkg/apis/velero/v1"
	velerov2alpha1api "github.com/velero-io/velero/pkg/apis/velero/v2alpha1"

	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	// +kubebuilder:scaffold:imports
)

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.

const (
	timeout = time.Second * 30
)

var (
	env         *envtest.Environment
	testEnv     *testEnvironment
	ctx, cancel = context.WithCancel(context.Background())
)

func TestAPIs(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Controller Suite")
}

var _ = BeforeSuite(func(done Done) {
	By("bootstrapping test environment")
	testEnv = newTestEnvironment()

	By("starting the manager")
	go func() {
		defer GinkgoRecover()
		Expect(testEnv.startManager()).To(Succeed())
	}()

	close(done)
})

var _ = AfterSuite(func() {
	By("tearing down the test environment")
	err := testEnv.stop()
	Expect(err).ToNot(HaveOccurred())
})

// testEnvironment encapsulates a Kubernetes local test environment.
type testEnvironment struct {
	manager.Manager
	client.Client
	Config *rest.Config

	doneMgr context.Context
}

// newTestEnvironment creates a new environment spinning up a local api-server.
//
// This function should be called only once for each package you're running tests within,
// usually the environment is initialized in a suite_test.go file within a `BeforeSuite` ginkgo block.
func newTestEnvironment() *testEnvironment {
	// scheme.Scheme is initialized with all native Kubernetes types
	err := velerov1api.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	err = velerov2alpha1api.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	env = &envtest.Environment{
		CRDDirectoryPaths: []string{filepath.Join("..", "config", "crd", "bases")},
	}

	if _, err := env.Start(); err != nil {
		panic(err)
	}

	mgr, err := manager.New(env.Config, manager.Options{
		Scheme: scheme.Scheme,
	})
	if err != nil {
		klog.Fatalf("Failed to start testenv manager: %v", err)
	}

	return &testEnvironment{
		Manager: mgr,
		Client:  mgr.GetClient(),
		Config:  mgr.GetConfig(),
		doneMgr: ctx,
	}
}

func (t *testEnvironment) startManager() error {
	return t.Manager.Start(t.doneMgr)
}

func (t *testEnvironment) stop() error {
	cancel()
	return env.Stop()
}

type fakeErrorBackupStoreGetter struct {
}

func (f *fakeErrorBackupStoreGetter) Get(*velerov1api.BackupStorageLocation, persistence.ObjectStoreGetter, logrus.FieldLogger) (persistence.BackupStore, error) {
	return nil, fmt.Errorf("some error")
}

type fakeSingleObjectBackupStoreGetter struct {
	store persistence.BackupStore
}

func (f *fakeSingleObjectBackupStoreGetter) Get(*velerov1api.BackupStorageLocation, persistence.ObjectStoreGetter, logrus.FieldLogger) (persistence.BackupStore, error) {
	return f.store, nil
}

// NewFakeSingleObjectBackupStoreGetter returns an ObjectBackupStoreGetter
// that will return only the given BackupStore.
func NewFakeSingleObjectBackupStoreGetter(store persistence.BackupStore) persistence.ObjectBackupStoreGetter {
	return &fakeSingleObjectBackupStoreGetter{store: store}
}

type fakeObjectBackupStoreGetter struct {
	stores map[string]*persistencemocks.BackupStore
}

func (f *fakeObjectBackupStoreGetter) Get(loc *velerov1api.BackupStorageLocation, _ persistence.ObjectStoreGetter, _ logrus.FieldLogger) (persistence.BackupStore, error) {
	return f.stores[loc.Name], nil
}

// NewFakeObjectBackupStoreGetter returns an ObjectBackupStoreGetter that will
// return the BackupStore for a given BackupStorageLocation name.
func NewFakeObjectBackupStoreGetter(stores map[string]*persistencemocks.BackupStore) persistence.ObjectBackupStoreGetter {
	return &fakeObjectBackupStoreGetter{stores: stores}
}
