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
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/vmware-tanzu/velero/pkg/persistence"
	persistencemocks "github.com/vmware-tanzu/velero/pkg/persistence/mocks"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	velerov2alpha1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v2alpha1"

	"k8s.io/client-go/kubernetes/scheme"
)

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.

const (
	timeout = time.Second * 30
)

var (
	ctx = context.Background()
)

func TestAPIs(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Controller Suite")
}

var _ = BeforeSuite(func() {
	By("registering API schemes")
	Expect(velerov1api.AddToScheme(scheme.Scheme)).To(Succeed())
	Expect(velerov2alpha1api.AddToScheme(scheme.Scheme)).To(Succeed())
})

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
