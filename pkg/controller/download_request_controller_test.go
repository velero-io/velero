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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	testclocks "k8s.io/utils/clock/testing"
	ctrl "sigs.k8s.io/controller-runtime"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	velerov1api "github.com/velero-io/velero/pkg/apis/velero/v1"
	"github.com/velero-io/velero/pkg/builder"
	persistencemocks "github.com/velero-io/velero/pkg/persistence/mocks"
	"github.com/velero-io/velero/pkg/plugin/clientmgmt"
	pluginmocks "github.com/velero-io/velero/pkg/plugin/mocks"
	velerotest "github.com/velero-io/velero/pkg/test"
)

var _ = Describe("Download Request Reconciler", func() {
	type request struct {
		downloadRequest      *velerov1api.DownloadRequest
		backup               *velerov1api.Backup
		restore              *velerov1api.Restore
		backupLocation       *velerov1api.BackupStorageLocation
		expired              bool
		expectedReconcileErr string
		expectGetsURL        bool
		expectedRequeue      ctrl.Result
	}

	defaultBackup := func() *velerov1api.Backup {
		return builder.ForBackup(velerov1api.DefaultNamespace, "a-backup").StorageLocation("a-location").Result()
	}

	DescribeTable("a Download request",
		func(test request) {
			// now will be used to set the fake clock's time; capture
			// it here so it can be referenced in the test case defs.
			now, err := time.Parse(time.RFC1123, time.RFC1123)
			Expect(err).ToNot(HaveOccurred())
			now = now.Local()

			rClock := testclocks.NewFakeClock(now)

			const signedURLTTL = 10 * time.Minute

			var (
				pluginManager = &pluginmocks.Manager{}
				backupStores  = make(map[string]*persistencemocks.BackupStore)
			)
			pluginManager.On("CleanupClients").Return(nil)

			Expect(test.downloadRequest).ToNot(BeNil())

			// Set .status.expiration properly for all requests test cases that are
			// meant to be expired. Since "expired" is relative to the controller's
			// clock time, it's easier to do this here than as part of the test case definitions.
			if test.expired {
				test.downloadRequest.Status.Expiration = &metav1.Time{Time: rClock.Now().Add(-1 * time.Minute)}
			}

			fakeClient := fake.NewClientBuilder().WithScheme(scheme.Scheme).Build()
			err = fakeClient.Create(context.TODO(), test.downloadRequest)
			Expect(err).ToNot(HaveOccurred())

			if test.backup != nil {
				err := fakeClient.Create(context.TODO(), test.backup)
				Expect(err).ToNot(HaveOccurred())
			}

			if test.backupLocation != nil {
				err := fakeClient.Create(context.TODO(), test.backupLocation)
				Expect(err).ToNot(HaveOccurred())
				backupStores[test.backupLocation.Name] = &persistencemocks.BackupStore{}
			}

			if test.restore != nil {
				err := fakeClient.Create(context.TODO(), test.restore)
				Expect(err).ToNot(HaveOccurred())
			}

			// Setup reconciler
			Expect(velerov1api.AddToScheme(scheme.Scheme)).To(Succeed())
			r := NewDownloadRequestReconciler(
				fakeClient,
				rClock,
				func(logrus.FieldLogger) clientmgmt.Manager { return pluginManager },
				NewFakeObjectBackupStoreGetter(backupStores),
				velerotest.NewLogger(),
				nil,
				nil,
			)

			if test.backupLocation != nil && test.expectGetsURL {
				backupStores[test.backupLocation.Name].On("GetDownloadURL", test.downloadRequest.Spec.Target).Return("a-url", nil)
			}

			actualResult, err := r.Reconcile(context.Background(), ctrl.Request{
				NamespacedName: types.NamespacedName{
					Namespace: velerov1api.DefaultNamespace,
					Name:      test.downloadRequest.Name,
				},
			})

			Expect(actualResult).To(BeEquivalentTo(test.expectedRequeue))
			if test.expectedReconcileErr == "" {
				Expect(err).ToNot(HaveOccurred())
			} else {
				Expect(err.Error()).To(Equal(test.expectedReconcileErr))
			}

			instance := &velerov1api.DownloadRequest{}
			err = r.client.Get(ctx, kbclient.ObjectKey{Name: test.downloadRequest.Name, Namespace: test.downloadRequest.Namespace}, instance)

			if test.expired {
				Expect(instance).ToNot(Equal(test.downloadRequest))
				Expect(apierrors.IsNotFound(err)).To(BeTrue())
			} else {
				if test.downloadRequest.Status.Phase == velerov1api.DownloadRequestPhaseProcessed {
					Expect(instance.Status).To(Equal(test.downloadRequest.Status))
				} else {
					Expect(instance.Status).ToNot(Equal(test.downloadRequest.Status))
				}
				Expect(err).ToNot(HaveOccurred())
			}

			if test.expectGetsURL {
				Expect(string(instance.Status.Phase)).To(Equal(string(velerov1api.DownloadRequestPhaseProcessed)))
				Expect(instance.Status.DownloadURL).To(Equal("a-url"))
				Expect(velerotest.TimesAreEqual(instance.Status.Expiration.Time, r.clock.Now().Add(signedURLTTL))).To(BeTrue())
			}
		},

		Entry("backup contents request for nonexistent backup returns nil", request{
			downloadRequest:      builder.ForDownloadRequest(velerov1api.DefaultNamespace, "a-download-request").Phase("").Target(velerov1api.DownloadTargetKindBackupContents, "a1-backup").Result(),
			backup:               builder.ForBackup(velerov1api.DefaultNamespace, "non-matching-backup").StorageLocation("a-location").Result(),
			backupLocation:       builder.ForBackupStorageLocation(velerov1api.DefaultNamespace, "a-location").Provider("a-provider").Bucket("a-bucket").Result(),
			expectedReconcileErr: "",
			expectedRequeue:      ctrl.Result{},
		}),
		Entry("restore log request for nonexistent restore returns nil", request{
			downloadRequest:      builder.ForDownloadRequest(velerov1api.DefaultNamespace, "a-download-request").Phase("").Target(velerov1api.DownloadTargetKindRestoreLog, "a-backup-20170912150214").Result(),
			restore:              builder.ForRestore(velerov1api.DefaultNamespace, "non-matching-restore").Phase(velerov1api.RestorePhaseCompleted).Backup("a-backup").Result(),
			backup:               defaultBackup(),
			backupLocation:       builder.ForBackupStorageLocation(velerov1api.DefaultNamespace, "a-location").Provider("a-provider").Bucket("a-bucket").Result(),
			expectedReconcileErr: "",
			expectedRequeue:      ctrl.Result{},
		}),
		Entry("backup contents request for backup with nonexistent location returns nil", request{
			downloadRequest:      builder.ForDownloadRequest(velerov1api.DefaultNamespace, "a-download-request").Phase("").Target(velerov1api.DownloadTargetKindBackupContents, "a-backup").Result(),
			backup:               defaultBackup(),
			backupLocation:       builder.ForBackupStorageLocation(velerov1api.DefaultNamespace, "non-matching-location").Provider("a-provider").Bucket("a-bucket").Result(),
			expectedReconcileErr: "",
			expectedRequeue:      ctrl.Result{},
		}),
		Entry("backup contents request with phase '' gets a url", request{
			downloadRequest: builder.ForDownloadRequest(velerov1api.DefaultNamespace, "a-download-request").Phase("").Target(velerov1api.DownloadTargetKindBackupContents, "a-backup").Result(),
			backup:          defaultBackup(),
			backupLocation:  builder.ForBackupStorageLocation(velerov1api.DefaultNamespace, "a-location").Provider("a-provider").Bucket("a-bucket").Result(),
			expectGetsURL:   true,
			expectedRequeue: ctrl.Result{},
		}),
		Entry("backup contents request with phase 'New' gets a url", request{
			downloadRequest: builder.ForDownloadRequest(velerov1api.DefaultNamespace, "a-download-request").Phase(velerov1api.DownloadRequestPhaseNew).Target(velerov1api.DownloadTargetKindBackupContents, "a-backup").Result(),
			backup:          defaultBackup(),
			backupLocation:  builder.ForBackupStorageLocation(velerov1api.DefaultNamespace, "a-location").Provider("a-provider").Bucket("a-bucket").Result(),
			expectGetsURL:   true,
			expectedRequeue: ctrl.Result{},
		}),
		Entry("backup log request with phase '' gets a url", request{
			downloadRequest: builder.ForDownloadRequest(velerov1api.DefaultNamespace, "a-download-request").Phase("").Target(velerov1api.DownloadTargetKindBackupLog, "a-backup").Result(),
			backup:          defaultBackup(),
			backupLocation:  builder.ForBackupStorageLocation(velerov1api.DefaultNamespace, "a-location").Provider("a-provider").Bucket("a-bucket").Result(),
			expectGetsURL:   true,
			expectedRequeue: ctrl.Result{},
		}),
		Entry("backup log request with phase 'New' gets a url", request{
			downloadRequest: builder.ForDownloadRequest(velerov1api.DefaultNamespace, "a-download-request").Phase(velerov1api.DownloadRequestPhaseNew).Target(velerov1api.DownloadTargetKindBackupLog, "a-backup").Result(),
			backup:          defaultBackup(),
			backupLocation:  builder.ForBackupStorageLocation(velerov1api.DefaultNamespace, "a-location").Provider("a-provider").Bucket("a-bucket").Result(),
			expectGetsURL:   true,
			expectedRequeue: ctrl.Result{},
		}),
		Entry("restore log request with phase '' gets a url", request{
			downloadRequest: builder.ForDownloadRequest(velerov1api.DefaultNamespace, "a-download-request").Phase("").Target(velerov1api.DownloadTargetKindRestoreLog, "a-backup-20170912150214").Result(),
			restore:         builder.ForRestore(velerov1api.DefaultNamespace, "a-backup-20170912150214").Phase(velerov1api.RestorePhaseCompleted).Backup("a-backup").Result(),
			backup:          defaultBackup(),
			backupLocation:  builder.ForBackupStorageLocation(velerov1api.DefaultNamespace, "a-location").Provider("a-provider").Bucket("a-bucket").Result(),
			expectGetsURL:   true,
			expectedRequeue: ctrl.Result{},
		}),
		Entry("restore log request with phase 'New' gets a url", request{
			downloadRequest: builder.ForDownloadRequest(velerov1api.DefaultNamespace, "a-download-request").Phase(velerov1api.DownloadRequestPhaseNew).Target(velerov1api.DownloadTargetKindRestoreLog, "a-backup-20170912150214").Result(),
			backup:          defaultBackup(),
			restore:         builder.ForRestore(velerov1api.DefaultNamespace, "a-backup-20170912150214").Phase(velerov1api.RestorePhaseCompleted).Backup("a-backup").Result(),
			backupLocation:  builder.ForBackupStorageLocation(velerov1api.DefaultNamespace, "a-location").Provider("a-provider").Bucket("a-bucket").Result(),
			expectGetsURL:   true,
			expectedRequeue: ctrl.Result{},
		}),
		Entry("restore results request with phase '' gets a url", request{
			downloadRequest: builder.ForDownloadRequest(velerov1api.DefaultNamespace, "a-download-request").Phase("").Target(velerov1api.DownloadTargetKindRestoreResults, "a-backup-20170912150214").Result(),
			restore:         builder.ForRestore(velerov1api.DefaultNamespace, "a-backup-20170912150214").Phase(velerov1api.RestorePhaseCompleted).Backup("a-backup").Result(),
			backup:          defaultBackup(),
			backupLocation:  builder.ForBackupStorageLocation(velerov1api.DefaultNamespace, "a-location").Provider("a-provider").Bucket("a-bucket").Result(),
			expectGetsURL:   true,
			expectedRequeue: ctrl.Result{},
		}),
		Entry("restore results request with phase 'New' gets a url", request{
			downloadRequest: builder.ForDownloadRequest(velerov1api.DefaultNamespace, "a-download-request").Phase(velerov1api.DownloadRequestPhaseNew).Target(velerov1api.DownloadTargetKindRestoreResults, "a-backup-20170912150214").Result(),
			restore:         builder.ForRestore(velerov1api.DefaultNamespace, "a-backup-20170912150214").Phase(velerov1api.RestorePhaseCompleted).Backup("a-backup").Result(),
			backup:          defaultBackup(),
			backupLocation:  builder.ForBackupStorageLocation(velerov1api.DefaultNamespace, "a-location").Provider("a-provider").Bucket("a-bucket").Result(),
			expectGetsURL:   true,
			expectedRequeue: ctrl.Result{},
		}),
		Entry("request with phase 'Processed' and not expired is not deleted", request{
			downloadRequest: builder.ForDownloadRequest(velerov1api.DefaultNamespace, "a-download-request").Phase(velerov1api.DownloadRequestPhaseProcessed).Target(velerov1api.DownloadTargetKindBackupLog, "a-backup-20170912150214").Result(),
			backup:          defaultBackup(),
			expectedRequeue: ctrl.Result{},
		}),
		Entry("request with phase 'Processed' and expired is deleted", request{
			downloadRequest: builder.ForDownloadRequest(velerov1api.DefaultNamespace, "a-download-request").Phase(velerov1api.DownloadRequestPhaseProcessed).Target(velerov1api.DownloadTargetKindBackupLog, "a-backup-20170912150214").Result(),
			backup:          defaultBackup(),
			expired:         true,
			expectedRequeue: ctrl.Result{},
		}),
		Entry("request with phase '' and expired is deleted", request{
			downloadRequest: builder.ForDownloadRequest(velerov1api.DefaultNamespace, "a-download-request").Phase("").Target(velerov1api.DownloadTargetKindBackupLog, "a-backup-20170912150214").Result(),
			backup:          defaultBackup(),
			expired:         true,
			expectedRequeue: ctrl.Result{},
		}),
		Entry("request with phase 'New' and expired is deleted", request{
			downloadRequest: builder.ForDownloadRequest(velerov1api.DefaultNamespace, "a-download-request").Phase(velerov1api.DownloadRequestPhaseNew).Target(velerov1api.DownloadTargetKindBackupLog, "a-backup-20170912150214").Result(),
			backup:          defaultBackup(),
			expired:         true,
			expectedRequeue: ctrl.Result{},
		}),
	)
})
