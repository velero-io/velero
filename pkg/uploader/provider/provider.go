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

package provider

import (
	"context"
	"time"

	"github.com/cockroachdb/errors"

	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/vmware-tanzu/velero/internal/credentials"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/uploader"
)

const restoreProgressCheckInterval = 10 * time.Second
const backupProgressCheckInterval = 10 * time.Second

var ErrorCanceled error = errors.New("uploader is canceled")

// Provider which is designed for one pod volume to do the backup or restore
type Provider interface {
	// RunBackup which will do backup for one specific volume and return snapshotID, isSnapshotEmpty, error
	// updater is used for updating backup progress which implement by third-party
	RunBackup(
		ctx context.Context,
		path string,
		realSource string,
		tags map[string]string,
		forceFull bool,
		parentSnapshot string,
		volMode uploader.PersistentVolumeMode,
		uploaderCfg map[string]string,
		updater uploader.ProgressUpdater) (string, bool, int64, int64, error)
	// RunRestore which will do restore for one specific volume with given snapshot id and return error
	// updater is used for updating backup progress which implement by third-party
	RunRestore(
		ctx context.Context,
		snapshotID string,
		volumePath string,
		volMode uploader.PersistentVolumeMode,
		uploaderConfig map[string]string,
		updater uploader.ProgressUpdater) (int64, error)
	// Close which will close related repository
	Close(ctx context.Context) error
}

// NewUploaderProvider initialize provider with specific uploaderType
func NewUploaderProvider(
	ctx context.Context,
	client client.Client,
	uploaderType string,
	requesterType string,
	repoIdentifier string,
	bsl *velerov1api.BackupStorageLocation,
	backupRepo *velerov1api.BackupRepository,
	credGetter *credentials.CredentialGetter,
	repoKeySelector *corev1api.SecretKeySelector,
	log logrus.FieldLogger,
) (Provider, error) {
	if requesterType == "" {
		return nil, errors.New("requester type is empty")
	}

	if credGetter.FromFile == nil {
		return nil, errors.New("uninitialized FileStore credential is not supported")
	}
	if uploaderType == uploader.KopiaType {
		return NewKopiaUploaderProvider(requesterType, ctx, credGetter, backupRepo, log)
	} else {
		return NewResticUploaderProvider(repoIdentifier, bsl, credGetter, repoKeySelector, log)
	}
}
