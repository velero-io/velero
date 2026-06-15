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

package provider

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/cockroachdb/errors"
	"github.com/kopia/kopia/snapshot/upload"
	"github.com/sirupsen/logrus"

	"github.com/vmware-tanzu/velero/pkg/uploader"
	"github.com/vmware-tanzu/velero/pkg/uploader/kopia"

	"github.com/vmware-tanzu/velero/internal/credentials"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	repokeys "github.com/vmware-tanzu/velero/pkg/repository/keys"
	"github.com/vmware-tanzu/velero/pkg/repository/udmrepo"
	"github.com/vmware-tanzu/velero/pkg/repository/udmrepo/service"
)

var kopiaBackupFunc = kopia.Backup
var kopiaRestoreFunc = kopia.Restore
var BackupRepoServiceCreateFunc = service.Create

// kopiaProvider recorded info related with kopiaProvider
type kopiaProvider struct {
	requestorType string
	bkRepo        udmrepo.BackupRepo
	credGetter    *credentials.CredentialGetter
	log           logrus.FieldLogger
	canceling     int32
}

// NewKopiaUploaderProvider initialized with open or create a repository
func NewKopiaUploaderProvider(
	requestorType string,
	ctx context.Context,
	credGetter *credentials.CredentialGetter,
	backupRepo *velerov1api.BackupRepository,
	log logrus.FieldLogger,
) (Provider, error) {
	kp := &kopiaProvider{
		requestorType: requestorType,
		log:           log,
		credGetter:    credGetter,
	}
	//repoUID which is used to generate kopia repository config with unique directory path
	repoUID := string(backupRepo.GetUID())
	repoOpt, err := udmrepo.NewRepoOptions(
		udmrepo.WithPassword(kp, ""),
		udmrepo.WithConfigFile("", repoUID),
		udmrepo.WithDescription("Initial kopia uploader provider"),
	)
	if err != nil {
		return nil, errors.Wrapf(err, "error to get repo options")
	}

	repoSvc := BackupRepoServiceCreateFunc(backupRepo.Spec.RepositoryType, log)
	log.WithField("repoUID", repoUID).Info("Opening backup repo")

	kp.bkRepo, err = repoSvc.Open(ctx, *repoOpt)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to find kopia repository")
	}
	return kp, nil
}

// CheckContext check context status check if context is timeout or cancel and backup restore once finished it will quit and return
func (kp *kopiaProvider) CheckContext(ctx context.Context, finishChan chan struct{}, restoreChan chan struct{}, uploader *upload.Uploader) {
	select {
	case <-finishChan:
		kp.log.Infof("Action finished")
		return
	case <-ctx.Done():
		atomic.StoreInt32(&kp.canceling, 1)

		if uploader != nil {
			uploader.Cancel()
			kp.log.Infof("Backup is been canceled")
		}
		if restoreChan != nil {
			close(restoreChan)
			kp.log.Infof("Restore is been canceled")
		}
		return
	}
}

func (kp *kopiaProvider) Close(ctx context.Context) error {
	return kp.bkRepo.Close(ctx)
}

// RunBackup which will backup specific path and update backup progress
// return snapshotID, isEmptySnapshot, error
func (kp *kopiaProvider) RunBackup(
	ctx context.Context,
	path string,
	realSource string,
	tags map[string]string,
	forceFull bool,
	parentSnapshot string,
	_ CBTParam,
	volMode uploader.PersistentVolumeMode,
	uploaderCfg map[string]string,
	updater uploader.ProgressUpdater) (string, bool, int64, int64, error) {
	if updater == nil {
		return "", false, 0, 0, errors.New("Need to initial backup progress updater first")
	}

	if path == "" {
		return "", false, 0, 0, errors.New("path is empty")
	}

	log := kp.log.WithFields(logrus.Fields{
		"path":           path,
		"realSource":     realSource,
		"parentSnapshot": parentSnapshot,
	})
	repoWriter := kopia.NewShimRepo(kp.bkRepo)
	kpUploader := upload.NewUploader(repoWriter)
	progress := kopia.NewProgress(updater, backupProgressCheckInterval, log)
	kpUploader.Progress = progress
	kpUploader.FailFast = true
	quit := make(chan struct{})
	log.Info("Starting backup")
	go kp.CheckContext(ctx, quit, nil, kpUploader)

	defer func() {
		close(quit)
	}()

	if tags == nil {
		tags = make(map[string]string)
	}
	tags[uploader.SnapshotRequesterTag] = kp.requestorType
	tags[uploader.SnapshotUploaderTag] = uploader.KopiaType

	if realSource != "" {
		realSource = fmt.Sprintf("%s/%s/%s", kp.requestorType, uploader.KopiaType, realSource)
	}

	if kp.bkRepo.GetAdvancedFeatures().MultiPartBackup {
		if uploaderCfg == nil {
			uploaderCfg = make(map[string]string)
		}

		uploaderCfg[kopia.UploaderConfigMultipartKey] = "true"
	}

	snapshotInfo, _, err := kopiaBackupFunc(ctx, kpUploader, repoWriter, path, realSource, forceFull, parentSnapshot, volMode, uploaderCfg, tags, log)
	if err != nil {
		snapshotID := ""
		if snapshotInfo != nil {
			snapshotID = snapshotInfo.ID
		} else {
			log.Infof("Kopia backup failed with %v and get empty snapshot ID", err)
		}

		if kpUploader.IsCanceled() {
			log.Warn("Kopia backup is canceled")
			return snapshotID, false, 0, 0, ErrorCanceled
		}
		return snapshotID, false, 0, 0, errors.Wrapf(err, "Failed to run kopia backup")
	}

	// which ensure that the statistic data of TotalBytes equal to BytesDone when finished
	updater.UpdateProgress(
		&uploader.Progress{
			TotalBytes: snapshotInfo.Size,
			BytesDone:  snapshotInfo.Size,
		},
	)

	log.Debugf("Kopia backup finished, snapshot ID %s, backup size %d", snapshotInfo.ID, snapshotInfo.Size)
	return snapshotInfo.ID, false, snapshotInfo.Size, progress.GetIncrementalSize(), nil
}

func (kp *kopiaProvider) GetPassword(param any) (string, error) {
	if kp.credGetter.FromSecret == nil {
		return "", errors.New("invalid credentials interface")
	}
	rawPass, err := kp.credGetter.FromSecret.Get(repokeys.RepoKeySelector())
	if err != nil {
		return "", errors.Wrap(err, "error to get password")
	}

	return strings.TrimSpace(rawPass), nil
}

// RunRestore which will restore specific path and update restore progress
func (kp *kopiaProvider) RunRestore(
	ctx context.Context,
	snapshotID string,
	volumePath string,
	volMode uploader.PersistentVolumeMode,
	uploaderCfg map[string]string,
	updater uploader.ProgressUpdater) (int64, error) {
	log := kp.log.WithFields(logrus.Fields{
		"snapshotID": snapshotID,
		"volumePath": volumePath,
	})

	repoWriter := kopia.NewShimRepo(kp.bkRepo)
	progress := kopia.NewProgress(updater, restoreProgressCheckInterval, log)
	restoreCancel := make(chan struct{})
	quit := make(chan struct{})

	log.Info("Starting restore")
	defer func() {
		close(quit)
	}()

	go kp.CheckContext(ctx, quit, restoreCancel, nil)

	// We use the cancel channel to control the restore cancel, so don't pass a context with cancel to Kopia restore.
	// Otherwise, Kopia restore will not response to the cancel control but return an arbitrary error.
	// Kopia restore cancel is not designed as well as Kopia backup which uses the context to control backup cancel all the way.
	size, fileCount, err := kopiaRestoreFunc(context.Background(), repoWriter, progress, snapshotID, volumePath, volMode, uploaderCfg, log, restoreCancel)

	if err != nil {
		return 0, errors.Wrapf(err, "Failed to run kopia restore")
	}

	if atomic.LoadInt32(&kp.canceling) == 1 {
		log.Error("Kopia restore is canceled")
		return 0, ErrorCanceled
	}

	// which ensure that the statistic data of TotalBytes equal to BytesDone when finished
	updater.UpdateProgress(&uploader.Progress{
		TotalBytes: size,
		BytesDone:  size,
	})

	output := fmt.Sprintf("Kopia restore finished, restore size %d, file count %d", size, fileCount)

	log.Info(output)

	return size, nil
}
