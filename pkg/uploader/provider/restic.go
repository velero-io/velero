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
	"os"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"

	"github.com/vmware-tanzu/velero/internal/credentials"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/restic"
	"github.com/vmware-tanzu/velero/pkg/uploader"
	uploaderutil "github.com/vmware-tanzu/velero/pkg/uploader/util"
	"github.com/vmware-tanzu/velero/pkg/util/filesystem"
)

// resticBackupCMDFunc and resticRestoreCMDFunc are mainly used to make testing more convenient
var resticBackupCMDFunc = restic.BackupCommand
var resticBackupFunc = restic.RunBackup
var resticGetSnapshotFunc = restic.GetSnapshotCommand
var resticGetSnapshotIDFunc = restic.GetSnapshotID
var resticRestoreCMDFunc = restic.RestoreCommand
var resticTempCACertFileFunc = restic.TempCACertFile
var resticCmdEnvFunc = restic.CmdEnv

type resticProvider struct {
	repoIdentifier  string
	credentialsFile string
	caCertFile      string
	cmdEnv          []string
	extraFlags      []string
	bsl             *velerov1api.BackupStorageLocation
	log             logrus.FieldLogger
}

func NewResticUploaderProvider(
	repoIdentifier string,
	bsl *velerov1api.BackupStorageLocation,
	credGetter *credentials.CredentialGetter,
	repoKeySelector *corev1api.SecretKeySelector,
	log logrus.FieldLogger,
) (Provider, error) {
	provider := resticProvider{
		repoIdentifier: repoIdentifier,
		bsl:            bsl,
		log:            log,
	}

	var err error
	provider.credentialsFile, err = credGetter.FromFile.Path(repoKeySelector)
	if err != nil {
		return nil, errors.Wrap(err, "error creating temp restic credentials file")
	}

	// if there's a caCert on the ObjectStorage, write it to disk so that it can be passed to restic
	if bsl.Spec.ObjectStorage != nil {
		var caCertData []byte

		// Try CACertRef first (new method), then fall back to CACert (deprecated)
		if bsl.Spec.ObjectStorage.CACertRef != nil {
			caCertString, err := credGetter.FromSecret.Get(bsl.Spec.ObjectStorage.CACertRef)
			if err != nil {
				return nil, errors.Wrap(err, "error getting CA certificate from secret")
			}
			caCertData = []byte(caCertString)
		} else if bsl.Spec.ObjectStorage.CACert != nil {
			caCertData = bsl.Spec.ObjectStorage.CACert
		}

		if caCertData != nil {
			provider.caCertFile, err = resticTempCACertFileFunc(caCertData, bsl.Name, filesystem.NewFileSystem())
			if err != nil {
				return nil, errors.Wrap(err, "error create temp cert file")
			}
		}
	}

	provider.cmdEnv, err = resticCmdEnvFunc(bsl, credGetter.FromFile)
	if err != nil {
		return nil, errors.Wrap(err, "error generating repository cmnd env")
	}

	// #4820: restrieve insecureSkipTLSVerify from BSL configuration for
	// AWS plugin. If nothing is return, that means insecureSkipTLSVerify
	// is not enable for Restic command.
	skipTLSRet := restic.GetInsecureSkipTLSVerifyFromBSL(bsl, log)
	if len(skipTLSRet) > 0 {
		provider.extraFlags = append(provider.extraFlags, skipTLSRet)
	}

	return &provider, nil
}

func (rp *resticProvider) Close(ctx context.Context) error {
	_, err := os.Stat(rp.credentialsFile)
	if err == nil {
		return os.Remove(rp.credentialsFile)
	} else if !os.IsNotExist(err) {
		return errors.Errorf("failed to get file %s info with error %v", rp.credentialsFile, err)
	}

	_, err = os.Stat(rp.caCertFile)
	if err == nil {
		return os.Remove(rp.caCertFile)
	} else if !os.IsNotExist(err) {
		return errors.Errorf("failed to get file %s info with error %v", rp.caCertFile, err)
	}
	return nil
}

// RunBackup runs a `backup` command and watches the output to provide
// progress updates to the caller and return snapshotID, isEmptySnapshot, error
func (rp *resticProvider) RunBackup(
	ctx context.Context,
	path string,
	realSource string,
	tags map[string]string,
	forceFull bool,
	parentSnapshot string,
	volMode uploader.PersistentVolumeMode,
	uploaderCfg map[string]string,
	updater uploader.ProgressUpdater) (string, bool, int64, int64, error) {
	if updater == nil {
		return "", false, 0, 0, errors.New("Need to initial backup progress updater first")
	}

	if path == "" {
		return "", false, 0, 0, errors.New("path is empty")
	}

	if realSource != "" {
		return "", false, 0, 0, errors.New("real source is not empty, this is not supported by restic uploader")
	}

	if volMode == uploader.PersistentVolumeBlock {
		return "", false, 0, 0, errors.New("unable to support block mode")
	}

	log := rp.log.WithFields(logrus.Fields{
		"path":           path,
		"parentSnapshot": parentSnapshot,
	})

	if len(uploaderCfg) > 0 {
		parallelFilesUpload, err := uploaderutil.GetParallelFilesUpload(uploaderCfg)
		if err != nil {
			return "", false, 0, 0, errors.Wrap(err, "failed to get uploader config")
		}
		if parallelFilesUpload > 0 {
			log.Warnf("ParallelFilesUpload is set to %d, but restic does not support parallel file uploads. Ignoring.", parallelFilesUpload)
		}
	}

	backupCmd := resticBackupCMDFunc(rp.repoIdentifier, rp.credentialsFile, path, tags)
	backupCmd.Env = rp.cmdEnv
	backupCmd.CACertFile = rp.caCertFile
	if len(rp.extraFlags) != 0 {
		backupCmd.ExtraFlags = append(backupCmd.ExtraFlags, rp.extraFlags...)
	}

	if parentSnapshot != "" {
		backupCmd.ExtraFlags = append(backupCmd.ExtraFlags, fmt.Sprintf("--parent=%s", parentSnapshot))
	}

	summary, stderrBuf, err := resticBackupFunc(backupCmd, log, updater)
	if err != nil {
		if strings.Contains(stderrBuf, "snapshot is empty") {
			log.Debugf("Restic backup got empty dir with %s path", path)
			return "", true, 0, 0, nil
		}
		return "", false, 0, 0, errors.WithStack(fmt.Errorf("error running restic backup command %s with error: %v stderr: %v", backupCmd.String(), err, stderrBuf))
	}
	// GetSnapshotID
	snapshotIDCmd := resticGetSnapshotFunc(rp.repoIdentifier, rp.credentialsFile, tags)
	snapshotIDCmd.Env = rp.cmdEnv
	snapshotIDCmd.CACertFile = rp.caCertFile
	if len(rp.extraFlags) != 0 {
		snapshotIDCmd.ExtraFlags = append(snapshotIDCmd.ExtraFlags, rp.extraFlags...)
	}
	snapshotID, err := resticGetSnapshotIDFunc(snapshotIDCmd)
	if err != nil {
		return "", false, 0, 0, errors.WithStack(fmt.Errorf("error getting snapshot id with error: %v", err))
	}
	log.Infof("Run command=%s, stdout=%s, stderr=%s", backupCmd.String(), summary, stderrBuf)
	return snapshotID, false, 0, 0, nil
}

// RunRestore runs a `restore` command and monitors the volume size to
// provide progress updates to the caller.
func (rp *resticProvider) RunRestore(
	ctx context.Context,
	snapshotID string,
	volumePath string,
	volMode uploader.PersistentVolumeMode,
	uploaderCfg map[string]string,
	updater uploader.ProgressUpdater) (int64, error) {
	if updater == nil {
		return 0, errors.New("Need to initial backup progress updater first")
	}
	log := rp.log.WithFields(logrus.Fields{
		"snapshotID": snapshotID,
		"volumePath": volumePath,
	})

	if volMode == uploader.PersistentVolumeBlock {
		return 0, errors.New("unable to support block mode")
	}

	restoreCmd := resticRestoreCMDFunc(rp.repoIdentifier, rp.credentialsFile, snapshotID, volumePath)
	restoreCmd.Env = rp.cmdEnv
	restoreCmd.CACertFile = rp.caCertFile
	if len(rp.extraFlags) != 0 {
		restoreCmd.ExtraFlags = append(restoreCmd.ExtraFlags, rp.extraFlags...)
	}

	extraFlags, err := rp.parseRestoreExtraFlags(uploaderCfg)
	if err != nil {
		return 0, errors.Wrap(err, "failed to parse uploader config")
	} else if len(extraFlags) != 0 {
		restoreCmd.ExtraFlags = append(restoreCmd.ExtraFlags, extraFlags...)
	}

	stdout, stderr, err := restic.RunRestore(restoreCmd, log, updater)

	log.Infof("Run command=%v, stdout=%s, stderr=%s", restoreCmd, stdout, stderr)
	return 0, err
}

func (rp *resticProvider) parseRestoreExtraFlags(uploaderCfg map[string]string) ([]string, error) {
	extraFlags := []string{}
	if len(uploaderCfg) == 0 {
		return extraFlags, nil
	}

	writeSparseFiles, err := uploaderutil.GetWriteSparseFiles(uploaderCfg)
	if err != nil {
		return extraFlags, errors.Wrap(err, "failed to get uploader config")
	}

	if writeSparseFiles {
		extraFlags = append(extraFlags, "--sparse")
	}

	if restoreConcurrency, err := uploaderutil.GetRestoreConcurrency(uploaderCfg); err == nil && restoreConcurrency > 0 {
		return extraFlags, errors.New("restic does not support parallel restore")
	}

	return extraFlags, nil
}
