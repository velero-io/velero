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
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"

	"github.com/vmware-tanzu/velero/internal/credentials"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	repokeys "github.com/vmware-tanzu/velero/pkg/repository/keys"
	"github.com/vmware-tanzu/velero/pkg/repository/udmrepo"
	"github.com/vmware-tanzu/velero/pkg/uploader"
)

type blockProvider struct {
	requestorType string
	bkRepo        udmrepo.BackupRepo
	credGetter    *credentials.CredentialGetter
	log           logrus.FieldLogger
}

// NewBlockUploaderProvider initialized with open or create a repository
func NewBlockUploaderProvider(
	requestorType string,
	ctx context.Context,
	credGetter *credentials.CredentialGetter,
	backupRepo *velerov1api.BackupRepository,
	log logrus.FieldLogger,
) (Provider, error) {
	bp := &blockProvider{
		requestorType: requestorType,
		log:           log,
		credGetter:    credGetter,
	}

	repoUID := string(backupRepo.GetUID())
	repoOpt, err := udmrepo.NewRepoOptions(
		udmrepo.WithPassword(bp, ""),
		udmrepo.WithConfigFile("", repoUID),
		udmrepo.WithDescription("Initial velero block uploader provider"),
	)
	if err != nil {
		return nil, errors.Wrapf(err, "error to get repo options")
	}

	repoSvc := BackupRepoServiceCreateFunc(backupRepo.Spec.RepositoryType, log)
	log.WithField("repoUID", repoUID).Info("Opening backup repo")

	bp.bkRepo, err = repoSvc.Open(ctx, *repoOpt)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to find backup repository")
	}

	return bp, nil
}

func (bp *blockProvider) Close(ctx context.Context) error {
	return bp.bkRepo.Close(ctx)
}

func (bp *blockProvider) GetPassword(param any) (string, error) {
	if bp.credGetter.FromSecret == nil {
		return "", errors.New("invalid credentials interface")
	}
	rawPass, err := bp.credGetter.FromSecret.Get(repokeys.RepoKeySelector())
	if err != nil {
		return "", errors.Wrap(err, "error to get password")
	}

	return strings.TrimSpace(rawPass), nil
}

// TODO: implement in the following PRs
func (bp *blockProvider) RunBackup(
	ctx context.Context,
	path string,
	realSource string,
	tags map[string]string,
	forceFull bool,
	parentSnapshot string,
	cbtParam CBTParam,
	volMode uploader.PersistentVolumeMode,
	uploaderCfg map[string]string,
	updater uploader.ProgressUpdater) (string, bool, int64, int64, error) {
	return "", false, 0, 0, errors.New("block backup not implemented")
}

// TODO: implement in the following PRs
func (bp *blockProvider) RunRestore(
	ctx context.Context,
	snapshotID string,
	volumePath string,
	volMode uploader.PersistentVolumeMode,
	uploaderCfg map[string]string,
	updater uploader.ProgressUpdater) (int64, error) {
	return 0, errors.New("block restore not implemented")
}
