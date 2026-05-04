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

package kopialib

import (
	"context"
	"encoding/json"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/kopia/kopia/repo"
	"github.com/kopia/kopia/repo/blob"
	"github.com/kopia/kopia/repo/format"
	"github.com/kopia/kopia/repo/maintenance"
	"github.com/pkg/errors"

	"github.com/vmware-tanzu/velero/pkg/kopia"
	"github.com/vmware-tanzu/velero/pkg/repository/udmrepo"
	"github.com/vmware-tanzu/velero/pkg/repository/udmrepo/kopialib/backend"
)

type kopiaBackendStore struct {
	name        string
	description string
	store       backend.Store
}

// backendStores lists the supported backend storages at present
var backendStores = []kopiaBackendStore{
	{udmrepo.StorageTypeAzure, "an Azure blob storage", &backend.AzureBackend{}},
	{udmrepo.StorageTypeFs, "a filesystem", &backend.FsBackend{}},
	{udmrepo.StorageTypeGcs, "a Google Cloud Storage bucket", &backend.GCSBackend{}},
	{udmrepo.StorageTypeS3, "an S3 bucket", &backend.S3Backend{}},
	{udmrepo.StorageTypeSftp, "an SFTP server", &backend.SFTPBackend{}},
}

const udmRepoBlobID = "udmrepo.Repository"

type udmRepoMetadata struct {
	UniqueID []byte `json:"uniqueID"`
}

type RepoStatus int

const (
	RepoStatusUnknown          = 0
	RepoStatusCorrupted        = 1
	RepoStatusSystemNotCreated = 2
	RepoStatusNotInitialized   = 3
	RepoStatusCreated          = 4
)

// CreateBackupRepo creates a Kopia repository and then connect to it.
// The storage must be empty, otherwise, it will fail
func CreateBackupRepo(ctx context.Context, repoOption udmrepo.RepoOptions, logger logrus.FieldLogger) error {
	backendStore, err := setupBackendStore(ctx, repoOption.StorageType, repoOption.StorageOptions, logger)
	if err != nil {
		return errors.Wrap(err, "error to setup backend storage")
	}

	st, err := backendStore.store.Connect(ctx, true, logger)
	if err != nil {
		return errors.Wrap(err, "error to connect to storage")
	}

	err = createWithStorage(ctx, st, repoOption)
	if err != nil {
		return errors.Wrap(err, "error to create repo with storage")
	}

	return nil
}

// ConnectBackupRepo connects to an existing Kopia repository.
// If the repository doesn't exist, it will fail
func ConnectBackupRepo(ctx context.Context, repoOption udmrepo.RepoOptions, logger logrus.FieldLogger) error {
	if repoOption.ConfigFilePath == "" {
		return errors.New("invalid config file path")
	}

	st, err := connectStore(ctx, repoOption, logger)
	if err != nil {
		return err
	}

	err = connectWithStorage(ctx, st, repoOption)
	if err != nil {
		return errors.Wrap(err, "error to connect repo with storage")
	}

	return nil
}

func GetRepositoryStatus(ctx context.Context, repoOption udmrepo.RepoOptions, logger logrus.FieldLogger) (RepoStatus, error) {
	st, err := connectStore(ctx, repoOption, logger)
	if errors.Is(err, backend.ErrStoreNotExist) {
		return RepoStatusSystemNotCreated, nil
	} else if err != nil {
		return RepoStatusUnknown, err
	}

	var formatBytes byteBuffer
	if err := st.GetBlob(ctx, format.KopiaRepositoryBlobID, 0, -1, &formatBytes); err != nil {
		if errors.Is(err, blob.ErrBlobNotFound) {
			logger.Debug("Kopia repository blob is not found")
			return RepoStatusSystemNotCreated, nil
		}

		return RepoStatusUnknown, errors.Wrap(err, "error reading format blob")
	}

	repoFmt, err := format.ParseKopiaRepositoryJSON(formatBytes.buffer)
	if err != nil {
		return RepoStatusCorrupted, err
	}

	var initInfoBytes byteBuffer
	if err := st.GetBlob(ctx, udmRepoBlobID, 0, -1, &initInfoBytes); err != nil {
		if errors.Is(err, blob.ErrBlobNotFound) {
			logger.Debug("Udm repo metadata blob is not found")
			return RepoStatusNotInitialized, nil
		}

		return RepoStatusUnknown, errors.Wrap(err, "error reading udm repo blob")
	}

	udmpRepo := &udmRepoMetadata{}
	if err := json.Unmarshal(initInfoBytes.buffer, udmpRepo); err != nil {
		return RepoStatusCorrupted, errors.Wrap(err, "invalid udm repo blob")
	}

	if !slices.Equal(udmpRepo.UniqueID, repoFmt.UniqueID) {
		return RepoStatusCorrupted, errors.Errorf("unique ID doesn't match: %v(%v)", udmpRepo.UniqueID, repoFmt.UniqueID)
	}

	return RepoStatusCreated, nil
}

func InitializeBackupRepo(ctx context.Context, repoOption udmrepo.RepoOptions, logger logrus.FieldLogger) error {
	if repoOption.ConfigFilePath == "" {
		return errors.New("invalid config file path")
	}

	st, err := connectStore(ctx, repoOption, logger)
	if err != nil {
		return err
	}

	err = connectWithStorage(ctx, st, repoOption)
	if err != nil {
		return errors.Wrap(err, "error connecting repo with storage")
	}

	err = writeInitParameters(ctx, repoOption, logger)
	if err != nil {
		return errors.Wrap(err, "error writing init parameters")
	}

	err = writeUdmRepoMetadata(ctx, st)
	if err != nil {
		return errors.Wrap(err, "error writing udm repo metadata")
	}

	return nil
}

func writeUdmRepoMetadata(ctx context.Context, st blob.Storage) error {
	var formatBytes byteBuffer
	if err := st.GetBlob(ctx, format.KopiaRepositoryBlobID, 0, -1, &formatBytes); err != nil {
		return errors.Wrap(err, "error reading format blob")
	}

	repoFmt, err := format.ParseKopiaRepositoryJSON(formatBytes.buffer)
	if err != nil {
		return err
	}

	udmpRepo := &udmRepoMetadata{
		UniqueID: repoFmt.UniqueID,
	}

	bytes, err := json.Marshal(udmpRepo)
	if err != nil {
		return errors.Wrap(err, "error marshaling udm repo metadata")
	}

	err = st.PutBlob(ctx, udmRepoBlobID, &byteBuffer{bytes}, blob.PutOptions{})
	if err != nil {
		return errors.Wrap(err, "error writing udm repo metadata")
	}

	return nil
}

func connectStore(ctx context.Context, repoOption udmrepo.RepoOptions, logger logrus.FieldLogger) (blob.Storage, error) {
	backendStore, err := setupBackendStore(ctx, repoOption.StorageType, repoOption.StorageOptions, logger)
	if err != nil {
		return nil, errors.Wrap(err, "error to setup backend storage")
	}

	st, err := backendStore.store.Connect(ctx, false, logger)
	if err != nil {
		return nil, errors.Wrap(err, "error to connect to storage")
	}

	return st, nil
}

func findBackendStore(storage string) *kopiaBackendStore {
	for _, options := range backendStores {
		if strings.EqualFold(options.name, storage) {
			return &options
		}
	}

	return nil
}

func setupBackendStore(ctx context.Context, storageType string, storageOptions map[string]string, logger logrus.FieldLogger) (*kopiaBackendStore, error) {
	backendStore := findBackendStore(storageType)
	if backendStore == nil {
		return nil, errors.New("error to find storage type")
	}

	err := backendStore.store.Setup(ctx, storageOptions, logger)
	if err != nil {
		return nil, errors.Wrap(err, "error to setup storage")
	}

	return backendStore, nil
}

func createWithStorage(ctx context.Context, st blob.Storage, repoOption udmrepo.RepoOptions) error {
	err := ensureEmpty(ctx, st)
	if err != nil {
		return errors.Wrap(err, "error to ensure repository storage empty")
	}

	options := backend.SetupNewRepositoryOptions(ctx, repoOption.GeneralOptions)

	if err := repo.Initialize(ctx, st, &options, repoOption.RepoPassword); err != nil {
		return errors.Wrap(err, "error to initialize repository")
	}

	return nil
}

func connectWithStorage(ctx context.Context, st blob.Storage, repoOption udmrepo.RepoOptions) error {
	options := backend.SetupConnectOptions(ctx, repoOption)
	if err := repo.Connect(ctx, repoOption.ConfigFilePath, st, repoOption.RepoPassword, &options); err != nil {
		return errors.Wrap(err, "error to connect to repository")
	}

	return nil
}

func ensureEmpty(ctx context.Context, s blob.Storage) error {
	hasDataError := errors.Errorf("has data")

	err := s.ListBlobs(ctx, "", func(cb blob.Metadata) error {
		return hasDataError
	})

	if errors.Is(err, hasDataError) {
		return errors.New("found existing data in storage location")
	}

	return errors.Wrap(err, "error to list blobs")
}

type byteBuffer struct {
	buffer []byte
}

type byteBufferReader struct {
	buffer []byte
	pos    int
}

func (b *byteBuffer) Write(p []byte) (int, error) {
	b.buffer = append(b.buffer, p...)
	return len(p), nil
}

func (b *byteBuffer) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(b.buffer)
	return int64(n), err
}

func (b *byteBuffer) Reset() {
	b.buffer = nil
}

func (b *byteBuffer) Length() int {
	return len(b.buffer)
}

func (b *byteBuffer) Reader() io.ReadSeekCloser {
	return &byteBufferReader{buffer: b.buffer}
}

func (b *byteBufferReader) Close() error {
	return nil
}

func (b *byteBufferReader) Read(out []byte) (int, error) {
	if b.pos == len(b.buffer) {
		return 0, io.EOF
	}

	copied := copy(out, b.buffer[b.pos:])
	b.pos += copied

	return copied, nil
}

func (b *byteBufferReader) Seek(offset int64, whence int) (int64, error) {
	newOffset := b.pos

	switch whence {
	case io.SeekStart:
		newOffset = int(offset)
	case io.SeekCurrent:
		newOffset += int(offset)
	case io.SeekEnd:
		newOffset = len(b.buffer) + int(offset)
	}

	if newOffset < 0 || newOffset > len(b.buffer) {
		return -1, errors.New("invalid seek")
	}

	b.pos = newOffset

	return int64(newOffset), nil
}

var funcGetParam = maintenance.GetParams

func writeInitParameters(ctx context.Context, repoOption udmrepo.RepoOptions, logger logrus.FieldLogger) error {
	r, err := openKopiaRepo(ctx, repoOption.ConfigFilePath, repoOption.RepoPassword, &openOptions{repoLogger: kopia.RepositoryLogger(logger)})
	if err != nil {
		return err
	}

	defer func() {
		c := r.Close(ctx)
		if c != nil {
			logger.WithError(c).Error("Failed to close repo")
		}
	}()

	params, err := funcGetParam(ctx, r)
	if err != nil {
		return errors.Wrap(err, "error getting existing maintenance params")
	}

	if params.Owner == backend.RepoOwnerFromRepoOptions(repoOption) {
		logger.Warn("Init parameters already exists, skip")
		return nil
	}

	if params.Owner != "" {
		logger.Warnf("Overwriting existing init params %v", params)
	}

	err = repo.WriteSession(ctx, r, repo.WriteSessionOptions{
		Purpose: "set init parameters",
	}, func(ctx context.Context, w repo.RepositoryWriter) error {
		p := maintenance.DefaultParams()

		if overwriteFullMaintainInterval != time.Duration(0) {
			logger.Infof("Full maintenance interval change from %v to %v", p.FullCycle.Interval, overwriteFullMaintainInterval)
			p.FullCycle.Interval = overwriteFullMaintainInterval
		}

		if overwriteQuickMaintainInterval != time.Duration(0) {
			logger.Infof("Quick maintenance interval change from %v to %v", p.QuickCycle.Interval, overwriteQuickMaintainInterval)
			p.QuickCycle.Interval = overwriteQuickMaintainInterval
		}
		// the repoOption.StorageOptions are set via
		// udmrepo.WithStoreOptions -> udmrepo.GetStoreOptions (interface)
		// -> pkg/repository/provider.GetStoreOptions(param interface{}) -> pkg/repository/provider.getStorageVariables(..., backupRepoConfig)
		// where backupRepoConfig comes from param.(RepoParam).BackupRepo.Spec.RepositoryConfig map[string]string
		// where RepositoryConfig comes from pkg/controller/getBackupRepositoryConfig(...)
		// where it gets a configMap name from pkg/cmd/server/config/Config.BackupRepoConfig
		// which gets set via velero server flag `backup-repository-configmap` "The name of ConfigMap containing backup repository configurations."
		// and data stored as json under ConfigMap.Data[repoType] where repoType is BackupRepository.Spec.RepositoryType: either kopia or restic
		// repoOption.StorageOptions[udmrepo.StoreOptionKeyFullMaintenanceInterval] would for example look like
		// configMapName.data.kopia: {"fullMaintenanceInterval": "eagerGC"}
		fullMaintIntervalOption := udmrepo.FullMaintenanceIntervalOptions(repoOption.StorageOptions[udmrepo.StoreOptionKeyFullMaintenanceInterval])
		priorMaintInterval := p.FullCycle.Interval
		switch fullMaintIntervalOption {
		case udmrepo.FastGC:
			p.FullCycle.Interval = udmrepo.FastGCInterval
		case udmrepo.EagerGC:
			p.FullCycle.Interval = udmrepo.EagerGCInterval
		case udmrepo.NormalGC:
			p.FullCycle.Interval = udmrepo.NormalGCInterval
		case "": // do nothing
		default:
			return errors.Errorf("invalid full maintenance interval option %s", fullMaintIntervalOption)
		}
		if priorMaintInterval != p.FullCycle.Interval {
			logger.Infof("Full maintenance interval change from %v to %v", priorMaintInterval, p.FullCycle.Interval)
		}

		p.Owner = r.ClientOptions().UsernameAtHost()

		if err := maintenance.SetParams(ctx, w, &p); err != nil {
			return errors.Wrap(err, "error to set maintenance params")
		}

		return nil
	})

	if err != nil {
		return errors.Wrap(err, "error to init write repo parameters")
	}

	return nil
}
