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
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/kopia/kopia/fs"
	"github.com/kopia/kopia/repo"
	"github.com/kopia/kopia/repo/compression"
	"github.com/kopia/kopia/repo/content/index"
	"github.com/kopia/kopia/repo/maintenance"
	"github.com/kopia/kopia/repo/manifest"
	"github.com/kopia/kopia/repo/object"
	"github.com/kopia/kopia/snapshot"
	"github.com/kopia/kopia/snapshot/snapshotfs"
	"github.com/kopia/kopia/snapshot/snapshotmaintenance"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/vmware-tanzu/velero/pkg/kopia"
	"github.com/vmware-tanzu/velero/pkg/repository/udmrepo"
	"github.com/vmware-tanzu/velero/pkg/repository/udmrepo/kopialib/backend"
)

type kopiaRepoService struct {
	logger logrus.FieldLogger
}

type kopiaRepository struct {
	rawRepo     repo.Repository
	rawWriter   repo.RepositoryWriter
	description string
	uploaded    int64
	openTime    time.Time
	throttle    logThrottle
	logger      logrus.FieldLogger
}

type kopiaMaintenance struct {
	mode      maintenance.Mode
	startTime time.Time
	uploaded  int64
	throttle  logThrottle
	logger    logrus.FieldLogger
}

type logThrottle struct {
	lastTime int64
	interval time.Duration
}

type kopiaObjectReader struct {
	rawReader object.Reader
}

type kopiaObjectWriter struct {
	rawWriter object.Writer
}

type openOptions struct {
	repoLogger io.Writer
}

const (
	defaultLogInterval             = time.Second * 10
	defaultMaintainCheckPeriod     = time.Hour
	overwriteFullMaintainInterval  = time.Duration(0)
	overwriteQuickMaintainInterval = time.Duration(0)
	repoBackend                    = "kopia"
)

var kopiaRepoOpen = repo.Open

// NewKopiaRepoService creates an instance of BackupRepoService implemented by Kopia
func NewKopiaRepoService(logger logrus.FieldLogger) udmrepo.BackupRepoService {
	ks := &kopiaRepoService{
		logger: logger,
	}

	return ks
}

func (ks *kopiaRepoService) Create(ctx context.Context, repoOption udmrepo.RepoOptions) error {
	repoCtx := kopia.SetupKopiaLog(ctx, ks.logger)

	status, err := GetRepositoryStatus(ctx, repoOption, ks.logger)
	if err != nil {
		return errors.Wrap(err, "error getting repo status")
	}

	if status != RepoStatusSystemNotCreated && status != RepoStatusNotInitialized {
		return errors.Errorf("unexpected repo status %v", status)
	}

	if status == RepoStatusSystemNotCreated {
		if err := CreateBackupRepo(repoCtx, repoOption, ks.logger); err != nil {
			return errors.Wrap(err, "error creating backup repo")
		}
	}

	if err := InitializeBackupRepo(ctx, repoOption, ks.logger); err != nil {
		return errors.Wrap(err, "error initializing backup repo")
	}

	return nil
}

func (ks *kopiaRepoService) Connect(ctx context.Context, repoOption udmrepo.RepoOptions) error {
	repoCtx := kopia.SetupKopiaLog(ctx, ks.logger)

	return ConnectBackupRepo(repoCtx, repoOption, ks.logger)
}

var funcGetRepositoryStatus = GetRepositoryStatus

func (ks *kopiaRepoService) IsReady(ctx context.Context, repoOption udmrepo.RepoOptions, readOnly bool) (bool, error) {
	repoCtx := kopia.SetupKopiaLog(ctx, ks.logger)

	status, err := funcGetRepositoryStatus(repoCtx, repoOption, ks.logger)
	if err != nil {
		return false, err
	}

	if status == RepoStatusCreated {
		return true, nil
	}

	if status == RepoStatusNotInitialized && readOnly {
		ks.logger.Warnf("Repo is not initialized, could be for read")
		return true, nil
	}

	ks.logger.Infof("Repo is not fully created, status %v", status)

	return false, nil
}

func (ks *kopiaRepoService) Open(ctx context.Context, repoOption udmrepo.RepoOptions) (udmrepo.BackupRepo, error) {
	repoConfig := repoOption.ConfigFilePath
	if repoConfig == "" {
		return nil, errors.New("invalid config file path")
	}

	if _, err := os.Stat(repoConfig); os.IsNotExist(err) {
		return nil, errors.Wrapf(err, "repo config %s doesn't exist", repoConfig)
	}

	repoCtx := kopia.SetupKopiaLog(ctx, ks.logger)

	r, err := openKopiaRepo(repoCtx, repoConfig, repoOption.RepoPassword, &openOptions{repoLogger: kopia.RepositoryLogger(ks.logger)})
	if err != nil {
		return nil, err
	}

	kr := kopiaRepository{
		rawRepo:     r,
		openTime:    time.Now(),
		description: repoOption.Description,
		throttle: logThrottle{
			interval: defaultLogInterval,
		},
		logger: ks.logger,
	}

	_, kr.rawWriter, err = r.NewWriter(repoCtx, repo.WriteSessionOptions{
		Purpose:  repoOption.Description,
		OnUpload: kr.updateProgress,
	})

	if err != nil {
		if e := r.Close(repoCtx); e != nil {
			ks.logger.WithError(e).Error("Failed to close raw repository on error")
		}

		return nil, errors.Wrap(err, "error to create repo writer")
	}

	return &kr, nil
}

func (ks *kopiaRepoService) Maintain(ctx context.Context, repoOption udmrepo.RepoOptions) error {
	repoConfig := repoOption.ConfigFilePath
	if repoConfig == "" {
		return errors.New("invalid config file path")
	}

	if _, err := os.Stat(repoConfig); os.IsNotExist(err) {
		return errors.Wrapf(err, "repo config %s doesn't exist", repoConfig)
	}

	repoCtx := kopia.SetupKopiaLog(ctx, ks.logger)

	ks.logger.Info("Start to open repo for maintenance, allow index write on load")

	r, err := openKopiaRepo(repoCtx, repoConfig, repoOption.RepoPassword, &openOptions{repoLogger: kopia.RepositoryLogger(ks.logger)})
	if err != nil {
		return err
	}

	ks.logger.Info("Succeeded to open repo for maintenance")

	defer func() {
		c := r.Close(repoCtx)
		if c != nil {
			ks.logger.WithError(c).Error("Failed to close repo")
		}
	}()

	km := kopiaMaintenance{
		mode:      maintenance.ModeAuto,
		startTime: time.Now(),
		throttle: logThrottle{
			interval: defaultLogInterval,
		},
		logger: ks.logger,
	}

	if mode, exist := repoOption.GeneralOptions[udmrepo.GenOptionMaintainMode]; exist {
		if strings.EqualFold(mode, udmrepo.GenOptionMaintainFull) {
			km.mode = maintenance.ModeFull
		} else if strings.EqualFold(mode, udmrepo.GenOptionMaintainQuick) {
			km.mode = maintenance.ModeQuick
		}
	}

	err = repo.DirectWriteSession(repoCtx, r.(repo.DirectRepository), repo.WriteSessionOptions{
		Purpose:  "UdmRepoMaintenance",
		OnUpload: km.maintainProgress,
	}, func(ctx context.Context, dw repo.DirectRepositoryWriter) error {
		return km.runMaintenance(ctx, dw)
	})

	if err != nil {
		return errors.Wrap(err, "error to maintain repo")
	}

	return nil
}

func (ks *kopiaRepoService) DefaultMaintenanceFrequency() time.Duration {
	return defaultMaintainCheckPeriod
}

func (ks *kopiaRepoService) ClientSideCacheLimit(repoOption map[string]string) int64 {
	defaultLimit := int64(backend.DefaultCacheLimitMB << 20)
	if repoOption == nil {
		return defaultLimit
	}

	if v, found := repoOption[repoBackend]; found {
		var configs map[string]any
		if err := json.Unmarshal([]byte(v), &configs); err != nil {
			ks.logger.WithError(err).Warnf("error unmarshalling config data from data %v", v)
			return defaultLimit
		}

		limit := defaultLimit
		if v, found := configs[udmrepo.StoreOptionCacheLimit]; found {
			if iv, ok := v.(float64); ok {
				limit = int64(iv) << 20
			} else {
				ks.logger.Warnf("ignore cache limit from data %v", v)
			}
		}

		return limit
	}

	return defaultLimit
}

func (km *kopiaMaintenance) runMaintenance(ctx context.Context, rep repo.DirectRepositoryWriter) error {
	err := snapshotmaintenance.Run(kopia.SetupKopiaLog(ctx, km.logger), rep, km.mode, false, maintenance.SafetyFull)
	if err != nil {
		return errors.Wrapf(err, "error to run maintenance under mode %s", km.mode)
	}

	return nil
}

// maintainProgress is called when the repository writes a piece of blob data to the storage during the maintenance
func (km *kopiaMaintenance) maintainProgress(uploaded int64) {
	total := atomic.AddInt64(&km.uploaded, uploaded)

	if km.throttle.shouldLog() {
		km.logger.WithFields(
			logrus.Fields{
				"Start Time": km.startTime.Format(time.RFC3339Nano),
				"Current":    time.Now().Format(time.RFC3339Nano),
			},
		).Debugf("Repo maintenance uploaded %d bytes.", total)
	}
}

func (kr *kopiaRepository) OpenObject(ctx context.Context, id udmrepo.ID) (udmrepo.ObjectReader, error) {
	if kr.rawRepo == nil {
		return nil, errors.New("repo is closed or not open")
	}

	objID, err := object.ParseID(string(id))
	if err != nil {
		return nil, errors.Wrapf(err, "error to parse object ID from %v", id)
	}

	reader, err := kr.rawRepo.OpenObject(kopia.SetupKopiaLog(ctx, kr.logger), objID)
	if err != nil {
		return nil, errors.Wrap(err, "error to open object")
	}

	return &kopiaObjectReader{
		rawReader: reader,
	}, nil
}

func (kr *kopiaRepository) GetManifest(ctx context.Context, id udmrepo.ID, mani *udmrepo.RepoManifest) error {
	if kr.rawRepo == nil {
		return errors.New("repo is closed or not open")
	}

	metadata, err := kr.rawRepo.GetManifest(kopia.SetupKopiaLog(ctx, kr.logger), manifest.ID(id), mani.Payload)
	if err != nil {
		return errors.Wrap(err, "error to get manifest")
	}

	mani.Metadata = getManifestEntryFromKopia(metadata)

	return nil
}

func (kr *kopiaRepository) FindManifests(ctx context.Context, filter udmrepo.ManifestFilter) ([]*udmrepo.ManifestEntryMetadata, error) {
	if kr.rawRepo == nil {
		return nil, errors.New("repo is closed or not open")
	}

	metadata, err := kr.rawRepo.FindManifests(kopia.SetupKopiaLog(ctx, kr.logger), filter.Labels)
	if err != nil {
		return nil, errors.Wrap(err, "error to find manifests")
	}

	return getManifestEntriesFromKopia(metadata), nil
}

func (kr *kopiaRepository) Time() time.Time {
	if kr.rawRepo == nil {
		return time.Time{}
	}

	return kr.rawRepo.Time()
}

func (kr *kopiaRepository) Close(ctx context.Context) error {
	if kr.rawWriter != nil {
		err := kr.rawWriter.Close(kopia.SetupKopiaLog(ctx, kr.logger))
		if err != nil {
			return errors.Wrap(err, "error to close repo writer")
		}

		kr.rawWriter = nil
	}

	if kr.rawRepo != nil {
		err := kr.rawRepo.Close(kopia.SetupKopiaLog(ctx, kr.logger))
		if err != nil {
			return errors.Wrap(err, "error to close repo")
		}

		kr.rawRepo = nil
	}

	return nil
}

func (kr *kopiaRepository) NewObjectWriter(ctx context.Context, opt udmrepo.ObjectWriteOptions) (udmrepo.ObjectWriter, error) {
	if kr.rawWriter == nil {
		return nil, errors.New("repo writer is closed or not open")
	}

	writer := kr.rawWriter.NewObjectWriter(kopia.SetupKopiaLog(ctx, kr.logger), object.WriterOptions{
		Description:        opt.Description,
		Prefix:             index.IDPrefix(opt.Prefix),
		AsyncWrites:        opt.AsyncWrites,
		Compressor:         getCompressorForObject(opt),
		MetadataCompressor: getMetadataCompressor(),
	})

	if writer == nil {
		return nil, errors.Errorf("error creating writer for object %s", opt.Description)
	}

	return &kopiaObjectWriter{
		rawWriter: writer,
	}, nil
}

const kopiaDirStreamType = "kopia:directory"

func (kr *kopiaRepository) WriteMetadata(ctx context.Context, meta *udmrepo.Metadata, opt udmrepo.ObjectWriteOptions) (udmrepo.ID, error) {
	if kr.rawWriter == nil {
		return "", errors.New("repo writer is closed or not open")
	}

	dirEntries := []*snapshot.DirEntry{}
	if meta.SubObjects != nil {
		for _, sub := range meta.SubObjects {
			rawID, err := object.ParseID(string(sub.ID))
			if err != nil {
				return "", errors.Wrapf(err, "error parsing object ID from %v", sub)
			}

			dirEntries = append(dirEntries, &snapshot.DirEntry{
				Name:        sub.Name,
				ObjectID:    rawID,
				Type:        getKopiaObjectType(sub.Type),
				FileSize:    sub.Size,
				Permissions: snapshot.Permissions(sub.Permissions),
				ModTime:     fs.UTCTimestampFromTime(sub.ModTime),
				UserID:      sub.UserID,
				GroupID:     sub.GroupID,
			})
		}
	}

	dirManifest := snapshot.DirManifest{
		StreamType: kopiaDirStreamType,
		Entries:    dirEntries,
	}

	oid, err := snapshotfs.WriteDirManifest(ctx, kr.rawWriter, opt.Description, &dirManifest, getMetadataCompressor())
	if err != nil {
		return "", errors.Wrapf(err, "error writing dir manifest: %v", opt.Description)
	}

	return udmrepo.ID(oid.String()), nil
}

func (kr *kopiaRepository) ReadMetadata(ctx context.Context, id udmrepo.ID) (*udmrepo.Metadata, error) {
	reader, err := kr.OpenObject(ctx, id)
	if err != nil {
		return nil, errors.Wrapf(err, "error to open metadata object %v", id)
	}
	defer reader.Close()

	dirManifest := snapshot.DirManifest{}
	if err := json.NewDecoder(reader).Decode(&dirManifest); err != nil {
		return nil, errors.Wrap(err, "unable to parse directory object")
	}

	meta := udmrepo.Metadata{}
	for _, sub := range dirManifest.Entries {
		meta.SubObjects = append(meta.SubObjects, udmrepo.ObjectMetadata{
			ID:          udmrepo.ID(sub.ObjectID.String()),
			Name:        sub.Name,
			Type:        getObjectDataType(sub.Type),
			Size:        sub.FileSize,
			ModTime:     sub.ModTime.ToTime(),
			Permissions: int(sub.Permissions),
			UserID:      sub.UserID,
			GroupID:     sub.GroupID,
		})
	}

	return &meta, nil
}

func (kr *kopiaRepository) PutManifest(ctx context.Context, manifest udmrepo.RepoManifest) (udmrepo.ID, error) {
	if kr.rawWriter == nil {
		return "", errors.New("repo writer is closed or not open")
	}

	id, err := kr.rawWriter.PutManifest(kopia.SetupKopiaLog(ctx, kr.logger), manifest.Metadata.Labels, manifest.Payload)
	if err != nil {
		return "", errors.Wrap(err, "error to put manifest")
	}

	return udmrepo.ID(id), nil
}

func (kr *kopiaRepository) DeleteManifest(ctx context.Context, id udmrepo.ID) error {
	if kr.rawWriter == nil {
		return errors.New("repo writer is closed or not open")
	}

	err := kr.rawWriter.DeleteManifest(kopia.SetupKopiaLog(ctx, kr.logger), manifest.ID(id))
	if err != nil {
		return errors.Wrap(err, "error to delete manifest")
	}

	return nil
}

func (kr *kopiaRepository) SaveSnapshot(ctx context.Context, snap udmrepo.Snapshot) (udmrepo.ID, error) {
	if kr.rawWriter == nil {
		return "", errors.New("repo writer is closed or not open")
	}

	if snap.Source == "" {
		return "", errors.New("invalid snapshot source")
	}

	rootObj, err := object.ParseID(string(snap.RootObject.ID))
	if err != nil {
		return "", errors.Wrapf(err, "error parsing root object ID %v", snap.RootObject.ID)
	}

	manifest := snapshot.Manifest{
		Source: snapshot.SourceInfo{
			UserName: udmrepo.GetRepoUser(),
			Host:     udmrepo.GetRepoDomain(),
			Path:     snap.Source,
		},
		Description: snap.Description,
		StartTime:   fs.UTCTimestampFromTime(snap.StartTime),
		EndTime:     fs.UTCTimestampFromTime(snap.EndTime),
		RootEntry: &snapshot.DirEntry{
			Type:        snapshot.EntryTypeDirectory,
			ObjectID:    rootObj,
			ModTime:     fs.UTCTimestampFromTime(snap.RootObject.ModTime),
			Permissions: snapshot.Permissions(snap.RootObject.Permissions),
			FileSize:    snap.RootObject.Size,
			UserID:      snap.RootObject.UserID,
			GroupID:     snap.RootObject.GroupID,
		},
		Tags: snap.Tags,
	}

	id, err := snapshot.SaveSnapshot(ctx, kr.rawWriter, &manifest)
	if err != nil {
		return "", errors.Wrap(err, "error saving snapshot")
	}

	return udmrepo.ID(id), nil
}

func (kr *kopiaRepository) GetSnapshot(ctx context.Context, id udmrepo.ID) (udmrepo.Snapshot, error) {
	snap, err := snapshot.LoadSnapshot(ctx, kr.rawRepo, manifest.ID(id))
	if err != nil {
		return udmrepo.Snapshot{}, errors.Wrap(err, "error getting snapshot manifest")
	}

	if snap.RootEntry == nil {
		return udmrepo.Snapshot{}, errors.New("invalid snapshot root entry")
	}

	return udmrepo.Snapshot{
		Source:      snap.Source.Path,
		Description: snap.Description,
		StartTime:   snap.StartTime.ToTime(),
		EndTime:     snap.EndTime.ToTime(),
		Tags:        snap.Tags,
		RootObject: udmrepo.ObjectMetadata{
			ID:          udmrepo.ID(snap.RootEntry.ObjectID.String()),
			Type:        udmrepo.ObjectDataTypeMetadata,
			Size:        snap.RootEntry.FileSize,
			ModTime:     snap.RootEntry.ModTime.ToTime(),
			Permissions: int(snap.RootEntry.Permissions),
			UserID:      snap.RootEntry.UserID,
			GroupID:     snap.RootEntry.GroupID,
		},
	}, nil
}

func (kr *kopiaRepository) DeleteSnapshot(ctx context.Context, id udmrepo.ID) error {
	if _, err := kr.GetSnapshot(ctx, id); err != nil {
		return errors.Wrap(err, "error getting snapshot")
	}

	return kr.DeleteManifest(ctx, id)
}

func (kr *kopiaRepository) ListSnapshot(ctx context.Context, source string) ([]udmrepo.Snapshot, error) {
	mani, err := snapshot.ListSnapshots(ctx, kr.rawRepo, snapshot.SourceInfo{
		Host:     udmrepo.GetRepoDomain(),
		UserName: udmrepo.GetRepoUser(),
		Path:     source,
	})
	if err != nil {
		return nil, errors.Wrapf(err, "error listing snapshot manifest for source %s", source)
	}

	snapshots := []udmrepo.Snapshot{}
	for _, snap := range mani {
		snapshots = append(snapshots, udmrepo.Snapshot{
			Source:      snap.Source.Path,
			Description: snap.Description,
			StartTime:   snap.StartTime.ToTime(),
			EndTime:     snap.EndTime.ToTime(),
			Tags:        snap.Tags,
			RootObject: udmrepo.ObjectMetadata{
				ID:          udmrepo.ID(snap.RootEntry.ObjectID.String()),
				Type:        udmrepo.ObjectDataTypeMetadata,
				Size:        snap.RootEntry.FileSize,
				ModTime:     snap.RootEntry.ModTime.ToTime(),
				Permissions: int(snap.RootEntry.Permissions),
				UserID:      snap.RootEntry.UserID,
				GroupID:     snap.RootEntry.GroupID,
			},
		})
	}

	return snapshots, nil
}

func (kr *kopiaRepository) Flush(ctx context.Context) error {
	if kr.rawWriter == nil {
		return errors.New("repo writer is closed or not open")
	}

	err := kr.rawWriter.Flush(kopia.SetupKopiaLog(ctx, kr.logger))
	if err != nil {
		return errors.Wrap(err, "error to flush repo")
	}

	return nil
}

func (kr *kopiaRepository) GetAdvancedFeatures() udmrepo.AdvancedFeatureInfo {
	return udmrepo.AdvancedFeatureInfo{
		MultiPartBackup: true,
	}
}

func (kr *kopiaRepository) ConcatenateObjects(ctx context.Context, objectIDs []udmrepo.ID) (udmrepo.ID, error) {
	if kr.rawWriter == nil {
		return "", errors.New("repo writer is closed or not open")
	}

	if len(objectIDs) == 0 {
		return udmrepo.ID(""), errors.New("object list is empty")
	}

	rawIDs := []object.ID{}
	for _, id := range objectIDs {
		rawID, err := object.ParseID(string(id))
		if err != nil {
			return udmrepo.ID(""), errors.Wrapf(err, "error to parse object ID from %v", id)
		}

		rawIDs = append(rawIDs, rawID)
	}

	result, err := kr.rawWriter.ConcatenateObjects(ctx, rawIDs, repo.ConcatenateOptions{
		Compressor: getMetadataCompressor(),
	})
	if err != nil {
		return udmrepo.ID(""), errors.Wrap(err, "error to concatenate objects")
	}

	return udmrepo.ID(result.String()), nil
}

// updateProgress is called when the repository writes a piece of blob data to the storage during data write
func (kr *kopiaRepository) updateProgress(uploaded int64) {
	total := atomic.AddInt64(&kr.uploaded, uploaded)

	if kr.throttle.shouldLog() {
		kr.logger.WithFields(
			logrus.Fields{
				"Description": kr.description,
				"Open Time":   kr.openTime.Format(time.RFC3339Nano),
				"Current":     time.Now().Format(time.RFC3339Nano),
			},
		).Debugf("Repo uploaded %d bytes.", total)
	}
}

func (kor *kopiaObjectReader) Read(p []byte) (int, error) {
	if kor.rawReader == nil {
		return 0, errors.New("object reader is closed or not open")
	}

	return kor.rawReader.Read(p)
}

func (kor *kopiaObjectReader) Seek(offset int64, whence int) (int64, error) {
	if kor.rawReader == nil {
		return -1, errors.New("object reader is closed or not open")
	}

	return kor.rawReader.Seek(offset, whence)
}

func (kor *kopiaObjectReader) Close() error {
	if kor.rawReader == nil {
		return nil
	}

	err := kor.rawReader.Close()
	if err != nil {
		return err
	}

	kor.rawReader = nil

	return nil
}

func (kor *kopiaObjectReader) Length() int64 {
	if kor.rawReader == nil {
		return -1
	}

	return kor.rawReader.Length()
}

func (kow *kopiaObjectWriter) Write(p []byte) (int, error) {
	if kow.rawWriter == nil {
		return 0, errors.New("object writer is closed or not open")
	}

	return kow.rawWriter.Write(p)
}

// TODO add implementation in following PRs
func (kow *kopiaObjectWriter) WriteAt(p []byte, offset int64) (int, error) {
	return 0, errors.New("not supported")
}

func (kow *kopiaObjectWriter) Checkpoint() (udmrepo.ID, error) {
	if kow.rawWriter == nil {
		return udmrepo.ID(""), errors.New("object writer is closed or not open")
	}

	id, err := kow.rawWriter.Checkpoint()
	if err != nil {
		return udmrepo.ID(""), errors.Wrap(err, "error to checkpoint object")
	}

	return udmrepo.ID(id.String()), nil
}

func (kow *kopiaObjectWriter) Result() (udmrepo.ID, error) {
	if kow.rawWriter == nil {
		return udmrepo.ID(""), errors.New("object writer is closed or not open")
	}

	id, err := kow.rawWriter.Result()
	if err != nil {
		return udmrepo.ID(""), errors.Wrap(err, "error to wait object")
	}

	return udmrepo.ID(id.String()), nil
}

func (kow *kopiaObjectWriter) Close() error {
	if kow.rawWriter == nil {
		return nil
	}

	err := kow.rawWriter.Close()
	if err != nil {
		return err
	}

	kow.rawWriter = nil

	return nil
}

// getCompressorForObject returns the compressor for an object, at present, we don't support compression
func getCompressorForObject(_ udmrepo.ObjectWriteOptions) compression.Name {
	return ""
}

// getMetadataCompressor returns the compressor for metadata, return kopia's default since we don't support compression
func getMetadataCompressor() compression.Name {
	return "zstd-fastest"
}

func getManifestEntryFromKopia(mani *manifest.EntryMetadata) *udmrepo.ManifestEntryMetadata {
	return &udmrepo.ManifestEntryMetadata{
		ID:      udmrepo.ID(mani.ID),
		Labels:  mani.Labels,
		Length:  int32(mani.Length),
		ModTime: mani.ModTime,
	}
}

func getManifestEntriesFromKopia(mani []*manifest.EntryMetadata) []*udmrepo.ManifestEntryMetadata {
	var ret []*udmrepo.ManifestEntryMetadata

	for _, entry := range mani {
		ret = append(ret, &udmrepo.ManifestEntryMetadata{
			ID:      udmrepo.ID(entry.ID),
			Labels:  entry.Labels,
			Length:  int32(entry.Length),
			ModTime: entry.ModTime,
		})
	}

	return ret
}

func (lt *logThrottle) shouldLog() bool {
	nextOutputTime := atomic.LoadInt64(&lt.lastTime)
	if nowNano := time.Now().UnixNano(); nowNano > nextOutputTime {
		if atomic.CompareAndSwapInt64(&lt.lastTime, nextOutputTime, nowNano+lt.interval.Nanoseconds()) {
			return true
		}
	}

	return false
}

func openKopiaRepo(ctx context.Context, configFile string, password string, options *openOptions) (repo.Repository, error) {
	r, err := kopiaRepoOpen(ctx, configFile, password, &repo.Options{
		ContentLogWriter: options.repoLogger,
	})
	if os.IsNotExist(err) {
		return nil, errors.Wrap(err, "error to open repo, repo doesn't exist")
	}

	if err != nil {
		return nil, errors.Wrap(err, "error to open repo")
	}

	return r, nil
}

func getKopiaObjectType(tp int) snapshot.EntryType {
	switch tp {
	case udmrepo.ObjectDataTypeMetadata:
		return snapshot.EntryTypeDirectory
	case udmrepo.ObjectDataTypeData:
		return snapshot.EntryTypeFile
	default:
		return snapshot.EntryTypeUnknown
	}
}

func getObjectDataType(tp snapshot.EntryType) int {
	switch tp {
	case snapshot.EntryTypeDirectory:
		return udmrepo.ObjectDataTypeMetadata
	case snapshot.EntryTypeFile:
		return udmrepo.ObjectDataTypeData
	default:
		return udmrepo.ObjectDataTypeUnknown
	}
}
