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

package block

import (
	"context"
	"io"
	"maps"
	"path/filepath"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"

	"github.com/vmware-tanzu/velero/pkg/cbtservice"
	"github.com/vmware-tanzu/velero/pkg/repository/udmrepo"
	"github.com/vmware-tanzu/velero/pkg/uploader"
	"github.com/vmware-tanzu/velero/pkg/uploader/cbt"
)

var openBlockDeviceFunc = openBlockDevice

type parentBackupInfo struct {
	parentObject udmrepo.ID
	changeID     string
	volumeID     string
}

type backupInfo struct {
	changeID string
}

// Backup backup specific sourcePath and update progress
func Backup(ctx context.Context, blkUp Uploader, repoWriter udmrepo.BackupRepo, sourcePath string, realSource string, cbtSource cbtservice.SourceInfo,
	forceFull bool, parentSnapshot string, cbtService cbtservice.Service, uploaderCfg map[string]string, tags map[string]string, log logrus.FieldLogger) (uploader.SnapshotInfo, bool, error) {
	if blkUp == nil {
		return uploader.SnapshotInfo{}, false, errors.New("get empty block uploader")
	}

	source, err := filepath.Abs(sourcePath)
	if err != nil {
		return uploader.SnapshotInfo{}, false, errors.Wrapf(err, "invalid source path %s", sourcePath)
	}

	source = filepath.Clean(source)

	sourceInfo := sourceInfo{
		realSource: filepath.Clean(realSource),
	}

	if realSource == "" {
		sourceInfo.realSource = source
	}

	sourceInfo.dev, err = openBlockDeviceFunc(source, true)
	if err != nil {
		return uploader.SnapshotInfo{}, false, errors.Wrapf(err, "error opening block device %s", source)
	}

	defer sourceInfo.dev.Close()

	sourceInfo.size, err = sourceInfo.dev.Seek(0, io.SeekEnd)
	if err != nil {
		return uploader.SnapshotInfo{}, false, errors.Wrapf(err, "error getting length of block device %s", source)
	}

	_, err = sourceInfo.dev.Seek(0, io.SeekStart)
	if err != nil {
		return uploader.SnapshotInfo{}, false, errors.Wrapf(err, "error reset pos of block device %s", source)
	}

	snapID, backupSize, snapshotSize, fallback, err := snapshotSource(ctx, repoWriter, blkUp, sourceInfo, forceFull, parentSnapshot, cbtSource, cbtService, tags, uploaderCfg, log, "Block Uploader")
	snapshotInfo := uploader.SnapshotInfo{
		ID:              snapID,
		SnapshotSize:    snapshotSize,
		IncrementalSize: backupSize,
		SourceSize:      sourceInfo.size,
		Fallback:        fallback,
	}

	return snapshotInfo, false, err
}

func snapshotSource(
	ctx context.Context,
	rep udmrepo.BackupRepo,
	u Uploader,
	source sourceInfo,
	forceFull bool,
	parentSnapshot string,
	cbtSource cbtservice.SourceInfo,
	cbtService cbtservice.Service,
	snapshotTags map[string]string,
	uploaderCfg map[string]string,
	log logrus.FieldLogger,
	description string,
) (string, int64, int64, bool, error) {
	log.Info("Start to snapshot...")
	snapshotStartTime := time.Now()

	bitmap := cbt.NewBitmap(blockSize, uint64(source.size), cbtSource.Snapshot, cbtSource.VolumeID)

	parentBackup, err := getParentBackupInfo(ctx, rep, forceFull, parentSnapshot, cbtSource.VolumeID, source.realSource, snapshotTags, log)
	if err != nil {
		log.WithError(err).Warn("Failed to get parent backup info, fallback to full backup")
		bitmap.SetError(errors.Wrap(err, "error getting parent backup info, fallback to full backup"))
	} else {
		bitmap.SetChangeID(parentBackup.changeID)
	}

	err = cbt.SetBitmapOrFull(ctx, cbtService, bitmap, false)
	if err != nil {
		parentBackup.parentObject = ""
		log.WithError(err).Warnf("Failed to create CBT with source %v", cbtSource)
	}

	fallback := false
	if !forceFull {
		fallback = (len(bitmap.Errors()) > 0)
	}

	snap, backupSize, err := u.Backup(source, parentBackup.parentObject, bitmap.Iterator(), uploaderCfg)
	if err != nil {
		return "", 0, 0, fallback, errors.Wrapf(err, "Failed to run uploader backup for si %v", source)
	}

	if snap.Tags == nil {
		snap.Tags = make(map[string]string)
	}

	snap.Tags[uploader.CBTChangeIDTag] = cbtSource.ChangeID
	snap.Tags[uploader.CBTVolumeIDTag] = cbtSource.VolumeID
	if snapshotTags != nil {
		maps.Copy(snap.Tags, snapshotTags)
	}

	snap.Description = description

	snapID, err := rep.SaveSnapshot(ctx, snap)
	if err != nil {
		return "", 0, 0, fallback, errors.Wrapf(err, "Failed to save snapshot %v", snap)
	}

	if err = rep.Flush(ctx); err != nil {
		return "", 0, 0, fallback, errors.Wrapf(err, "Failed to flush repository")
	}

	log.Infof("Created snapshot with root %v and ID %v in %v", snap.RootObject, snapID, time.Since(snapshotStartTime).Truncate(time.Second))

	return string(snapID), backupSize, snap.TotalSize, fallback, nil
}

func getParentBackupInfo(ctx context.Context, rep udmrepo.BackupRepo, forceFull bool, parentSnapshot string, volumeID string,
	realSource string, snapshotTags map[string]string, log logrus.FieldLogger) (parentBackupInfo, error) {
	if forceFull {
		log.Info("Forcing full snapshot")
		return parentBackupInfo{}, nil
	}

	if volumeID == "" {
		return parentBackupInfo{}, errors.New("volumeID is not provided from the volume snapshot")
	}

	var previous *udmrepo.Snapshot
	if parentSnapshot != "" {
		log.Infof("Loading provided parent snapshot %s", parentSnapshot)

		snap, err := rep.GetSnapshot(ctx, udmrepo.ID(parentSnapshot))
		if err != nil {
			return parentBackupInfo{}, errors.Wrapf(err, "error loading previous snapshot")
		}

		previous = &snap
	} else {
		log.Infof("Searching for parent snapshot")

		snap, err := findPreviousSnapshot(ctx, rep, realSource, snapshotTags, nil, log)
		if err != nil {
			return parentBackupInfo{}, errors.Wrapf(err, "error searching previous snapshot")
		}

		previous = &snap
	}

	if previous.Tags == nil {
		return parentBackupInfo{}, errors.Errorf("no tag from parent snapshot %s", previous.ID)
	}

	if previous.Tags[uploader.CBTChangeIDTag] == "" {
		return parentBackupInfo{}, errors.Errorf("no ChangeID tag from parent snapshot %s", previous.ID)
	}

	if previous.Tags[uploader.CBTVolumeIDTag] == "" {
		return parentBackupInfo{}, errors.Errorf("no VolumeID tag from parent snapshot %s", previous.ID)
	}

	if previous.Tags[uploader.CBTVolumeIDTag] != volumeID {
		return parentBackupInfo{}, errors.Errorf("VolumeID %s from parent snapshot %s is not expected as %s", previous.Tags[uploader.CBTVolumeIDTag], previous.ID, volumeID)
	}

	obj, err := loadObjectFromSnapshot(ctx, rep, previous)
	if err != nil {
		return parentBackupInfo{}, errors.Wrapf(err, "error loading object from parent snapshot %s", previous.ID)
	}

	log.Infof("Using parent snapshot %s, start time %v, end time %v, description %s", previous.ID, previous.StartTime, previous.EndTime, previous.Description)

	return parentBackupInfo{
		parentObject: obj,
		changeID:     previous.Tags[uploader.CBTChangeIDTag],
		volumeID:     previous.Tags[uploader.CBTVolumeIDTag],
	}, nil
}

// Restore restore specific sourcePath with given snapshotID and update progress
func Restore(ctx context.Context, blkUp Uploader, rep udmrepo.BackupRepo, snapshotID, dest string, incremental bool, cbtSource cbtservice.SourceInfo, cbtService cbtservice.Service, uploaderCfg map[string]string, log logrus.FieldLogger) (int64, int64, bool, error) {
	log.Info("Start to restore...")

	snapshot, err := rep.GetSnapshot(ctx, udmrepo.ID(snapshotID))
	if err != nil {
		return 0, 0, false, errors.Wrapf(err, "Unable to load snapshot %v", snapshotID)
	}
	log.Infof("Restore from snapshot %s, incremental %v, cbt source %v, description %s, created time %v, tags %v", snapshotID, incremental, cbtSource, snapshot.Description, snapshot.EndTime, snapshot.Tags)

	bitmap := cbt.NewBitmap(blockSize, uint64(snapshot.TotalSize), cbtSource.Snapshot, cbtSource.VolumeID)

	if incremental {
		if bkInfo, err := getBackupInfo(snapshot, cbtSource.VolumeID); err != nil {
			log.WithError(err).Warn("Failed to get backup info, fallback to full restore")

			bitmap.SetError(errors.Wrap(err, "error getting backup info, fallback to full restore"))
			bitmap.SetFull()
		} else {
			bitmap.SetChangeID(bkInfo.changeID)
			if err = cbt.SetBitmapOrFull(ctx, cbtService, bitmap, true); err != nil {
				log.WithError(err).Warnf("Failed to create CBT with source %v", cbtSource)
			}
		}
	} else {
		bitmap.SetFull()
	}

	fallback := false
	if incremental {
		fallback = (len(bitmap.Errors()) > 0)
	}

	destPath, err := filepath.Abs(dest)
	if err != nil {
		return 0, 0, fallback, errors.Wrapf(err, "invalid dest path '%s'", dest)
	}

	destPath = filepath.Clean(destPath)

	destDev, err := openBlockDeviceFunc(destPath, false)
	if err != nil {
		return 0, 0, fallback, errors.Wrapf(err, "error opening block device '%s'", destPath)
	}

	defer destDev.Close()

	destSize, err := destDev.Seek(0, io.SeekEnd)
	if err != nil {
		return 0, 0, fallback, errors.Wrapf(err, "error getting length of block device %s", dest)
	}

	_, err = destDev.Seek(0, io.SeekStart)
	if err != nil {
		return 0, 0, fallback, errors.Wrapf(err, "error reset pos of block device %s", dest)
	}

	incrementalBytes, totalSize, err := blkUp.Restore(snapshot, destInfo{dev: destDev, path: destPath, size: destSize}, bitmap.Iterator(), uploaderCfg)
	if err != nil {
		return 0, 0, fallback, errors.Wrapf(err, "error restoring to block dev %s", destPath)
	}

	return incrementalBytes, totalSize, fallback, nil
}

func getBackupInfo(snapshot udmrepo.Snapshot, volumeID string) (backupInfo, error) {
	if snapshot.Tags == nil {
		return backupInfo{}, errors.Errorf("no tag from snapshot %s", snapshot.ID)
	}

	if snapshot.Tags[uploader.CBTChangeIDTag] == "" {
		return backupInfo{}, errors.Errorf("no ChangeID tag from snapshot %s", snapshot.ID)
	}

	if snapshot.Tags[uploader.CBTVolumeIDTag] == "" {
		return backupInfo{}, errors.Errorf("no VolumeID tag from snapshot %s", snapshot.ID)
	}

	if volumeID == "" {
		return backupInfo{}, errors.New("no VolumeID tag from the volume snapshot")
	}

	if snapshot.Tags[uploader.CBTVolumeIDTag] != volumeID {
		return backupInfo{}, errors.Errorf("volumeID %s from snapshot %s is not expected as %s", snapshot.Tags[uploader.CBTVolumeIDTag], snapshot.ID, volumeID)
	}

	return backupInfo{
		changeID: snapshot.Tags[uploader.CBTChangeIDTag],
	}, nil
}

func findPreviousSnapshot(ctx context.Context, rep udmrepo.BackupRepo, path string, snapshotTags map[string]string, noLaterThan *time.Time, log logrus.FieldLogger) (udmrepo.Snapshot, error) {
	snaps, err := rep.ListSnapshot(ctx, path)
	if err != nil {
		return udmrepo.Snapshot{}, errors.Wrapf(err, "error list snapshots for %s", path)
	}

	var previous *udmrepo.Snapshot

	for _, snap := range snaps {
		log.Debugf("Found one snapshot %s, start time %v, tags %v", snap.RootObject.ID, snap.StartTime, snap.Tags)

		requester, found := snap.Tags[uploader.SnapshotRequesterTag]
		if !found {
			continue
		}

		if requester != snapshotTags[uploader.SnapshotRequesterTag] {
			continue
		}

		uploaderName, found := snap.Tags[uploader.SnapshotUploaderTag]
		if !found {
			continue
		}

		if uploaderName != uploader.BlockType {
			continue
		}

		if noLaterThan != nil && snap.StartTime.After(*noLaterThan) {
			continue
		}

		if previous == nil || snap.StartTime.After(previous.StartTime) {
			previous = &snap
		}
	}

	if previous == nil {
		return udmrepo.Snapshot{}, errors.Errorf("no matching snapshot found for source %s", path)
	}

	return *previous, nil
}
