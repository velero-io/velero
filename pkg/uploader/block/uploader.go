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
	"bytes"
	"context"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"

	"github.com/vmware-tanzu/velero/pkg/repository/udmrepo"
	"github.com/vmware-tanzu/velero/pkg/uploader"
	cbt "github.com/vmware-tanzu/velero/pkg/uploader/cbt/types"
	"github.com/vmware-tanzu/velero/pkg/util/freelist"
)

var ErrCanceled = errors.New("uploader is canceled")

const (
	blockSize         = (1 << 20)
	bufferSize        = 100 << 20
	bdevSourceSizeTag = "bdev-source-size"
)

type sourceInfo struct {
	dev        *os.File
	realSource string
	size       int64
}

type destInfo struct {
	dev  *os.File
	path string
	size int64
}

type Uploader interface {
	Backup(sourceInfo, udmrepo.ID, cbt.Iterator, map[string]string) (udmrepo.Snapshot, int64, error)
	Restore(udmrepo.Snapshot, destInfo, cbt.Iterator, map[string]string) (int64, error)
}

type blockUploader struct {
	ctx        context.Context
	repoWriter udmrepo.BackupRepo
	progress   uploader.ProgressUpdater
	log        logrus.FieldLogger
}

func NewUploader(ctx context.Context, repoWriter udmrepo.BackupRepo, progress uploader.ProgressUpdater, log logrus.FieldLogger) Uploader {
	return &blockUploader{
		ctx:        ctx,
		repoWriter: repoWriter,
		progress:   progress,
		log:        log,
	}
}

func (blkup *blockUploader) Backup(source sourceInfo, parentObject udmrepo.ID, bitmap cbt.Iterator, configs map[string]string) (udmrepo.Snapshot, int64, error) {
	snapStart := blkup.repoWriter.Time()

	if bitmap == nil {
		return udmrepo.Snapshot{}, 0, errors.New("bitmap is not available")
	}

	backupMode := udmrepo.ObjectDataBackupModeInc
	if parentObject == "" {
		backupMode = udmrepo.ObjectDataBackupModeFull
	}

	destObj, err := blkup.repoWriter.NewObjectWriter(blkup.ctx, udmrepo.ObjectWriteOptions{
		Description:  "BDEV:" + getObjectName(source.realSource),
		DataType:     udmrepo.ObjectDataTypeData,
		AccessMode:   udmrepo.ObjectDataAccessModeBlock,
		ParentObject: parentObject,
		BackupMode:   backupMode,
		AsyncWrites:  runtime.NumCPU(),
	})
	if err != nil {
		return udmrepo.Snapshot{}, 0, errors.Wrap(err, "error creating object writer")
	}

	defer destObj.Close()

	id, backupSize, objectSize, err := blkup.backupObject(source.dev, destObj, bitmap, source.size)
	if err != nil {
		return udmrepo.Snapshot{}, 0, errors.Wrapf(err, "error backing up bdev %s", source.realSource)
	}

	entryID, err := blkup.repoWriter.WriteMetadata(blkup.ctx, &udmrepo.Metadata{
		SubObjects: []udmrepo.ObjectMetadata{
			{
				ID:          id,
				Name:        getObjectName(source.realSource),
				Type:        udmrepo.ObjectDataTypeData,
				Size:        objectSize,
				Permissions: 0o777,
			},
		},
	},
		udmrepo.ObjectWriteOptions{
			Description: "bdev-root",
		})
	if err != nil {
		return udmrepo.Snapshot{}, 0, errors.Wrap(err, "error writing metadata")
	}

	snapEnd := blkup.repoWriter.Time()

	return udmrepo.Snapshot{
		Source:      source.realSource,
		StartTime:   snapStart,
		EndTime:     snapEnd,
		Description: source.realSource,
		TotalSize:   objectSize,
		RootObject: udmrepo.ObjectMetadata{
			ID:          entryID,
			Name:        "bdev-root",
			Type:        udmrepo.ObjectDataTypeMetadata,
			Permissions: 0o777,
		},
		Tags: map[string]string{
			bdevSourceSizeTag: strconv.FormatInt(source.size, 10),
		},
	}, backupSize, nil
}

func (blkup *blockUploader) Restore(snapshot udmrepo.Snapshot, dest destInfo, bitmap cbt.Iterator, configs map[string]string) (int64, error) {
	if bitmap == nil {
		return 0, errors.New("bitmap is not available")
	}

	meta, err := blkup.repoWriter.ReadMetadata(blkup.ctx, snapshot.RootObject.ID)
	if err != nil {
		return 0, errors.Wrapf(err, "error reading snapshot metadata for %s", snapshot.Description)
	}

	if len(meta.SubObjects) != 1 {
		return 0, errors.Wrapf(err, "unexpected number of bdev object (%d) for snapshot %s", len(meta.SubObjects), snapshot.Description)
	}

	sourceSize, err := getSourceSize(snapshot)
	if err != nil {
		sourceSize = meta.SubObjects[0].Size
		blkup.log.Warnf("Failed to get source size from snapshot %s, use backup size %v", snapshot.Description, sourceSize)
	}

	if sourceSize > meta.SubObjects[0].Size {
		return 0, errors.Wrapf(err, "unexpected size (%v vs. %v) for bdev object %s", meta.SubObjects[0].Size, sourceSize, meta.SubObjects[0].Name)
	}

	if sourceSize > dest.size {
		return 0, errors.Wrapf(err, "dest dev(%s) size is too small (%v vs. %v)", dest.path, dest.size, sourceSize)
	}

	reader, err := blkup.repoWriter.OpenObject(blkup.ctx, meta.SubObjects[0].ID)
	if err != nil {
		return 0, errors.Wrapf(err, "error opening bdev object %v", meta.SubObjects[0].Name)
	}
	defer reader.Close()

	size, err := blkup.restoreData(reader, dest.dev, bitmap, sourceSize, dest.path)
	if err != nil {
		return 0, errors.Wrapf(err, "error restoring bdev object %s to volume %s", meta.SubObjects[0].Name, dest.path)
	}

	return size, nil
}

func (blkup *blockUploader) backupObject(dev *os.File, dest udmrepo.ObjectWriter, bitmap cbt.Iterator, totalLength int64) (udmrepo.ID, int64, int64, error) {
	backupSize, objectSize, err := blkup.backupData(dev, dest, bitmap, totalLength)
	if err != nil {
		return "", backupSize, objectSize, err
	}

	id, err := dest.Result()
	return id, backupSize, objectSize, err
}

type readResult struct {
	buffer []byte
	offset int64
	err    error
}

func (r *readResult) resetBuffer(list *freelist.FreeList) {
	if r.buffer != nil {
		list.Return(r.buffer)
		r.buffer = nil
	}
}

func (blkup *blockUploader) backupData(reader io.ReaderAt, writer udmrepo.ObjectWriter, bitmap cbt.Iterator, totalLength int64) (int64, int64, error) {
	blockSize := bitmap.BlockSize()
	list := freelist.New(bufferSize, int(blockSize))
	resultChan := make(chan readResult, list.Capacity())
	totalCount := bitmap.Count()
	aligned := (totalLength + int64(blockSize) - 1) / int64(blockSize) * int64(blockSize)

	quit := make(chan struct{})
	defer close(quit)

	go func() {
		defer close(resultChan)

		offset, valid := bitmap.Next()
		var buffer []byte
		for valid {
			select {
			case <-blkup.ctx.Done():
				return
			case <-quit:
				return
			case buffer = <-list.Chunks():
			}

			length := blockSize
			if offset+uint64(length) > uint64(totalLength) {
				length = uint(uint64(totalLength) - offset)
				clear(buffer)
			}

			readBytes, err := reader.ReadAt(buffer[:length], int64(offset))
			if err == nil && readBytes <= 0 {
				err = io.ErrUnexpectedEOF
			}

			r := readResult{
				buffer: buffer,
				offset: int64(offset),
				err:    err,
			}

			if r.err != nil {
				r.resetBuffer(list)
			}

			resultChan <- r

			if r.err != nil {
				return
			}

			offset, valid = bitmap.Next()
		}
	}()

	var lastPos int64
	var result readResult
	var written int64
	var curCount int64
	var writeErr error
	var readerRunning bool

	for curCount < int64(totalCount) {
		select {
		case <-blkup.ctx.Done():
			writeErr = ErrCanceled
		case result, readerRunning = <-resultChan:
			if !readerRunning {
				if blkup.ctx.Err() != nil {
					writeErr = ErrCanceled
				} else {
					writeErr = io.ErrUnexpectedEOF
				}
			}
		}

		if writeErr != nil {
			break
		}

		if result.err != nil {
			writeErr = result.err
			break
		}

		n, err := writer.WriteAt(result.buffer, result.offset)
		if err != nil {
			writeErr = err
			break
		}

		if blockSize != uint(n) {
			writeErr = io.ErrShortWrite
			break
		}

		written += int64(blockSize)
		lastPos = result.offset + int64(blockSize)
		result.resetBuffer(list)
		curCount++

		blkup.progress.UpdateProgress(&uploader.Progress{BytesDone: lastPos, TotalBytes: aligned})
	}

	result.resetBuffer(list)

	if writeErr != nil {
		return written, aligned, writeErr
	}

	if lastPos < aligned {
		s, err := copyTailData(reader, writer, totalLength, int64(blockSize))
		if err != nil {
			return written, aligned, errors.Wrapf(err, "unable to write tail data at %v", lastPos)
		}

		written += s

		blkup.progress.UpdateProgress(&uploader.Progress{BytesDone: aligned, TotalBytes: aligned})
	}

	return written, aligned, nil
}

func copyTailData(source io.ReaderAt, writer udmrepo.ObjectWriter, totalLength int64, blockSize int64) (int64, error) {
	roundUp := (totalLength + blockSize - 1) / blockSize * blockSize
	roundDown := totalLength / blockSize * blockSize
	length := totalLength - roundDown

	if length == 0 {
		if _, err := writer.WriteAt(nil, roundUp); err != nil {
			return -1, errors.Wrapf(err, "error writing sparse to %v", roundUp)
		}
	} else {
		buffer := make([]byte, blockSize)
		if _, err := source.ReadAt(buffer[:length], roundDown); err != nil {
			return -1, errors.Wrapf(err, "error reading tail data with length %v", length)
		}

		if _, err := writer.WriteAt(buffer, roundDown); err != nil {
			return -1, errors.Wrapf(err, "error writing tail data at %v", roundDown)
		}
	}

	return length, nil
}

func getObjectName(source string) string {
	s := strings.ReplaceAll(source, "/", "-")
	s = strings.ReplaceAll(s, "\\", "-")
	return strings.Trim(s, "-")
}

func (blkup *blockUploader) restoreData(reader io.ReadSeeker, dest *os.File, bitmap cbt.Iterator, totalLength int64, destPath string) (int64, error) {
	list := freelist.New(bufferSize, blockSize)
	resultChan := make(chan readResult, list.Capacity())
	zeroBlock := make([]byte, blockSize)
	totalCount := bitmap.Count()

	quit := make(chan struct{})
	defer close(quit)

	go func() {
		defer close(resultChan)

		offset, valid := bitmap.Next()
		var buffer []byte
		var nextPos = uint64(0)
		for valid {
			select {
			case <-blkup.ctx.Done():
				return
			case <-quit:
				return
			case buffer = <-list.Chunks():
			}

			var err error

			if nextPos != offset {
				_, err = reader.Seek(int64(offset), io.SeekStart)
			}

			if err == nil {
				var length int
				length, err = io.ReadFull(reader, buffer)
				if err == nil && length <= 0 {
					err = io.ErrUnexpectedEOF
				}
			}

			r := readResult{
				buffer: buffer,
				offset: int64(offset),
				err:    err,
			}

			if r.err != nil {
				r.resetBuffer(list)
			}

			resultChan <- r

			if r.err != nil {
				return
			}

			nextPos = offset + uint64(blockSize)
			offset, valid = bitmap.Next()
		}
	}()

	var written int64
	var result readResult
	var writeErr error
	var readerRunning bool
	var zeroStart int64 = -1
	var zeroLength int64
	var curCount int64

	for curCount < int64(totalCount) {
		select {
		case <-blkup.ctx.Done():
			writeErr = ErrCanceled
		case result, readerRunning = <-resultChan:
			if !readerRunning {
				if blkup.ctx.Err() != nil {
					writeErr = ErrCanceled
				} else {
					writeErr = io.ErrUnexpectedEOF
				}
			}
		}

		if writeErr != nil {
			break
		}

		if result.err != nil {
			writeErr = result.err
			break
		}

		length := min(int64(blockSize), totalLength-result.offset)
		if bytes.Equal(result.buffer, zeroBlock) {
			if zeroStart == -1 {
				zeroStart = result.offset
				zeroLength = length
			} else if result.offset == zeroStart+zeroLength {
				zeroLength += length
			} else {
				if err := blkup.flushZeroBlocks(dest, zeroStart, zeroLength, zeroBlock, destPath); err != nil {
					writeErr = errors.Wrapf(err, "error flushing zero blocks from %v, length %v", zeroStart, zeroLength)
					break
				}
				zeroStart = result.offset
				zeroLength = length
			}
		} else {
			if zeroStart != -1 {
				if err := blkup.flushZeroBlocks(dest, zeroStart, zeroLength, zeroBlock, destPath); err != nil {
					writeErr = errors.Wrapf(err, "error flushing zero blocks from %v, length %v", zeroStart, zeroLength)
					break
				}

				zeroStart = -1
				zeroLength = 0
			}

			n, err := dest.WriteAt(result.buffer[:length], result.offset)
			if err != nil {
				writeErr = err
				break
			}

			if length != int64(n) {
				writeErr = io.ErrShortWrite
				break
			}
		}

		written += length
		curCount++

		result.resetBuffer(list)

		blkup.progress.UpdateProgress(&uploader.Progress{BytesDone: written, TotalBytes: totalLength})
	}

	result.resetBuffer(list)

	if writeErr != nil {
		return written, writeErr
	}

	if zeroStart != -1 {
		if err := blkup.flushZeroBlocks(dest, zeroStart, zeroLength, zeroBlock, destPath); err != nil {
			return written, errors.Wrapf(err, "error flushing zero blocks from %v, length %v", zeroStart, zeroLength)
		}
	}

	return written, nil
}

func (blkup *blockUploader) flushZeroBlocks(dest *os.File, start int64, length int64, zeroBlock []byte, destPath string) error {
	err := blkZeroOut(dest, start, length)
	if err == nil {
		return nil
	}

	blkup.log.WithError(err).Warnf("Failed to call zero out from dev %s, start %v, length %v. Fallback to conservative way", destPath, start, length)

	var written int64
	for written < length {
		writeSize := min(len(zeroBlock), int(length-written))

		n, err := dest.WriteAt(zeroBlock[:writeSize], start+written)
		if err != nil {
			return errors.Wrapf(err, "error writing zero buffer at %v, length %v", start+written, writeSize)
		}

		if writeSize != n {
			return errors.Wrapf(err, "short write zero buffer at %v, length %v", start+written, writeSize)
		}

		written += int64(writeSize)
	}

	return nil
}

func getSourceSize(snapshot udmrepo.Snapshot) (int64, error) {
	if snapshot.Tags == nil {
		return 0, errors.New("source size tag is empty")
	}

	s, found := snapshot.Tags[bdevSourceSizeTag]
	if !found {
		return 0, errors.New("source size tag is missing")
	}

	size, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, errors.Wrapf(err, "error parsing size from %s", s)
	}

	return size, nil
}

func loadObjectFromSnapshot(ctx context.Context, rep udmrepo.BackupRepo, snapshot *udmrepo.Snapshot) (udmrepo.ID, error) {
	if snapshot == nil {
		return "", errors.New("snapshot is empty")
	}

	meta, err := rep.ReadMetadata(ctx, snapshot.RootObject.ID)
	if err != nil {
		return "", errors.Wrapf(err, "error reading snapshot metadata for %s", snapshot.Description)
	}

	if len(meta.SubObjects) != 1 {
		return "", errors.Errorf("unexpected number of bdev object (%d) for snapshot %s", len(meta.SubObjects), snapshot.Description)
	}

	return meta.SubObjects[0].ID, nil
}
