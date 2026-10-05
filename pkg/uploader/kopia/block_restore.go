//go:build !windows
// +build !windows

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

package kopia

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/cockroachdb/errors"
	"github.com/kopia/kopia/fs"
	"github.com/kopia/kopia/snapshot/restore"
)

type BlockOutput struct {
	*restore.FilesystemOutput

	targetFileName string
	targetFile     *os.File
}

var _ restore.Output = &BlockOutput{}

const bufferSize = 128 * 1024

func (o *BlockOutput) WriteFile(ctx context.Context, relativePath string, remoteFile fs.File, progressCb restore.FileWriteProgress) error {
	remoteReader, err := remoteFile.Open(ctx)
	if err != nil {
		return errors.Wrapf(err, "failed to open remote file %s", remoteFile.Name())
	}
	defer remoteReader.Close()

	targetFile, err := os.Create(o.targetFileName)
	if err != nil {
		return errors.Wrapf(err, "failed to open file %s", o.targetFileName)
	}
	o.targetFile = targetFile

	buffer := make([]byte, bufferSize)

	readData := true
	for readData {
		bytesToWrite, err := remoteReader.Read(buffer)
		if err != nil {
			if err != io.EOF {
				return errors.Wrapf(err, "failed to read data from remote file %s", o.targetFileName)
			}
			readData = false
		}

		if bytesToWrite > 0 {
			offset := 0
			for bytesToWrite > 0 {
				if bytesWritten, err := targetFile.Write(buffer[offset:bytesToWrite]); err == nil {
					progressCb(int64(bytesWritten))
					bytesToWrite -= bytesWritten
					offset += bytesWritten
				} else {
					return errors.Wrapf(err, "failed to write data to file %s", o.targetFileName)
				}
			}
		}
	}

	return nil
}

func (o *BlockOutput) BeginDirectory(ctx context.Context, relativePath string, e fs.Directory) error {
	var err error
	o.targetFileName, err = filepath.EvalSymlinks(o.TargetPath)
	if err != nil {
		return errors.Wrapf(err, "unable to evaluate symlinks for %s", o.targetFileName)
	}

	fileInfo, err := os.Lstat(o.targetFileName)
	if err != nil {
		return errors.Wrapf(err, "unable to get the target device information for %s", o.TargetPath)
	}

	if (fileInfo.Sys().(*syscall.Stat_t).Mode & syscall.S_IFMT) != syscall.S_IFBLK {
		return errors.Errorf("target file %s is not a block device", o.TargetPath)
	}

	return nil
}

func (o *BlockOutput) Flush() error {
	if o.targetFile != nil {
		if err := o.targetFile.Sync(); err != nil {
			return errors.Wrapf(err, "error syncing block dev %v", o.targetFileName)
		}
	}

	return nil
}

func (o *BlockOutput) Terminate() error {
	if o.targetFile != nil {
		if err := o.targetFile.Close(); err != nil {
			return errors.Wrapf(err, "error closing block dev %v", o.targetFileName)
		}
	}

	return nil
}
