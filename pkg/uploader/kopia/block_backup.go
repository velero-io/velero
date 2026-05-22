//go:build !windows

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
	"os"
	"syscall"

	"github.com/kopia/kopia/fs"
	"github.com/kopia/kopia/fs/virtualfs"
	"github.com/pkg/errors"
)

const ErrNotPermitted = "operation not permitted"

func getLocalBlockEntry(sourcePath string) (fs.Entry, error) {
	source, err := resolveSymlink(sourcePath)
	if err != nil {
		return nil, errors.Wrap(err, "resolveSymlink")
	}

	fileInfo, err := os.Lstat(source)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to get the source device information %s", source)
	}

	if (fileInfo.Sys().(*syscall.Stat_t).Mode & syscall.S_IFMT) != syscall.S_IFBLK {
		return nil, errors.Errorf("source path %s is not a block device", source)
	}

	device, err := os.Open(source)
	if err != nil {
		if os.IsPermission(err) || err.Error() == ErrNotPermitted {
			return nil, errors.Wrapf(err, "no permission to open the source device %s, make sure that node agent is running in privileged mode", source)
		}
		return nil, errors.Wrapf(err, "unable to open the source device %s", source)
	}

	sf := virtualfs.StreamingFileFromReader(source, device)
	return virtualfs.NewStaticDirectory(source, []fs.Entry{sf}), nil
}
