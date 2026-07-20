//go:build linux
// +build linux

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
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"github.com/cockroachdb/errors"
)

var lstatFunc = os.Lstat
var openFileFunc = os.OpenFile

// openBlockDevice opens a block device for read/write, caller needs to close the returned handle
func openBlockDevice(path string, read bool) (*os.File, error) {
	devPath, err := resolveSymlink(path)
	if err != nil {
		return nil, errors.Wrap(err, "resolveSymlink")
	}

	fileInfo, err := lstatFunc(devPath)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to get the device information %s", devPath)
	}

	if (fileInfo.Sys().(*syscall.Stat_t).Mode & syscall.S_IFMT) != syscall.S_IFBLK {
		return nil, errors.Errorf("path %s is not a block device", devPath)
	}

	flag := os.O_RDWR
	mode := os.FileMode(0666)
	if read {
		flag = os.O_RDONLY
		mode = 0
	}

	device, err := openFileFunc(devPath, flag|syscall.O_DIRECT, mode)
	if err != nil {
		if os.IsPermission(err) || errors.Is(err, syscall.EPERM) {
			return nil, errors.Wrapf(err, "no permission to open device %s with mode %v", devPath, mode)
		}
		return nil, errors.Wrapf(err, "unable to open device %s", devPath)
	}

	return device, nil
}

func resolveSymlink(path string) (string, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return "", errors.Wrap(err, "stat")
	}

	if (st.Mode() & os.ModeSymlink) == 0 {
		return path, nil
	}

	return filepath.EvalSymlinks(path)
}

func blkZeroOut(dest *os.File, start int64, length int64) error {
	const BLKZEROOUT = 0x127b

	zeroRange := [2]uint64{uint64(start), uint64(length)}

	rawConn, err := dest.SyscallConn()
	if err != nil {
		return errors.Wrap(err, "error getting raw connection")
	}

	ioctlErr := syscall.Errno(0)
	if err := rawConn.Control(func(fd uintptr) {
		if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, BLKZEROOUT, uintptr(unsafe.Pointer(&zeroRange[0]))); errno != 0 {
			ioctlErr = errno
		}
	}); err != nil {
		return errors.Wrap(err, "error controlling block dev")
	}

	if ioctlErr != 0 {
		return errors.Wrapf(ioctlErr, "error calling ioctl on block dev")
	}

	return nil
}
