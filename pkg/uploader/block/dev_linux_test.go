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
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

type fakeBlockDevFileInfo struct{}

func (fakeBlockDevFileInfo) Name() string       { return "fake-blk" }
func (fakeBlockDevFileInfo) Size() int64        { return 0 }
func (fakeBlockDevFileInfo) Mode() os.FileMode  { return os.ModeDevice }
func (fakeBlockDevFileInfo) ModTime() time.Time { return time.Time{} }
func (fakeBlockDevFileInfo) IsDir() bool        { return false }
func (fakeBlockDevFileInfo) Sys() any {
	return &syscall.Stat_t{Mode: syscall.S_IFBLK}
}

func TestResolveSymlink(t *testing.T) {
	testCases := []struct {
		name        string
		setupPath   func(t *testing.T) string
		expectError bool
		errContains string
		checkResult func(t *testing.T, input, result string)
	}{
		{
			name: "path does not exist returns error",
			setupPath: func(t *testing.T) string {
				t.Helper()
				return filepath.Join(t.TempDir(), "nonexistent")
			},
			expectError: true,
			errContains: "stat",
		},
		{
			name: "regular file returns same path",
			setupPath: func(t *testing.T) string {
				t.Helper()
				f, err := os.CreateTemp(t.TempDir(), "regular-*")
				require.NoError(t, err)
				f.Close()
				return f.Name()
			},
			checkResult: func(t *testing.T, input, result string) {
				t.Helper()
				assert.Equal(t, input, result)
			},
		},
		{
			name: "directory returns same path",
			setupPath: func(t *testing.T) string {
				t.Helper()
				return t.TempDir()
			},
			checkResult: func(t *testing.T, input, result string) {
				t.Helper()
				assert.Equal(t, input, result)
			},
		},
		{
			name: "symlink to existing file returns target real path",
			setupPath: func(t *testing.T) string {
				t.Helper()
				dir := t.TempDir()
				target, err := os.CreateTemp(dir, "target-*")
				require.NoError(t, err)
				target.Close()
				linkPath := filepath.Join(dir, "link")
				require.NoError(t, os.Symlink(target.Name(), linkPath))
				return linkPath
			},
			checkResult: func(t *testing.T, input, result string) {
				t.Helper()
				assert.NotEqual(t, input, result)
				fi, err := os.Lstat(result)
				require.NoError(t, err)
				assert.Zero(t, fi.Mode()&os.ModeSymlink)
			},
		},
		{
			name: "symlink to existing directory returns resolved path",
			setupPath: func(t *testing.T) string {
				t.Helper()
				outer := t.TempDir()
				inner := t.TempDir()
				linkPath := filepath.Join(outer, "dirlink")
				require.NoError(t, os.Symlink(inner, linkPath))
				return linkPath
			},
			checkResult: func(t *testing.T, input, result string) {
				t.Helper()
				assert.NotEqual(t, input, result)
				fi, err := os.Lstat(result)
				require.NoError(t, err)
				assert.True(t, fi.IsDir())
			},
		},
		{
			name: "broken symlink — target does not exist — returns error",
			setupPath: func(t *testing.T) string {
				t.Helper()
				dir := t.TempDir()
				linkPath := filepath.Join(dir, "broken-link")
				require.NoError(t, os.Symlink(filepath.Join(dir, "nonexistent-target"), linkPath))
				return linkPath
			},
			expectError: true,
			errContains: "no such file or directory",
		},
		{
			name: "chain of symlinks is fully resolved",
			setupPath: func(t *testing.T) string {
				t.Helper()
				dir := t.TempDir()
				// real → link1 → link2 (two-hop chain)
				real, err := os.CreateTemp(dir, "real-*")
				require.NoError(t, err)
				real.Close()
				link1 := filepath.Join(dir, "link1")
				require.NoError(t, os.Symlink(real.Name(), link1))
				link2 := filepath.Join(dir, "link2")
				require.NoError(t, os.Symlink(link1, link2))
				return link2
			},
			checkResult: func(t *testing.T, input, result string) {
				t.Helper()
				assert.NotEqual(t, input, result)
				fi, err := os.Lstat(result)
				require.NoError(t, err)
				assert.Zero(t, fi.Mode()&os.ModeSymlink)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			input := tc.setupPath(t)
			result, err := resolveSymlink(input)

			if tc.expectError {
				require.Error(t, err)
				if tc.errContains != "" {
					require.ErrorContains(t, err, tc.errContains)
				}
				assert.Empty(t, result)
			} else {
				require.NoError(t, err)
				if tc.checkResult != nil {
					tc.checkResult(t, input, result)
				}
			}
		})
	}
}

func TestOpenBlockDevice(t *testing.T) {
	testCases := []struct {
		name           string
		setupPath      func(t *testing.T) string
		read           bool
		expectError    bool
		errContains    string
		injectLstat    func(string) (os.FileInfo, error)
		injectOpenFile func(string, int, os.FileMode) (*os.File, error)
	}{
		{
			name: "path does not exist — resolveSymlink fails",
			setupPath: func(t *testing.T) string {
				t.Helper()
				return filepath.Join(t.TempDir(), "nonexistent")
			},
			read:        true,
			expectError: true,
			errContains: "resolveSymlink",
		},
		{
			name: "regular file is not a block device — read mode",
			setupPath: func(t *testing.T) string {
				t.Helper()
				f, err := os.CreateTemp(t.TempDir(), "regular-*")
				require.NoError(t, err)
				f.Close()
				return f.Name()
			},
			read:        true,
			expectError: true,
			errContains: "is not a block device",
		},
		{
			name: "regular file is not a block device — write mode",
			setupPath: func(t *testing.T) string {
				t.Helper()
				f, err := os.CreateTemp(t.TempDir(), "regular-*")
				require.NoError(t, err)
				f.Close()
				return f.Name()
			},
			read:        false,
			expectError: true,
			errContains: "is not a block device",
		},
		{
			name: "directory is not a block device",
			setupPath: func(t *testing.T) string {
				t.Helper()
				return t.TempDir()
			},
			read:        true,
			expectError: true,
			errContains: "is not a block device",
		},
		{
			name: "symlink to regular file is not a block device",
			setupPath: func(t *testing.T) string {
				t.Helper()
				dir := t.TempDir()
				target, err := os.CreateTemp(dir, "target-*")
				require.NoError(t, err)
				target.Close()
				linkPath := filepath.Join(dir, "link")
				require.NoError(t, os.Symlink(target.Name(), linkPath))
				return linkPath
			},
			read:        true,
			expectError: true,
			errContains: "is not a block device",
		},
		{
			name: "broken symlink — resolveSymlink fails",
			setupPath: func(t *testing.T) string {
				t.Helper()
				dir := t.TempDir()
				linkPath := filepath.Join(dir, "broken-link")
				require.NoError(t, os.Symlink(filepath.Join(dir, "ghost"), linkPath))
				return linkPath
			},
			read:        true,
			expectError: true,
			errContains: "resolveSymlink",
		},
		{
			name: "EACCES from OpenFile — permission denied message",
			setupPath: func(t *testing.T) string {
				t.Helper()
				f, err := os.CreateTemp(t.TempDir(), "blk-*")
				require.NoError(t, err)
				f.Close()
				return f.Name()
			},
			read:        true,
			expectError: true,
			errContains: "no permission to open device",
			injectLstat: func(_ string) (os.FileInfo, error) {
				return fakeBlockDevFileInfo{}, nil
			},
			injectOpenFile: func(name string, _ int, _ os.FileMode) (*os.File, error) {
				t.Helper()
				return nil, &os.PathError{Op: "open", Path: name, Err: syscall.EACCES}
			},
		},
		{
			name: "EPERM from OpenFile — permission denied message",
			setupPath: func(t *testing.T) string {
				t.Helper()
				f, err := os.CreateTemp(t.TempDir(), "blk-*")
				require.NoError(t, err)
				f.Close()
				return f.Name()
			},
			read:        false,
			expectError: true,
			errContains: "no permission to open device",
			injectLstat: func(_ string) (os.FileInfo, error) {
				return fakeBlockDevFileInfo{}, nil
			},
			injectOpenFile: func(name string, _ int, _ os.FileMode) (*os.File, error) {
				return nil, &os.PathError{Op: "open", Path: name, Err: syscall.EPERM}
			},
		},
		{
			name: "generic OpenFile error — unable to open device message",
			setupPath: func(t *testing.T) string {
				t.Helper()
				f, err := os.CreateTemp(t.TempDir(), "blk-*")
				require.NoError(t, err)
				f.Close()
				return f.Name()
			},
			read:        true,
			expectError: true,
			errContains: "unable to open device",
			injectLstat: func(_ string) (os.FileInfo, error) {
				t.Helper()
				return fakeBlockDevFileInfo{}, nil
			},
			injectOpenFile: func(name string, _ int, _ os.FileMode) (*os.File, error) {
				t.Helper()
				return nil, &os.PathError{Op: "open", Path: name, Err: syscall.EIO}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Cleanup(func() {
				lstatFunc = os.Lstat
				openFileFunc = os.OpenFile
			})
			if tc.injectLstat != nil {
				lstatFunc = tc.injectLstat
			}
			if tc.injectOpenFile != nil {
				openFileFunc = tc.injectOpenFile
			}

			path := tc.setupPath(t)
			f, err := openBlockDevice(path, tc.read)

			if tc.expectError {
				require.Error(t, err)
				if tc.errContains != "" {
					require.ErrorContains(t, err, tc.errContains)
				}
				assert.Nil(t, f)
			} else {
				require.NoError(t, err)
				require.NotNil(t, f)
				f.Close()
			}
		})
	}
}

func TestBlkZeroOut(t *testing.T) {
	t.Run("closed file returns error", func(t *testing.T) {
		f, err := os.CreateTemp(t.TempDir(), "blkzeroout-test-*")
		require.NoError(t, err)
		err = f.Close()
		require.NoError(t, err)

		err = blkZeroOut(f, 0, 1024)
		assert.Error(t, err)
	})

	t.Run("regular file returns ioctl error", func(t *testing.T) {
		f, err := os.CreateTemp(t.TempDir(), "blkzeroout-test-*")
		require.NoError(t, err)
		defer f.Close()

		err = blkZeroOut(f, 0, 1024)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "error calling ioctl on block dev")

		// On regular files, ioctl with BLKZEROOUT should fail with ENOTTY (inappropriate ioctl for device) or EINVAL
		isENOTTY := errors.Is(err, syscall.ENOTTY)
		isEINVAL := errors.Is(err, syscall.EINVAL)
		assert.True(t, isENOTTY || isEINVAL, "expected error to be ENOTTY or EINVAL, got: %v", err)
	})

	t.Run("loop device range is zeroed", func(t *testing.T) {
		const (
			devSize   = 4 << 20
			zeroStart = 1 << 20
			zeroLen   = 1 << 20
		)

		devPath := setupLoopDevice(t, devSize, 0xab)

		dev, err := openBlockDevice(devPath, false)
		require.NoError(t, err)
		defer dev.Close()

		require.NoError(t, blkZeroOut(dev, zeroStart, zeroLen))

		// Read back without O_DIRECT, BLKZEROOUT invalidates the page cache of the range
		data, err := os.ReadFile(devPath)
		require.NoError(t, err)
		require.Len(t, data, devSize)

		assert.Equal(t, bytes.Repeat([]byte{0xab}, zeroStart), data[:zeroStart], "data before the range is changed")
		assert.Equal(t, make([]byte, zeroLen), data[zeroStart:zeroStart+zeroLen], "range is not zeroed")
		assert.Equal(t, bytes.Repeat([]byte{0xab}, devSize-zeroStart-zeroLen), data[zeroStart+zeroLen:], "data after the range is changed")
	})
}

func TestBlkZeroOutIoctl(t *testing.T) {
	// BLKZEROOUT is _IO(0x12, 127), only the direction bits vary by arch
	assert.Equal(t, uint32(0x12), uint32(blkZeroOutIoctl>>8)&0xff, "ioctl type")
	assert.Equal(t, uint32(127), uint32(blkZeroOutIoctl)&0xff, "ioctl number")
}

// setupLoopDevice attaches a loop device backed by a file of the given size filled with fill,
// the test is skipped if loop devices are not available
func setupLoopDevice(t *testing.T, size int, fill byte) string {
	t.Helper()

	if os.Geteuid() != 0 {
		t.Skip("loop device setup requires root")
	}

	ctl, err := os.OpenFile("/dev/loop-control", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("loop device is not available: %v", err)
	}
	defer ctl.Close()

	backing, err := os.CreateTemp(t.TempDir(), "blkzeroout-loop-*")
	require.NoError(t, err)
	defer backing.Close()

	_, err = backing.Write(bytes.Repeat([]byte{fill}, size))
	require.NoError(t, err)
	require.NoError(t, backing.Sync())

	num, err := unix.IoctlRetInt(int(ctl.Fd()), unix.LOOP_CTL_GET_FREE)
	if err != nil {
		t.Skipf("unable to get free loop device: %v", err)
	}

	devPath := fmt.Sprintf("/dev/loop%d", num)
	if _, err := os.Stat(devPath); os.IsNotExist(err) {
		// Containers may not have the device node, create it on our own
		devPath = filepath.Join(t.TempDir(), fmt.Sprintf("loop%d", num))
		if err := unix.Mknod(devPath, unix.S_IFBLK|0600, int(unix.Mkdev(7, uint32(num)))); err != nil {
			t.Skipf("unable to create loop device node %s: %v", devPath, err)
		}
	}

	loop, err := os.OpenFile(devPath, os.O_RDWR, 0)
	if err != nil {
		t.Skipf("unable to open loop device %s: %v", devPath, err)
	}

	require.NoError(t, unix.IoctlSetInt(int(loop.Fd()), unix.LOOP_SET_FD, int(backing.Fd())))
	t.Cleanup(func() {
		_ = unix.IoctlSetInt(int(loop.Fd()), unix.LOOP_CLR_FD, 0)
		loop.Close()
	})

	return devPath
}
