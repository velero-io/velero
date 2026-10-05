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
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
}
