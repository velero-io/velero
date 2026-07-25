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
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kopia/kopia/fs"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeEntry struct {
	name  string
	mode  os.FileMode
	owner fs.OwnerInfo
}

func (e *fakeEntry) Name() string                { return e.name }
func (e *fakeEntry) Size() int64                 { return 0 }
func (e *fakeEntry) Mode() os.FileMode           { return e.mode }
func (e *fakeEntry) ModTime() time.Time          { return time.Time{} }
func (e *fakeEntry) IsDir() bool                 { return e.mode.IsDir() }
func (e *fakeEntry) Sys() any                    { return nil }
func (e *fakeEntry) Owner() fs.OwnerInfo         { return e.owner }
func (e *fakeEntry) Device() fs.DeviceInfo       { return fs.DeviceInfo{} }
func (e *fakeEntry) LocalFilesystemPath() string { return "" }
func (e *fakeEntry) Close()                      {}

type fakeDirectory struct {
	fakeEntry
	entries []fs.Entry
}

func (d *fakeDirectory) Child(ctx context.Context, name string) (fs.Entry, error) {
	return fs.IterateEntriesAndFindChild(ctx, d, name)
}

func (d *fakeDirectory) Iterate(ctx context.Context) (fs.DirectoryIterator, error) {
	return fs.StaticIterator(d.entries, nil), nil
}

func (d *fakeDirectory) SupportsMultipleIterations() bool { return true }

func TestVerifyRestoredAttrs(t *testing.T) {
	owner := fs.OwnerInfo{UserID: uint32(os.Getuid()), GroupID: uint32(os.Getgid())}
	otherOwner := fs.OwnerInfo{UserID: owner.UserID + 1, GroupID: owner.GroupID}

	writeFile := func(t *testing.T, path string, mode os.FileMode) {
		t.Helper()
		require.NoError(t, os.WriteFile(path, []byte("data"), mode))
		require.NoError(t, os.Chmod(path, mode))
	}

	type testCase struct {
		name          string
		setup         func(t *testing.T, dir string) fs.Entry
		expectedWarns []string
		expectedDebug string
	}

	testCases := []testCase{
		{
			name: "root entry is not a directory",
			setup: func(t *testing.T, dir string) fs.Entry {
				t.Helper()
				return &fakeEntry{name: "root", mode: 0o640, owner: owner}
			},
		},
		{
			name: "all attributes match",
			setup: func(t *testing.T, dir string) fs.Entry {
				t.Helper()
				writeFile(t, filepath.Join(dir, "file1"), 0o640)
				require.NoError(t, os.Mkdir(filepath.Join(dir, "sub"), 0o750))
				require.NoError(t, os.Chmod(filepath.Join(dir, "sub"), 0o750))
				writeFile(t, filepath.Join(dir, "sub", "file2"), 0o600)

				return &fakeDirectory{
					fakeEntry: fakeEntry{name: "root", mode: os.ModeDir | 0o755, owner: owner},
					entries: []fs.Entry{
						&fakeEntry{name: "file1", mode: 0o640, owner: owner},
						&fakeDirectory{
							fakeEntry: fakeEntry{name: "sub", mode: os.ModeDir | 0o750, owner: owner},
							entries: []fs.Entry{
								&fakeEntry{name: "file2", mode: 0o600, owner: owner},
							},
						},
					},
				}
			},
			expectedDebug: "Verified owner/permissions of 3 entries",
		},
		{
			name: "owner mismatch is detected and classified",
			setup: func(t *testing.T, dir string) fs.Entry {
				t.Helper()
				writeFile(t, filepath.Join(dir, "file1"), 0o640)

				return &fakeDirectory{
					fakeEntry: fakeEntry{name: "root", mode: os.ModeDir | 0o755, owner: owner},
					entries: []fs.Entry{
						&fakeEntry{name: "file1", mode: 0o640, owner: otherOwner},
					},
				}
			},
			expectedWarns: []string{
				"doesn't match the owner/permissions recorded in the snapshot",
				"1 of 1 checked entries with unexpected owner",
				fmt.Sprintf("file1: expected %d:%d 0640, actual %d:%d 0640", otherOwner.UserID, otherOwner.GroupID, owner.UserID, owner.GroupID),
				"chown",
			},
		},
		{
			name: "permission mismatch is detected and classified",
			setup: func(t *testing.T, dir string) fs.Entry {
				t.Helper()
				writeFile(t, filepath.Join(dir, "file1"), 0o644)

				return &fakeDirectory{
					fakeEntry: fakeEntry{name: "root", mode: os.ModeDir | 0o755, owner: owner},
					entries: []fs.Entry{
						&fakeEntry{name: "file1", mode: 0o600, owner: owner},
					},
				}
			},
			expectedWarns: []string{
				"1 with unexpected permissions",
				fmt.Sprintf("file1: expected %d:%d 0600, actual %d:%d 0644", owner.UserID, owner.GroupID, owner.UserID, owner.GroupID),
				"chmod succeeded when retried",
			},
		},
		{
			name: "missing and non-regular entries are skipped",
			setup: func(t *testing.T, dir string) fs.Entry {
				t.Helper()
				writeFile(t, filepath.Join(dir, "file1"), 0o640)

				return &fakeDirectory{
					fakeEntry: fakeEntry{name: "root", mode: os.ModeDir | 0o755, owner: owner},
					entries: []fs.Entry{
						&fakeEntry{name: "file1", mode: 0o640, owner: owner},
						&fakeEntry{name: "ghost", mode: 0o640, owner: otherOwner},
						&fakeEntry{name: "link", mode: os.ModeSymlink | 0o777, owner: otherOwner},
					},
				}
			},
			expectedDebug: "Verified owner/permissions of 1 entries",
		},
		{
			name: "verified entries are capped",
			setup: func(t *testing.T, dir string) fs.Entry {
				t.Helper()
				entries := []fs.Entry{}
				for i := range maxAttrVerifyEntries + 5 {
					name := fmt.Sprintf("file%d", i)
					writeFile(t, filepath.Join(dir, name), 0o640)
					entries = append(entries, &fakeEntry{name: name, mode: 0o640, owner: owner})
				}

				return &fakeDirectory{
					fakeEntry: fakeEntry{name: "root", mode: os.ModeDir | 0o755, owner: owner},
					entries:   entries,
				}
			},
			expectedDebug: fmt.Sprintf("Verified owner/permissions of %d entries", maxAttrVerifyEntries),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			rootEntry := tc.setup(t, dir)

			logger, hook := test.NewNullLogger()
			logger.SetLevel(logrus.DebugLevel)

			verifyRestoredAttrs(t.Context(), rootEntry, dir, logger)

			warns := []string{}
			debugs := []string{}
			for _, entry := range hook.AllEntries() {
				switch entry.Level {
				case logrus.WarnLevel:
					warns = append(warns, entry.Message)
				case logrus.DebugLevel:
					debugs = append(debugs, entry.Message)
				}
			}

			if len(tc.expectedWarns) == 0 {
				assert.Empty(t, warns)
			} else {
				require.Len(t, warns, 1)
				for _, expected := range tc.expectedWarns {
					assert.Contains(t, warns[0], expected)
				}
			}

			if tc.expectedDebug != "" {
				require.Len(t, debugs, 1)
				assert.Contains(t, debugs[0], tc.expectedDebug)
			}
		})
	}
}

func TestClassifyAttrMismatch(t *testing.T) {
	t.Run("chmod succeeds when retried", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "file1")
		require.NoError(t, os.WriteFile(path, []byte("data"), 0o644))

		verdict := classifyAttrMismatch(&attrMismatch{localPath: path, mode: 0o600})

		assert.Equal(t, "chmod succeeded when retried", verdict)

		st, err := os.Lstat(path)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), st.Mode()&fs.ModBits)
	})

	t.Run("chmod is rejected on a missing file", func(t *testing.T) {
		verdict := classifyAttrMismatch(&attrMismatch{localPath: filepath.Join(t.TempDir(), "missing"), mode: 0o600})

		assert.Contains(t, verdict, "chmod is rejected by the volume")
	})
}

func TestModeOctal(t *testing.T) {
	assert.Equal(t, uint32(0o640), modeOctal(0o640))
	assert.Equal(t, uint32(0o4755), modeOctal(os.ModeSetuid|0o755))
	assert.Equal(t, uint32(0o2750), modeOctal(os.ModeSetgid|0o750))
	assert.Equal(t, uint32(0o1777), modeOctal(os.ModeSticky|0o777))
}
