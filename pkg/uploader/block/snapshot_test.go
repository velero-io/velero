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

// Tests live in package block (not block_test) so they can access unexported
// types sourceInfo and destInfo, which appear in the Uploader interface.
package block

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/vmware-tanzu/velero/pkg/cbtservice"
	"github.com/vmware-tanzu/velero/pkg/repository/udmrepo"
	udmrepomocks "github.com/vmware-tanzu/velero/pkg/repository/udmrepo/mocks"
	"github.com/vmware-tanzu/velero/pkg/uploader"
	cbttypes "github.com/vmware-tanzu/velero/pkg/uploader/cbt/types"
)

type mockUploader struct {
	mock.Mock
}

func (m *mockUploader) Backup(src sourceInfo, parent udmrepo.ID, iter cbttypes.Iterator, cfg map[string]string) (udmrepo.Snapshot, int64, error) {
	args := m.Called(src, parent, iter, cfg)
	return args.Get(0).(udmrepo.Snapshot), args.Get(1).(int64), args.Error(2)
}

func (m *mockUploader) Restore(snap udmrepo.Snapshot, dest destInfo, iter cbttypes.Iterator, cfg map[string]string) (int64, error) {
	args := m.Called(snap, dest, iter, cfg)
	return args.Get(0).(int64), args.Error(1)
}

func testLog() logrus.FieldLogger {
	l := logrus.New()
	l.SetLevel(logrus.DebugLevel)
	return l
}

func tempFile(t *testing.T, content string) *os.File {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "blktest-*")
	require.NoError(t, err)
	if content != "" {
		_, err = f.WriteString(content)
		require.NoError(t, err)
	}
	t.Cleanup(func() {
		f.Close()
		os.Remove(f.Name())
	})
	return f
}

func TestBackup(t *testing.T) {
	testCases := []struct {
		name           string
		useNilBlkup    bool
		setupOpenDev   func(t *testing.T) *os.File
		setupMocks     func(blkup *mockUploader, repo *udmrepomocks.BackupRepo)
		expectedErrStr string
		checkInfo      func(*testing.T, uploader.SnapshotInfo)
	}{
		{
			name:           "nil uploader returns error",
			useNilBlkup:    true,
			expectedErrStr: "get empty block uploader",
		},
		{
			name:           "openBlockDevice error",
			expectedErrStr: "error opening block device",
		},
		{
			name: "SnapshotSource error propagates",
			setupOpenDev: func(t *testing.T) *os.File {
				t.Helper()
				return tempFile(t, "")
			},
			setupMocks: func(blkup *mockUploader, _ *udmrepomocks.BackupRepo) {
				blkup.On("Backup", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(udmrepo.Snapshot{}, int64(0), errors.New("I/O error"))
			},
			expectedErrStr: "Failed to run uploader backup",
		},
		{
			name: "success returns correct SnapshotInfo",
			setupOpenDev: func(t *testing.T) *os.File {
				t.Helper()
				return tempFile(t, "test-block-data")
			},
			setupMocks: func(blkup *mockUploader, repo *udmrepomocks.BackupRepo) {
				blkup.On("Backup", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(udmrepo.Snapshot{RootObject: udmrepo.ObjectMetadata{ID: "root"}}, int64(8), nil)
				repo.On("SaveSnapshot", mock.Anything, mock.Anything).Return(udmrepo.ID("snap-001"), nil)
				repo.On("Flush", mock.Anything).Return(nil)
			},
			checkInfo: func(t *testing.T, info uploader.SnapshotInfo) {
				t.Helper()
				assert.Equal(t, "snap-001", info.ID)
				assert.Equal(t, int64(8), info.IncrementalSize)
				assert.Positive(t, info.Size)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			mockBlkup := &mockUploader{}
			mockRepo := udmrepomocks.NewBackupRepo(t)

			var blkup Uploader
			if !tc.useNilBlkup {
				blkup = mockBlkup
			}

			if tc.setupOpenDev != nil {
				f := tc.setupOpenDev(t)
				openBlockDeviceFunc = func(_ string, _ bool) (*os.File, error) {
					return f, nil
				}
			} else {
				openBlockDeviceFunc = func(_ string, _ bool) (*os.File, error) {
					return nil, errors.New("device not available")
				}
			}

			if tc.setupMocks != nil {
				tc.setupMocks(mockBlkup, mockRepo)
			}

			info, isEmpty, err := Backup(
				ctx, blkup, mockRepo,
				"/dev/sda", "",
				cbtservice.SourceInfo{},
				true, "", nil,
				map[string]string{}, map[string]string{},
				testLog(),
			)

			if tc.expectedErrStr != "" {
				require.Error(t, err)
				require.ErrorContains(t, err, tc.expectedErrStr)
			} else {
				require.NoError(t, err)
				assert.False(t, isEmpty)
			}

			if tc.checkInfo != nil {
				tc.checkInfo(t, info)
			}

			mockBlkup.AssertExpectations(t)
		})
	}
}

func TestSnapshotSource(t *testing.T) {
	baseSource := sourceInfo{realSource: "/test/vol", size: 1024}

	testCases := []struct {
		name           string
		setupMocks     func(blkup *mockUploader, repo *udmrepomocks.BackupRepo)
		expectedErrStr string
		expectedSnapID string
		expectedSize   int64
	}{
		{
			name: "uploader Backup error",
			setupMocks: func(blkup *mockUploader, _ *udmrepomocks.BackupRepo) {
				blkup.On("Backup", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(udmrepo.Snapshot{}, int64(0), errors.New("uploader error"))
			},
			expectedErrStr: "Failed to run uploader backup",
		},
		{
			name: "SaveSnapshot error",
			setupMocks: func(blkup *mockUploader, repo *udmrepomocks.BackupRepo) {
				blkup.On("Backup", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(udmrepo.Snapshot{}, int64(0), nil)
				repo.On("SaveSnapshot", mock.Anything, mock.Anything).
					Return(udmrepo.ID(""), errors.New("save failed"))
			},
			expectedErrStr: "Failed to save snapshot",
		},
		{
			name: "Flush error",
			setupMocks: func(blkup *mockUploader, repo *udmrepomocks.BackupRepo) {
				blkup.On("Backup", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(udmrepo.Snapshot{}, int64(0), nil)
				repo.On("SaveSnapshot", mock.Anything, mock.Anything).Return(udmrepo.ID("snap-001"), nil)
				repo.On("Flush", mock.Anything).Return(errors.New("flush failed"))
			},
			expectedErrStr: "Failed to flush repository",
		},
		{
			name: "success with nil cbtService falls back to full bitmap",
			setupMocks: func(blkup *mockUploader, repo *udmrepomocks.BackupRepo) {
				blkup.On("Backup", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(udmrepo.Snapshot{RootObject: udmrepo.ObjectMetadata{ID: "root"}}, int64(512), nil)
				repo.On("SaveSnapshot", mock.Anything, mock.Anything).Return(udmrepo.ID("snap-success"), nil)
				repo.On("Flush", mock.Anything).Return(nil)
			},
			expectedSnapID: "snap-success",
			expectedSize:   512,
		},
		{
			name: "tags from cbtSource and snapshotTags are merged onto snapshot",
			setupMocks: func(blkup *mockUploader, repo *udmrepomocks.BackupRepo) {
				blkup.On("Backup", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(udmrepo.Snapshot{}, int64(0), nil)
				repo.On("SaveSnapshot", mock.Anything, mock.MatchedBy(func(snap udmrepo.Snapshot) bool {
					return snap.Tags[uploader.CBTChangeIDTag] == "cid-1" &&
						snap.Tags[uploader.CBTVolumeIDTag] == "vid-1" &&
						snap.Tags["custom"] == "val" &&
						snap.Description == "Block Uploader"
				})).Return(udmrepo.ID("snap-tags"), nil)
				repo.On("Flush", mock.Anything).Return(nil)
			},
			expectedSnapID: "snap-tags",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			mockBlkup := &mockUploader{}
			mockRepo := udmrepomocks.NewBackupRepo(t)

			tc.setupMocks(mockBlkup, mockRepo)

			cbtSrc := cbtservice.SourceInfo{ChangeID: "cid-1", VolumeID: "vid-1"}
			snapshotTags := map[string]string{"custom": "val"}

			snapID, size, err := snapshotSource(
				ctx, mockRepo, mockBlkup,
				baseSource,
				true, "",
				cbtSrc, nil,
				snapshotTags, map[string]string{},
				testLog(), "Block Uploader",
			)

			if tc.expectedErrStr != "" {
				require.Error(t, err)
				require.ErrorContains(t, err, tc.expectedErrStr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedSnapID, snapID)
				assert.Equal(t, tc.expectedSize, size)
			}

			mockBlkup.AssertExpectations(t)
		})
	}
}

func TestGetParentBackupInfo(t *testing.T) {
	const volumeID = "vol-123"
	const realSource = "/test/source"

	snapshotTags := map[string]string{
		uploader.SnapshotRequesterTag: "test-requester",
		uploader.SnapshotUploaderTag:  uploader.BlockType,
	}

	validSnap := udmrepo.Snapshot{
		RootObject: udmrepo.ObjectMetadata{ID: "root-obj"},
		Tags: map[string]string{
			uploader.CBTChangeIDTag:       "cid-abc",
			uploader.CBTVolumeIDTag:       volumeID,
			uploader.SnapshotRequesterTag: "test-requester",
			uploader.SnapshotUploaderTag:  uploader.BlockType,
		},
	}

	testCases := []struct {
		name           string
		forceFull      bool
		parentSnapshot string
		setupMocks     func(repo *udmrepomocks.BackupRepo)
		expectEmpty    bool
		expectedParent udmrepo.ID
		expectedCID    string
		expectedVID    string
	}{
		{
			name:        "forceFull skips all parent lookup",
			forceFull:   true,
			expectEmpty: true,
		},
		{
			name:           "GetSnapshot fails — falls back to full",
			parentSnapshot: "snap-parent",
			setupMocks: func(repo *udmrepomocks.BackupRepo) {
				repo.On("GetSnapshot", mock.Anything, udmrepo.ID("snap-parent")).
					Return(udmrepo.Snapshot{}, errors.New("not found"))
			},
			expectEmpty: true,
		},
		{
			name:           "parent snapshot has nil tags — falls back to full",
			parentSnapshot: "snap-notags",
			setupMocks: func(repo *udmrepomocks.BackupRepo) {
				repo.On("GetSnapshot", mock.Anything, udmrepo.ID("snap-notags")).
					Return(udmrepo.Snapshot{Tags: nil}, nil)
			},
			expectEmpty: true,
		},
		{
			name:           "parent snapshot missing ChangeID tag — falls back to full",
			parentSnapshot: "snap-nocid",
			setupMocks: func(repo *udmrepomocks.BackupRepo) {
				repo.On("GetSnapshot", mock.Anything, udmrepo.ID("snap-nocid")).
					Return(udmrepo.Snapshot{Tags: map[string]string{uploader.CBTVolumeIDTag: volumeID}}, nil)
			},
			expectEmpty: true,
		},
		{
			name:           "parent snapshot missing VolumeID tag — falls back to full",
			parentSnapshot: "snap-novid",
			setupMocks: func(repo *udmrepomocks.BackupRepo) {
				repo.On("GetSnapshot", mock.Anything, udmrepo.ID("snap-novid")).
					Return(udmrepo.Snapshot{Tags: map[string]string{uploader.CBTChangeIDTag: "cid"}}, nil)
			},
			expectEmpty: true,
		},
		{
			name:           "parent snapshot VolumeID mismatch — falls back to full",
			parentSnapshot: "snap-vidmismatch",
			setupMocks: func(repo *udmrepomocks.BackupRepo) {
				repo.On("GetSnapshot", mock.Anything, udmrepo.ID("snap-vidmismatch")).
					Return(udmrepo.Snapshot{Tags: map[string]string{
						uploader.CBTChangeIDTag: "cid",
						uploader.CBTVolumeIDTag: "different-vol",
					}}, nil)
			},
			expectEmpty: true,
		},
		{
			name:           "valid parent snapshot — returns parent info",
			parentSnapshot: "snap-valid",
			setupMocks: func(repo *udmrepomocks.BackupRepo) {
				repo.On("GetSnapshot", mock.Anything, udmrepo.ID("snap-valid")).
					Return(validSnap, nil)
				repo.On("ReadMetadata", mock.Anything, udmrepo.ID("root-obj")).
					Return(&udmrepo.Metadata{SubObjects: []udmrepo.ObjectMetadata{{ID: "root-obj"}}}, nil)
			},
			expectedParent: "root-obj",
			expectedCID:    "cid-abc",
			expectedVID:    volumeID,
		},
		{
			name: "no parentSnapshot — ListSnapshot fails — falls back to full",
			setupMocks: func(repo *udmrepomocks.BackupRepo) {
				repo.On("ListSnapshot", mock.Anything, realSource).
					Return(nil, errors.New("list error"))
			},
			expectEmpty: true,
		},
		{
			name: "no parentSnapshot — no matching snapshot — falls back to full",
			setupMocks: func(repo *udmrepomocks.BackupRepo) {
				repo.On("ListSnapshot", mock.Anything, realSource).
					Return([]udmrepo.Snapshot{{Tags: map[string]string{"other": "tag"}}}, nil)
			},
			expectEmpty: true,
		},
		{
			name: "no parentSnapshot — matching snapshot found — returns parent info",
			setupMocks: func(repo *udmrepomocks.BackupRepo) {
				repo.On("ListSnapshot", mock.Anything, realSource).
					Return([]udmrepo.Snapshot{validSnap}, nil)
				repo.On("ReadMetadata", mock.Anything, udmrepo.ID("root-obj")).
					Return(&udmrepo.Metadata{SubObjects: []udmrepo.ObjectMetadata{{ID: "root-obj"}}}, nil)
			},
			expectedParent: "root-obj",
			expectedCID:    "cid-abc",
			expectedVID:    volumeID,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			mockRepo := udmrepomocks.NewBackupRepo(t)

			if tc.setupMocks != nil {
				tc.setupMocks(mockRepo)
			}

			info := getParentBackupInfo(ctx, mockRepo, tc.forceFull, tc.parentSnapshot, volumeID, realSource, snapshotTags, testLog())

			if tc.expectEmpty {
				assert.Empty(t, info.parentObject)
				assert.Empty(t, info.changeID)
				assert.Empty(t, info.volumeID)
			} else {
				assert.Equal(t, tc.expectedParent, info.parentObject)
				assert.Equal(t, tc.expectedCID, info.changeID)
				assert.Equal(t, tc.expectedVID, info.volumeID)
			}
		})
	}
}

func TestFindPreviousSnapshot(t *testing.T) {
	snapshotTags := map[string]string{
		uploader.SnapshotRequesterTag: "test-requester",
		uploader.SnapshotUploaderTag:  uploader.BlockType,
	}

	matchingSnap := func(id string, start time.Time) udmrepo.Snapshot {
		return udmrepo.Snapshot{
			RootObject: udmrepo.ObjectMetadata{ID: udmrepo.ID(id)},
			StartTime:  start,
			Tags: map[string]string{
				uploader.SnapshotRequesterTag: "test-requester",
				uploader.SnapshotUploaderTag:  uploader.BlockType,
			},
		}
	}

	testCases := []struct {
		name           string
		setupMocks     func(repo *udmrepomocks.BackupRepo)
		expectedErrStr string
		expectedID     string
	}{
		{
			name: "ListSnapshot error",
			setupMocks: func(repo *udmrepomocks.BackupRepo) {
				repo.On("ListSnapshot", mock.Anything, "source").
					Return(nil, errors.New("list error"))
			},
			expectedErrStr: "error list snapshots",
		},
		{
			name: "empty snapshot list — no match",
			setupMocks: func(repo *udmrepomocks.BackupRepo) {
				repo.On("ListSnapshot", mock.Anything, "source").
					Return([]udmrepo.Snapshot{}, nil)
			},
			expectedErrStr: "no matching snapshot found",
		},
		{
			name: "snapshots without matching tags are filtered",
			setupMocks: func(repo *udmrepomocks.BackupRepo) {
				repo.On("ListSnapshot", mock.Anything, "source").
					Return([]udmrepo.Snapshot{
						{Tags: map[string]string{"unrelated": "tag"}},
						{Tags: nil},
					}, nil)
			},
			expectedErrStr: "no matching snapshot found",
		},
		{
			name: "snapshot with wrong requester tag is filtered",
			setupMocks: func(repo *udmrepomocks.BackupRepo) {
				repo.On("ListSnapshot", mock.Anything, "source").
					Return([]udmrepo.Snapshot{{
						Tags: map[string]string{
							uploader.SnapshotRequesterTag: "other-requester",
							uploader.SnapshotUploaderTag:  uploader.BlockType,
						},
					}}, nil)
			},
			expectedErrStr: "no matching snapshot found",
		},
		{
			name: "snapshot with wrong uploader tag is filtered",
			setupMocks: func(repo *udmrepomocks.BackupRepo) {
				repo.On("ListSnapshot", mock.Anything, "source").
					Return([]udmrepo.Snapshot{{
						Tags: map[string]string{
							uploader.SnapshotRequesterTag: "test-requester",
							uploader.SnapshotUploaderTag:  "kopia",
						},
					}}, nil)
			},
			expectedErrStr: "no matching snapshot found",
		},
		{
			name: "single matching snapshot is returned",
			setupMocks: func(repo *udmrepomocks.BackupRepo) {
				repo.On("ListSnapshot", mock.Anything, "source").
					Return([]udmrepo.Snapshot{matchingSnap("snap-a", time.Now())}, nil)
			},
			expectedID: "snap-a",
		},
		{
			name: "most recent of multiple matching snapshots is returned",
			setupMocks: func(repo *udmrepomocks.BackupRepo) {
				now := time.Now()
				repo.On("ListSnapshot", mock.Anything, "source").
					Return([]udmrepo.Snapshot{
						matchingSnap("snap-old", now.Add(-2*time.Hour)),
						matchingSnap("snap-new", now.Add(-time.Minute)),
						matchingSnap("snap-mid", now.Add(-time.Hour)),
					}, nil)
			},
			expectedID: "snap-new",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			mockRepo := udmrepomocks.NewBackupRepo(t)
			tc.setupMocks(mockRepo)

			snap, err := findPreviousSnapshot(ctx, mockRepo, "source", snapshotTags, nil, testLog())

			if tc.expectedErrStr != "" {
				require.Error(t, err)
				require.ErrorContains(t, err, tc.expectedErrStr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, udmrepo.ID(tc.expectedID), snap.RootObject.ID)
			}
		})
	}
}

func TestRestore(t *testing.T) {
	storedSnap := udmrepo.Snapshot{Description: "test snapshot"}

	testCases := []struct {
		name           string
		setupMocks     func(blkup *mockUploader, repo *udmrepomocks.BackupRepo)
		setupOpenDev   func(t *testing.T) *os.File
		expectedErrStr string
		expectedSize   int64
	}{
		{
			name: "GetSnapshot error",
			setupMocks: func(_ *mockUploader, repo *udmrepomocks.BackupRepo) {
				repo.On("GetSnapshot", mock.Anything, udmrepo.ID("snap-001")).
					Return(udmrepo.Snapshot{}, errors.New("not found"))
			},
			expectedErrStr: "Unable to load snapshot",
		},
		{
			name: "openBlockDevice error",
			setupMocks: func(_ *mockUploader, repo *udmrepomocks.BackupRepo) {
				repo.On("GetSnapshot", mock.Anything, udmrepo.ID("snap-001")).
					Return(storedSnap, nil)
			},
			expectedErrStr: "error opening block device",
		},
		{
			name: "Restore error",
			setupMocks: func(blkup *mockUploader, repo *udmrepomocks.BackupRepo) {
				repo.On("GetSnapshot", mock.Anything, udmrepo.ID("snap-001")).
					Return(storedSnap, nil)
				blkup.On("Restore", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(int64(0), errors.New("restore I/O error"))
			},
			setupOpenDev: func(t *testing.T) *os.File {
				t.Helper()
				return tempFile(t, "")
			},
			expectedErrStr: "error restoring to block dev",
		},
		{
			name: "success returns size",
			setupMocks: func(blkup *mockUploader, repo *udmrepomocks.BackupRepo) {
				repo.On("GetSnapshot", mock.Anything, udmrepo.ID("snap-001")).
					Return(storedSnap, nil)
				blkup.On("Restore", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(int64(4096), nil)
			},
			setupOpenDev: func(t *testing.T) *os.File {
				t.Helper()
				return tempFile(t, "")
			},
			expectedSize: 4096,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			mockBlkup := &mockUploader{}
			mockRepo := udmrepomocks.NewBackupRepo(t)

			tc.setupMocks(mockBlkup, mockRepo)

			if tc.setupOpenDev != nil {
				f := tc.setupOpenDev(t)
				openBlockDeviceFunc = func(_ string, _ bool) (*os.File, error) {
					return f, nil
				}
			} else {
				openBlockDeviceFunc = func(_ string, _ bool) (*os.File, error) {
					return nil, errors.New("device not available")
				}
			}

			size, err := Restore(ctx, mockBlkup, mockRepo, "snap-001", "/dev/sdb", map[string]string{}, testLog())

			if tc.expectedErrStr != "" {
				require.Error(t, err)
				require.ErrorContains(t, err, tc.expectedErrStr)
				assert.Equal(t, int64(0), size)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedSize, size)
			}

			mockBlkup.AssertExpectations(t)
		})
	}
}
