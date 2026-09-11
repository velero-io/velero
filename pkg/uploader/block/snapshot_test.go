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
	"strings"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"

	"github.com/vmware-tanzu/velero/pkg/cbtservice"
	cbtservicemocks "github.com/vmware-tanzu/velero/pkg/cbtservice/mocks"
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

func (m *mockUploader) Restore(snap udmrepo.Snapshot, dest destInfo, iter cbttypes.Iterator, cfg map[string]string) (int64, int64, error) {
	args := m.Called(snap, dest, iter, cfg)
	return args.Get(0).(int64), args.Get(1).(int64), args.Error(2)
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
			name: "success returns correct SnapshotInfo with snapshotSize larger than sourceSize",
			setupOpenDev: func(t *testing.T) *os.File {
				t.Helper()
				return tempFile(t, "test-block-data")
			},
			setupMocks: func(blkup *mockUploader, repo *udmrepomocks.BackupRepo) {
				blkup.On("Backup", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(udmrepo.Snapshot{
						RootObject: udmrepo.ObjectMetadata{ID: "root"},
						TotalSize:  int64(2048),
					}, int64(8), nil)
				repo.On("SaveSnapshot", mock.Anything, mock.Anything).Return(udmrepo.ID("snap-001"), nil)
				repo.On("Flush", mock.Anything).Return(nil)
			},
			checkInfo: func(t *testing.T, info uploader.SnapshotInfo) {
				t.Helper()
				assert.Equal(t, "snap-001", info.ID)
				assert.Equal(t, int64(8), info.IncrementalSize)
				assert.Equal(t, int64(2048), info.SnapshotSize)
				assert.Equal(t, int64(len("test-block-data")), info.SourceSize)
				assert.False(t, info.Fallback)
			},
		},
		{
			name: "success with CBT and snapshotSize equal to sourceSize",
			setupOpenDev: func(t *testing.T) *os.File {
				t.Helper()
				return tempFile(t, "test-block-data")
			},
			setupMocks: func(blkup *mockUploader, repo *udmrepomocks.BackupRepo) {
				blkup.On("Backup", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(udmrepo.Snapshot{
						RootObject: udmrepo.ObjectMetadata{ID: "root"},
						TotalSize:  int64(len("test-block-data")),
					}, int64(8), nil)
				repo.On("SaveSnapshot", mock.Anything, mock.Anything).Return(udmrepo.ID("snap-001"), nil)
				repo.On("Flush", mock.Anything).Return(nil)
			},
			checkInfo: func(t *testing.T, info uploader.SnapshotInfo) {
				t.Helper()
				assert.Equal(t, "snap-001", info.ID)
				assert.Equal(t, int64(8), info.IncrementalSize)
				assert.Equal(t, int64(len("test-block-data")), info.SnapshotSize)
				assert.Equal(t, int64(len("test-block-data")), info.SourceSize)
				assert.False(t, info.Fallback)
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
		name                 string
		forceFull            *bool
		parentSnapshot       string
		setupMocks           func(blkup *mockUploader, repo *udmrepomocks.BackupRepo)
		expectedErrStr       string
		expectedSnapID       string
		expectedSize         int64
		expectedSnapshotSize int64
		expectedFallback     bool
		cbtService           func(t *testing.T) cbtservice.Service
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
				blkup.On("Backup", mock.Anything, mock.Anything, mock.MatchedBy(func(iter cbttypes.Iterator) bool {
					// In full mode, the iterator should cover the whole range if it's a full backup
					return iter != nil
				}), mock.Anything).
					Return(udmrepo.Snapshot{RootObject: udmrepo.ObjectMetadata{ID: "root"}, TotalSize: 2048}, int64(512), nil)
				repo.On("SaveSnapshot", mock.Anything, mock.Anything).Return(udmrepo.ID("snap-success"), nil)
				repo.On("Flush", mock.Anything).Return(nil)
			},
			expectedSnapID:       "snap-success",
			expectedSize:         512,
			expectedSnapshotSize: 2048,
			expectedFallback:     false,
		},
		{
			name: "tags from cbtSource and snapshotTags are merged onto snapshot",
			setupMocks: func(blkup *mockUploader, repo *udmrepomocks.BackupRepo) {
				blkup.On("Backup", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(udmrepo.Snapshot{TotalSize: 4096}, int64(256), nil)
				repo.On("SaveSnapshot", mock.Anything, mock.MatchedBy(func(snap udmrepo.Snapshot) bool {
					return snap.Tags[uploader.CBTChangeIDTag] == "cid-1" &&
						snap.Tags[uploader.CBTVolumeIDTag] == "vid-1" &&
						snap.Tags["custom"] == "val" &&
						snap.Description == "Block Uploader"
				})).Return(udmrepo.ID("snap-tags"), nil)
				repo.On("Flush", mock.Anything).Return(nil)
			},
			expectedSnapID:       "snap-tags",
			expectedSize:         256,
			expectedSnapshotSize: 4096,
			expectedFallback:     false,
		},
		{
			name: "success with cbtService getting allocated blocks",
			cbtService: func(t *testing.T) cbtservice.Service {
				t.Helper()
				m := cbtservicemocks.NewService(t)
				m.On("GetAllocatedBlocks", mock.Anything, "snap-1", mock.Anything).
					Run(func(args mock.Arguments) {
						record := args.Get(2).(func([]cbtservice.Range) error)
						record([]cbtservice.Range{{Offset: 0, Length: 1024}})
					}).Return(nil)
				return m
			},
			setupMocks: func(blkup *mockUploader, repo *udmrepomocks.BackupRepo) {
				blkup.On("Backup", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(udmrepo.Snapshot{RootObject: udmrepo.ObjectMetadata{ID: "root"}, TotalSize: 8192}, int64(1024), nil)
				repo.On("SaveSnapshot", mock.Anything, mock.Anything).Return(udmrepo.ID("snap-cbt-alloc"), nil)
				repo.On("Flush", mock.Anything).Return(nil)
			},
			expectedSnapID:       "snap-cbt-alloc",
			expectedSize:         1024,
			expectedSnapshotSize: 8192,
			expectedFallback:     false,
		},
		{
			name: "cbtService error falls back to full",
			cbtService: func(t *testing.T) cbtservice.Service {
				t.Helper()
				m := cbtservicemocks.NewService(t)
				m.On("GetAllocatedBlocks", mock.Anything, "snap-1", mock.Anything).
					Return(errors.New("CBT error"))
				return m
			},
			setupMocks: func(blkup *mockUploader, repo *udmrepomocks.BackupRepo) {
				// Should be called with parentObject as empty because of fallback
				blkup.On("Backup", mock.Anything, udmrepo.ID(""), mock.Anything, mock.Anything).
					Return(udmrepo.Snapshot{TotalSize: 1024}, int64(1024), nil)
				repo.On("SaveSnapshot", mock.Anything, mock.Anything).Return(udmrepo.ID("snap-cbt-fallback"), nil)
				repo.On("Flush", mock.Anything).Return(nil)
			},
			expectedSnapID:       "snap-cbt-fallback",
			expectedSize:         1024,
			expectedSnapshotSize: 1024,
			expectedFallback:     false,
		},
		{
			name:           "incremental backup falls back to full when parent snapshot load fails",
			forceFull:      ptr.To(false),
			parentSnapshot: "snap-parent",
			setupMocks: func(blkup *mockUploader, repo *udmrepomocks.BackupRepo) {
				repo.On("GetSnapshot", mock.Anything, udmrepo.ID("snap-parent")).
					Return(udmrepo.Snapshot{}, errors.New("parent not found"))
				blkup.On("Backup", mock.Anything, udmrepo.ID(""), mock.Anything, mock.Anything).
					Return(udmrepo.Snapshot{TotalSize: 1024}, int64(1024), nil)
				repo.On("SaveSnapshot", mock.Anything, mock.Anything).Return(udmrepo.ID("snap-inc-fallback"), nil)
				repo.On("Flush", mock.Anything).Return(nil)
			},
			expectedSnapID:       "snap-inc-fallback",
			expectedSize:         1024,
			expectedSnapshotSize: 1024,
			expectedFallback:     true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			mockBlkup := &mockUploader{}
			mockRepo := udmrepomocks.NewBackupRepo(t)

			tc.setupMocks(mockBlkup, mockRepo)

			cbtSrc := cbtservice.SourceInfo{Snapshot: "snap-1", ChangeID: "cid-1", VolumeID: "vid-1"}
			snapshotTags := map[string]string{"custom": "val"}

			var cbtSvc cbtservice.Service
			if tc.cbtService != nil {
				cbtSvc = tc.cbtService(t)
			}

			forceFull := true
			if tc.forceFull != nil {
				forceFull = *tc.forceFull
			}

			snapID, size, snapshotSize, fallback, err := snapshotSource(
				ctx, mockRepo, mockBlkup,
				baseSource,
				forceFull, tc.parentSnapshot,
				cbtSrc, cbtSvc,
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
				assert.Equal(t, tc.expectedSnapshotSize, snapshotSize)
				assert.Equal(t, tc.expectedFallback, fallback)
			}

			mockBlkup.AssertExpectations(t)
		})
	}
}

// TestGetParentBackupInfoLogsDiscoveredParentID pins that the parent-selection messages
// name the snapshot they are about. On the discovery branch the parentSnapshot parameter
// is empty by definition, so logging it there emits "Using parent snapshot , start time ..."
// - a decision logged without the identifier needed to act on it.
func TestGetParentBackupInfoLogsDiscoveredParentID(t *testing.T) {
	const volumeID = "vol-123"
	const realSource = "/test/source"
	const parentSnapID = "snap-parent-42"
	const rootObj = "root-obj-42"

	snapshotTags := map[string]string{
		uploader.SnapshotRequesterTag: "test-requester",
		uploader.SnapshotUploaderTag:  uploader.BlockType,
	}

	logger, hook := logrustest.NewNullLogger()
	logger.SetLevel(logrus.DebugLevel)

	repo := udmrepomocks.NewBackupRepo(t)
	repo.On("ListSnapshot", mock.Anything, realSource).
		Return([]udmrepo.Snapshot{{
			ID:         parentSnapID,
			RootObject: udmrepo.ObjectMetadata{ID: rootObj},
			Tags: map[string]string{
				uploader.CBTChangeIDTag:       "cid-abc",
				uploader.CBTVolumeIDTag:       volumeID,
				uploader.SnapshotRequesterTag: "test-requester",
				uploader.SnapshotUploaderTag:  uploader.BlockType,
			},
		}}, nil)
	repo.On("ReadMetadata", mock.Anything, udmrepo.ID(rootObj)).
		Return(&udmrepo.Metadata{
			SubObjects: []udmrepo.ObjectMetadata{{ID: udmrepo.ID("parent-obj")}},
		}, nil)

	info, err := getParentBackupInfo(
		context.Background(), repo,
		false, "", // no explicit parent -> discovery branch
		volumeID, realSource, snapshotTags, logger,
	)
	require.NoError(t, err)

	require.Equal(t, udmrepo.ID("parent-obj"), info.parentObject)

	var found bool
	for _, entry := range hook.AllEntries() {
		if strings.HasPrefix(entry.Message, "Using parent snapshot ") {
			found = true
			assert.Contains(t, entry.Message, parentSnapID,
				"parent-selection message must name the discovered snapshot, got %q", entry.Message)
		}
	}
	require.True(t, found, "expected a \"Using parent snapshot\" message")
}

func TestGetParentBackupInfo(t *testing.T) {
	const volumeID = "vol-123"
	const realSource = "/test/source"

	snapshotTags := map[string]string{
		uploader.SnapshotRequesterTag: "test-requester",
		uploader.SnapshotUploaderTag:  uploader.BlockType,
	}

	validSnap := udmrepo.Snapshot{
		ID:         "snap-valid",
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
		emptyVolID     bool
		setupMocks     func(repo *udmrepomocks.BackupRepo)
		expectErr      bool
		expectedErrStr string
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
			name:           "volumeID not provided",
			emptyVolID:     true,
			expectEmpty:    true,
			expectErr:      true,
			expectedErrStr: "volumeID is not provided from the volume snapshot",
		},
		{
			name:           "GetSnapshot fails — falls back to full",
			parentSnapshot: "snap-parent",
			setupMocks: func(repo *udmrepomocks.BackupRepo) {
				repo.On("GetSnapshot", mock.Anything, udmrepo.ID("snap-parent")).
					Return(udmrepo.Snapshot{}, errors.New("not found"))
			},
			expectEmpty:    true,
			expectErr:      true,
			expectedErrStr: "error loading previous snapshot",
		},
		{
			name:           "parent snapshot has nil tags — falls back to full",
			parentSnapshot: "snap-notags",
			setupMocks: func(repo *udmrepomocks.BackupRepo) {
				repo.On("GetSnapshot", mock.Anything, udmrepo.ID("snap-notags")).
					Return(udmrepo.Snapshot{ID: "snap-notags", Tags: nil}, nil)
			},
			expectEmpty:    true,
			expectErr:      true,
			expectedErrStr: "no tag from parent snapshot snap-notags",
		},
		{
			name:           "parent snapshot missing ChangeID tag — falls back to full",
			parentSnapshot: "snap-nocid",
			setupMocks: func(repo *udmrepomocks.BackupRepo) {
				repo.On("GetSnapshot", mock.Anything, udmrepo.ID("snap-nocid")).
					Return(udmrepo.Snapshot{ID: "snap-nocid", Tags: map[string]string{uploader.CBTVolumeIDTag: volumeID}}, nil)
			},
			expectEmpty:    true,
			expectErr:      true,
			expectedErrStr: "no ChangeID tag from parent snapshot snap-nocid",
		},
		{
			name:           "parent snapshot missing VolumeID tag — falls back to full",
			parentSnapshot: "snap-novid",
			setupMocks: func(repo *udmrepomocks.BackupRepo) {
				repo.On("GetSnapshot", mock.Anything, udmrepo.ID("snap-novid")).
					Return(udmrepo.Snapshot{ID: "snap-novid", Tags: map[string]string{uploader.CBTChangeIDTag: "cid"}}, nil)
			},
			expectEmpty:    true,
			expectErr:      true,
			expectedErrStr: "no VolumeID tag from parent snapshot snap-novid",
		},
		{
			name:           "parent snapshot VolumeID mismatch — falls back to full",
			parentSnapshot: "snap-vidmismatch",
			setupMocks: func(repo *udmrepomocks.BackupRepo) {
				repo.On("GetSnapshot", mock.Anything, udmrepo.ID("snap-vidmismatch")).
					Return(udmrepo.Snapshot{ID: "snap-vidmismatch", Tags: map[string]string{
						uploader.CBTChangeIDTag: "cid",
						uploader.CBTVolumeIDTag: "different-vol",
					}}, nil)
			},
			expectEmpty:    true,
			expectErr:      true,
			expectedErrStr: "VolumeID different-vol from parent snapshot snap-vidmismatch is not expected as vol-123",
		},
		{
			name:           "loadObjectFromSnapshot fails — falls back to full",
			parentSnapshot: "snap-valid",
			setupMocks: func(repo *udmrepomocks.BackupRepo) {
				repo.On("GetSnapshot", mock.Anything, udmrepo.ID("snap-valid")).
					Return(validSnap, nil)
				repo.On("ReadMetadata", mock.Anything, udmrepo.ID("root-obj")).
					Return(nil, errors.New("read error"))
			},
			expectEmpty:    true,
			expectErr:      true,
			expectedErrStr: "error loading object from parent snapshot snap-valid",
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
			expectEmpty:    true,
			expectErr:      true,
			expectedErrStr: "error searching previous snapshot",
		},
		{
			name: "no parentSnapshot — no matching snapshot — falls back to full",
			setupMocks: func(repo *udmrepomocks.BackupRepo) {
				repo.On("ListSnapshot", mock.Anything, realSource).
					Return([]udmrepo.Snapshot{{Tags: map[string]string{"other": "tag"}}}, nil)
			},
			expectEmpty:    true,
			expectErr:      true,
			expectedErrStr: "error searching previous snapshot",
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

			volID := volumeID
			if tc.emptyVolID {
				volID = ""
			}

			info, err := getParentBackupInfo(ctx, mockRepo, tc.forceFull, tc.parentSnapshot, volID, realSource, snapshotTags, testLog())

			if tc.expectErr {
				require.Error(t, err)
				if tc.expectedErrStr != "" {
					assert.Contains(t, err.Error(), tc.expectedErrStr)
				}
			} else {
				require.NoError(t, err)
			}

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

func TestGetBackupInfo(t *testing.T) {
	const volumeID = "vol-123"

	validSnap := udmrepo.Snapshot{
		ID: "snap-valid",
		Tags: map[string]string{
			uploader.CBTChangeIDTag: "cid-abc",
			uploader.CBTVolumeIDTag: volumeID,
		},
	}

	testCases := []struct {
		name           string
		snapshot       udmrepo.Snapshot
		volumeID       string
		expectErr      bool
		expectedErrStr string
		expectedCID    string
	}{
		{
			name:           "nil tags",
			snapshot:       udmrepo.Snapshot{ID: "snap-nil-tags"},
			volumeID:       volumeID,
			expectErr:      true,
			expectedErrStr: "no tag from snapshot snap-nil-tags",
		},
		{
			name: "missing ChangeID tag",
			snapshot: udmrepo.Snapshot{
				ID:   "snap-no-cid",
				Tags: map[string]string{uploader.CBTVolumeIDTag: volumeID},
			},
			volumeID:       volumeID,
			expectErr:      true,
			expectedErrStr: "no ChangeID tag from snapshot snap-no-cid",
		},
		{
			name: "missing VolumeID tag",
			snapshot: udmrepo.Snapshot{
				ID:   "snap-no-vid",
				Tags: map[string]string{uploader.CBTChangeIDTag: "cid-abc"},
			},
			volumeID:       volumeID,
			expectErr:      true,
			expectedErrStr: "no VolumeID tag from snapshot snap-no-vid",
		},
		{
			name: "empty volumeID parameter",
			snapshot: udmrepo.Snapshot{
				ID: "snap-valid",
				Tags: map[string]string{
					uploader.CBTChangeIDTag: "cid-abc",
					uploader.CBTVolumeIDTag: volumeID,
				},
			},
			volumeID:       "",
			expectErr:      true,
			expectedErrStr: "no VolumeID tag from the volume snapshot",
		},
		{
			name: "volumeID mismatch",
			snapshot: udmrepo.Snapshot{
				ID: "snap-vid-mismatch",
				Tags: map[string]string{
					uploader.CBTChangeIDTag: "cid-abc",
					uploader.CBTVolumeIDTag: "other-vol",
				},
			},
			volumeID:       volumeID,
			expectErr:      true,
			expectedErrStr: "volumeID other-vol from snapshot snap-vid-mismatch is not expected as vol-123",
		},
		{
			name:        "valid snapshot",
			snapshot:    validSnap,
			volumeID:    volumeID,
			expectErr:   false,
			expectedCID: "cid-abc",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			info, err := getBackupInfo(tc.snapshot, tc.volumeID)
			if tc.expectErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrStr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedCID, info.changeID)
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
		name             string
		incremental      bool
		cbtSource        cbtservice.SourceInfo
		cbtService       func(t *testing.T) cbtservice.Service
		setupMocks       func(blkup *mockUploader, repo *udmrepomocks.BackupRepo)
		setupOpenDev     func(t *testing.T) *os.File
		expectedErrStr   string
		expectedSize     int64
		expectedFallback bool
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
					Return(int64(0), int64(0), errors.New("restore I/O error"))
			},
			setupOpenDev: func(t *testing.T) *os.File {
				t.Helper()
				return tempFile(t, "")
			},
			expectedErrStr: "error restoring to block dev",
		},
		{
			name: "success returns size (full restore)",
			setupMocks: func(blkup *mockUploader, repo *udmrepomocks.BackupRepo) {
				repo.On("GetSnapshot", mock.Anything, udmrepo.ID("snap-001")).
					Return(storedSnap, nil)
				blkup.On("Restore", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(int64(4096), int64(4096), nil)
			},
			setupOpenDev: func(t *testing.T) *os.File {
				t.Helper()
				return tempFile(t, "")
			},
			expectedSize:     4096,
			expectedFallback: false,
		},
		{
			name:        "incremental restore success",
			incremental: true,
			cbtSource:   cbtservice.SourceInfo{Snapshot: "snap-cbt", VolumeID: "vol-1"},
			cbtService: func(t *testing.T) cbtservice.Service {
				t.Helper()
				m := cbtservicemocks.NewService(t)
				m.On("GetChangedBlocks", mock.Anything, "snap-cbt", "cid-1", mock.Anything).
					Run(func(args mock.Arguments) {
						record := args.Get(3).(func([]cbtservice.Range) error)
						record([]cbtservice.Range{{Offset: 0, Length: 512}})
					}).Return(nil)
				return m
			},
			setupMocks: func(blkup *mockUploader, repo *udmrepomocks.BackupRepo) {
				snapWithTags := udmrepo.Snapshot{
					Tags: map[string]string{
						uploader.CBTChangeIDTag: "cid-1",
						uploader.CBTVolumeIDTag: "vol-1",
					},
					TotalSize: 1024,
				}
				repo.On("GetSnapshot", mock.Anything, udmrepo.ID("snap-001")).Return(snapWithTags, nil)
				blkup.On("Restore", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(int64(512), int64(512), nil)
			},
			setupOpenDev: func(t *testing.T) *os.File {
				t.Helper()
				return tempFile(t, "")
			},
			expectedSize:     512,
			expectedFallback: false,
		},
		{
			name:        "incremental restore fallback - missing tags",
			incremental: true,
			setupMocks: func(blkup *mockUploader, repo *udmrepomocks.BackupRepo) {
				repo.On("GetSnapshot", mock.Anything, udmrepo.ID("snap-001")).Return(storedSnap, nil)
				blkup.On("Restore", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(int64(4096), int64(4096), nil)
			},
			setupOpenDev: func(t *testing.T) *os.File {
				t.Helper()
				return tempFile(t, "")
			},
			expectedSize:     4096,
			expectedFallback: true,
		},
		{
			name:        "incremental restore fallback - empty cbtSource VolumeID",
			incremental: true,
			cbtSource:   cbtservice.SourceInfo{Snapshot: "snap-cbt", VolumeID: ""},
			setupMocks: func(blkup *mockUploader, repo *udmrepomocks.BackupRepo) {
				snapWithTags := udmrepo.Snapshot{
					Tags: map[string]string{
						uploader.CBTChangeIDTag: "cid-1",
						uploader.CBTVolumeIDTag: "vol-1",
					},
				}
				repo.On("GetSnapshot", mock.Anything, udmrepo.ID("snap-001")).Return(snapWithTags, nil)
				blkup.On("Restore", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(int64(4096), int64(4096), nil)
			},
			setupOpenDev: func(t *testing.T) *os.File {
				t.Helper()
				return tempFile(t, "")
			},
			expectedSize:     4096,
			expectedFallback: true,
		},
		{
			name:        "incremental restore fallback - VolumeID mismatch",
			incremental: true,
			cbtSource:   cbtservice.SourceInfo{VolumeID: "vol-actual"},
			setupMocks: func(blkup *mockUploader, repo *udmrepomocks.BackupRepo) {
				snapWithTags := udmrepo.Snapshot{
					Tags: map[string]string{
						uploader.CBTChangeIDTag: "cid-1",
						uploader.CBTVolumeIDTag: "vol-expected",
					},
				}
				repo.On("GetSnapshot", mock.Anything, udmrepo.ID("snap-001")).Return(snapWithTags, nil)
				blkup.On("Restore", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(int64(4096), int64(4096), nil)
			},
			setupOpenDev: func(t *testing.T) *os.File {
				t.Helper()
				return tempFile(t, "")
			},
			expectedSize:     4096,
			expectedFallback: true,
		},
		{
			name:        "incremental restore fallback - CBT service error",
			incremental: true,
			cbtSource:   cbtservice.SourceInfo{Snapshot: "snap-cbt", VolumeID: "vol-1"},
			cbtService: func(t *testing.T) cbtservice.Service {
				t.Helper()
				m := cbtservicemocks.NewService(t)
				m.On("GetChangedBlocks", mock.Anything, "snap-cbt", "cid-1", mock.Anything).
					Return(errors.New("CBT error"))
				return m
			},
			setupMocks: func(blkup *mockUploader, repo *udmrepomocks.BackupRepo) {
				snapWithTags := udmrepo.Snapshot{
					Tags: map[string]string{
						uploader.CBTChangeIDTag: "cid-1",
						uploader.CBTVolumeIDTag: "vol-1",
					},
					TotalSize: 1024,
				}
				repo.On("GetSnapshot", mock.Anything, udmrepo.ID("snap-001")).Return(snapWithTags, nil)
				blkup.On("Restore", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(int64(1024), int64(1024), nil)
			},
			setupOpenDev: func(t *testing.T) *os.File {
				t.Helper()
				return tempFile(t, "")
			},
			expectedSize:     1024,
			expectedFallback: true,
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

			var cbtSvc cbtservice.Service
			if tc.cbtService != nil {
				cbtSvc = tc.cbtService(t)
			}

			_, size, fallback, err := Restore(ctx, mockBlkup, mockRepo, "snap-001", "/dev/sdb", tc.incremental, tc.cbtSource, cbtSvc, map[string]string{}, testLog())

			if tc.expectedErrStr != "" {
				require.Error(t, err)
				require.ErrorContains(t, err, tc.expectedErrStr)
				assert.Equal(t, int64(0), size)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedSize, size)
				assert.Equal(t, tc.expectedFallback, fallback)
			}

			mockBlkup.AssertExpectations(t)
		})
	}
}
