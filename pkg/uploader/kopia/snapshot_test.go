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
	"strings"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/kopia/kopia/fs"
	"github.com/kopia/kopia/fs/virtualfs"
	"github.com/kopia/kopia/repo"
	"github.com/kopia/kopia/repo/manifest"
	"github.com/kopia/kopia/snapshot"
	"github.com/kopia/kopia/snapshot/policy"
	"github.com/kopia/kopia/snapshot/restore"
	"github.com/kopia/kopia/snapshot/snapshotfs"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	repomocks "github.com/vmware-tanzu/velero/pkg/repository/mocks"
	"github.com/vmware-tanzu/velero/pkg/uploader"
	uploadermocks "github.com/vmware-tanzu/velero/pkg/uploader/mocks"
)

type snapshotMockes struct {
	policyMock     *uploadermocks.Policy
	snapshotMock   *uploadermocks.Snapshot
	uploderMock    *uploadermocks.Uploader
	repoWriterMock *repomocks.RepositoryWriter
}

type mockArgs struct {
	methodName string
	returns    []any
}

func injectSnapshotFuncs() *snapshotMockes {
	s := &snapshotMockes{
		policyMock:     &uploadermocks.Policy{},
		snapshotMock:   &uploadermocks.Snapshot{},
		uploderMock:    &uploadermocks.Uploader{},
		repoWriterMock: &repomocks.RepositoryWriter{},
	}

	applyRetentionPolicyFunc = s.policyMock.ApplyRetentionPolicy
	setPolicyFunc = s.policyMock.SetPolicy
	treeForSourceFunc = s.policyMock.TreeForSource
	loadSnapshotFunc = s.snapshotMock.LoadSnapshot
	saveSnapshotFunc = s.snapshotMock.SaveSnapshot
	return s
}

func MockFuncs(s *snapshotMockes, args []mockArgs) {
	s.snapshotMock.On("LoadSnapshot", mock.Anything, mock.Anything, mock.Anything).Return(args[0].returns...)
	s.snapshotMock.On("SaveSnapshot", mock.Anything, mock.Anything, mock.Anything).Return(args[1].returns...)
	s.policyMock.On("TreeForSource", mock.Anything, mock.Anything, mock.Anything).Return(args[2].returns...)
	s.policyMock.On("ApplyRetentionPolicy", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(args[3].returns...)
	s.policyMock.On("SetPolicy", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(args[4].returns...)
	s.uploderMock.On("Upload", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(args[5].returns...)
	s.repoWriterMock.On("Flush", mock.Anything).Return(args[6].returns...)
}

func TestSnapshotSource(t *testing.T) {
	ctx := t.Context()
	sourceInfo := snapshot.SourceInfo{
		UserName: "testUserName",
		Host:     "testHost",
		Path:     "/var",
	}
	rootDir, err := getLocalFSEntry(sourceInfo.Path)
	require.NoError(t, err)
	log := logrus.New()
	manifest := &snapshot.Manifest{
		ID:        "test",
		RootEntry: &snapshot.DirEntry{},
	}

	testCases := []struct {
		name        string
		args        []mockArgs
		uploaderCfg map[string]string
		notError    bool
	}{
		{
			name: "regular test",
			args: []mockArgs{
				{methodName: "LoadSnapshot", returns: []any{manifest, nil}},
				{methodName: "SaveSnapshot", returns: []any{manifest.ID, nil}},
				{methodName: "TreeForSource", returns: []any{nil, nil}},
				{methodName: "ApplyRetentionPolicy", returns: []any{nil, nil}},
				{methodName: "SetPolicy", returns: []any{nil}},
				{methodName: "Upload", returns: []any{manifest, nil}},
				{methodName: "Flush", returns: []any{nil}},
			},
			notError: true,
		},
		{
			name: "failed to load snapshot, should fallback to full backup and not error",
			args: []mockArgs{
				{methodName: "LoadSnapshot", returns: []any{manifest, errors.New("failed to load snapshot")}},
				{methodName: "SaveSnapshot", returns: []any{manifest.ID, nil}},
				{methodName: "TreeForSource", returns: []any{nil, nil}},
				{methodName: "ApplyRetentionPolicy", returns: []any{nil, nil}},
				{methodName: "SetPolicy", returns: []any{nil}},
				{methodName: "Upload", returns: []any{manifest, nil}},
				{methodName: "Flush", returns: []any{nil}},
			},
			notError: true,
		},
		{
			name: "failed to save snapshot",
			args: []mockArgs{
				{methodName: "LoadSnapshot", returns: []any{manifest, nil}},
				{methodName: "SaveSnapshot", returns: []any{manifest.ID, errors.New("failed to save snapshot")}},
				{methodName: "TreeForSource", returns: []any{nil, nil}},
				{methodName: "ApplyRetentionPolicy", returns: []any{nil, nil}},
				{methodName: "SetPolicy", returns: []any{nil}},
				{methodName: "Upload", returns: []any{manifest, nil}},
				{methodName: "Flush", returns: []any{nil}},
			},
			notError: false,
		},
		{
			name: "failed to set policy",
			args: []mockArgs{
				{methodName: "LoadSnapshot", returns: []any{manifest, nil}},
				{methodName: "SaveSnapshot", returns: []any{manifest.ID, nil}},
				{methodName: "TreeForSource", returns: []any{nil, nil}},
				{methodName: "ApplyRetentionPolicy", returns: []any{nil, nil}},
				{methodName: "SetPolicy", returns: []any{errors.New("failed to set policy")}},
				{methodName: "Upload", returns: []any{manifest, nil}},
				{methodName: "Flush", returns: []any{nil}},
			},
			notError: false,
		},
		{
			name: "set policy with parallel files upload",
			args: []mockArgs{
				{methodName: "LoadSnapshot", returns: []any{manifest, nil}},
				{methodName: "SaveSnapshot", returns: []any{manifest.ID, nil}},
				{methodName: "TreeForSource", returns: []any{nil, nil}},
				{methodName: "ApplyRetentionPolicy", returns: []any{nil, nil}},
				{methodName: "SetPolicy", returns: []any{nil}},
				{methodName: "Upload", returns: []any{manifest, nil}},
				{methodName: "Flush", returns: []any{nil}},
			},
			uploaderCfg: map[string]string{
				"ParallelFilesUpload": "10",
			},
			notError: true,
		},
		{
			name: "failed to upload snapshot",
			args: []mockArgs{
				{methodName: "LoadSnapshot", returns: []any{manifest, nil}},
				{methodName: "SaveSnapshot", returns: []any{manifest.ID, nil}},
				{methodName: "TreeForSource", returns: []any{nil, nil}},
				{methodName: "ApplyRetentionPolicy", returns: []any{nil, nil}},
				{methodName: "SetPolicy", returns: []any{nil}},
				{methodName: "Upload", returns: []any{manifest, errors.New("failed to upload snapshot")}},
				{methodName: "Flush", returns: []any{nil}},
			},
			notError: false,
		},
		{
			name: "failed to flush repo",
			args: []mockArgs{
				{methodName: "LoadSnapshot", returns: []any{manifest, nil}},
				{methodName: "SaveSnapshot", returns: []any{manifest.ID, errors.New("failed to save snapshot")}},
				{methodName: "TreeForSource", returns: []any{nil, nil}},
				{methodName: "ApplyRetentionPolicy", returns: []any{nil, nil}},
				{methodName: "SetPolicy", returns: []any{nil}},
				{methodName: "Upload", returns: []any{manifest, nil}},
				{methodName: "Flush", returns: []any{errors.New("failed to flush repo")}},
			},
			notError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			s := injectSnapshotFuncs()
			MockFuncs(s, tc.args)
			_, _, err = SnapshotSource(ctx, s.repoWriterMock, s.uploderMock, sourceInfo, rootDir, false, "/", nil, tc.uploaderCfg, log, "TestSnapshotSource")
			if tc.notError {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestReportSnapshotStatus(t *testing.T) {
	testCases := []struct {
		shouldError      bool
		expectedResult   string
		expectedSize     int64
		directorySummary *fs.DirectorySummary
		expectedErrors   []string
	}{
		{
			shouldError:    false,
			expectedResult: "sample-manifest-id",
			expectedSize:   1024,
			directorySummary: &fs.DirectorySummary{
				TotalFileSize: 1024,
			},
		},
		{
			shouldError:    true,
			expectedResult: "sample-manifest-id",
			expectedSize:   1024,
			directorySummary: &fs.DirectorySummary{
				FailedEntries: []*fs.EntryWithError{
					{
						EntryPath: "/path/to/file.txt",
						Error:     "Unknown file error",
					},
				},
			},
			expectedErrors: []string{"Error when processing /path/to/file.txt: Unknown file error"},
		},
	}

	for _, tc := range testCases {
		manifest := &snapshot.Manifest{
			ID: manifest.ID("sample-manifest-id"),
			Stats: snapshot.Stats{
				TotalFileSize: 1024,
			},
			RootEntry: &snapshot.DirEntry{
				DirSummary: tc.directorySummary,
			},
		}

		result, size, err := reportSnapshotStatus(manifest, policy.BuildTree(nil, getDefaultPolicy()))

		switch {
		case tc.shouldError && err == nil:
			t.Errorf("expected error, but got nil")
		case !tc.shouldError && err != nil:
			t.Errorf("unexpected error: %v", err)
		case tc.shouldError && err != nil:
			expectedErr := strings.Join(tc.expectedErrors, "\n")
			if err.Error() != expectedErr {
				t.Errorf("unexpected error: got %v, want %v", err, expectedErr)
			}
		}

		if result != tc.expectedResult {
			t.Errorf("unexpected result: got %v, want %v", result, tc.expectedResult)
		}

		if size != tc.expectedSize {
			t.Errorf("unexpected size: got %v, want %v", size, tc.expectedSize)
		}
	}
}

func TestFindPreviousSnapshotManifest(t *testing.T) {
	// Prepare test data
	sourceInfo := snapshot.SourceInfo{
		UserName: "user1",
		Host:     "host1",
		Path:     "/path/to/dir1",
	}
	snapshotTags := map[string]string{
		uploader.SnapshotRequesterTag: "user1",
		uploader.SnapshotUploaderTag:  "uploader1",
	}
	noLaterThan := fs.UTCTimestampFromTime(time.Now())

	testCases := []struct {
		name              string
		listSnapshotsFunc func(ctx context.Context, rep repo.Repository, si snapshot.SourceInfo) ([]*snapshot.Manifest, error)
		expectedSnapshots []*snapshot.Manifest
		expectedError     error
	}{
		// No matching snapshots
		{
			name: "No matching snapshots",
			listSnapshotsFunc: func(ctx context.Context, rep repo.Repository, si snapshot.SourceInfo) ([]*snapshot.Manifest, error) {
				return []*snapshot.Manifest{}, nil
			},
			expectedSnapshots: []*snapshot.Manifest{},
			expectedError:     nil,
		},
		{
			name: "Error getting manifest",
			listSnapshotsFunc: func(ctx context.Context, rep repo.Repository, si snapshot.SourceInfo) ([]*snapshot.Manifest, error) {
				return []*snapshot.Manifest{}, errors.New("Error getting manifest")
			},
			expectedSnapshots: []*snapshot.Manifest{},
			expectedError:     errors.New("Error getting manifest"),
		},
		// Only one matching snapshot
		{
			name: "One matching snapshot",
			listSnapshotsFunc: func(ctx context.Context, rep repo.Repository, si snapshot.SourceInfo) ([]*snapshot.Manifest, error) {
				return []*snapshot.Manifest{
					{
						Tags: map[string]string{
							uploader.SnapshotRequesterTag: "user1",
							uploader.SnapshotUploaderTag:  "uploader1",
							"otherTag":                    "value",
							"anotherCustomTag":            "123",
							"snapshotRequestor":           "user1",
							"snapshotUploader":            "uploader1",
						},
					},
				}, nil
			},
			expectedSnapshots: []*snapshot.Manifest{
				{
					Tags: map[string]string{
						uploader.SnapshotRequesterTag: "user1",
						uploader.SnapshotUploaderTag:  "uploader1",
						"otherTag":                    "value",
						"anotherCustomTag":            "123",
						"snapshotRequestor":           "user1",
						"snapshotUploader":            "uploader1",
					},
				},
			},
			expectedError: nil,
		},
		// Multiple matching snapshots
		{
			name: "Multiple matching snapshots",
			listSnapshotsFunc: func(ctx context.Context, rep repo.Repository, si snapshot.SourceInfo) ([]*snapshot.Manifest, error) {
				return []*snapshot.Manifest{
					{
						Tags: map[string]string{
							uploader.SnapshotRequesterTag: "user1",
							uploader.SnapshotUploaderTag:  "uploader1",
							"otherTag":                    "value1",
							"snapshotRequestor":           "user1",
							"snapshotUploader":            "uploader1",
						},
					},
					{
						Tags: map[string]string{
							uploader.SnapshotRequesterTag: "user1",
							uploader.SnapshotUploaderTag:  "uploader1",
							"otherTag":                    "value2",
							"snapshotRequestor":           "user1",
							"snapshotUploader":            "uploader1",
						},
					},
				}, nil
			},
			expectedSnapshots: []*snapshot.Manifest{
				{
					Tags: map[string]string{
						uploader.SnapshotRequesterTag: "user1",
						uploader.SnapshotUploaderTag:  "uploader1",
						"otherTag":                    "value1",
						"snapshotRequestor":           "user1",
						"snapshotUploader":            "uploader1",
					},
				},
			},
			expectedError: nil,
		},
		// Snapshot with different requester
		{
			name: "Snapshot with different requester",
			listSnapshotsFunc: func(ctx context.Context, rep repo.Repository, si snapshot.SourceInfo) ([]*snapshot.Manifest, error) {
				return []*snapshot.Manifest{
					{
						Tags: map[string]string{
							uploader.SnapshotRequesterTag: "user2",
							uploader.SnapshotUploaderTag:  "uploader1",
							"otherTag":                    "value",
							"snapshotRequestor":           "user2",
							"snapshotUploader":            "uploader1",
						},
					},
				}, nil
			},
			expectedSnapshots: []*snapshot.Manifest{},
			expectedError:     nil,
		},
		// Snapshot with different uploader
		{
			name: "Snapshot with different uploader",
			listSnapshotsFunc: func(ctx context.Context, rep repo.Repository, si snapshot.SourceInfo) ([]*snapshot.Manifest, error) {
				return []*snapshot.Manifest{
					{
						Tags: map[string]string{
							uploader.SnapshotRequesterTag: "user1",
							uploader.SnapshotUploaderTag:  "uploader2",
							"otherTag":                    "value",
							"snapshotRequestor":           "user1",
							"snapshotUploader":            "uploader2",
						},
					},
				}, nil
			},
			expectedSnapshots: []*snapshot.Manifest{},
			expectedError:     nil,
		},
		// Snapshot with a later start time
		{
			name: "Snapshot with a later start time",
			listSnapshotsFunc: func(ctx context.Context, rep repo.Repository, si snapshot.SourceInfo) ([]*snapshot.Manifest, error) {
				return []*snapshot.Manifest{
					{
						Tags: map[string]string{
							uploader.SnapshotRequesterTag: "user1",
							uploader.SnapshotUploaderTag:  "uploader1",
							"otherTag":                    "value",
							"snapshotRequestor":           "user1",
							"snapshotUploader":            "uploader1",
						},
						StartTime: fs.UTCTimestampFromTime(time.Now().Add(time.Hour)),
					},
				}, nil
			},
			expectedSnapshots: []*snapshot.Manifest{},
			expectedError:     nil,
		},
		// Snapshot with incomplete reason
		{
			name: "Snapshot with incomplete reason",
			listSnapshotsFunc: func(ctx context.Context, rep repo.Repository, si snapshot.SourceInfo) ([]*snapshot.Manifest, error) {
				return []*snapshot.Manifest{
					{
						Tags: map[string]string{
							uploader.SnapshotRequesterTag: "user1",
							uploader.SnapshotUploaderTag:  "uploader1",
							"otherTag":                    "value",
							"snapshotRequestor":           "user1",
							"snapshotUploader":            "uploader1",
						},
						IncompleteReason: "reason",
					},
				}, nil
			},
			expectedSnapshots: []*snapshot.Manifest{},
			expectedError:     nil,
		},
		// Multiple snapshots with some matching conditions
		{
			name: "Multiple snapshots with matching conditions",
			listSnapshotsFunc: func(ctx context.Context, rep repo.Repository, si snapshot.SourceInfo) ([]*snapshot.Manifest, error) {
				return []*snapshot.Manifest{
					{
						Tags: map[string]string{
							uploader.SnapshotRequesterTag: "user1",
							uploader.SnapshotUploaderTag:  "uploader1",
							"otherTag":                    "value1",
							"snapshotRequestor":           "user1",
							"snapshotUploader":            "uploader1",
						},
					},
					{
						Tags: map[string]string{
							uploader.SnapshotRequesterTag: "user1",
							uploader.SnapshotUploaderTag:  "uploader1",
							"otherTag":                    "value2",
							"snapshotRequestor":           "user1",
							"snapshotUploader":            "uploader1",
						},
						StartTime:        fs.UTCTimestampFromTime(time.Now().Add(-time.Hour)),
						IncompleteReason: "reason",
					},
					{
						Tags: map[string]string{
							uploader.SnapshotRequesterTag: "user1",
							uploader.SnapshotUploaderTag:  "uploader1",
							"otherTag":                    "value3",
							"snapshotRequestor":           "user1",
							"snapshotUploader":            "uploader1",
						},
						StartTime: fs.UTCTimestampFromTime(time.Now().Add(-time.Hour)),
					},
				}, nil
			},
			expectedSnapshots: []*snapshot.Manifest{
				{
					Tags: map[string]string{
						uploader.SnapshotRequesterTag: "user1",
						uploader.SnapshotUploaderTag:  "uploader1",
						"otherTag":                    "value3",
						"snapshotRequestor":           "user1",
						"snapshotUploader":            "uploader1",
					},
					StartTime: fs.UTCTimestampFromTime(time.Now().Add(-time.Hour)),
				},
			},
			expectedError: nil,
		},
		// Snapshot with manifest SnapshotRequesterTag not found
		{
			name: "Snapshot with manifest SnapshotRequesterTag not found",
			listSnapshotsFunc: func(ctx context.Context, rep repo.Repository, si snapshot.SourceInfo) ([]*snapshot.Manifest, error) {
				return []*snapshot.Manifest{
					{
						Tags: map[string]string{
							"requester":                  "user1",
							uploader.SnapshotUploaderTag: "uploader1",
							"otherTag":                   "value",
							"snapshotRequestor":          "user1",
							"snapshotUploader":           "uploader1",
						},
						IncompleteReason: "reason",
					},
				}, nil
			},
			expectedSnapshots: []*snapshot.Manifest{},
			expectedError:     nil,
		},
		// Snapshot with manifest SnapshotRequesterTag not found
		{
			name: "Snapshot with manifest SnapshotUploaderTag not found",
			listSnapshotsFunc: func(ctx context.Context, rep repo.Repository, si snapshot.SourceInfo) ([]*snapshot.Manifest, error) {
				return []*snapshot.Manifest{
					{
						Tags: map[string]string{
							uploader.SnapshotRequesterTag: "user1",
							"uploader":                    "uploader1",
							"otherTag":                    "value",
							"snapshotRequestor":           "user1",
							"snapshotUploader":            "uploader1",
						},
						IncompleteReason: "reason",
					},
				}, nil
			},
			expectedSnapshots: []*snapshot.Manifest{},
			expectedError:     nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var repo repo.Repository
			listSnapshotsFunc = tc.listSnapshotsFunc
			snapshots, err := findPreviousSnapshotManifest(t.Context(), repo, sourceInfo, snapshotTags, &noLaterThan, logrus.New())

			// Check if the returned error matches the expected error
			if tc.expectedError != nil {
				require.ErrorContains(t, err, tc.expectedError.Error())
			} else {
				require.NoError(t, err)
			}

			// Check the number of returned snapshots
			if len(snapshots) != len(tc.expectedSnapshots) {
				t.Errorf("Expected %d snapshots, got %d", len(tc.expectedSnapshots), len(snapshots))
			}
		})
	}
}

func TestBackup(t *testing.T) {
	type testCase struct {
		name                  string
		sourcePath            string
		forceFull             bool
		parentSnapshot        string
		tags                  map[string]string
		isEmptyUploader       bool
		isSnapshotSourceError bool
		expectedError         error
		expectedEmpty         bool
		volMode               uploader.PersistentVolumeMode
	}
	manifest := &snapshot.Manifest{
		ID:        "test",
		RootEntry: &snapshot.DirEntry{},
	}
	// Define test cases
	testCases := []testCase{
		{
			name:          "Successful backup",
			sourcePath:    "/",
			tags:          map[string]string{},
			expectedError: nil,
		},
		{
			name:            "Empty fsUploader",
			isEmptyUploader: true,
			sourcePath:      "/",
			tags:            nil,
			expectedError:   errors.New("get empty kopia uploader"),
		},
		{
			name:          "Unable to read directory",
			sourcePath:    "/invalid/path",
			tags:          nil,
			expectedError: errors.New("no such file or directory"),
		},
		{
			name:          "Source path is not a block device",
			sourcePath:    "/",
			tags:          nil,
			volMode:       uploader.PersistentVolumeBlock,
			expectedError: errors.New("source path / is not a block device"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.volMode == "" {
				tc.volMode = uploader.PersistentVolumeFilesystem
			}
			s := injectSnapshotFuncs()
			args := []mockArgs{
				{methodName: "LoadSnapshot", returns: []any{manifest, nil}},
				{methodName: "SaveSnapshot", returns: []any{manifest.ID, nil}},
				{methodName: "TreeForSource", returns: []any{nil, nil}},
				{methodName: "ApplyRetentionPolicy", returns: []any{nil, nil}},
				{methodName: "SetPolicy", returns: []any{nil}},
				{methodName: "Upload", returns: []any{manifest, nil}},
				{methodName: "Flush", returns: []any{nil}},
			}
			MockFuncs(s, args)
			if tc.isSnapshotSourceError {
				s.repoWriterMock.On("FindManifests", mock.Anything, mock.Anything).Return(nil, errors.New("Failed to get manifests"))
				s.repoWriterMock.On("Flush", mock.Anything).Return(errors.New("Failed to get manifests"))
			} else {
				s.repoWriterMock.On("FindManifests", mock.Anything, mock.Anything).Return(nil, nil)
			}

			var isSnapshotEmpty bool
			var snapshotInfo *uploader.SnapshotInfo
			var err error
			if tc.isEmptyUploader {
				snapshotInfo, isSnapshotEmpty, err = Backup(t.Context(), nil, s.repoWriterMock, tc.sourcePath, "", tc.forceFull, tc.parentSnapshot, tc.volMode, map[string]string{}, tc.tags, &logrus.Logger{})
			} else {
				snapshotInfo, isSnapshotEmpty, err = Backup(t.Context(), s.uploderMock, s.repoWriterMock, tc.sourcePath, "", tc.forceFull, tc.parentSnapshot, tc.volMode, map[string]string{}, tc.tags, &logrus.Logger{})
			}
			// Check if the returned error matches the expected error
			if tc.expectedError != nil {
				require.ErrorContains(t, err, tc.expectedError.Error())
			} else {
				require.NoError(t, err)
			}

			assert.Equal(t, tc.expectedEmpty, isSnapshotEmpty)

			if err == nil {
				assert.NotNil(t, snapshotInfo)
			}
		})
	}
}

func TestRestore(t *testing.T) {
	type testCase struct {
		name                string
		snapshotID          string
		invalidManifestType bool
		filesystemEntryFunc func(ctx context.Context, rep repo.Repository, rootID string, consistentAttributes bool) (fs.Entry, error)
		restoreEntryFunc    func(ctx context.Context, rep repo.Repository, output restore.Output, rootEntry fs.Entry, options restore.Options) (restore.Stats, error)
		flushVolumeFunc     func(string) error
		dest                string
		expectedBytes       int64
		expectedCount       int32
		expectedError       error
		volMode             uploader.PersistentVolumeMode
	}

	// Define test cases
	testCases := []testCase{
		{
			name:                "manifest is not a snapshot",
			invalidManifestType: true,
			dest:                "/path/to/destination",
			expectedError:       errors.New("Unable to load snapshot"),
		},
		{
			name:          "Failed to get filesystem entry",
			snapshotID:    "snapshot-123",
			expectedError: errors.New("Unable to get filesystem entry"),
		},
		{
			name: "Failed to restore with filesystem entry",
			filesystemEntryFunc: func(ctx context.Context, rep repo.Repository, rootID string, consistentAttributes bool) (fs.Entry, error) {
				return snapshotfs.EntryFromDirEntry(rep, &snapshot.DirEntry{Type: snapshot.EntryTypeFile}), nil
			},
			restoreEntryFunc: func(ctx context.Context, rep repo.Repository, output restore.Output, rootEntry fs.Entry, options restore.Options) (restore.Stats, error) {
				return restore.Stats{}, errors.New("Unable to get filesystem entry")
			},
			snapshotID:    "snapshot-123",
			expectedError: errors.New("Unable to get filesystem entry"),
		},
		{
			name: "Expect successful",
			filesystemEntryFunc: func(ctx context.Context, rep repo.Repository, rootID string, consistentAttributes bool) (fs.Entry, error) {
				return snapshotfs.EntryFromDirEntry(rep, &snapshot.DirEntry{Type: snapshot.EntryTypeFile}), nil
			},
			restoreEntryFunc: func(ctx context.Context, rep repo.Repository, output restore.Output, rootEntry fs.Entry, options restore.Options) (restore.Stats, error) {
				return restore.Stats{}, nil
			},
			snapshotID:    "snapshot-123",
			expectedError: nil,
		},
		{
			name: "Expect block volume successful",
			filesystemEntryFunc: func(ctx context.Context, rep repo.Repository, rootID string, consistentAttributes bool) (fs.Entry, error) {
				return snapshotfs.EntryFromDirEntry(rep, &snapshot.DirEntry{Type: snapshot.EntryTypeFile}), nil
			},
			restoreEntryFunc: func(ctx context.Context, rep repo.Repository, output restore.Output, rootEntry fs.Entry, options restore.Options) (restore.Stats, error) {
				return restore.Stats{}, nil
			},
			snapshotID:    "snapshot-123",
			expectedError: nil,
			volMode:       uploader.PersistentVolumeBlock,
		},
		{
			name: "Unable to evaluate symlinks for block volume",
			filesystemEntryFunc: func(ctx context.Context, rep repo.Repository, rootID string, consistentAttributes bool) (fs.Entry, error) {
				return snapshotfs.EntryFromDirEntry(rep, &snapshot.DirEntry{Type: snapshot.EntryTypeFile}), nil
			},
			restoreEntryFunc: func(ctx context.Context, rep repo.Repository, output restore.Output, rootEntry fs.Entry, options restore.Options) (restore.Stats, error) {
				err := output.BeginDirectory(ctx, "fake-dir", virtualfs.NewStaticDirectory("fake-dir", nil))
				return restore.Stats{}, err
			},
			snapshotID:    "snapshot-123",
			expectedError: errors.New("unable to evaluate symlinks for"),
			volMode:       uploader.PersistentVolumeBlock,
			dest:          "/wrong-dest",
		},
		{
			name: "Target file is not a block device",
			filesystemEntryFunc: func(ctx context.Context, rep repo.Repository, rootID string, consistentAttributes bool) (fs.Entry, error) {
				return snapshotfs.EntryFromDirEntry(rep, &snapshot.DirEntry{Type: snapshot.EntryTypeFile}), nil
			},
			restoreEntryFunc: func(ctx context.Context, rep repo.Repository, output restore.Output, rootEntry fs.Entry, options restore.Options) (restore.Stats, error) {
				err := output.BeginDirectory(ctx, "fake-dir", virtualfs.NewStaticDirectory("fake-dir", nil))
				return restore.Stats{}, err
			},
			snapshotID:    "snapshot-123",
			expectedError: errors.New("target file /tmp is not a block device"),
			volMode:       uploader.PersistentVolumeBlock,
			dest:          "/tmp",
		},
		{
			name: "Flush is not supported",
			filesystemEntryFunc: func(ctx context.Context, rep repo.Repository, rootID string, consistentAttributes bool) (fs.Entry, error) {
				return snapshotfs.EntryFromDirEntry(rep, &snapshot.DirEntry{Type: snapshot.EntryTypeFile}), nil
			},
			restoreEntryFunc: func(ctx context.Context, rep repo.Repository, output restore.Output, rootEntry fs.Entry, options restore.Options) (restore.Stats, error) {
				return restore.Stats{}, nil
			},
			flushVolumeFunc: func(string) error { return errFlushUnsupported },
			snapshotID:      "snapshot-123",
			expectedError:   nil,
		},
		{
			name: "Flush fails",
			filesystemEntryFunc: func(ctx context.Context, rep repo.Repository, rootID string, consistentAttributes bool) (fs.Entry, error) {
				return snapshotfs.EntryFromDirEntry(rep, &snapshot.DirEntry{Type: snapshot.EntryTypeFile}), nil
			},
			restoreEntryFunc: func(ctx context.Context, rep repo.Repository, output restore.Output, rootEntry fs.Entry, options restore.Options) (restore.Stats, error) {
				return restore.Stats{}, nil
			},
			flushVolumeFunc: func(string) error { return errors.New("fake-flush-error") },
			snapshotID:      "snapshot-123",
			expectedError:   errors.New("fake-flush-error"),
		},
	}

	em := &manifest.EntryMetadata{
		ID:     "test",
		Labels: map[string]string{},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.volMode == "" {
				tc.volMode = uploader.PersistentVolumeFilesystem
			}

			if tc.invalidManifestType {
				em.Labels[manifest.TypeLabelKey] = ""
			} else {
				em.Labels[manifest.TypeLabelKey] = snapshot.ManifestType
			}

			if tc.filesystemEntryFunc != nil {
				filesystemEntryFunc = tc.filesystemEntryFunc
			}

			if tc.restoreEntryFunc != nil {
				restoreEntryFunc = tc.restoreEntryFunc
			}

			if tc.flushVolumeFunc != nil {
				flushVolumeFunc = tc.flushVolumeFunc
			}

			repoWriterMock := &repomocks.RepositoryWriter{}
			repoWriterMock.On("GetManifest", mock.Anything, mock.Anything, mock.Anything).Return(em, nil)
			repoWriterMock.On("OpenObject", mock.Anything, mock.Anything).Return(em, nil)

			progress := new(Progress)
			bytesRestored, fileCount, err := Restore(t.Context(), repoWriterMock, progress, tc.snapshotID, tc.dest, tc.volMode, map[string]string{}, logrus.New(), nil)

			// Check if the returned error matches the expected error
			if tc.expectedError != nil {
				require.ErrorContains(t, err, tc.expectedError.Error())
			} else {
				require.NoError(t, err)
			}

			// Check the number of bytes restored
			assert.Equal(t, tc.expectedBytes, bytesRestored)

			// Check the number of files restored
			assert.Equal(t, tc.expectedCount, fileCount)
		})
	}
}
