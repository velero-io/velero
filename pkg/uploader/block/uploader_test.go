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
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/vmware-tanzu/velero/pkg/repository/udmrepo"
	udmrepomocks "github.com/vmware-tanzu/velero/pkg/repository/udmrepo/mocks"
	"github.com/vmware-tanzu/velero/pkg/uploader"
	cbt "github.com/vmware-tanzu/velero/pkg/uploader/cbt/types"
	cbtmocks "github.com/vmware-tanzu/velero/pkg/uploader/cbt/types/mocks"
)

type mockProgressUpdater struct {
	mock.Mock
}

func (m *mockProgressUpdater) UpdateProgress(p *uploader.Progress) {
	m.Called(p)
}

func TestNewUploader(t *testing.T) {
	ctx := context.Background()
	repoWriter := udmrepomocks.NewBackupRepo(t)
	progress := &mockProgressUpdater{}
	log := logrus.New()

	uploader := NewUploader(ctx, repoWriter, progress, log)

	blkup, ok := uploader.(*blockUploader)
	assert.True(t, ok)
	assert.Equal(t, ctx, blkup.ctx)
	assert.Equal(t, repoWriter, blkup.repoWriter)
	assert.Equal(t, progress, blkup.progress)
	assert.Equal(t, log, blkup.log)
}

func TestGetObjectName(t *testing.T) {
	testCases := []struct {
		name     string
		source   string
		expected string
	}{
		{
			name:     "no slashes",
			source:   "test",
			expected: "test",
		},
		{
			name:     "unix path",
			source:   "/var/lib/kubelet/pods/uuid/volumes/test",
			expected: "var-lib-kubelet-pods-uuid-volumes-test",
		},
		{
			name:     "windows path",
			source:   `c:\var\lib\kubelet\pods\uuid\volumes\test`,
			expected: `c:-var-lib-kubelet-pods-uuid-volumes-test`,
		},
		{
			name:     "mixed slashes",
			source:   `c:\var/lib\kubelet/pods`,
			expected: `c:-var-lib-kubelet-pods`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := getObjectName(tc.source)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestCopyTailData(t *testing.T) {
	testCases := []struct {
		name        string
		totalLength int64
		blockSize   int64
		sourceData  []byte
		writeErr    error
		readErr     error
		expected    int64
		expectErr   bool
	}{
		{
			name:        "tail length 0",
			totalLength: 2048,
			blockSize:   1024,
			expected:    0,
		},
		{
			name:        "tail length 512 with 1024 block size",
			totalLength: 1536,
			blockSize:   1024,
			sourceData:  make([]byte, 1536),
			expected:    512,
		},
		{
			name:        "tail length with write error",
			totalLength: 1536,
			blockSize:   1024,
			sourceData:  make([]byte, 1536),
			writeErr:    errors.New("write error"),
			expectErr:   true,
		},
		{
			name:        "tail length 0 with sparse write error",
			totalLength: 2048,
			blockSize:   1024,
			writeErr:    errors.New("write error"),
			expectErr:   true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			writer := udmrepomocks.NewObjectWriter(t)
			var source io.ReaderAt

			if tc.totalLength%tc.blockSize == 0 {
				writer.On("WriteAt", []byte(nil), tc.totalLength).Return(0, tc.writeErr)
			} else {
				length := tc.totalLength - (tc.totalLength/tc.blockSize)*tc.blockSize
				paddedData := make([]byte, tc.blockSize)
				copy(paddedData[:length], tc.sourceData)

				source = bytes.NewReader(tc.sourceData)
				writer.On("WriteAt", paddedData, (tc.totalLength/tc.blockSize)*tc.blockSize).Return(int(tc.blockSize), tc.writeErr)
			}

			n, err := copyTailData(source, writer, tc.totalLength, tc.blockSize)
			if tc.expectErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expected, n)
			}
		})
	}
}

func TestBlockUploaderBackup(t *testing.T) {
	testCases := []struct {
		name             string
		nilBitmap        bool
		createObjErr     error
		writeMetaErr     error
		writeObjErr      error
		parentObj        udmrepo.ID
		cancelCtx        bool
		cancelInProgress bool
		readDataErr      bool
		shortWrite       bool
		fewerBlocks      bool
		expectErr        bool
		expectErrStr     string
	}{
		{
			name:      "nil bitmap",
			nilBitmap: true,
			expectErr: true,
		},
		{
			name:         "canceled context",
			cancelCtx:    true,
			expectErr:    true,
			expectErrStr: "uploader is canceled",
		},
		{
			name:             "canceled in progress",
			cancelInProgress: true,
			expectErr:        true,
			expectErrStr:     "error backing up bdev /data/volume1: uploader is canceled",
		},
		{
			name:         "create object writer err",
			createObjErr: errors.New("create obj err"),
			expectErr:    true,
		},
		{
			name:         "read data err",
			readDataErr:  true,
			expectErr:    true,
			expectErrStr: "EOF",
		},
		{
			name:         "short write err",
			shortWrite:   true,
			expectErr:    true,
			expectErrStr: "short write",
		},
		{
			name:         "unexpected EOF fewer blocks",
			fewerBlocks:  true,
			expectErr:    true,
			expectErrStr: "unexpected EOF",
		},
		{
			name:         "write meta err",
			writeMetaErr: errors.New("write meta err"),
			expectErr:    true,
		},
		{
			name:      "success full backup",
			parentObj: "",
			expectErr: false,
		},
		{
			name:      "success inc backup",
			parentObj: "parent-01",
			expectErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			var cancel context.CancelFunc
			ctx, cancel = context.WithCancel(ctx)

			if tc.cancelCtx {
				cancel()
			} else if tc.cancelInProgress {
				go func() {
					time.Sleep(100 * time.Millisecond)
					cancel()
				}()
			} else {
				defer cancel()
			}

			repoWriter := udmrepomocks.NewBackupRepo(t)
			progress := &mockProgressUpdater{}
			progress.On("UpdateProgress", mock.Anything).Return()
			log := logrus.New()
			log.Out = io.Discard

			blkup := NewUploader(ctx, repoWriter, progress, log)

			f, err := os.CreateTemp(t.TempDir(), "blktest-*")
			require.NoError(t, err)
			defer os.Remove(f.Name())
			defer f.Close()

			if tc.cancelInProgress {
				require.NoError(t, f.Truncate(2*1048576))
			} else if tc.readDataErr {
				// Don't truncate so that reading hits EOF immediately
			} else {
				require.NoError(t, f.Truncate(1048576))
			}

			fi, err := f.Stat()
			require.NoError(t, err)

			srcInfo := sourceInfo{
				dev:        f,
				realSource: "/data/volume1",
				size:       fi.Size(),
			}

			if tc.readDataErr {
				srcInfo.size = 1048576
			}

			repoWriter.On("Time").Return(time.Now())

			var iterator cbt.Iterator
			if !tc.nilBitmap {
				iterMock := cbtmocks.NewIterator(t)
				iterator = iterMock

				backupMode := udmrepo.ObjectDataBackupModeInc
				if tc.parentObj == "" {
					backupMode = udmrepo.ObjectDataBackupModeFull
				}

				objWriter := udmrepomocks.NewObjectWriter(t)
				if tc.createObjErr == nil {
					objWriter.On("Close").Return(nil)

					if tc.cancelInProgress {
						iterMock.On("BlockSize").Return(uint(1048576))
						iterMock.On("Count").Return(uint64(1000))
						iterMock.On("Next").Return(uint64(0), true)

						objWriter.On("WriteAt", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
							<-ctx.Done()
						}).Return(1048576, nil)
						objWriter.On("Result").Return(udmrepo.ID(""), errors.New("write failed")).Maybe()
					} else if tc.cancelCtx {
						iterMock.On("BlockSize").Return(uint(1048576))
						iterMock.On("Count").Return(uint64(1))
						iterMock.On("Next").Return(uint64(0), true).Maybe()

						objWriter.On("Result").Return(udmrepo.ID(""), errors.New("write failed")).Maybe()
					} else if tc.shortWrite {
						iterMock.On("BlockSize").Return(uint(1048576))
						iterMock.On("Count").Return(uint64(1))
						iterMock.On("Next").Return(uint64(0), true)

						objWriter.On("WriteAt", mock.Anything, mock.Anything).Return(512, nil)
						objWriter.On("Result").Return(udmrepo.ID(""), errors.New("write failed")).Maybe()
					} else if tc.fewerBlocks {
						iterMock.On("BlockSize").Return(uint(1048576))
						iterMock.On("Count").Return(uint64(5))
						iterMock.On("Next").Return(uint64(0), false)

						objWriter.On("Result").Return(udmrepo.ID(""), errors.New("write failed")).Maybe()
					} else if tc.readDataErr {
						iterMock.On("BlockSize").Return(uint(1048576))
						iterMock.On("Count").Return(uint64(1))
						iterMock.On("Next").Return(uint64(0), true)

						objWriter.On("Result").Return(udmrepo.ID(""), errors.New("write failed")).Maybe()
					} else {
						// Setup backupData sequence: next returns false immediately
						iterMock.On("BlockSize").Return(uint(1048576))
						iterMock.On("Count").Return(uint64(0))
						iterMock.On("Next").Return(uint64(0), false)

						if tc.writeObjErr != nil {
							objWriter.On("WriteAt", mock.Anything, mock.Anything).Return(0, tc.writeObjErr)
							objWriter.On("Result").Return(udmrepo.ID(""), errors.New("write failed"))
						} else {
							objWriter.On("WriteAt", mock.Anything, mock.Anything).Return(1048576, nil)
							objWriter.On("Result").Return(udmrepo.ID("obj-01"), nil)
							repoWriter.On("WriteMetadata", mock.Anything, mock.Anything, mock.Anything).Return(udmrepo.ID("meta-01"), tc.writeMetaErr)
						}
					}
				}

				repoWriter.On("NewObjectWriter", mock.Anything, mock.MatchedBy(func(opt udmrepo.ObjectWriteOptions) bool {
					return opt.Description == "BDEV:data-volume1" && opt.BackupMode == backupMode
				})).Return(objWriter, tc.createObjErr)
			}

			snap, size, err := blkup.Backup(srcInfo, tc.parentObj, iterator, nil)

			if tc.expectErr {
				require.Error(t, err)
				if tc.expectErrStr != "" {
					assert.Contains(t, err.Error(), tc.expectErrStr)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, "/data/volume1", snap.Source)
				assert.Equal(t, udmrepo.ID("meta-01"), snap.RootObject.ID)
				assert.Equal(t, int64(0), size)
			}
		})
	}
}

func TestLoadObjectFromSnapshot(t *testing.T) {
	testCases := []struct {
		name           string
		snapshot       *udmrepo.Snapshot
		setupMocks     func(repo *udmrepomocks.BackupRepo)
		expectedErrStr string
		expectedID     udmrepo.ID
	}{
		{
			name:           "nil snapshot",
			snapshot:       nil,
			expectedErrStr: "snapshot is empty",
		},
		{
			name: "ReadMetadata error",
			snapshot: &udmrepo.Snapshot{
				RootObject: udmrepo.ObjectMetadata{ID: "root-obj"},
			},
			setupMocks: func(repo *udmrepomocks.BackupRepo) {
				repo.On("ReadMetadata", mock.Anything, udmrepo.ID("root-obj")).
					Return(nil, errors.New("read error"))
			},
			expectedErrStr: "error reading snapshot metadata",
		},
		{
			name: "unexpected number of subobjects (0)",
			snapshot: &udmrepo.Snapshot{
				RootObject: udmrepo.ObjectMetadata{ID: "root-obj"},
			},
			setupMocks: func(repo *udmrepomocks.BackupRepo) {
				repo.On("ReadMetadata", mock.Anything, udmrepo.ID("root-obj")).
					Return(&udmrepo.Metadata{SubObjects: []udmrepo.ObjectMetadata{}}, nil)
			},
			expectedErrStr: "unexpected number of bdev object",
		},
		{
			name: "unexpected number of subobjects (2)",
			snapshot: &udmrepo.Snapshot{
				RootObject: udmrepo.ObjectMetadata{ID: "root-obj"},
			},
			setupMocks: func(repo *udmrepomocks.BackupRepo) {
				repo.On("ReadMetadata", mock.Anything, udmrepo.ID("root-obj")).
					Return(&udmrepo.Metadata{SubObjects: []udmrepo.ObjectMetadata{{ID: "obj-1"}, {ID: "obj-2"}}}, nil)
			},
			expectedErrStr: "unexpected number of bdev object",
		},
		{
			name: "success",
			snapshot: &udmrepo.Snapshot{
				RootObject: udmrepo.ObjectMetadata{ID: "root-obj"},
			},
			setupMocks: func(repo *udmrepomocks.BackupRepo) {
				repo.On("ReadMetadata", mock.Anything, udmrepo.ID("root-obj")).
					Return(&udmrepo.Metadata{SubObjects: []udmrepo.ObjectMetadata{{ID: "bdev-obj"}}}, nil)
			},
			expectedID: "bdev-obj",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			mockRepo := udmrepomocks.NewBackupRepo(t)

			if tc.setupMocks != nil {
				tc.setupMocks(mockRepo)
			}

			id, err := loadObjectFromSnapshot(ctx, mockRepo, tc.snapshot)

			if tc.expectedErrStr != "" {
				require.Error(t, err)
				require.ErrorContains(t, err, tc.expectedErrStr)
				assert.Empty(t, id)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedID, id)
			}
		})
	}
}
