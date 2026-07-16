/*
Copyright the Velero contributors.

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

package kopialib

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/kopia/kopia/repo"
	"github.com/kopia/kopia/repo/content"
	"github.com/kopia/kopia/repo/object"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/vmware-tanzu/velero/pkg/repository/udmrepo"
	repomocks "github.com/vmware-tanzu/velero/pkg/repository/udmrepo/kopialib/backend/mocks"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
	"github.com/vmware-tanzu/velero/pkg/util/freelist"
)

type mockDirectRepository struct {
	repo.DirectRepository
	mock.Mock
}

func (m *mockDirectRepository) ContentInfo(ctx context.Context, contentID content.ID) (content.Info, error) {
	args := m.Called(ctx, contentID)
	return args.Get(0).(content.Info), args.Error(1)
}

func (m *mockDirectRepository) ContentReader() content.Reader {
	args := m.Called()
	return args.Get(0).(content.Reader)
}

type mockContentReader struct {
	content.Reader
	mock.Mock
}

func (m *mockContentReader) GetContent(ctx context.Context, contentID content.ID) ([]byte, error) {
	args := m.Called(ctx, contentID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

func TestContentInfo(t *testing.T) {
	testCases := []struct {
		name        string
		rawRepo     repo.Repository
		contentID   content.ID
		expectedErr string
	}{
		{
			name: "success",
			rawRepo: func() repo.Repository {
				m := repomocks.NewMockRepository(t)
				m.On("ContentInfo", mock.Anything, mock.Anything).Return(content.Info{}, nil)
				return m
			}(),
		},
		{
			name: "error",
			rawRepo: func() repo.Repository {
				m := repomocks.NewMockRepository(t)
				m.On("ContentInfo", mock.Anything, mock.Anything).Return(content.Info{}, assert.AnError)
				return m
			}(),
			expectedErr: assert.AnError.Error(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			kr := &kopiaRepository{rawRepo: tc.rawRepo, logger: velerotest.NewLogger()}
			_, err := kr.ContentInfo(context.Background(), tc.contentID)
			if tc.expectedErr != "" {
				assert.EqualError(t, err, tc.expectedErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGetContent(t *testing.T) {
	testCases := []struct {
		name        string
		rawRepo     repo.Repository
		contentID   content.ID
		expectedErr string
	}{
		{
			name:        "invalid repo interface",
			rawRepo:     repomocks.NewMockRepository(t),
			expectedErr: "invalid repo interface",
		},
		{
			name: "success",
			rawRepo: func() repo.Repository {
				m := &mockDirectRepository{}
				cr := &mockContentReader{}
				cr.On("GetContent", mock.Anything, mock.Anything).Return([]byte("test"), nil)
				m.On("ContentReader").Return(cr)
				return m
			}(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			kr := &kopiaRepository{rawRepo: tc.rawRepo, logger: velerotest.NewLogger()}
			_, err := kr.GetContent(context.Background(), tc.contentID)
			if tc.expectedErr != "" {
				assert.EqualError(t, err, tc.expectedErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPrefetchContents(t *testing.T) {
	mockRepo := repomocks.NewMockRepository(t)
	id, _ := content.ParseID("123")
	mockRepo.On("PrefetchContents", mock.Anything, mock.Anything, mock.Anything).Return([]content.ID{id})
	kr := &kopiaRepository{rawRepo: mockRepo, logger: velerotest.NewLogger()}
	res := kr.PrefetchContents(context.Background(), []content.ID{id}, "hint")
	assert.Equal(t, []content.ID{id}, res)
}

func TestGetFlattenedEntries(t *testing.T) {
	kr := &kopiaRepository{logger: velerotest.NewLogger()}
	rawID := object.ID{}
	_, err := kr.getFlattenedEntries(context.Background(), rawID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "object is not an indirect object")
}

func TestNewObjectWriterEx(t *testing.T) {
	testCases := []struct {
		name        string
		opt         udmrepo.ObjectWriteOptions
		rawWriter   *repomocks.MockRepositoryWriter
		expectedErr string
	}{
		{
			name: "block mode success without parent",
			opt: udmrepo.ObjectWriteOptions{
				AccessMode: udmrepo.ObjectDataAccessModeBlock,
			},
			rawWriter: repomocks.NewMockRepositoryWriter(t),
		},
		{
			name: "block mode with parent, invalid parent ID",
			opt: udmrepo.ObjectWriteOptions{
				AccessMode:   udmrepo.ObjectDataAccessModeBlock,
				ParentObject: udmrepo.ID("invalid-parent"),
			},
			rawWriter:   repomocks.NewMockRepositoryWriter(t),
			expectedErr: "error parsing parent object ID from invalid-parent: malformed content ID: \"invalid-parent\": invalid content hash: encoding/hex: invalid byte: U+0069 'i'",
		},
		{
			name: "block mode with parent, valid ID but failed to load index",
			opt: udmrepo.ObjectWriteOptions{
				AccessMode:   udmrepo.ObjectDataAccessModeBlock,
				ParentObject: udmrepo.ID("I0123456789abcdef"),
			},
			rawWriter:   repomocks.NewMockRepositoryWriter(t),
			expectedErr: "error getting parent object entries from I0123456789abcdef: unexpected content error: invalid repo interface",
		},
		{
			name: "file mode with parent",
			opt: udmrepo.ObjectWriteOptions{
				AccessMode:   udmrepo.ObjectDataAccessModeFile,
				ParentObject: udmrepo.ID("some-parent"),
			},
			rawWriter:   repomocks.NewMockRepositoryWriter(t),
			expectedErr: "parent object is only supported for block mode",
		},
		{
			name: "block mode success with async writes",
			opt: udmrepo.ObjectWriteOptions{
				AccessMode:  udmrepo.ObjectDataAccessModeBlock,
				AsyncWrites: 4,
			},
			rawWriter: repomocks.NewMockRepositoryWriter(t),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			kr := &kopiaRepository{logger: velerotest.NewLogger()}
			if tc.rawWriter != nil {
				kr.rawWriter = tc.rawWriter
			}

			_, err := kr.NewObjectWriter(context.Background(), tc.opt)

			if tc.expectedErr == "" {
				require.NoError(t, err)
			} else {
				require.EqualError(t, err, tc.expectedErr)
			}
		})
	}
}

func TestKopiaObjectWriterEx_Write(t *testing.T) {
	testCases := []struct {
		name        string
		setupWriter func(t *testing.T) *kopiaObjectWriterEx
		inputData   []byte
		expectedErr string
		expectedLen int
		verify      func(t *testing.T, kow *kopiaObjectWriterEx)
	}{
		{
			name: "writer is closed",
			setupWriter: func(t *testing.T) *kopiaObjectWriterEx {
				t.Helper()
				return &kopiaObjectWriterEx{
					rawRepoWriter: nil,
				}
			},
			inputData:   make([]byte, 1024),
			expectedErr: "object writer is closed or not open",
		},
		{
			name: "write error exists",
			setupWriter: func(t *testing.T) *kopiaObjectWriterEx {
				t.Helper()
				kow := &kopiaObjectWriterEx{
					rawRepoWriter: repomocks.NewMockRepositoryWriter(t),
					blockSize:     1024,
				}
				kow.saveWriteError(errors.New("previous error"))
				return kow
			},
			inputData:   make([]byte, 1024),
			expectedErr: "error happened during writing object: previous error",
		},
		{
			name: "invalid length",
			setupWriter: func(t *testing.T) *kopiaObjectWriterEx {
				t.Helper()
				return &kopiaObjectWriterEx{
					rawRepoWriter: repomocks.NewMockRepositoryWriter(t),
					blockSize:     1024,
				}
			},
			inputData:   make([]byte, 1023),
			expectedErr: "invalid length 1023",
		},
		{
			name: "write object returns nil writer",
			setupWriter: func(t *testing.T) *kopiaObjectWriterEx {
				t.Helper()
				mockRepoWriter := repomocks.NewMockRepositoryWriter(t)
				mockRepoWriter.On("NewObjectWriter", mock.Anything, mock.Anything).Return(nil)

				return &kopiaObjectWriterEx{
					ctx:           context.Background(),
					rawRepoWriter: mockRepoWriter,
					blockSize:     1024,
					logger:        velerotest.NewLogger(),
				}
			},
			inputData:   make([]byte, 1024),
			expectedLen: 1024,
			verify: func(t *testing.T, kow *kopiaObjectWriterEx) {
				t.Helper()
				err := kow.getWriteError()
				require.Error(t, err)
				assert.Contains(t, err.Error(), "error opening writer for -b0")
			},
		},
		{
			name: "write object result error",
			setupWriter: func(t *testing.T) *kopiaObjectWriterEx {
				t.Helper()
				mockRepoWriter := repomocks.NewMockRepositoryWriter(t)
				mockWriter := repomocks.NewWriter(t)

				mockWriter.On("Write", mock.Anything).Return(1024, nil)
				mockWriter.On("Close").Return(nil)

				mockWriter.On("Result").Return(object.EmptyID, errors.New("simulated result error"))

				mockRepoWriter.On("NewObjectWriter", mock.Anything, mock.Anything).Return(mockWriter)

				return &kopiaObjectWriterEx{
					ctx:           context.Background(),
					rawRepoWriter: mockRepoWriter,
					blockSize:     1024,
					logger:        velerotest.NewLogger(),
				}
			},
			inputData:   make([]byte, 1024),
			expectedLen: 1024,
			verify: func(t *testing.T, kow *kopiaObjectWriterEx) {
				t.Helper()
				err := kow.getWriteError()
				require.Error(t, err)
				assert.Contains(t, err.Error(), "simulated result error")
			},
		},
		{
			name: "success sync write",
			setupWriter: func(t *testing.T) *kopiaObjectWriterEx {
				t.Helper()
				mockRepoWriter := repomocks.NewMockRepositoryWriter(t)
				mockWriter := repomocks.NewWriter(t)

				mockWriter.On("Write", mock.Anything).Return(1024, nil)
				mockWriter.On("Close").Return(nil)

				id, _ := object.ParseID("I12345")
				mockWriter.On("Result").Return(id, nil)

				mockRepoWriter.On("NewObjectWriter", mock.Anything, mock.Anything).Return(mockWriter)

				return &kopiaObjectWriterEx{
					ctx:           context.Background(),
					rawRepoWriter: mockRepoWriter,
					blockSize:     1024,
					logger:        velerotest.NewLogger(),
				}
			},
			inputData:   make([]byte, 1024),
			expectedLen: 1024,
		},
		{
			name: "success async write",
			setupWriter: func(t *testing.T) *kopiaObjectWriterEx {
				t.Helper()
				mockRepoWriter := repomocks.NewMockRepositoryWriter(t)
				mockWriter := repomocks.NewWriter(t)

				mockWriter.On("Write", mock.Anything).Return(1024, nil)
				mockWriter.On("Close").Return(nil)

				id, _ := object.ParseID("I12345")
				mockWriter.On("Result").Return(id, nil)

				mockRepoWriter.On("NewObjectWriter", mock.Anything, mock.Anything).Return(mockWriter)

				sem := make(chan struct{}, 1)
				buf := freelist.New(1024, 1024)

				return &kopiaObjectWriterEx{
					ctx:            context.Background(),
					rawRepoWriter:  mockRepoWriter,
					blockSize:      1024,
					asyncWritesSem: sem,
					asyncBuffer:    buf,
					logger:         velerotest.NewLogger(),
				}
			},
			inputData:   make([]byte, 1024),
			expectedLen: 1024,
		},
		{
			name: "success multiple blocks in one write",
			setupWriter: func(t *testing.T) *kopiaObjectWriterEx {
				t.Helper()
				mockRepoWriter := repomocks.NewMockRepositoryWriter(t)
				mockWriter := repomocks.NewWriter(t)

				mockWriter.On("Write", mock.Anything).Return(1024, nil)
				mockWriter.On("Close").Return(nil)

				id, _ := object.ParseID("I12345")
				mockWriter.On("Result").Return(id, nil)

				mockRepoWriter.On("NewObjectWriter", mock.Anything, mock.Anything).Return(mockWriter)

				return &kopiaObjectWriterEx{
					ctx:           context.Background(),
					rawRepoWriter: mockRepoWriter,
					blockSize:     1024,
					logger:        velerotest.NewLogger(),
				}
			},
			inputData:   make([]byte, 2048),
			expectedLen: 2048,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			kow := tc.setupWriter(t)
			l, err := kow.Write(tc.inputData)

			if kow.asyncWritesSem != nil {
				kow.asyncWritesGroup.Wait()
			}

			if tc.expectedErr != "" {
				assert.EqualError(t, err, tc.expectedErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedLen, l)
				if tc.verify != nil {
					tc.verify(t, kow)
				}
			}
		})
	}
}

func TestKopiaObjectWriterEx_Result(t *testing.T) {
	testCases := []struct {
		name        string
		setupWriter func(t *testing.T) *kopiaObjectWriterEx
		expectedErr string
		expectedID  udmrepo.ID
	}{
		{
			name: "write error exists",
			setupWriter: func(t *testing.T) *kopiaObjectWriterEx {
				t.Helper()
				kow := &kopiaObjectWriterEx{}
				kow.saveWriteError(errors.New("async write failed"))
				return kow
			},
			expectedErr: "error happened during writing object: async write failed",
		},
		{
			name: "writer closed",
			setupWriter: func(t *testing.T) *kopiaObjectWriterEx {
				t.Helper()
				kow := &kopiaObjectWriterEx{
					rawRepoWriter: nil,
				}
				return kow
			},
			expectedErr: "error to write indirect object: object writer is closed or not open",
		},
		{
			name: "success",
			setupWriter: func(t *testing.T) *kopiaObjectWriterEx {
				t.Helper()
				mockRepoWriter := repomocks.NewMockRepositoryWriter(t)
				mockWriter := repomocks.NewWriter(t)

				mockWriter.On("Write", mock.Anything).Return(100, nil)
				mockWriter.On("Close").Return(nil)

				id, _ := object.ParseID("Iabcdef")
				mockWriter.On("Result").Return(id, nil)

				mockRepoWriter.On("NewObjectWriter", mock.Anything, mock.Anything).Return(mockWriter)

				return &kopiaObjectWriterEx{
					ctx:           context.Background(),
					rawRepoWriter: mockRepoWriter,
					logger:        velerotest.NewLogger(),
				}
			},
			expectedID: udmrepo.ID("IIabcdef"),
		},
		{
			name: "write indirect object encoding failure",
			setupWriter: func(t *testing.T) *kopiaObjectWriterEx {
				t.Helper()
				mockRepoWriter := repomocks.NewMockRepositoryWriter(t)
				mockWriter := repomocks.NewWriter(t)

				mockWriter.On("Write", mock.Anything).Return(0, errors.New("json encoding failed"))
				mockWriter.On("Close").Return(nil)

				mockRepoWriter.On("NewObjectWriter", mock.Anything, mock.Anything).Return(mockWriter)

				return &kopiaObjectWriterEx{
					ctx:           context.Background(),
					rawRepoWriter: mockRepoWriter,
					logger:        velerotest.NewLogger(),
				}
			},
			expectedErr: "error to write indirect object: unable to write indirect object index: json encoding failed",
		},
		{
			name: "write indirect object result failure",
			setupWriter: func(t *testing.T) *kopiaObjectWriterEx {
				t.Helper()
				mockRepoWriter := repomocks.NewMockRepositoryWriter(t)
				mockWriter := repomocks.NewWriter(t)

				mockWriter.On("Write", mock.Anything).Return(100, nil)
				mockWriter.On("Close").Return(nil)

				mockWriter.On("Result").Return(object.EmptyID, errors.New("result generation failed"))

				mockRepoWriter.On("NewObjectWriter", mock.Anything, mock.Anything).Return(mockWriter)

				return &kopiaObjectWriterEx{
					ctx:           context.Background(),
					rawRepoWriter: mockRepoWriter,
					logger:        velerotest.NewLogger(),
				}
			},
			expectedErr: "error to write indirect object: result generation failed",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			kow := tc.setupWriter(t)
			id, err := kow.Result()

			if tc.expectedErr != "" {
				assert.EqualError(t, err, tc.expectedErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedID, id)
			}
		})
	}
}

func TestKopiaObjectWriterEx_Close(t *testing.T) {
	kow := &kopiaObjectWriterEx{}
	err := kow.Close()
	assert.NoError(t, err)
}

func TestKopiaObjectWriterEx_ConcurrentWrite(t *testing.T) {
	mockRepoWriter := repomocks.NewMockRepositoryWriter(t)
	mockWriter := repomocks.NewWriter(t)

	mockWriter.On("Write", mock.Anything).Return(1024, nil)
	mockWriter.On("Close").Return(nil)

	id, _ := object.ParseID("I12345")
	mockWriter.On("Result").Return(id, nil)

	mockRepoWriter.On("NewObjectWriter", mock.Anything, mock.Anything).Return(mockWriter)

	kow := &kopiaObjectWriterEx{
		ctx:           context.Background(),
		rawRepoWriter: mockRepoWriter,
		blockSize:     1024,
		logger:        velerotest.NewLogger(),
	}

	numGoroutines := 10
	var wg sync.WaitGroup

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			data := make([]byte, 1024)
			l, err := kow.Write(data)
			assert.NoError(t, err)
			assert.Equal(t, 1024, l)
		}()
	}

	wg.Wait()

	assert.Len(t, kow.entries, numGoroutines)
}

func TestKopiaObjectWriterEx_ConcurrentAsyncWrite(t *testing.T) {
	mockRepoWriter := repomocks.NewMockRepositoryWriter(t)
	mockWriter := repomocks.NewWriter(t)

	mockWriter.On("Write", mock.Anything).Return(1024, nil)
	mockWriter.On("Close").Return(nil)

	id, _ := object.ParseID("I12345")
	mockWriter.On("Result").Return(id, nil)

	mockRepoWriter.On("NewObjectWriter", mock.Anything, mock.Anything).Return(mockWriter)

	sem := make(chan struct{}, 5)
	buf := freelist.New(5*1024, 1024)

	kow := &kopiaObjectWriterEx{
		ctx:            context.Background(),
		rawRepoWriter:  mockRepoWriter,
		blockSize:      1024,
		asyncWritesSem: sem,
		asyncBuffer:    buf,
		logger:         velerotest.NewLogger(),
	}

	numGoroutines := 10
	var wg sync.WaitGroup

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			data := make([]byte, 1024)
			l, err := kow.Write(data)
			assert.NoError(t, err)
			assert.Equal(t, 1024, l)
		}()
	}

	wg.Wait()

	kow.asyncWritesGroup.Wait()

	assert.Len(t, kow.entries, numGoroutines)
}

func TestKopiaObjectWriterEx_MultipleWrites(t *testing.T) {
	mockRepoWriter := repomocks.NewMockRepositoryWriter(t)
	mockWriter := repomocks.NewWriter(t)

	mockWriter.On("Write", mock.Anything).Return(1024, nil)
	mockWriter.On("Close").Return(nil)

	id, _ := object.ParseID("I12345")
	mockWriter.On("Result").Return(id, nil)

	mockRepoWriter.On("NewObjectWriter", mock.Anything, mock.Anything).Return(mockWriter)

	kow := &kopiaObjectWriterEx{
		ctx:           context.Background(),
		rawRepoWriter: mockRepoWriter,
		blockSize:     1024,
		logger:        velerotest.NewLogger(),
	}

	l, err := kow.Write(make([]byte, 1024))
	require.NoError(t, err)
	assert.Equal(t, 1024, l)

	l, err = kow.Write(make([]byte, 2048))
	require.NoError(t, err)
	assert.Equal(t, 2048, l)

	// In the end we expect 3 blocks to be tracked in `kow.entries`
	assert.Len(t, kow.entries, 3)
	assert.Equal(t, int64(0), kow.entries[0].Start)
	assert.Equal(t, int64(1024), kow.entries[1].Start)
	assert.Equal(t, int64(2048), kow.entries[2].Start)
}

func TestKopiaObjectWriterEx_WriteAt(t *testing.T) {
	testCases := []struct {
		name        string
		setupWriter func(t *testing.T) *kopiaObjectWriterEx
		inputData   []byte
		offset      int64
		expectedErr string
		expectedLen int
		verify      func(t *testing.T, kow *kopiaObjectWriterEx)
	}{
		{
			name: "writer is closed",
			setupWriter: func(t *testing.T) *kopiaObjectWriterEx {
				t.Helper()
				return &kopiaObjectWriterEx{
					rawRepoWriter: nil,
				}
			},
			inputData:   make([]byte, 1024),
			offset:      0,
			expectedErr: "object writer is closed or not open",
		},
		{
			name: "invalid offset",
			setupWriter: func(t *testing.T) *kopiaObjectWriterEx {
				t.Helper()
				return &kopiaObjectWriterEx{
					rawRepoWriter: repomocks.NewMockRepositoryWriter(t),
					blockSize:     1024,
				}
			},
			inputData:   make([]byte, 1024),
			offset:      1023,
			expectedErr: "invalid offset 1023",
		},
		{
			name: "invalid length",
			setupWriter: func(t *testing.T) *kopiaObjectWriterEx {
				t.Helper()
				return &kopiaObjectWriterEx{
					rawRepoWriter: repomocks.NewMockRepositoryWriter(t),
					blockSize:     1024,
				}
			},
			inputData:   make([]byte, 1023),
			offset:      0,
			expectedErr: "invalid length 1023",
		},
		{
			name: "cannot write back",
			setupWriter: func(t *testing.T) *kopiaObjectWriterEx {
				t.Helper()
				return &kopiaObjectWriterEx{
					rawRepoWriter: repomocks.NewMockRepositoryWriter(t),
					blockSize:     1024,
					entries: []object.IndirectObjectEntry{
						{Start: 0, Length: 1024},
					},
				}
			},
			inputData:   make([]byte, 1024),
			offset:      0,
			expectedErr: "cannot write back, cur pos 1024",
		},
		{
			name: "success write at cur pos",
			setupWriter: func(t *testing.T) *kopiaObjectWriterEx {
				t.Helper()
				mockRepoWriter := repomocks.NewMockRepositoryWriter(t)
				mockWriter := repomocks.NewWriter(t)

				mockWriter.On("Write", mock.Anything).Return(1024, nil)
				mockWriter.On("Close").Return(nil)

				id, _ := object.ParseID("I12345")
				mockWriter.On("Result").Return(id, nil)

				mockRepoWriter.On("NewObjectWriter", mock.Anything, mock.Anything).Return(mockWriter)

				return &kopiaObjectWriterEx{
					ctx:           context.Background(),
					rawRepoWriter: mockRepoWriter,
					blockSize:     1024,
					logger:        velerotest.NewLogger(),
				}
			},
			inputData:   make([]byte, 1024),
			offset:      0,
			expectedLen: 1024,
			verify: func(t *testing.T, kow *kopiaObjectWriterEx) {
				t.Helper()
				assert.Len(t, kow.entries, 1)
				assert.Equal(t, int64(0), kow.entries[0].Start)
			},
		},
		{
			name: "success write with gap filling zeros",
			setupWriter: func(t *testing.T) *kopiaObjectWriterEx {
				t.Helper()
				mockRepoWriter := repomocks.NewMockRepositoryWriter(t)
				mockWriter := repomocks.NewWriter(t)

				mockWriter.On("Write", mock.Anything).Return(1024, nil)
				mockWriter.On("Close").Return(nil)

				id, _ := object.ParseID("I12345")
				mockWriter.On("Result").Return(id, nil)

				mockRepoWriter.On("NewObjectWriter", mock.Anything, mock.Anything).Return(mockWriter)

				return &kopiaObjectWriterEx{
					ctx:           context.Background(),
					rawRepoWriter: mockRepoWriter,
					blockSize:     1024,
					zeroObject:    object.EmptyID,
					logger:        velerotest.NewLogger(),
				}
			},
			inputData:   make([]byte, 1024),
			offset:      1024,
			expectedLen: 1024,
			verify: func(t *testing.T, kow *kopiaObjectWriterEx) {
				t.Helper()
				assert.Len(t, kow.entries, 2)
				assert.Equal(t, int64(0), kow.entries[0].Start)
				id, _ := object.ParseID("I12345")
				assert.Equal(t, id, kow.entries[0].Object)
				assert.Equal(t, id, kow.zeroObject)
				assert.Equal(t, int64(1024), kow.entries[1].Start)
			},
		},
		{
			name: "success write with gap filling from parent",
			setupWriter: func(t *testing.T) *kopiaObjectWriterEx {
				t.Helper()
				mockRepoWriter := repomocks.NewMockRepositoryWriter(t)
				mockWriter := repomocks.NewWriter(t)

				mockWriter.On("Write", mock.Anything).Return(1024, nil)
				mockWriter.On("Close").Return(nil)

				id, _ := object.ParseID("I12345")
				mockWriter.On("Result").Return(id, nil)

				mockRepoWriter.On("NewObjectWriter", mock.Anything, mock.Anything).Return(mockWriter)

				parentID, _ := object.ParseID("Iparent")
				return &kopiaObjectWriterEx{
					ctx:           context.Background(),
					rawRepoWriter: mockRepoWriter,
					blockSize:     1024,
					parentEntries: []object.IndirectObjectEntry{
						{Start: 0, Length: 1024, Object: parentID},
					},
					logger: velerotest.NewLogger(),
				}
			},
			inputData:   make([]byte, 1024),
			offset:      1024,
			expectedLen: 1024,
			verify: func(t *testing.T, kow *kopiaObjectWriterEx) {
				t.Helper()
				assert.Len(t, kow.entries, 2)
				assert.Equal(t, int64(0), kow.entries[0].Start)
				parentID, _ := object.ParseID("Iparent")
				assert.Equal(t, parentID, kow.entries[0].Object)
				assert.Equal(t, int64(1024), kow.entries[1].Start)
			},
		},
		{
			name: "success write zero length",
			setupWriter: func(t *testing.T) *kopiaObjectWriterEx {
				t.Helper()
				mockRepoWriter := repomocks.NewMockRepositoryWriter(t)
				return &kopiaObjectWriterEx{
					ctx:           context.Background(),
					rawRepoWriter: mockRepoWriter,
					blockSize:     1024,
					logger:        velerotest.NewLogger(),
				}
			},
			inputData:   []byte{},
			offset:      0,
			expectedLen: 0,
			verify: func(t *testing.T, kow *kopiaObjectWriterEx) {
				t.Helper()
				assert.Empty(t, kow.entries)
			},
		},
		{
			name: "gap filling with invalid parent entry length",
			setupWriter: func(t *testing.T) *kopiaObjectWriterEx {
				t.Helper()
				mockRepoWriter := repomocks.NewMockRepositoryWriter(t)
				return &kopiaObjectWriterEx{
					ctx:           context.Background(),
					rawRepoWriter: mockRepoWriter,
					blockSize:     1024,
					parentEntries: []object.IndirectObjectEntry{
						{Start: 0, Length: 512, Object: object.EmptyID},
					},
					logger: velerotest.NewLogger(),
				}
			},
			inputData:   make([]byte, 1024),
			offset:      1024,
			expectedErr: "parent entry 0 length 512 does not match child block size 1024",
		},
		{
			name: "gap filling partially with parent and rest with zeros",
			setupWriter: func(t *testing.T) *kopiaObjectWriterEx {
				t.Helper()
				mockRepoWriter := repomocks.NewMockRepositoryWriter(t)
				mockWriter := repomocks.NewWriter(t)

				mockWriter.On("Write", mock.Anything).Return(1024, nil)
				mockWriter.On("Close").Return(nil)

				id, _ := object.ParseID("I12345")
				mockWriter.On("Result").Return(id, nil)

				mockRepoWriter.On("NewObjectWriter", mock.Anything, mock.Anything).Return(mockWriter)

				parentID, _ := object.ParseID("Iparent")
				return &kopiaObjectWriterEx{
					ctx:           context.Background(),
					rawRepoWriter: mockRepoWriter,
					blockSize:     1024,
					zeroObject:    object.EmptyID,
					parentEntries: []object.IndirectObjectEntry{
						{Start: 0, Length: 1024, Object: parentID},
					},
					logger: velerotest.NewLogger(),
				}
			},
			inputData:   make([]byte, 1024),
			offset:      2048,
			expectedLen: 1024,
			verify: func(t *testing.T, kow *kopiaObjectWriterEx) {
				t.Helper()
				assert.Len(t, kow.entries, 3)
				assert.Equal(t, int64(0), kow.entries[0].Start)

				parentID, _ := object.ParseID("Iparent")
				assert.Equal(t, parentID, kow.entries[0].Object)

				zeroID, _ := object.ParseID("I12345")
				assert.Equal(t, int64(1024), kow.entries[1].Start)
				assert.Equal(t, zeroID, kow.entries[1].Object)

				assert.Equal(t, int64(2048), kow.entries[2].Start)
			},
		},
		{
			name: "writeZeroObject failure",
			setupWriter: func(t *testing.T) *kopiaObjectWriterEx {
				t.Helper()
				mockRepoWriter := repomocks.NewMockRepositoryWriter(t)
				mockWriter := repomocks.NewWriter(t)

				mockWriter.On("Write", mock.Anything).Return(0, errors.New("simulated zero object write error"))
				mockWriter.On("Close").Return(nil)

				mockRepoWriter.On("NewObjectWriter", mock.Anything, mock.Anything).Return(mockWriter)

				return &kopiaObjectWriterEx{
					ctx:           context.Background(),
					rawRepoWriter: mockRepoWriter,
					blockSize:     1024,
					zeroObject:    object.EmptyID,
					logger:        velerotest.NewLogger(),
				}
			},
			inputData:   make([]byte, 1024),
			offset:      1024,
			expectedErr: "error writing zero object for -b0: error writing for -b0: simulated zero object write error",
		},
		{
			name: "writeObject short write",
			setupWriter: func(t *testing.T) *kopiaObjectWriterEx {
				t.Helper()
				mockRepoWriter := repomocks.NewMockRepositoryWriter(t)
				mockWriter := repomocks.NewWriter(t)

				mockWriter.On("Write", mock.Anything).Return(512, nil)
				mockWriter.On("Close").Return(nil)

				mockRepoWriter.On("NewObjectWriter", mock.Anything, mock.Anything).Return(mockWriter)

				return &kopiaObjectWriterEx{
					ctx:           context.Background(),
					rawRepoWriter: mockRepoWriter,
					blockSize:     1024,
					logger:        velerotest.NewLogger(),
				}
			},
			inputData:   make([]byte, 1024),
			offset:      0,
			expectedLen: 1024,
			verify: func(t *testing.T, kow *kopiaObjectWriterEx) {
				t.Helper()
				err := kow.getWriteError()
				require.Error(t, err)
				assert.Contains(t, err.Error(), "short write for -b0")
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			kow := tc.setupWriter(t)
			l, err := kow.WriteAt(tc.inputData, tc.offset)

			if kow.asyncWritesSem != nil {
				kow.asyncWritesGroup.Wait()
			}

			if tc.expectedErr != "" {
				assert.EqualError(t, err, tc.expectedErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedLen, l)
				if tc.verify != nil {
					tc.verify(t, kow)
				}
			}
		})
	}
}

func TestKopiaObjectWriterEx_MultipleWriteAt(t *testing.T) {
	mockRepoWriter := repomocks.NewMockRepositoryWriter(t)
	mockWriter := repomocks.NewWriter(t)

	mockWriter.On("Write", mock.Anything).Return(1024, nil)
	mockWriter.On("Close").Return(nil)

	id, _ := object.ParseID("I12345")
	mockWriter.On("Result").Return(id, nil)

	mockRepoWriter.On("NewObjectWriter", mock.Anything, mock.Anything).Return(mockWriter)

	kow := &kopiaObjectWriterEx{
		ctx:           context.Background(),
		rawRepoWriter: mockRepoWriter,
		blockSize:     1024,
		zeroObject:    object.EmptyID,
		logger:        velerotest.NewLogger(),
	}

	l, err := kow.WriteAt(make([]byte, 1024), 0)
	require.NoError(t, err)
	assert.Equal(t, 1024, l)

	l, err = kow.WriteAt(make([]byte, 1024), 2048)
	require.NoError(t, err)
	assert.Equal(t, 1024, l)

	assert.Len(t, kow.entries, 3)
	assert.Equal(t, int64(0), kow.entries[0].Start)
	assert.Equal(t, int64(1024), kow.entries[1].Start)
	assert.Equal(t, id, kow.entries[1].Object)
	assert.Equal(t, int64(2048), kow.entries[2].Start)
}

func TestKopiaObjectWriterEx_ConcurrentWriteAt(t *testing.T) {
	mockRepoWriter := repomocks.NewMockRepositoryWriter(t)
	mockWriter := repomocks.NewWriter(t)

	mockWriter.On("Write", mock.Anything).Return(1024, nil)
	mockWriter.On("Close").Return(nil)

	id, _ := object.ParseID("I12345")
	mockWriter.On("Result").Return(id, nil)

	mockRepoWriter.On("NewObjectWriter", mock.Anything, mock.Anything).Return(mockWriter)

	kow := &kopiaObjectWriterEx{
		ctx:           context.Background(),
		rawRepoWriter: mockRepoWriter,
		blockSize:     1024,
		logger:        velerotest.NewLogger(),
	}

	numGoroutines := 10
	var wg sync.WaitGroup

	start := make(chan struct{})

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(offset int64) {
			defer wg.Done()
			<-start

			data := make([]byte, 1024)
			_, err := kow.WriteAt(data, offset)

			if err != nil {
				assert.Contains(t, err.Error(), "cannot write back")
			}
		}(int64(i * 1024))
	}

	close(start)
	wg.Wait()

	assert.NotEmpty(t, kow.entries)
}

type dummyObjectWriter struct {
	writtenBytes int
}

func (dw *dummyObjectWriter) Write(p []byte) (int, error) {
	dw.writtenBytes += len(p)
	return len(p), nil
}

func (dw *dummyObjectWriter) Close() error {
	return nil
}

func (dw *dummyObjectWriter) Result() (object.ID, error) {
	id, _ := object.ParseID("I12345")
	return id, nil
}

func (dw *dummyObjectWriter) Checkpoint() (object.ID, error) {
	return dw.Result()
}

type dummyRepoWriter struct {
	repo.RepositoryWriter
}

func (drw *dummyRepoWriter) NewObjectWriter(ctx context.Context, opt object.WriterOptions) object.Writer {
	return &dummyObjectWriter{}
}

func TestKopiaObjectWriterEx_LargeSequentialWrite(t *testing.T) {
	mockRepoWriter := &dummyRepoWriter{}

	blockSize := int64(1 << 20)

	kow := &kopiaObjectWriterEx{
		ctx:           context.Background(),
		rawRepoWriter: mockRepoWriter,
		blockSize:     blockSize,
		logger:        velerotest.NewLogger(),
	}

	data := make([]byte, blockSize)
	blocks := 5120

	for i := 0; i < blocks; i++ {
		l, err := kow.Write(data)
		require.NoError(t, err)
		assert.Equal(t, int(blockSize), l)
	}

	assert.Len(t, kow.entries, blocks)
	assert.Equal(t, int64(blocks-1)*blockSize, kow.entries[blocks-1].Start)
}

func TestKopiaObjectWriterEx_LargeSparseWriteAt(t *testing.T) {
	mockRepoWriter := &dummyRepoWriter{}

	blockSize := int64(1 << 20)

	kow := &kopiaObjectWriterEx{
		ctx:           context.Background(),
		rawRepoWriter: mockRepoWriter,
		blockSize:     blockSize,
		zeroObject:    object.EmptyID,
		logger:        velerotest.NewLogger(),
	}

	var offset int64 = 5 * 1024 * 1024 * 1024

	data := make([]byte, blockSize)
	l, err := kow.WriteAt(data, offset)
	require.NoError(t, err)
	assert.Equal(t, int(blockSize), l)

	expectedEntries := 5121
	assert.Len(t, kow.entries, expectedEntries)
	assert.Equal(t, int64(0), kow.entries[0].Start)
	assert.Equal(t, offset, kow.entries[expectedEntries-1].Start)
}

func TestKopiaObjectWriterEx_MixedWriteAndWriteAt(t *testing.T) {
	mockRepoWriter := repomocks.NewMockRepositoryWriter(t)
	mockWriter := repomocks.NewWriter(t)

	blockSize := int64(1024)

	mockWriter.On("Write", mock.Anything).Return(int(blockSize), nil)
	mockWriter.On("Close").Return(nil)

	id, _ := object.ParseID("I12345")
	mockWriter.On("Result").Return(id, nil)

	mockRepoWriter.On("NewObjectWriter", mock.Anything, mock.Anything).Return(mockWriter)

	kow := &kopiaObjectWriterEx{
		ctx:           context.Background(),
		rawRepoWriter: mockRepoWriter,
		blockSize:     blockSize,
		zeroObject:    object.EmptyID,
		logger:        velerotest.NewLogger(),
	}

	// 1. Write 1 block sequentially
	data1 := make([]byte, blockSize)
	l, err := kow.Write(data1)
	require.NoError(t, err)
	assert.Equal(t, int(blockSize), l)

	// Entries: [0:1024]
	assert.Len(t, kow.entries, 1)
	assert.Equal(t, int64(0), kow.entries[0].Start)

	// 2. WriteAt with gap (offset = 2048). This creates a gap block at 1024
	data2 := make([]byte, blockSize)
	l, err = kow.WriteAt(data2, 2048)
	require.NoError(t, err)
	assert.Equal(t, int(blockSize), l)

	// Entries should now be 3: [0:1024, 1024:2048(zero object), 2048:3072]
	assert.Len(t, kow.entries, 3)
	assert.Equal(t, int64(0), kow.entries[0].Start)
	assert.Equal(t, int64(1024), kow.entries[1].Start)
	assert.Equal(t, id, kow.entries[1].Object) // filled with zero block
	assert.Equal(t, int64(2048), kow.entries[2].Start)

	// 3. Write another block sequentially. It should append at 3072.
	data3 := make([]byte, blockSize)
	l, err = kow.Write(data3)
	require.NoError(t, err)
	assert.Equal(t, int(blockSize), l)

	// Entries should now be 4: [0:1024, 1024:2048(zero object), 2048:3072, 3072:4096]
	assert.Len(t, kow.entries, 4)
	assert.Equal(t, int64(3072), kow.entries[3].Start)
}

func TestKopiaObjectWriterEx_ConcurrentAsyncErrors(t *testing.T) {
	mockRepoWriter := repomocks.NewMockRepositoryWriter(t)
	mockWriter := repomocks.NewWriter(t)

	mockWriter.On("Write", mock.Anything).Return(0, errors.New("simulated async error"))
	mockWriter.On("Close").Return(nil)

	mockRepoWriter.On("NewObjectWriter", mock.Anything, mock.Anything).Return(mockWriter)

	sem := make(chan struct{}, 10)
	buf := freelist.New(10*1024, 1024)

	kow := &kopiaObjectWriterEx{
		ctx:            context.Background(),
		rawRepoWriter:  mockRepoWriter,
		blockSize:      1024,
		asyncWritesSem: sem,
		asyncBuffer:    buf,
		logger:         velerotest.NewLogger(),
	}

	data := make([]byte, 1024)

	// Issue multiple writes so they all spawn async goroutines
	// First few writes shouldn't fail immediately until getWriteError catches the asynchronous fault
	for i := 0; i < 10; i++ {
		l, err := kow.Write(data)
		require.NoError(t, err)
		assert.Equal(t, 1024, l)
	}

	id, err := kow.Result()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "simulated async error")
	assert.Equal(t, udmrepo.ID(""), id)
}

func TestKopiaObjectWriterEx_ConcurrentWriteAndWriteAt(t *testing.T) {
	mockRepoWriter := repomocks.NewMockRepositoryWriter(t)
	mockWriter := repomocks.NewWriter(t)

	mockWriter.On("Write", mock.Anything).Return(1024, nil)
	mockWriter.On("Close").Return(nil)

	id, _ := object.ParseID("I12345")
	mockWriter.On("Result").Return(id, nil)

	mockRepoWriter.On("NewObjectWriter", mock.Anything, mock.Anything).Return(mockWriter)

	kow := &kopiaObjectWriterEx{
		ctx:           context.Background(),
		rawRepoWriter: mockRepoWriter,
		blockSize:     1024,
		zeroObject:    object.EmptyID,
		logger:        velerotest.NewLogger(),
	}

	var wg sync.WaitGroup
	start := make(chan struct{})

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			l, err := kow.Write(make([]byte, 1024))
			require.NoError(t, err)
			assert.Equal(t, 1024, l)
		}()
	}

	// Fire multiple sparse WriteAts alongside them
	// Note: Because order is totally random and WriteAt strictly demands monotonic offsets,
	// some will hit the legitimate "cannot write back" error, which we safely expect.
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(offset int64) {
			defer wg.Done()
			<-start
			_, err := kow.WriteAt(make([]byte, 1024), offset)
			if err != nil {
				assert.Contains(t, err.Error(), "cannot write back")
			}
		}(int64(i * 2048))
	}

	close(start)
	wg.Wait()

	// We only care that the locking effectively mitigated a panic or slice data corruption
	assert.NotEmpty(t, kow.entries)
}

func TestKopiaObjectWriterEx_Checkpoint(t *testing.T) {
	kow := &kopiaObjectWriterEx{}
	id, err := kow.Checkpoint()
	require.Error(t, err)
	assert.Equal(t, udmrepo.ID(""), id)
	assert.Equal(t, "not supported", err.Error())
}
