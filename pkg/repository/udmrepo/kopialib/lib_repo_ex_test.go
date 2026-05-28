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
	"github.com/vmware-tanzu/velero/pkg/repository/udmrepo/kopialib/freelist"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
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

	// Since we are writing 3 blocks, Write should be called 3 times and Close 3 times
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

	// Write 1st block
	l, err := kow.Write(make([]byte, 1024))
	require.NoError(t, err)
	assert.Equal(t, 1024, l)

	// Write 2nd and 3rd block
	l, err = kow.Write(make([]byte, 2048))
	require.NoError(t, err)
	assert.Equal(t, 2048, l)

	// In the end we expect 3 blocks to be tracked in `kow.entries`
	assert.Len(t, kow.entries, 3)
	assert.Equal(t, int64(0), kow.entries[0].Start)
	assert.Equal(t, int64(1024), kow.entries[1].Start)
	assert.Equal(t, int64(2048), kow.entries[2].Start)
}
