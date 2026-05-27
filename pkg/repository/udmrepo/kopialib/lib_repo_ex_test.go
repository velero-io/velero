package kopialib

import (
	"context"
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
