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
	"math"
	"os"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/kopia/kopia/repo"
	"github.com/kopia/kopia/repo/manifest"
	"github.com/kopia/kopia/repo/object"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/vmware-tanzu/velero/pkg/repository/udmrepo"
	repomocks "github.com/vmware-tanzu/velero/pkg/repository/udmrepo/kopialib/backend/mocks"

	velerotest "github.com/vmware-tanzu/velero/pkg/test"
)

func TestOpen(t *testing.T) {
	var directRpo *repomocks.MockRepository
	testCases := []struct {
		name           string
		repoOptions    udmrepo.RepoOptions
		returnRepo     *repomocks.MockRepository
		repoOpen       func(context.Context, string, string, *repo.Options) (repo.Repository, error)
		newWriterError error
		mockClose      bool
		expectedErr    string
		expected       *kopiaRepository
	}{
		{
			name:        "invalid config file",
			expectedErr: "invalid config file path",
		},
		{
			name: "config file doesn't exist",
			repoOptions: udmrepo.RepoOptions{
				ConfigFilePath: "fake-file",
			},
			expectedErr: "repo config fake-file doesn't exist: stat fake-file: no such file or directory",
		},
		{
			name: "repo open fail, repo not exist",
			repoOptions: udmrepo.RepoOptions{
				ConfigFilePath: "/tmp",
			},
			repoOpen: func(context.Context, string, string, *repo.Options) (repo.Repository, error) {
				return nil, os.ErrNotExist
			},
			expectedErr: "error to open repo, repo doesn't exist: file does not exist",
		},
		{
			name: "repo open fail, other error",
			repoOptions: udmrepo.RepoOptions{
				ConfigFilePath: "/tmp",
			},
			repoOpen: func(context.Context, string, string, *repo.Options) (repo.Repository, error) {
				return nil, errors.New("fake-repo-open-error")
			},
			expectedErr: "error to open repo: fake-repo-open-error",
		},
		{
			name: "create repository writer fail",
			repoOptions: udmrepo.RepoOptions{
				ConfigFilePath: "/tmp",
			},
			repoOpen: func(context.Context, string, string, *repo.Options) (repo.Repository, error) {
				return directRpo, nil
			},
			returnRepo:     repomocks.NewMockRepository(t),
			mockClose:      true,
			newWriterError: errors.New("fake-new-writer-error"),
			expectedErr:    "error to create repo writer: fake-new-writer-error",
		},
		{
			name: "create repository success",
			repoOptions: udmrepo.RepoOptions{
				ConfigFilePath: "/tmp",
				Description:    "fake-description",
			},
			repoOpen: func(context.Context, string, string, *repo.Options) (repo.Repository, error) {
				return directRpo, nil
			},
			returnRepo: repomocks.NewMockRepository(t),
			expected: &kopiaRepository{
				description: "fake-description",
				throttle: logThrottle{
					interval: defaultLogInterval,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logger := velerotest.NewLogger()

			service := kopiaRepoService{
				logger: logger,
			}

			if tc.repoOpen != nil {
				kopiaRepoOpen = tc.repoOpen
			}

			if tc.returnRepo != nil {
				directRpo = tc.returnRepo
			}

			if tc.returnRepo != nil {
				tc.returnRepo.On("NewWriter", mock.Anything, mock.Anything).Return(nil, nil, tc.newWriterError)

				if tc.mockClose {
					tc.returnRepo.On("Close", mock.Anything).Return(nil)
				}
			}

			repo, err := service.Open(t.Context(), tc.repoOptions)

			if repo != nil {
				require.Equal(t, tc.expected.description, repo.(*kopiaRepository).description)
				require.Equal(t, tc.expected.throttle.interval, repo.(*kopiaRepository).throttle.interval)
				require.Equal(t, repo.(*kopiaRepository).logger, logger)
			}

			if tc.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.expectedErr)
			}
		})
	}
}

func TestMaintain(t *testing.T) {
	testCases := []struct {
		name               string
		repoOptions        udmrepo.RepoOptions
		returnRepo         *repomocks.MockRepository
		returnRepoWriter   *repomocks.MockRepositoryWriter
		repoOpen           func(context.Context, string, string, *repo.Options) (repo.Repository, error)
		newRepoWriterError error
		findManifestError  error
		expectedErr        string
	}{
		{
			name:        "invalid config file",
			expectedErr: "invalid config file path",
		},
		{
			name: "config file doesn't exist",
			repoOptions: udmrepo.RepoOptions{
				ConfigFilePath: "fake-file",
			},
			expectedErr: "repo config fake-file doesn't exist: stat fake-file: no such file or directory",
		},
		{
			name: "repo open fail, repo not exist",
			repoOptions: udmrepo.RepoOptions{
				ConfigFilePath: "/tmp",
				GeneralOptions: map[string]string{},
			},
			repoOpen: func(context.Context, string, string, *repo.Options) (repo.Repository, error) {
				return nil, os.ErrNotExist
			},
			expectedErr: "error to open repo, repo doesn't exist: file does not exist",
		},
		{
			name: "repo open fail, other error",
			repoOptions: udmrepo.RepoOptions{
				ConfigFilePath: "/tmp",
				GeneralOptions: map[string]string{},
			},
			repoOpen: func(context.Context, string, string, *repo.Options) (repo.Repository, error) {
				return nil, errors.New("fake-repo-open-error")
			},
			expectedErr: "error to open repo: fake-repo-open-error",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logger := velerotest.NewLogger()
			ctx := t.Context()

			service := kopiaRepoService{
				logger: logger,
			}

			if tc.repoOpen != nil {
				kopiaRepoOpen = tc.repoOpen
			}

			if tc.returnRepo != nil {
				tc.returnRepo.On("Close", mock.Anything).Return(nil)
			}

			err := service.Maintain(ctx, tc.repoOptions)

			if tc.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.expectedErr)
			}
		})
	}
}

func TestShouldLog(t *testing.T) {
	testCases := []struct {
		name     string
		lastTime int64
		interval time.Duration
		retValue bool
	}{
		{
			name:     "first time",
			retValue: true,
		},
		{
			name:     "not run",
			lastTime: time.Now().Add(time.Hour).UnixNano(),
			interval: time.Second * 10,
		},
		{
			name:     "not first time, run",
			lastTime: time.Now().Add(-time.Hour).UnixNano(),
			interval: time.Second * 10,
			retValue: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			lt := logThrottle{
				lastTime: tc.lastTime,
				interval: tc.interval,
			}

			before := lt.lastTime

			nw := time.Now()

			s := lt.shouldLog()

			require.Equal(t, s, tc.retValue)

			if s {
				require.GreaterOrEqual(t, lt.lastTime-nw.UnixNano(), lt.interval)
			} else {
				require.Equal(t, lt.lastTime, before)
			}
		})
	}
}

func TestOpenObject(t *testing.T) {
	testCases := []struct {
		name        string
		rawRepo     *repomocks.MockRepository
		objectID    string
		retErr      error
		expectedErr string
	}{
		{
			name:        "raw repo is nil",
			expectedErr: "repo is closed or not open",
		},
		{
			name:        "objectID is invalid",
			rawRepo:     repomocks.NewMockRepository(t),
			objectID:    "fake-id",
			expectedErr: "error to parse object ID from fake-id: malformed content ID: \"fake-id\": invalid content prefix",
		},
		{
			name:        "raw open fail",
			rawRepo:     repomocks.NewMockRepository(t),
			retErr:      errors.New("fake-open-error"),
			expectedErr: "error to open object: fake-open-error",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			kr := &kopiaRepository{}

			if tc.rawRepo != nil {
				if tc.retErr != nil {
					tc.rawRepo.On("OpenObject", mock.Anything, mock.Anything).Return(nil, tc.retErr)
				}

				kr.rawRepo = tc.rawRepo
			}

			_, err := kr.OpenObject(t.Context(), udmrepo.ID(tc.objectID))

			if tc.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.expectedErr)
			}
		})
	}
}

func TestGetManifest(t *testing.T) {
	testCases := []struct {
		name        string
		rawRepo     *repomocks.MockRepository
		retErr      error
		expectedErr string
	}{
		{
			name:        "raw repo is nil",
			expectedErr: "repo is closed or not open",
		},
		{
			name:        "raw get fail",
			rawRepo:     repomocks.NewMockRepository(t),
			retErr:      errors.New("fake-get-error"),
			expectedErr: "error to get manifest: fake-get-error",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			kr := &kopiaRepository{}

			if tc.rawRepo != nil {
				if tc.retErr != nil {
					tc.rawRepo.On("GetManifest", mock.Anything, mock.Anything, mock.Anything).Return(nil, tc.retErr)
				}

				kr.rawRepo = tc.rawRepo
			}

			err := kr.GetManifest(t.Context(), udmrepo.ID(""), &udmrepo.RepoManifest{})

			if tc.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.expectedErr)
			}
		})
	}
}

func TestFindManifests(t *testing.T) {
	testCases := []struct {
		name        string
		rawRepo     *repomocks.MockRepository
		retErr      error
		expectedErr string
	}{
		{
			name:        "raw repo is nil",
			expectedErr: "repo is closed or not open",
		},
		{
			name:        "raw find fail",
			rawRepo:     repomocks.NewMockRepository(t),
			retErr:      errors.New("fake-find-error"),
			expectedErr: "error to find manifests: fake-find-error",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			kr := &kopiaRepository{}

			if tc.rawRepo != nil {
				tc.rawRepo.On("FindManifests", mock.Anything, mock.Anything).Return(nil, tc.retErr)
				kr.rawRepo = tc.rawRepo
			}

			_, err := kr.FindManifests(t.Context(), udmrepo.ManifestFilter{})

			if tc.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.expectedErr)
			}
		})
	}
}

func TestClose(t *testing.T) {
	testCases := []struct {
		name            string
		rawRepo         *repomocks.MockRepository
		rawWriter       *repomocks.MockRepositoryWriter
		rawRepoRetErr   error
		rawWriterRetErr error
		expectedErr     string
	}{
		{
			name: "both nil",
		},
		{
			name:      "writer is not nil",
			rawWriter: repomocks.NewMockRepositoryWriter(t),
		},
		{
			name:    "repo is not nil",
			rawRepo: repomocks.NewMockRepository(t),
		},
		{
			name:            "writer close error",
			rawWriter:       repomocks.NewMockRepositoryWriter(t),
			rawWriterRetErr: errors.New("fake-writer-close-error"),
			expectedErr:     "error to close repo writer: fake-writer-close-error",
		},
		{
			name:          "repo is not nil",
			rawRepo:       repomocks.NewMockRepository(t),
			rawRepoRetErr: errors.New("fake-repo-close-error"),
			expectedErr:   "error to close repo: fake-repo-close-error",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			kr := &kopiaRepository{}

			if tc.rawRepo != nil {
				tc.rawRepo.On("Close", mock.Anything).Return(tc.rawRepoRetErr)
				kr.rawRepo = tc.rawRepo
			}

			if tc.rawWriter != nil {
				tc.rawWriter.On("Close", mock.Anything).Return(tc.rawWriterRetErr)
				kr.rawWriter = tc.rawWriter
			}

			err := kr.Close(t.Context())

			if tc.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.expectedErr)
			}
		})
	}
}

func TestPutManifest(t *testing.T) {
	testCases := []struct {
		name            string
		rawWriter       *repomocks.MockRepositoryWriter
		rawWriterRetErr error
		expectedErr     string
	}{
		{
			name:        "raw writer is nil",
			expectedErr: "repo writer is closed or not open",
		},
		{
			name:            "raw put fail",
			rawWriter:       repomocks.NewMockRepositoryWriter(t),
			rawWriterRetErr: errors.New("fake-writer-put-error"),
			expectedErr:     "error to put manifest: fake-writer-put-error",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			kr := &kopiaRepository{}

			if tc.rawWriter != nil {
				tc.rawWriter.On("PutManifest", mock.Anything, mock.Anything, mock.Anything).Return(manifest.ID(""), tc.rawWriterRetErr)
				kr.rawWriter = tc.rawWriter
			}

			_, err := kr.PutManifest(t.Context(), udmrepo.RepoManifest{
				Metadata: &udmrepo.ManifestEntryMetadata{},
			})

			if tc.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.expectedErr)
			}
		})
	}
}

func TestDeleteManifest(t *testing.T) {
	testCases := []struct {
		name            string
		rawWriter       *repomocks.MockRepositoryWriter
		rawWriterRetErr error
		expectedErr     string
	}{
		{
			name:        "raw writer is nil",
			expectedErr: "repo writer is closed or not open",
		},
		{
			name:            "raw delete fail",
			rawWriter:       repomocks.NewMockRepositoryWriter(t),
			rawWriterRetErr: errors.New("fake-writer-delete-error"),
			expectedErr:     "error to delete manifest: fake-writer-delete-error",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			kr := &kopiaRepository{}

			if tc.rawWriter != nil {
				tc.rawWriter.On("DeleteManifest", mock.Anything, mock.Anything).Return(tc.rawWriterRetErr)
				kr.rawWriter = tc.rawWriter
			}

			err := kr.DeleteManifest(t.Context(), udmrepo.ID(""))

			if tc.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.expectedErr)
			}
		})
	}
}

func TestFlush(t *testing.T) {
	testCases := []struct {
		name            string
		rawWriter       *repomocks.MockRepositoryWriter
		rawWriterRetErr error
		expectedErr     string
	}{
		{
			name:        "raw writer is nil",
			expectedErr: "repo writer is closed or not open",
		},
		{
			name:            "raw flush fail",
			rawWriter:       repomocks.NewMockRepositoryWriter(t),
			rawWriterRetErr: errors.New("fake-writer-flush-error"),
			expectedErr:     "error to flush repo: fake-writer-flush-error",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			kr := &kopiaRepository{}

			if tc.rawWriter != nil {
				tc.rawWriter.On("Flush", mock.Anything).Return(tc.rawWriterRetErr)
				kr.rawWriter = tc.rawWriter
			}

			err := kr.Flush(t.Context())

			if tc.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.expectedErr)
			}
		})
	}
}

func TestConcatenateObjects(t *testing.T) {
	testCases := []struct {
		name            string
		setWriter       bool
		rawWriter       *repomocks.MockRepositoryWriter
		rawWriterRetErr error
		objectIDs       []udmrepo.ID
		expectedErr     string
	}{
		{
			name:        "writer is nil",
			expectedErr: "repo writer is closed or not open",
		},
		{
			name:        "empty object list",
			setWriter:   true,
			expectedErr: "object list is empty",
		},
		{
			name: "invalid object id",
			objectIDs: []udmrepo.ID{
				"I123456",
				"fake-id",
				"I678901",
			},
			setWriter:   true,
			expectedErr: "error to parse object ID from fake-id: malformed content ID: \"fake-id\": invalid content prefix",
		},
		{
			name:            "concatenate error",
			rawWriter:       repomocks.NewMockRepositoryWriter(t),
			rawWriterRetErr: errors.New("fake-concatenate-error"),
			objectIDs: []udmrepo.ID{
				"I123456",
			},
			setWriter:   true,
			expectedErr: "error to concatenate objects: fake-concatenate-error",
		},
		{
			name:      "succeed",
			rawWriter: repomocks.NewMockRepositoryWriter(t),
			objectIDs: []udmrepo.ID{
				"I123456",
			},
			setWriter: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			kr := &kopiaRepository{}

			if tc.rawWriter != nil {
				require.NotNil(t, tc.rawWriter)
				tc.rawWriter.On("ConcatenateObjects", mock.Anything, mock.Anything, mock.Anything).Return(object.ID{}, tc.rawWriterRetErr)
			}

			if tc.setWriter {
				kr.rawWriter = tc.rawWriter
			}

			_, err := kr.ConcatenateObjects(t.Context(), tc.objectIDs)

			if tc.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.expectedErr)
			}
		})
	}
}

func TestNewObjectWriter(t *testing.T) {
	rawObjWriter := repomocks.NewWriter(t)
	testCases := []struct {
		name         string
		rawWriter    *repomocks.MockRepositoryWriter
		rawWriterRet object.Writer
		expectedRet  udmrepo.ObjectWriter
	}{
		{
			name: "raw writer is nil",
		},
		{
			name:      "new object writer fail",
			rawWriter: repomocks.NewMockRepositoryWriter(t),
		},
		{
			name:         "succeed",
			rawWriter:    repomocks.NewMockRepositoryWriter(t),
			rawWriterRet: rawObjWriter,
			expectedRet:  &kopiaObjectWriter{rawWriter: rawObjWriter},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			kr := &kopiaRepository{}

			if tc.rawWriter != nil {
				tc.rawWriter.On("NewObjectWriter", mock.Anything, mock.Anything).Return(tc.rawWriterRet)
				kr.rawWriter = tc.rawWriter
			}

			ret := kr.NewObjectWriter(t.Context(), udmrepo.ObjectWriteOptions{})

			assert.Equal(t, tc.expectedRet, ret)
		})
	}
}

func TestUpdateProgress(t *testing.T) {
	testCases := []struct {
		name       string
		progress   int64
		uploaded   int64
		throttle   logThrottle
		logMessage string
	}{
		{
			name: "should not output",
			throttle: logThrottle{
				lastTime: math.MaxInt64,
			},
		},
		{
			name:       "should output",
			progress:   100,
			uploaded:   200,
			logMessage: "Repo uploaded 300 bytes.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logMessage := ""
			kr := &kopiaRepository{
				logger:   velerotest.NewSingleLogger(&logMessage),
				throttle: tc.throttle,
				uploaded: tc.uploaded,
			}

			kr.updateProgress(tc.progress)

			if len(tc.logMessage) > 0 {
				assert.Contains(t, logMessage, tc.logMessage)
			} else {
				assert.Empty(t, logMessage)
			}
		})
	}
}

func TestReaderRead(t *testing.T) {
	testCases := []struct {
		name            string
		rawObjReader    *repomocks.Reader
		rawReaderRetErr error
		expectedErr     string
	}{
		{
			name:        "raw reader is nil",
			expectedErr: "object reader is closed or not open",
		},
		{
			name:            "raw read fail",
			rawObjReader:    repomocks.NewReader(t),
			rawReaderRetErr: errors.New("fake-read-error"),
			expectedErr:     "fake-read-error",
		},
		{
			name:         "succeed",
			rawObjReader: repomocks.NewReader(t),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			kr := &kopiaObjectReader{}

			if tc.rawObjReader != nil {
				tc.rawObjReader.On("Read", mock.Anything).Return(0, tc.rawReaderRetErr)
				kr.rawReader = tc.rawObjReader
			}

			_, err := kr.Read(nil)

			if tc.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.expectedErr)
			}
		})
	}
}

func TestReaderSeek(t *testing.T) {
	testCases := []struct {
		name            string
		rawObjReader    *repomocks.Reader
		rawReaderRet    int64
		rawReaderRetErr error
		expectedRet     int64
		expectedErr     string
	}{
		{
			name:        "raw reader is nil",
			expectedErr: "object reader is closed or not open",
		},
		{
			name:            "raw seek fail",
			rawObjReader:    repomocks.NewReader(t),
			rawReaderRetErr: errors.New("fake-seek-error"),
			expectedErr:     "fake-seek-error",
		},
		{
			name:         "succeed",
			rawObjReader: repomocks.NewReader(t),
			rawReaderRet: 100,
			expectedRet:  100,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			kr := &kopiaObjectReader{}

			if tc.rawObjReader != nil {
				tc.rawObjReader.On("Seek", mock.Anything, mock.Anything).Return(tc.rawReaderRet, tc.rawReaderRetErr)
				kr.rawReader = tc.rawObjReader
			}

			ret, err := kr.Seek(0, 0)

			if tc.expectedErr == "" {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedRet, ret)
			} else {
				assert.EqualError(t, err, tc.expectedErr)
			}
		})
	}
}

func TestReaderClose(t *testing.T) {
	testCases := []struct {
		name            string
		rawObjReader    *repomocks.Reader
		rawReaderRetErr error
		expectedErr     string
	}{
		{
			name: "raw reader is nil",
		},
		{
			name:            "raw close fail",
			rawObjReader:    repomocks.NewReader(t),
			rawReaderRetErr: errors.New("fake-close-error"),
			expectedErr:     "fake-close-error",
		},
		{
			name:         "succeed",
			rawObjReader: repomocks.NewReader(t),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			kr := &kopiaObjectReader{}

			if tc.rawObjReader != nil {
				tc.rawObjReader.On("Close").Return(tc.rawReaderRetErr)
				kr.rawReader = tc.rawObjReader
			}

			err := kr.Close()

			if tc.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.expectedErr)
			}
		})
	}
}

func TestReaderLength(t *testing.T) {
	testCases := []struct {
		name         string
		rawObjReader *repomocks.Reader
		rawReaderRet int64
		expectedRet  int64
	}{
		{
			name:        "raw reader is nil",
			expectedRet: -1,
		},
		{
			name:         "raw length fail",
			rawObjReader: repomocks.NewReader(t),
			rawReaderRet: 0,
			expectedRet:  0,
		},
		{
			name:         "succeed",
			rawObjReader: repomocks.NewReader(t),
			rawReaderRet: 200,
			expectedRet:  200,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			kr := &kopiaObjectReader{}

			if tc.rawObjReader != nil {
				tc.rawObjReader.On("Length").Return(tc.rawReaderRet)
				kr.rawReader = tc.rawObjReader
			}

			ret := kr.Length()

			assert.Equal(t, tc.expectedRet, ret)
		})
	}
}

func TestWriterWrite(t *testing.T) {
	testCases := []struct {
		name            string
		rawObjWriter    *repomocks.Writer
		rawWrtierRet    int
		rawWriterRetErr error
		expectedRet     int
		expectedErr     string
	}{
		{
			name:        "raw writer is nil",
			expectedErr: "object writer is closed or not open",
		},
		{
			name:            "raw read fail",
			rawObjWriter:    repomocks.NewWriter(t),
			rawWriterRetErr: errors.New("fake-write-error"),
			expectedErr:     "fake-write-error",
		},
		{
			name:         "succeed",
			rawObjWriter: repomocks.NewWriter(t),
			rawWrtierRet: 200,
			expectedRet:  200,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			kr := &kopiaObjectWriter{}

			if tc.rawObjWriter != nil {
				tc.rawObjWriter.On("Write", mock.Anything).Return(tc.rawWrtierRet, tc.rawWriterRetErr)
				kr.rawWriter = tc.rawObjWriter
			}

			ret, err := kr.Write(nil)

			if tc.expectedErr == "" {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedRet, ret)
			} else {
				assert.EqualError(t, err, tc.expectedErr)
			}
		})
	}
}

func TestWriterCheckpoint(t *testing.T) {
	testCases := []struct {
		name            string
		rawObjWriter    *repomocks.Writer
		rawWrtierRet    object.ID
		rawWriterRetErr error
		expectedRet     udmrepo.ID
		expectedErr     string
	}{
		{
			name:        "raw writer is nil",
			expectedErr: "object writer is closed or not open",
		},
		{
			name:            "raw checkpoint fail",
			rawObjWriter:    repomocks.NewWriter(t),
			rawWriterRetErr: errors.New("fake-checkpoint-error"),
			expectedErr:     "error to checkpoint object: fake-checkpoint-error",
		},
		{
			name:         "succeed",
			rawObjWriter: repomocks.NewWriter(t),
			rawWrtierRet: object.ID{},
			expectedRet:  udmrepo.ID(""),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			kr := &kopiaObjectWriter{}

			if tc.rawObjWriter != nil {
				tc.rawObjWriter.On("Checkpoint").Return(tc.rawWrtierRet, tc.rawWriterRetErr)
				kr.rawWriter = tc.rawObjWriter
			}

			ret, err := kr.Checkpoint()

			if tc.expectedErr == "" {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedRet, ret)
			} else {
				assert.EqualError(t, err, tc.expectedErr)
			}
		})
	}
}

func TestWriterResult(t *testing.T) {
	testCases := []struct {
		name            string
		rawObjWriter    *repomocks.Writer
		rawWrtierRet    object.ID
		rawWriterRetErr error
		expectedRet     udmrepo.ID
		expectedErr     string
	}{
		{
			name:        "raw writer is nil",
			expectedErr: "object writer is closed or not open",
		},
		{
			name:            "raw result fail",
			rawObjWriter:    repomocks.NewWriter(t),
			rawWriterRetErr: errors.New("fake-result-error"),
			expectedErr:     "error to wait object: fake-result-error",
		},
		{
			name:         "succeed",
			rawObjWriter: repomocks.NewWriter(t),
			rawWrtierRet: object.ID{},
			expectedRet:  udmrepo.ID(""),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			kr := &kopiaObjectWriter{}

			if tc.rawObjWriter != nil {
				tc.rawObjWriter.On("Result").Return(tc.rawWrtierRet, tc.rawWriterRetErr)
				kr.rawWriter = tc.rawObjWriter
			}

			ret, err := kr.Result()

			if tc.expectedErr == "" {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedRet, ret)
			} else {
				assert.EqualError(t, err, tc.expectedErr)
			}
		})
	}
}

func TestWriterClose(t *testing.T) {
	testCases := []struct {
		name            string
		rawObjWriter    *repomocks.Writer
		rawWriterRetErr error
		expectedErr     string
	}{
		{
			name: "raw writer is nil",
		},
		{
			name:            "raw close fail",
			rawObjWriter:    repomocks.NewWriter(t),
			rawWriterRetErr: errors.New("fake-close-error"),
			expectedErr:     "fake-close-error",
		},
		{
			name:         "succeed",
			rawObjWriter: repomocks.NewWriter(t),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			kr := &kopiaObjectWriter{}

			if tc.rawObjWriter != nil {
				tc.rawObjWriter.On("Close").Return(tc.rawWriterRetErr)
				kr.rawWriter = tc.rawObjWriter
			}

			err := kr.Close()

			if tc.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.expectedErr)
			}
		})
	}
}

func TestMaintainProgress(t *testing.T) {
	testCases := []struct {
		name       string
		progress   int64
		uploaded   int64
		throttle   logThrottle
		logMessage string
	}{
		{
			name: "should not output",
			throttle: logThrottle{
				lastTime: math.MaxInt64,
			},
		},
		{
			name:       "should output",
			progress:   100,
			uploaded:   200,
			logMessage: "Repo maintenance uploaded 300 bytes.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logMessage := ""
			km := &kopiaMaintenance{
				logger:   velerotest.NewSingleLogger(&logMessage),
				throttle: tc.throttle,
				uploaded: tc.uploaded,
			}

			km.maintainProgress(tc.progress)

			if len(tc.logMessage) > 0 {
				assert.Contains(t, logMessage, tc.logMessage)
			} else {
				assert.Empty(t, logMessage)
			}
		})
	}
}

func TestClientSideCacheLimit(t *testing.T) {
	testCases := []struct {
		name       string
		repoOption map[string]string
		expected   int64
	}{
		{
			name:     "nil option",
			expected: 5000 << 20,
		},
		{
			name: "no option",
			repoOption: map[string]string{
				"other-repo": "\"enableCompression\": true",
			},
			expected: 5000 << 20,
		},
		{
			name: "unmarshall fails",
			repoOption: map[string]string{
				"kopia": "wrong-json",
			},
			expected: 5000 << 20,
		},
		{
			name: "no cache limit",
			repoOption: map[string]string{
				"kopia": "{\"enableCompression\": true}",
			},
			expected: 5000 << 20,
		},
		{
			name: "wrong cache value type",
			repoOption: map[string]string{
				"kopia": "{\"cacheLimitMB\": \"abcd\",\"enableCompression\": true}",
			},
			expected: 5000 << 20,
		},
		{
			name: "succeed",
			repoOption: map[string]string{
				"kopia": "{\"cacheLimitMB\": 1,\"enableCompression\": true}",
			},
			expected: 1048576,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ks := &kopiaRepoService{
				logger: velerotest.NewLogger(),
			}

			limit := ks.ClientSideCacheLimit(tc.repoOption)

			assert.Equal(t, tc.expected, limit)
		})
	}
}

func TestIsReady(t *testing.T) {
	testCases := []struct {
		name         string
		funGetStatus func(context.Context, udmrepo.RepoOptions, logrus.FieldLogger) (RepoStatus, error)
		readOnly     bool
		expected     bool
		expectedErr  string
	}{
		{
			name: "get status error",
			funGetStatus: func(context.Context, udmrepo.RepoOptions, logrus.FieldLogger) (RepoStatus, error) {
				return RepoStatusUnknown, errors.New("fake-get-error")
			},
			expectedErr: "fake-get-error",
		},
		{
			name: "success",
			funGetStatus: func(context.Context, udmrepo.RepoOptions, logrus.FieldLogger) (RepoStatus, error) {
				return RepoStatusCreated, nil
			},
			expected: true,
		},
		{
			name: "not initialized, not readonly",
			funGetStatus: func(context.Context, udmrepo.RepoOptions, logrus.FieldLogger) (RepoStatus, error) {
				return RepoStatusNotInitialized, nil
			},
		},
		{
			name: "not initialized, readonly",
			funGetStatus: func(context.Context, udmrepo.RepoOptions, logrus.FieldLogger) (RepoStatus, error) {
				return RepoStatusNotInitialized, nil
			},
			readOnly: true,
			expected: true,
		},
		{
			name: "other status 1",
			funGetStatus: func(context.Context, udmrepo.RepoOptions, logrus.FieldLogger) (RepoStatus, error) {
				return RepoStatusUnknown, nil
			},
		},
		{
			name: "other status 2",
			funGetStatus: func(context.Context, udmrepo.RepoOptions, logrus.FieldLogger) (RepoStatus, error) {
				return RepoStatusCorrupted, nil
			},
		},
		{
			name: "other status 3",
			funGetStatus: func(context.Context, udmrepo.RepoOptions, logrus.FieldLogger) (RepoStatus, error) {
				return RepoStatusSystemNotCreated, nil
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ks := &kopiaRepoService{
				logger: velerotest.NewLogger(),
			}

			funcGetRepositoryStatus = tc.funGetStatus
			ready, err := ks.IsReady(t.Context(), udmrepo.RepoOptions{}, tc.readOnly)

			if tc.expectedErr != "" {
				require.EqualError(t, err, tc.expectedErr)
			} else {
				require.NoError(t, err)
			}

			require.Equal(t, tc.expected, ready)
		})
	}
}
