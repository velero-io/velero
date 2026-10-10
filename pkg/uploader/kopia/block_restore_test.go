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
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kopia/kopia/fs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type partialWriter struct {
	limit int
}

func (p *partialWriter) Write(b []byte) (int, error) {
	n := len(b)
	if n > p.limit {
		n = p.limit
	}
	return n, nil
}

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) {
	return 0, nil
}

type errorWriter struct {
	err error
}

func (e errorWriter) Write([]byte) (int, error) {
	return 0, e.err
}

func TestWriteBufferContentsPartialWrites(t *testing.T) {
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i)
	}

	var progress int64
	err := writeBufferContents(&partialWriter{limit: 50}, data, len(data), func(n int64) {
		progress += n
	})
	require.NoError(t, err)
	assert.Equal(t, int64(len(data)), progress)
}

func TestWriteBufferContentsZeroWriteReturnsError(t *testing.T) {
	data := []byte("test")
	err := writeBufferContents(zeroWriter{}, data, len(data), func(int64) {})
	require.ErrorIs(t, err, io.ErrShortWrite)
}

func TestWriteBufferContentsWriteError(t *testing.T) {
	writeErr := errors.New("write failed")
	data := []byte("test")
	err := writeBufferContents(errorWriter{err: writeErr}, data, len(data), func(int64) {})
	require.ErrorIs(t, err, writeErr)
}

func TestWriteBufferContentsIncorrectSliceEndPanics(t *testing.T) {
	data := make([]byte, 256)

	panicked := false
	func() {
		defer func() {
			if recover() != nil {
				panicked = true
			}
		}()

		pw := &partialWriter{limit: 50}
		buffer := data
		bytesToWrite := len(buffer)
		offset := 0
		for bytesToWrite > 0 {
			n, _ := pw.Write(buffer[offset:bytesToWrite])
			bytesToWrite -= n
			offset += n
		}
	}()

	assert.True(t, panicked, "incorrect slice end should panic on partial writes")
}

type mockFile struct {
	name    string
	size    int64
	reader  io.ReadCloser
	openErr error
}

func (m *mockFile) Name() string                { return m.name }
func (m *mockFile) Size() int64                 { return m.size }
func (m *mockFile) Mode() os.FileMode           { return 0o644 }
func (m *mockFile) ModTime() time.Time          { return time.Time{} }
func (m *mockFile) IsDir() bool                 { return false }
func (m *mockFile) Sys() any                    { return nil }
func (m *mockFile) Owner() fs.OwnerInfo         { return fs.OwnerInfo{} }
func (m *mockFile) Device() fs.DeviceInfo       { return fs.DeviceInfo{} }
func (m *mockFile) LocalFilesystemPath() string { return "" }
func (m *mockFile) Close()                      {}
func (m *mockFile) Open(context.Context) (fs.Reader, error) {
	if m.openErr != nil {
		return nil, m.openErr
	}
	return &mockReader{reader: m.reader, entry: m}, nil
}

type mockReader struct {
	reader io.ReadCloser
	entry  fs.Entry
}

func (r *mockReader) Read(p []byte) (int, error)     { return r.reader.Read(p) }
func (r *mockReader) Close() error                   { return r.reader.Close() }
func (r *mockReader) Seek(int64, int) (int64, error) { return 0, nil }
func (r *mockReader) Entry() (fs.Entry, error)       { return r.entry, nil }

func TestBlockOutputWriteFile(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "block-data")
	require.NoError(t, os.WriteFile(tmpFile, make([]byte, 512), 0o644))

	data := make([]byte, 512)
	for i := range data {
		data[i] = byte(i % 256)
	}

	output := &BlockOutput{
		targetFileName: tmpFile,
	}

	remoteFile := &mockFile{
		name:   "bdev",
		size:   int64(len(data)),
		reader: io.NopCloser(bytes.NewReader(data)),
	}

	err := output.WriteFile(context.Background(), "bdev", remoteFile, func(int64) {})
	require.NoError(t, err)

	written, err := os.ReadFile(tmpFile)
	require.NoError(t, err)
	assert.Equal(t, data, written)
}

func TestBlockOutputWriteFileOpenError(t *testing.T) {
	openErr := errors.New("open failed")
	output := &BlockOutput{targetFileName: filepath.Join(t.TempDir(), "missing")}

	remoteFile := &mockFile{
		name:    "bdev",
		openErr: openErr,
	}

	err := output.WriteFile(context.Background(), "bdev", remoteFile, func(int64) {})
	require.ErrorIs(t, err, openErr)
}

func TestBlockOutputWriteFileTargetOpenError(t *testing.T) {
	output := &BlockOutput{targetFileName: filepath.Join(t.TempDir(), "missing", "bdev")}

	remoteFile := &mockFile{
		name:   "bdev",
		reader: io.NopCloser(bytes.NewReader([]byte("data"))),
	}

	err := output.WriteFile(context.Background(), "bdev", remoteFile, func(int64) {})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to open file")
}
