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

package test

import (
	"io"
	"io/fs"
	"os"

	"github.com/spf13/afero"

	"github.com/velero-io/velero/pkg/util/filesystem"
)

type FakeFileSystem struct {
	fs afero.Fs

	ReadDirCalls []string
}

func NewFakeFileSystem() *FakeFileSystem {
	return &FakeFileSystem{
		fs: afero.NewMemMapFs(),
	}
}

func (fs *FakeFileSystem) Glob(path string) ([]string, error) {
	return afero.Glob(fs.fs, path)
}

func (fs *FakeFileSystem) TempDir(dir, prefix string) (string, error) {
	return afero.TempDir(fs.fs, dir, prefix)
}

func (fs *FakeFileSystem) MkdirAll(path string, perm os.FileMode) error {
	return fs.fs.MkdirAll(path, perm)
}

func (fs *FakeFileSystem) Create(name string) (io.WriteCloser, error) {
	return fs.fs.Create(name)
}

func (fs *FakeFileSystem) OpenFile(name string, flag int, perm os.FileMode) (io.WriteCloser, error) {
	return fs.fs.OpenFile(name, flag, perm)
}

func (fs *FakeFileSystem) RemoveAll(path string) error {
	return fs.fs.RemoveAll(path)
}

func (fs *FakeFileSystem) ReadDir(dirname string) ([]fs.FileInfo, error) {
	fs.ReadDirCalls = append(fs.ReadDirCalls, dirname)
	return afero.ReadDir(fs.fs, dirname)
}

func (fs *FakeFileSystem) ReadFile(filename string) ([]byte, error) {
	return afero.ReadFile(fs.fs, filename)
}

func (fs *FakeFileSystem) DirExists(path string) (bool, error) {
	return afero.DirExists(fs.fs, path)
}

func (fs *FakeFileSystem) Stat(path string) (os.FileInfo, error) {
	return fs.fs.Stat(path)
}

func (fs *FakeFileSystem) WithFile(path string, data []byte) *FakeFileSystem {
	file, _ := fs.fs.Create(path)
	_, _ = file.Write(data)
	file.Close()

	return fs
}

func (fs *FakeFileSystem) WithFileAndMode(path string, data []byte, mode os.FileMode) *FakeFileSystem {
	file, _ := fs.fs.OpenFile(path, os.O_CREATE|os.O_RDWR, mode)
	_, _ = file.Write(data)
	file.Close()

	return fs
}

func (fs *FakeFileSystem) WithDirectory(path string) *FakeFileSystem {
	_ = fs.fs.MkdirAll(path, 0755)
	return fs
}

func (fs *FakeFileSystem) WithDirectories(path ...string) *FakeFileSystem {
	for _, dir := range path {
		fs = fs.WithDirectory(dir)
	}

	return fs
}

func (fs *FakeFileSystem) TempFile(dir, prefix string) (filesystem.NameWriteCloser, error) {
	return afero.TempFile(fs.fs, dir, prefix)
}
