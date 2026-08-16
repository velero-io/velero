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

package archive

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/vmware-tanzu/velero/pkg/util/filesystem"
)

// Extractor unzips/extracts a backup tarball to a local
// temp directory.
type Extractor struct {
	log logrus.FieldLogger
	fs  filesystem.Interface
}

func NewExtractor(log logrus.FieldLogger, fs filesystem.Interface) *Extractor {
	return &Extractor{
		log: log,
		fs:  fs,
	}
}

// UnzipAndExtractBackup extracts a reader on a gzipped tarball to a local temp directory
func (e *Extractor) UnzipAndExtractBackup(src io.Reader) (string, error) {
	gzr, err := gzip.NewReader(src)
	if err != nil {
		e.log.Infof("error creating gzip reader: %v", err)
		return "", err
	}
	defer gzr.Close()

	return e.readBackup(tar.NewReader(gzr))
}

func (e *Extractor) writeFile(target string, tarRdr *tar.Reader) error {
	file, err := e.fs.Create(target)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := io.Copy(file, tarRdr); err != nil {
		return err
	}
	return nil
}

// sanitizeArchivePath sanitizes archive file path from "G305: Zip Slip vulnerability"
func sanitizeArchivePath(destDir, sourcePath string) (targetPath string, err error) {
	targetPath = filepath.Join(destDir, sourcePath)

	// filepath.Rel reports targetPath relative to destDir; a result of ".." or one that
	// starts with "../" means the joined path landed outside destDir. A plain
	// strings.HasPrefix check has no separator boundary, so a sibling directory whose
	// name begins with destDir's (e.g. "<destDir>-evil") would wrongly be accepted.
	rel, err := filepath.Rel(destDir, targetPath)
	if err != nil {
		return "", fmt.Errorf("invalid archive path %q: %w", sourcePath, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("invalid archive path %q: escapes target directory", sourcePath)
	}

	return targetPath, nil
}

func (e *Extractor) readBackup(tarRdr *tar.Reader) (string, error) {
	dir, err := e.fs.TempDir("", "")
	if err != nil {
		e.log.Infof("error creating temp dir: %v", err)
		return "", err
	}

	for {
		header, err := tarRdr.Next()

		if err == io.EOF {
			break
		}
		if err != nil {
			e.log.Infof("error reading tar: %v", err)
			return "", err
		}

		target, err := sanitizeArchivePath(dir, header.Name)
		if err != nil {
			e.log.Infof("error sanitizing archive path: %s", err.Error())
			return "", err
		}

		switch header.Typeflag {
		case tar.TypeDir:
			err := e.fs.MkdirAll(target, header.FileInfo().Mode())
			if err != nil {
				e.log.Infof("mkdirall error: %v", err)
				return "", err
			}

		case tar.TypeReg:
			// make sure we have the directory created
			err := e.fs.MkdirAll(filepath.Dir(target), header.FileInfo().Mode())
			if err != nil {
				e.log.Infof("mkdirall error: %v", err)
				return "", err
			}

			// create the file
			if err := e.writeFile(target, tarRdr); err != nil {
				e.log.Infof("error copying: %v", err)
				return "", err
			}
		}
	}

	return dir, nil
}
