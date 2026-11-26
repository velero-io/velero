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
	"bytes"
	"compress/gzip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/velero-io/velero/pkg/test"
)

// FuzzSanitizeArchivePath checks that a path accepted by sanitizeArchivePath
// never resolves outside the destination directory.
func FuzzSanitizeArchivePath(f *testing.F) {
	for _, seed := range []string{
		"resources/pods/namespaces/ns/pod.json",
		"../escape.txt",
		"a/../../escape",
		"/etc/passwd",
		"a/./b",
		"",
		"..",
		"dest-evil/file",
	} {
		f.Add(seed)
	}

	const destDir = "/tmp/velero-fuzz/dest"

	f.Fuzz(func(t *testing.T, sourcePath string) {
		target, err := sanitizeArchivePath(destDir, sourcePath)
		if err != nil {
			return
		}

		rel, err := filepath.Rel(destDir, target)
		if err != nil {
			t.Fatalf("accepted %q but filepath.Rel failed: %v", sourcePath, err)
		}
		if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			t.Fatalf("accepted %q, target %q is outside %q", sourcePath, target, destDir)
		}
	})
}

// FuzzUnzipAndExtractBackup feeds arbitrary bytes to the backup extractor and
// checks that it returns an error or a result without panicking.
func FuzzUnzipAndExtractBackup(f *testing.F) {
	f.Add(validBackupArchive(f))
	f.Add(traversalArchive(f))
	f.Add([]byte{})
	f.Add([]byte("not a gzip stream"))

	f.Fuzz(func(t *testing.T, data []byte) {
		ext := NewExtractor(test.NewLogger(), test.NewFakeFileSystem())
		// Keep extraction small so the fuzzer does not spend time on large inputs.
		ext.maxExtractionSize = 1 << 20

		_, _ = ext.UnzipAndExtractBackup(bytes.NewReader(data))
	})
}

func validBackupArchive(f *testing.F) []byte {
	f.Helper()
	return buildArchive(f, []tar.Header{
		{Name: "resources/", Typeflag: tar.TypeDir, Mode: 0755},
		{Name: "resources/pods/", Typeflag: tar.TypeDir, Mode: 0755},
		{Name: "resources/pods/namespaces/ns/pod.json", Typeflag: tar.TypeReg, Mode: 0644, Size: 2},
	}, []byte("{}"))
}

func traversalArchive(f *testing.F) []byte {
	f.Helper()
	return buildArchive(f, []tar.Header{
		{Name: "../escape.txt", Typeflag: tar.TypeReg, Mode: 0644, Size: 2},
	}, []byte("{}"))
}

// buildArchive writes the headers to a gzipped tarball. Regular files get the
// provided content, which must match their declared size.
func buildArchive(f *testing.F, headers []tar.Header, content []byte) []byte {
	f.Helper()

	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)

	for i := range headers {
		h := headers[i]
		if err := tw.WriteHeader(&h); err != nil {
			f.Fatalf("writing tar header %q: %v", h.Name, err)
		}
		if h.Typeflag == tar.TypeReg {
			if _, err := tw.Write(content); err != nil {
				f.Fatalf("writing tar content %q: %v", h.Name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		f.Fatalf("closing tar writer: %v", err)
	}
	if err := gzw.Close(); err != nil {
		f.Fatalf("closing gzip writer: %v", err)
	}
	return buf.Bytes()
}
