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

package uploader

import (
	"fmt"
	"strings"
)

const (
	KopiaType            = "kopia"
	BlockType            = "velero-block"
	SnapshotRequesterTag = "snapshot-requester"
	SnapshotUploaderTag  = "snapshot-uploader"
)

type PersistentVolumeMode string

const (
	// PersistentVolumeBlock means the volume will not be formatted with a filesystem and will remain a raw block device.
	PersistentVolumeBlock PersistentVolumeMode = "Block"
	// PersistentVolumeFilesystem means the volume will be or is formatted with a filesystem.
	PersistentVolumeFilesystem PersistentVolumeMode = "Filesystem"
)

// ValidateUploaderType validates if the input param is a valid uploader type.
// It will return an error if it's invalid.
func ValidateUploaderType(t string) (string, error) {
	t = strings.TrimSpace(t)
	if t != KopiaType && t != BlockType {
		return "", fmt.Errorf("invalid uploader type '%s', valid types: '%s', '%s'", t, KopiaType, BlockType)
	}

	return "", nil
}

type SnapshotInfo struct {
	ID   string `json:"id"`
	Size int64  `json:"Size"`
}

// Progress which defined two variables to record progress
type Progress struct {
	TotalBytes int64 `json:"totalBytes,omitempty"`
	BytesDone  int64 `json:"doneBytes,omitempty"`
}

// UploaderProgress which defined generic interface to update progress
type ProgressUpdater interface {
	UpdateProgress(p *Progress)
}
