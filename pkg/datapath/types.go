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

package datapath

import (
	"context"

	"github.com/vmware-tanzu/velero/pkg/uploader"
)

// Result represents the result of a backup/restore
type Result struct {
	Backup  BackupResult
	Restore RestoreResult
}

// BackupResult represents the result of a backup
type BackupResult struct {
	SnapshotID       string      `json:"snapshotID"`
	EmptySnapshot    bool        `json:"emptySnapshot"`
	Source           AccessPoint `json:"source,omitempty"`
	TotalBytes       int64       `json:"totalBytes,omitempty"`
	IncrementalBytes int64       `json:"incrementalBytes,omitempty"`
}

// RestoreResult represents the result of a restore
type RestoreResult struct {
	Target     AccessPoint `json:"target,omitempty"`
	TotalBytes int64       `json:"totalBytes,omitempty"`
}

// Callbacks defines the collection of callbacks during backup/restore
type Callbacks struct {
	OnCompleted func(context.Context, string, string, Result)
	OnFailed    func(context.Context, string, string, error)
	OnCancelled func(context.Context, string, string)
	OnProgress  func(context.Context, string, string, *uploader.Progress)
}

// AccessPoint represents an access point that has been exposed to a data path instance
type AccessPoint struct {
	ByPath  string                        `json:"byPath"`
	VolMode uploader.PersistentVolumeMode `json:"volumeMode"`
}

// AsyncBR is the interface for asynchronous data path methods
type AsyncBR interface {
	// Init initializes an asynchronous data path instance
	Init(ctx context.Context, param any) error

	// StartBackup starts an asynchronous data path instance for backup
	StartBackup(source AccessPoint, dataMoverConfig map[string]string, param any) error

	// StartRestore starts an asynchronous data path instance for restore
	StartRestore(snapshotID string, target AccessPoint, dataMoverConfig map[string]string, param any) error

	// Cancel cancels an asynchronous data path instance
	Cancel()

	// Close closes an asynchronous data path instance
	Close(ctx context.Context)
}
