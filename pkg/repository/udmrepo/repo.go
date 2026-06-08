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

package udmrepo

import (
	"context"
	"io"
	"time"
)

type ID string

// ManifestEntryMetadata is the metadata describing one manifest data
type ManifestEntryMetadata struct {
	ID      ID                // The ID of the manifest data
	Length  int32             // The data size of the manifest data
	Labels  map[string]string // Labels saved together with the manifest data
	ModTime time.Time         // Modified time of the manifest data
}

type RepoManifest struct {
	Payload  any                    // The user data of manifest
	Metadata *ManifestEntryMetadata // The metadata data of manifest
}

type ManifestFilter struct {
	Labels map[string]string
}

const (
	// Below consts descrbe the data type of one object.
	// Metadata: This type describes how the data is organized.
	// For a file system backup, the Metadata describes a Dir or File.
	// For a block backup, the Metadata describes a Disk and its incremental link.
	ObjectDataTypeUnknown  int = 0
	ObjectDataTypeMetadata int = 1
	ObjectDataTypeData     int = 2

	// Below consts defines the access mode when creating an object for write
	ObjectDataAccessModeUnknown int = 0
	ObjectDataAccessModeFile    int = 1
	ObjectDataAccessModeBlock   int = 2

	ObjectDataBackupModeUnknown int = 0
	ObjectDataBackupModeFull    int = 1
	ObjectDataBackupModeInc     int = 2
)

// ObjectWriteOptions defines the options when creating an object for write
type ObjectWriteOptions struct {
	FullPath     string // Full logical path of the object
	DataType     int    // OBJECT_DATA_TYPE_*
	Description  string // A description of the object, could be empty
	Prefix       ID     // A prefix of the name used to save the object
	AccessMode   int    // OBJECT_DATA_ACCESS_*
	BackupMode   int    // OBJECT_DATA_BACKUP_*
	AsyncWrites  int    // Num of async writes for the object, 0 means no async write
	ParentObject ID     // The object in the previous snapshot, for incremental backup
}

type AdvancedFeatureInfo struct {
	MultiPartBackup bool // if set to true, it means the repo supports multiple-part backup
}

type ObjectMetadata struct {
	ID          ID
	Name        string
	Type        int // OBJECT_DATA_TYPE_*
	Size        int64
	ModTime     time.Time
	Permissions int
	UserID      uint32
	GroupID     uint32
}

type Metadata struct {
	SubObjects []ObjectMetadata
	Summary    string
}

type Snapshot struct {
	Source      string
	Description string
	StartTime   time.Time
	EndTime     time.Time
	Tags        map[string]string
	TotalSize   int64
	RootObject  ObjectMetadata
}

// BackupRepoService is used to initialize, open or maintain a backup repository
type BackupRepoService interface {
	// Create creates a new backup repository.
	// repoOption: option to the backup repository and the underlying backup storage.
	Create(ctx context.Context, repoOption RepoOptions) error

	// Connect connects to an existing backup repository.
	// repoOption: option to the backup repository and the underlying backup storage.
	Connect(ctx context.Context, repoOption RepoOptions) error

	// IsReady checks if the backup repository has been ready in the underlying backup storage.
	// repoOption: option to the underlying backup storage
	IsReady(ctx context.Context, repoOption RepoOptions, readOnly bool) (bool, error)

	// Open opens an backup repository that has been created/connected.
	// repoOption: options to open the backup repository and the underlying storage.
	Open(ctx context.Context, repoOption RepoOptions) (BackupRepo, error)

	// Maintain is periodically called to maintain the backup repository to eliminate redundant data.
	// repoOption: options to maintain the backup repository.
	Maintain(ctx context.Context, repoOption RepoOptions) error

	// DefaultMaintenanceFrequency returns the defgault frequency of maintenance, callers refer this
	// frequency to maintain the backup repository to get the best maintenance performance
	DefaultMaintenanceFrequency() time.Duration

	// ClientSideCacheLimit returns the max cache size required on client side
	ClientSideCacheLimit(repoOption map[string]string) int64
}

// BackupRepo provides the access to the backup repository
type BackupRepo interface {
	// OpenObject opens an existing object for read.
	// id: the object's unified identifier.
	OpenObject(ctx context.Context, id ID) (ObjectReader, error)

	// GetManifest gets a manifest data from the backup repository.
	GetManifest(ctx context.Context, id ID, mani *RepoManifest) error

	// FindManifests gets one or more manifest data that match the given labels
	FindManifests(ctx context.Context, filter ManifestFilter) ([]*ManifestEntryMetadata, error)

	// NewObjectWriter creates a new object and return the object's writer interface.
	// return: A unified identifier of the object on success.
	NewObjectWriter(ctx context.Context, opt ObjectWriteOptions) (ObjectWriter, error)

	// WriteMetadata writes metadata to the repo, metadata is used to describe data, e.g., file system
	// dirs are saved as metadata
	WriteMetadata(ctx context.Context, meta *Metadata, opt ObjectWriteOptions) (ID, error)

	// ReadMetadata reads a metadata from repo by the metadata's object ID
	ReadMetadata(ctx context.Context, id ID) (*Metadata, error)

	// PutManifest saves a manifest object into the backup repository.
	PutManifest(ctx context.Context, mani RepoManifest) (ID, error)

	// DeleteManifest deletes a manifest object from the backup repository.
	DeleteManifest(ctx context.Context, id ID) error

	// Flush flushes all the backup repository data
	Flush(ctx context.Context) error

	// GetAdvancedFeatures returns the support for advanced features
	GetAdvancedFeatures() AdvancedFeatureInfo

	// ConcatenateObjects is for multiple-part backup, it concatenates multiple objects into one object
	ConcatenateObjects(ctx context.Context, objectIDs []ID) (ID, error)

	// Time returns the local time of the backup repository. It may be different from the time of the caller
	Time() time.Time

	// SaveSnapshot saves a repo snapshot
	SaveSnapshot(ctx context.Context, snapshot Snapshot) (ID, error)

	// GetSnapshot returns a repo snapshot from snapshot ID
	GetSnapshot(ctx context.Context, id ID) (Snapshot, error)

	// DeleteSnapshot deletes a repo snapshot
	DeleteSnapshot(ctx context.Context, id ID) error

	// ListSnapshot lists all snapshots in repo for the given source
	ListSnapshot(ctx context.Context, source string) ([]Snapshot, error)

	// Close closes the backup repository
	Close(ctx context.Context) error
}

type ObjectReader interface {
	io.ReadCloser
	io.Seeker

	// Length returns the logical size of the object
	Length() int64
}

type ObjectWriter interface {
	io.WriteCloser

	// WriterAt is used in the cases that the object is not written sequentially
	io.WriterAt

	// Checkpoint is periodically called to preserve the state of data written to the repo so far.
	// Checkpoint returns a unified identifier that represent the current state.
	// An empty ID could be returned on success if the backup repository doesn't support this.
	Checkpoint() (ID, error)

	// Result waits for the completion of the object write.
	// Result returns the object's unified identifier after the write completes.
	Result() (ID, error)
}
