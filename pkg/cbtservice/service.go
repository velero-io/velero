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

package cbtservice

import "context"

// Range defines the range of a change
type Range struct {
	Offset uint64
	Length uint64
}

// SourceInfo is the information provided to the uploader, the uploader calls CBT service with this information
type SourceInfo struct {
	// Snapshot is the identifier of the current snapshot
	Snapshot string

	// ChangeID is the identifier associated to the current snapshot that is used as changeID for following backups
	ChangeID string

	// VolumeID is the identifier uniquely identifier a volume in the storage to which the CBT is associated
	VolumeID string
}

// Service defines the methods for CBT service which could be implemented by Kubernetes SnapshotMetadataService or other customized services
type Service interface {
	// GetAllocatedBlocks enumerates the allocated blocks of the snapshot and call the record callback
	GetAllocatedBlocks(ctx context.Context, snapshot string, record func([]Range) error) error

	// GetChangedBlocks enumerates the changed blocks of the snapshot since PIT of changeID and call the record callback
	GetChangedBlocks(ctx context.Context, snapshot string, changeID string, record func([]Range) error) error
}
