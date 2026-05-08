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

package types

// Bitmap defines the methods to store and iterate the CBT bitmap
type Bitmap interface {
	// Set sets bits within the provided range
	Set(uint64, uint64)

	// SetFull sets all bits to the bitmap
	SetFull()

	// Snapshot returns snapshot of the bitmap
	Snapshot() string

	// ChangeID returns the changeID of the bitmap
	ChangeID() string

	// VolumeID return ID of the volume from which the snapshot is taken
	VolumeID() string

	// Iterator returns the iterator for the CBT Bitmap
	Iterator() Iterator
}

// Iterator defines the methods to iterate the CBT bitmap and query the associated information
type Iterator interface {
	// ChangeID returns the changeID of the bitmap
	ChangeID() string

	// Snapshot returns snapshot of the bitmap
	Snapshot() string

	// VolumeID return ID of the volume from which the snapshot is taken
	VolumeID() string

	// BlockSize returns the granularity of the bitmap
	BlockSize() uint

	// Count returns the toal number of count in the bitmap
	Count() uint64

	// Next returns the offset of the next set block and whether it comes to the end of the iteration
	Next() (uint64, bool)
}
