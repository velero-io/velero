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

package cbt

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBitmapProperties(t *testing.T) {
	b := NewBitmap(1024*1024, 10000*1024*1024, "snap-1", "change-1", "vol-1")
	assert.Equal(t, "snap-1", b.Snapshot())
	assert.Equal(t, "change-1", b.ChangeID())
	assert.Equal(t, "vol-1", b.VolumeID())
}

func TestBitmapSet(t *testing.T) {
	const mb = 1024 * 1024
	const gb = 1024 * 1024 * 1024

	tests := []struct {
		name          string
		blockSize     uint
		totalLength   uint64
		setCalls      []struct{ offset, length uint64 }
		expectedCount uint64
		expectedNext  []uint64
	}{
		{
			name:        "set single block within bounds",
			blockSize:   mb,
			totalLength: 10 * gb,
			setCalls: []struct{ offset, length uint64 }{
				{0, 1000},
			},
			expectedCount: 1,
			expectedNext:  []uint64{0},
		},
		{
			name:        "set exactly one block",
			blockSize:   mb,
			totalLength: 10 * gb,
			setCalls: []struct{ offset, length uint64 }{
				{0, mb},
			},
			expectedCount: 1,
			expectedNext:  []uint64{0},
		},
		{
			name:        "set overlapping two blocks",
			blockSize:   mb,
			totalLength: 10 * gb,
			setCalls: []struct{ offset, length uint64 }{
				{mb - 1, 2},
			},
			expectedCount: 2,
			expectedNext:  []uint64{0, mb},
		},
		{
			name:        "set multiple non-contiguous blocks",
			blockSize:   mb,
			totalLength: 20 * gb,
			setCalls: []struct{ offset, length uint64 }{
				{0, 100},
				{2 * mb, 100},
			},
			expectedCount: 2,
			expectedNext:  []uint64{0, 2 * mb},
		},
		{
			name:        "set completely out of bounds (offset >= length)",
			blockSize:   mb,
			totalLength: 10 * gb,
			setCalls: []struct{ offset, length uint64 }{
				{10 * gb, 100},
				{15 * gb, 100},
			},
			expectedCount: 0,
			expectedNext:  []uint64{},
		},
		{
			name:        "set partially out of bounds (truncated)",
			blockSize:   mb,
			totalLength: 10 * gb,
			setCalls: []struct{ offset, length uint64 }{
				{10*gb - mb/2, mb}, // Starts in the last block, length pushes it out of bounds
			},
			expectedCount: 1, // Only the last block should be set
			expectedNext:  []uint64{10*gb - mb},
		},
		{
			name:        "set spanning entire length",
			blockSize:   mb,
			totalLength: 3 * mb, // 3 blocks: 0-1MB, 1MB-2MB, 2MB-3MB
			setCalls: []struct{ offset, length uint64 }{
				{0, 3 * mb},
			},
			expectedCount: 3,
			expectedNext:  []uint64{0, mb, 2 * mb},
		},
		{
			name:        "set large contiguous range",
			blockSize:   mb,
			totalLength: 100 * gb,
			setCalls: []struct{ offset, length uint64 }{
				{10 * mb, 5 * mb}, // Starts at 10MB, spans 5 full blocks
			},
			expectedCount: 5,
			expectedNext:  []uint64{10 * mb, 11 * mb, 12 * mb, 13 * mb, 14 * mb},
		},
		{
			name:        "set empty length",
			blockSize:   mb,
			totalLength: 10 * gb,
			setCalls: []struct{ offset, length uint64 }{
				{mb, 0},
			},
			expectedCount: 0,
			expectedNext:  []uint64{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := NewBitmap(tt.blockSize, tt.totalLength, "snap-1", "change-1", "vol-1")

			for _, call := range tt.setCalls {
				b.Set(call.offset, call.length)
			}

			iter := b.Iterator()
			require.NotNil(t, iter)

			assert.Equal(t, tt.expectedCount, iter.Count())

			var actualNext []uint64
			for {
				offset, hasNext := iter.Next()
				if !hasNext {
					assert.Equal(t, InvalidOffset64, offset)
					break
				}
				actualNext = append(actualNext, offset)
			}

			if len(tt.expectedNext) == 0 {
				assert.Empty(t, actualNext)
			} else {
				assert.Equal(t, tt.expectedNext, actualNext)
			}
		})
	}
}

func TestBitmapSetFull(t *testing.T) {
	const mb = 1024 * 1024
	// Total length 3MB, blockSize 1MB. This means 3 blocks total:
	// block 0: 0 - 1MB
	// block 1: 1MB - 2MB
	// block 2: 2MB - 3MB
	b := NewBitmap(mb, 3*mb, "snap-1", "change-1", "vol-1")
	b.SetFull()

	iter := b.Iterator()
	require.NotNil(t, iter)

	assert.Equal(t, uint64(3), iter.Count())

	expectedOffsets := []uint64{0, mb, 2 * mb}
	var actualOffsets []uint64
	for {
		offset, hasNext := iter.Next()
		if !hasNext {
			break
		}
		actualOffsets = append(actualOffsets, offset)
	}

	assert.Equal(t, expectedOffsets, actualOffsets)
}

func TestBitmapIterator(t *testing.T) {
	const mb = 1024 * 1024
	const gb = 1024 * 1024 * 1024

	b := NewBitmap(mb, 10*gb, "snap-1", "change-1", "vol-1")

	// Set multiple ranges to test contiguous iteration
	b.Set(mb, 100)      // Block 1
	b.Set(3*mb, 5*mb)   // Blocks 3, 4, 5, 6, 7
	b.Set(10*gb-mb, mb) // Last block

	iter := b.Iterator()
	require.NotNil(t, iter)

	// Test iterator properties
	assert.Equal(t, "snap-1", iter.Snapshot())
	assert.Equal(t, "change-1", iter.ChangeID())
	assert.Equal(t, "vol-1", iter.VolumeID())
	assert.Equal(t, uint(mb), iter.BlockSize())
	assert.Equal(t, uint64(7), iter.Count()) // 1 + 5 + 1 = 7 blocks

	expectedOffsets := []uint64{
		mb,
		3 * mb, 4 * mb, 5 * mb, 6 * mb, 7 * mb,
		10*gb - mb,
	}

	// Test iteration
	var actualOffsets []uint64
	for {
		offset, hasNext := iter.Next()
		if !hasNext {
			assert.Equal(t, InvalidOffset64, offset)
			break
		}
		actualOffsets = append(actualOffsets, offset)
	}

	assert.Equal(t, expectedOffsets, actualOffsets)

	// Test end of iteration multiple times to ensure it stays exhausted
	offset, hasNext := iter.Next()
	assert.False(t, hasNext)
	assert.Equal(t, InvalidOffset64, offset)

	offset, hasNext = iter.Next()
	assert.False(t, hasNext)
	assert.Equal(t, InvalidOffset64, offset)
}

func TestBitmapIteratorNilBitmap(t *testing.T) {
	// Directly create bitmapImpl with a nil roaring.Bitmap to test safety
	b := &bitmapImpl{
		bitmap: nil,
	}

	iter := b.Iterator()
	assert.Nil(t, iter)
}
