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
	"math/bits"

	"github.com/RoaringBitmap/roaring"

	"github.com/vmware-tanzu/velero/pkg/uploader/cbt/types"
)

const (
	InvalidOffset64 = ^uint64(0)
)

type bitmapImpl struct {
	bitmap       *roaring.Bitmap
	blockSize    uint
	blockSizeLog int
	length       uint64
	snapshot     string
	changeID     string
	volumeID     string
}

type bitmapIterator struct {
	bitmapImpl
	iterator roaring.IntPeekable
}

func NewBitmap(blockSize uint, length uint64, snapshot string, changeID string, volumeID string) types.Bitmap {
	return &bitmapImpl{
		bitmap:       roaring.New(),
		blockSize:    blockSize,
		blockSizeLog: bits.Len(blockSize) - 1,
		length:       length,
		snapshot:     snapshot,
		changeID:     changeID,
		volumeID:     volumeID,
	}
}

func (c *bitmapImpl) Set(offset, length uint64) {
	if offset >= c.length {
		return
	}

	if offset+length > c.length {
		length = c.length - offset
	}

	start := offset >> c.blockSizeLog
	end := (offset + length + uint64(c.blockSize) - 1) >> c.blockSizeLog

	c.bitmap.AddRange(start, end)
}

func (c *bitmapImpl) SetFull() {
	start := uint64(0)
	end := (c.length + uint64(c.blockSize) - 1) >> c.blockSizeLog

	c.bitmap.AddRange(start, end)
}

func (c *bitmapImpl) Snapshot() string {
	return c.snapshot
}

func (c *bitmapImpl) ChangeID() string {
	return c.changeID
}

func (c *bitmapImpl) VolumeID() string {
	return c.volumeID
}

func (c *bitmapImpl) Iterator() types.Iterator {
	if c.bitmap == nil {
		return nil
	}

	return &bitmapIterator{
		bitmapImpl: *c,
		iterator:   c.bitmap.Iterator(),
	}
}

func (c *bitmapIterator) Next() (uint64, bool) {
	if !c.iterator.HasNext() {
		return InvalidOffset64, false
	}

	return uint64(c.iterator.Next()) << c.blockSizeLog, true
}

func (c *bitmapIterator) Count() uint64 {
	return c.bitmap.GetCardinality()
}

func (c *bitmapIterator) BlockSize() uint {
	return c.blockSize
}
