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

package freelist

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	size := 1024
	chunkSize := 256
	numChunks := size / chunkSize

	fl := New(size, chunkSize)

	assert.NotNil(t, fl)
	assert.Equal(t, chunkSize, fl.chunkSize)
	assert.Len(t, fl.memory, size)
	assert.Equal(t, numChunks, cap(fl.chunks))
	assert.Len(t, fl.chunks, numChunks)
	assert.Equal(t, numChunks, fl.Capacity())
}

func TestGetAndReturn(t *testing.T) {
	size := 1024
	chunkSize := 256

	fl := New(size, chunkSize)

	chunk := fl.Get()
	assert.Equal(t, chunkSize, cap(chunk))
	assert.Len(t, chunk, chunkSize)
	assert.Equal(t, 3, fl.Capacity())

	fl.Return(chunk)
	assert.Equal(t, 4, fl.Capacity())
}

func TestReturnPanic(t *testing.T) {
	fl := New(1024, 256)

	invalidChunk := make([]byte, 128)
	assert.PanicsWithValue(t, "chunk (128) is not allocated by me", func() {
		fl.Return(invalidChunk)
	})
}

func TestChunks(t *testing.T) {
	fl := New(1024, 256)

	chunks := fl.Chunks()
	assert.Len(t, chunks, 4)
	assert.Equal(t, cap(fl.chunks), cap(chunks))
}

func TestCapacity(t *testing.T) {
	fl := New(1024, 256)

	assert.Equal(t, 4, fl.Capacity())

	fl.Get()
	assert.Equal(t, 3, fl.Capacity())
}

func TestConcurrentAccess(t *testing.T) {
	size := 1024 * 10
	chunkSize := 256
	numChunks := size / chunkSize

	fl := New(size, chunkSize)

	var wg sync.WaitGroup
	for i := 0; i < numChunks; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			chunk := fl.Get()
			assert.Equal(t, chunkSize, cap(chunk))
			assert.Len(t, chunk, chunkSize)

			for j := 0; j < len(chunk); j++ {
				chunk[j] = byte(j % 256)
			}

			fl.Return(chunk)
		}()
	}

	wg.Wait()
	assert.Equal(t, numChunks, fl.Capacity())
}
