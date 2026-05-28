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
	"fmt"
)

type FreeList struct {
	chunks    chan []byte
	memory    []byte
	chunkSize int
}

func New(size, chunkSize int) *FreeList {
	memory := make([]byte, size)
	numChunks := size / chunkSize
	chunks := make(chan []byte, numChunks)

	for i := range numChunks {
		start := i * chunkSize
		end := start + chunkSize

		chunks <- memory[start:end:end]
	}

	return &FreeList{
		chunks:    chunks,
		memory:    memory,
		chunkSize: chunkSize,
	}
}

func (f *FreeList) Chunks() <-chan []byte {
	return f.chunks
}

func (f *FreeList) Get() []byte {
	return <-f.chunks
}

func (f *FreeList) Return(chunk []byte) {
	if cap(chunk) != f.chunkSize {
		panic(fmt.Sprintf("chunk (%v) is not allocated by me", cap(chunk)))
	}

	chunk = chunk[:cap(chunk)]
	f.chunks <- chunk
}

func (f *FreeList) Capacity() int {
	return len(f.chunks)
}
