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
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/vmware-tanzu/velero/pkg/cbtservice"
	cbtservicemocks "github.com/vmware-tanzu/velero/pkg/cbtservice/mocks"
)

func TestSetBitmapOrFull(t *testing.T) {
	const mb = 1024 * 1024
	tests := []struct {
		name           string
		nilService     bool
		incOnly        bool
		snapshotID     string
		changeID       string
		setupMocks     func(*cbtservicemocks.Service)
		expectedErrStr string
		expectedCount  uint64
		expectedNext   []uint64
	}{
		{
			name:           "nil service",
			nilService:     true,
			snapshotID:     "snap-1",
			changeID:       "change-1",
			setupMocks:     func(svc *cbtservicemocks.Service) {},
			expectedErrStr: "CBT service is absent, fallback to real full",
			expectedCount:  3,
			expectedNext:   []uint64{0, mb, 2 * mb},
		},
		{
			name:           "invalid snapshot",
			snapshotID:     "",
			setupMocks:     func(svc *cbtservicemocks.Service) {},
			expectedErrStr: "invalid snapshot, fallback to real full",
			expectedCount:  3,
			expectedNext:   []uint64{0, mb, 2 * mb},
		},
		{
			name:           "invalid changeID",
			incOnly:        true,
			snapshotID:     "snap-1",
			changeID:       "",
			setupMocks:     func(svc *cbtservicemocks.Service) {},
			expectedErrStr: "invalid changeID, fallback to real full",
			expectedCount:  3,
			expectedNext:   []uint64{0, mb, 2 * mb},
		},
		{
			name:       "allocated blocks success",
			snapshotID: "snap-1",
			changeID:   "",
			setupMocks: func(svc *cbtservicemocks.Service) {
				svc.On("GetAllocatedBlocks", mock.Anything, "snap-1", mock.Anything).Run(func(args mock.Arguments) {
					record := args.Get(2).(func([]cbtservice.Range) error)
					record([]cbtservice.Range{
						{Offset: 0, Length: uint64(mb)},
						{Offset: uint64(2 * mb), Length: uint64(mb)},
					})
				}).Return(nil)
			},
			expectedCount: 2,
			expectedNext:  []uint64{0, 2 * mb},
		},
		{
			name:       "allocated blocks error",
			snapshotID: "snap-1",
			changeID:   "",
			setupMocks: func(svc *cbtservicemocks.Service) {
				svc.On("GetAllocatedBlocks", mock.Anything, "snap-1", mock.Anything).Return(errors.New("mock alloc error"))
			},
			expectedErrStr: "error getting allocated blocks from CBT service, fallback to real full: mock alloc error",
			expectedCount:  3,
			expectedNext:   []uint64{0, mb, 2 * mb},
		},
		{
			name:       "changed blocks success",
			snapshotID: "snap-1",
			changeID:   "change-1",
			setupMocks: func(svc *cbtservicemocks.Service) {
				svc.On("GetChangedBlocks", mock.Anything, "snap-1", "change-1", mock.Anything).Run(func(args mock.Arguments) {
					record := args.Get(3).(func([]cbtservice.Range) error)
					record([]cbtservice.Range{
						{Offset: uint64(mb), Length: uint64(mb)},
					})
				}).Return(nil)
			},
			expectedCount: 1,
			expectedNext:  []uint64{mb},
		},
		{
			name:       "changed blocks error with incOnly",
			incOnly:    true,
			snapshotID: "snap-1",
			changeID:   "change-1",
			setupMocks: func(svc *cbtservicemocks.Service) {
				svc.On("GetChangedBlocks", mock.Anything, "snap-1", "change-1", mock.Anything).Return(errors.New("mock changed error"))
			},
			expectedErrStr: "error getting changed blocks from CBT service, fallback to real full: mock changed error",
			expectedCount:  3,
			expectedNext:   []uint64{0, mb, 2 * mb},
		},
		{
			name:       "both changed blocks error and allocated blocks error",
			snapshotID: "snap-1",
			changeID:   "change-1",
			setupMocks: func(svc *cbtservicemocks.Service) {
				svc.On("GetChangedBlocks", mock.Anything, "snap-1", "change-1", mock.Anything).Return(errors.New("mock changed error"))
				svc.On("GetAllocatedBlocks", mock.Anything, "snap-1", mock.Anything).Return(errors.New("mock alloc error"))
			},
			expectedErrStr: "error getting both changed and allocated blocks from CBT service, fallback to real full: mock alloc error",
			expectedCount:  3,
			expectedNext:   []uint64{0, mb, 2 * mb},
		},
		{
			name:       "changed blocks error fallback to full",
			snapshotID: "snap-1",
			changeID:   "change-1",
			setupMocks: func(svc *cbtservicemocks.Service) {
				svc.On("GetChangedBlocks", mock.Anything, "snap-1", "change-1", mock.Anything).Return(errors.New("mock changed error"))

				svc.On("GetAllocatedBlocks", mock.Anything, "snap-1", mock.Anything).Run(func(args mock.Arguments) {
					record := args.Get(2).(func([]cbtservice.Range) error)
					record([]cbtservice.Range{
						{Offset: 0, Length: uint64(mb)},
						{Offset: uint64(2 * mb), Length: uint64(mb)},
					})
				}).Return(nil)
			},
			expectedErrStr: "error getting changed blocks from CBT service, fallback to full: mock changed error",
			expectedCount:  2,
			expectedNext:   []uint64{0, 2 * mb},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svcMock := new(cbtservicemocks.Service)

			if tt.setupMocks != nil {
				tt.setupMocks(svcMock)
			}

			var svc cbtservice.Service
			if !tt.nilService {
				svc = svcMock
			}

			bmp := NewBitmap(mb, 3*mb, tt.snapshotID, tt.changeID, "vol-1")

			err := SetBitmapOrFull(context.Background(), svc, bmp, tt.incOnly)

			if tt.expectedErrStr != "" {
				require.Error(t, err)
				require.EqualError(t, err, tt.expectedErrStr)
			} else {
				require.NoError(t, err)
			}

			if !tt.nilService {
				svcMock.AssertExpectations(t)
			}

			iter := bmp.Iterator()
			require.NotNil(t, iter)
			assert.Equal(t, tt.expectedCount, iter.Count())

			var actualOffsets []uint64
			for {
				offset, hasNext := iter.Next()
				if !hasNext {
					break
				}
				actualOffsets = append(actualOffsets, offset)
			}

			if len(tt.expectedNext) > 0 {
				assert.Equal(t, tt.expectedNext, actualOffsets)
			} else {
				assert.Empty(t, actualOffsets)
			}
		})
	}
}
