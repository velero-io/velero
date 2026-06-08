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

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/vmware-tanzu/velero/pkg/cbtservice"
	cbtservicemocks "github.com/vmware-tanzu/velero/pkg/cbtservice/mocks"
	cbtmocks "github.com/vmware-tanzu/velero/pkg/uploader/cbt/types/mocks"
)

func TestSetBitmapOrFull(t *testing.T) {
	tests := []struct {
		name           string
		nilService     bool
		setupMocks     func(*cbtservicemocks.Service, *cbtmocks.Bitmap)
		expectedErrStr string
	}{
		{
			name:       "nil service",
			nilService: true,
			setupMocks: func(svc *cbtservicemocks.Service, bmp *cbtmocks.Bitmap) {
				bmp.On("SetFull").Return()
			},
			expectedErrStr: "CBT service is absent",
		},
		{
			name: "invalid snapshot",
			setupMocks: func(svc *cbtservicemocks.Service, bmp *cbtmocks.Bitmap) {
				bmp.On("Snapshot").Return("")
				bmp.On("SetFull").Return()
			},
			expectedErrStr: "invalid snapshot",
		},
		{
			name: "allocated blocks success",
			setupMocks: func(svc *cbtservicemocks.Service, bmp *cbtmocks.Bitmap) {
				bmp.On("Snapshot").Return("snap-1")
				bmp.On("ChangeID").Return("")

				svc.On("GetAllocatedBlocks", mock.Anything, "snap-1", mock.Anything).Run(func(args mock.Arguments) {
					record := args.Get(2).(func([]cbtservice.Range) error)
					record([]cbtservice.Range{
						{Offset: 0, Length: 4096},
						{Offset: 8192, Length: 4096},
					})
				}).Return(nil)

				bmp.On("Set", uint64(0), uint64(4096)).Return()
				bmp.On("Set", uint64(8192), uint64(4096)).Return()
			},
		},
		{
			name: "allocated blocks error",
			setupMocks: func(svc *cbtservicemocks.Service, bmp *cbtmocks.Bitmap) {
				bmp.On("Snapshot").Return("snap-1")
				bmp.On("ChangeID").Return("")

				svc.On("GetAllocatedBlocks", mock.Anything, "snap-1", mock.Anything).Return(errors.New("mock alloc error"))
				bmp.On("SetFull").Return()
			},
			expectedErrStr: "error getting allocated blocks from CBT service: mock alloc error",
		},
		{
			name: "changed blocks success",
			setupMocks: func(svc *cbtservicemocks.Service, bmp *cbtmocks.Bitmap) {
				bmp.On("Snapshot").Return("snap-1")
				bmp.On("ChangeID").Return("change-1")

				svc.On("GetChangedBlocks", mock.Anything, "snap-1", "change-1", mock.Anything).Run(func(args mock.Arguments) {
					record := args.Get(3).(func([]cbtservice.Range) error)
					record([]cbtservice.Range{
						{Offset: 4096, Length: 4096},
					})
				}).Return(nil)

				bmp.On("Set", uint64(4096), uint64(4096)).Return()
			},
		},
		{
			name: "changed blocks error",
			setupMocks: func(svc *cbtservicemocks.Service, bmp *cbtmocks.Bitmap) {
				bmp.On("Snapshot").Return("snap-1")
				bmp.On("ChangeID").Return("change-1")

				svc.On("GetChangedBlocks", mock.Anything, "snap-1", "change-1", mock.Anything).Return(errors.New("mock changed error"))
				bmp.On("SetFull").Return()
			},
			expectedErrStr: "error getting changed blocks from CBT service: mock changed error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svcMock := new(cbtservicemocks.Service)
			bmpMock := new(cbtmocks.Bitmap)

			if tt.setupMocks != nil {
				tt.setupMocks(svcMock, bmpMock)
			}

			var svc cbtservice.Service
			if !tt.nilService {
				svc = svcMock
			}

			err := SetBitmapOrFull(context.Background(), svc, bmpMock)

			if tt.expectedErrStr != "" {
				require.Error(t, err)
				require.EqualError(t, err, tt.expectedErrStr)
			} else {
				require.NoError(t, err)
			}

			if !tt.nilService {
				svcMock.AssertExpectations(t)
			}
			bmpMock.AssertExpectations(t)
		})
	}
}
