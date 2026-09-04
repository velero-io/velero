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

	"github.com/cockroachdb/errors"

	"github.com/vmware-tanzu/velero/pkg/cbtservice"
	"github.com/vmware-tanzu/velero/pkg/uploader/cbt/types"
)

// SetBitmapOrFull translates the allocated/changed blocks from CBT service to the given bitmap or set the bitmap to full when error happens
func SetBitmapOrFull(ctx context.Context, service cbtservice.Service, bitmap types.Bitmap, incOnly bool) (ret error) {
	setFull := false

	defer func() {
		bitmap.SetError(ret)

		if setFull {
			bitmap.SetFull()
		}
	}()

	if service == nil {
		setFull = true
		return errors.New("CBT service is absent, fallback to real full")
	}

	if bitmap.Snapshot() == "" {
		setFull = true
		return errors.New("invalid snapshot, fallback to real full")
	}

	if incOnly && bitmap.ChangeID() == "" {
		setFull = true
		return errors.New("invalid changeID, fallback to real full")
	}

	var changedErr error
	if bitmap.ChangeID() != "" {
		err := service.GetChangedBlocks(ctx, bitmap.Snapshot(), bitmap.ChangeID(), func(blocks []cbtservice.Range) error {
			for _, b := range blocks {
				bitmap.Set(b.Offset, b.Length)
			}

			return nil
		})

		if err == nil {
			return nil
		}

		if incOnly {
			setFull = true
			return errors.Wrap(err, "error getting changed blocks from CBT service, fallback to real full")
		}

		changedErr = err
	}

	err := service.GetAllocatedBlocks(ctx, bitmap.Snapshot(), func(blocks []cbtservice.Range) error {
		for _, b := range blocks {
			bitmap.Set(b.Offset, b.Length)
		}

		return nil
	})

	if err != nil {
		setFull = true

		if changedErr != nil {
			return errors.Wrap(err, "error getting both changed and allocated blocks from CBT service, fallback to real full")
		} else {
			return errors.Wrap(err, "error getting allocated blocks from CBT service, fallback to real full")
		}
	}

	if changedErr != nil {
		return errors.Wrap(changedErr, "error getting changed blocks from CBT service, fallback to full")
	}

	return nil
}
