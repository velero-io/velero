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

// Tier reports which CBT data source ended up populating the bitmap.
type Tier int

const (
	// TierChanged means the bitmap holds only the blocks changed since the parent
	// snapshot. This is the cheapest and the intended result of an incremental backup.
	TierChanged Tier = iota

	// TierAllocated means the bitmap holds every allocated block of the snapshot.
	// It is the intended result when no changeID is available (a full backup), and a
	// degradation when the changed-blocks query failed: more data than a delta, but
	// far less than the whole device.
	TierAllocated

	// TierFull means no CBT data could be obtained at all and every block, allocated
	// or not, was marked dirty.
	TierFull
)

// SetBitmapOrFull translates the allocated/changed blocks from CBT service to the given bitmap,
// degrading through a ladder of changed blocks -> allocated blocks -> full bitmap.
//
// The ladder matters because the tiers differ by orders of magnitude: on a sparsely used
// volume the allocated-blocks tier is a small fraction of the device, so a failed delta
// query should cost an allocated-blocks backup, not a whole-device one. Marking the whole
// device dirty makes a failed incremental more expensive than an explicit full backup of
// the same volume would have been.
//
// The returned Tier reports which source populated the bitmap and is the caller's control
// signal. The returned error is diagnostic: it explains why the result is not TierChanged,
// and is nil only when the bitmap was populated exactly as requested. A non-nil error with
// a tier other than TierFull is not fatal - the bitmap is usable.
func SetBitmapOrFull(ctx context.Context, service cbtservice.Service, bitmap types.Bitmap) (tier Tier, err error) {
	defer func() {
		if tier == TierFull {
			bitmap.SetFull()
		}
	}()

	if service == nil {
		return TierFull, errors.New("CBT service is absent")
	}

	if bitmap.Snapshot() == "" {
		return TierFull, errors.New("invalid snapshot")
	}

	record := func(blocks []cbtservice.Range) error {
		for _, b := range blocks {
			bitmap.Set(b.Offset, b.Length)
		}

		return nil
	}

	var changedErr error
	if changeID := bitmap.ChangeID(); changeID != "" {
		changedErr = service.GetChangedBlocks(ctx, bitmap.Snapshot(), changeID, record)
		if changedErr == nil {
			return TierChanged, nil
		}
		// The delta is unavailable, but the allocated-blocks query is a separate call that
		// may still succeed - the base snapshot can be gone while the service is healthy.
		// Any blocks already recorded above stay set; a superset of the true delta is safe.
	}

	if allocatedErr := service.GetAllocatedBlocks(ctx, bitmap.Snapshot(), record); allocatedErr != nil {
		if changedErr != nil {
			return TierFull, errors.Wrapf(allocatedErr,
				"error getting allocated blocks from CBT service after changed blocks failed (%v)", changedErr)
		}

		return TierFull, errors.Wrap(allocatedErr, "error getting allocated blocks from CBT service")
	}

	if changedErr != nil {
		return TierAllocated, errors.Wrap(changedErr, "error getting changed blocks from CBT service")
	}

	return TierAllocated, nil
}
