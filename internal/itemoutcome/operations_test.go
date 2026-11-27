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

package itemoutcome

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func operation(gr, ns, name string, state OperationState, errMsg string) OperationResult {
	return OperationResult{GroupResource: gr, Namespace: ns, Name: name, State: state, Error: errMsg}
}

// A failed operation is the only operation that changes a row: the item was
// processed synchronously, so success only confirms what the row already says.
func TestApplyOperationsRaisesRowOnFailure(t *testing.T) {
	items := &ItemOutcomes{
		SchemaVersion: SchemaVersion,
		Items: []ItemOutcome{
			row(pvcGR, "ns", "disk1", OutcomeSucceeded, nil),
			row("configmaps", "ns", "clean", OutcomeSucceeded, nil),
		},
	}

	pending := ApplyOperations(items, []OperationResult{
		operation(pvcGR, "ns", "disk1", OperationFailed, "snapshot create failed"),
		operation("configmaps", "ns", "clean", OperationSucceeded, ""),
	})

	assert.Empty(t, pending)
	require.True(t, items.Finalized)

	assert.Equal(t, OutcomeFailed, items.Items[0].Outcome)
	assert.Equal(t, []string{"snapshot create failed"}, items.Items[0].Messages)
	assert.Equal(t, OutcomeSucceeded, items.Items[1].Outcome, "a successful operation changes nothing")
}

// An operation can outlive the row that would explain it, so the overlay gives
// it one rather than dropping it.
func TestApplyOperationsAddsRowForUnmatchedOperation(t *testing.T) {
	items := &ItemOutcomes{SchemaVersion: SchemaVersion}

	pending := ApplyOperations(items, []OperationResult{
		operation("persistentvolumeclaims", "ns", "orphan", OperationFailed, "boom"),
	})

	assert.Empty(t, pending)
	require.Len(t, items.Items, 1)
	assert.Equal(t, "orphan", items.Items[0].Name)
	assert.Equal(t, OutcomeFailed, items.Items[0].Outcome)
	assert.Equal(t, []string{"boom"}, items.Items[0].Messages)
}

// A non-terminal operation is not a verdict. Report it to the caller instead of
// letting the row's captured outcome stand in for one.
func TestApplyOperationsReturnsPendingWithoutApplying(t *testing.T) {
	items := &ItemOutcomes{
		SchemaVersion: SchemaVersion,
		Items:         []ItemOutcome{row(pvcGR, "ns", "disk1", OutcomeSucceeded, nil)},
	}

	pending := ApplyOperations(items, []OperationResult{
		operation(pvcGR, "ns", "disk1", OperationPending, ""),
	})

	require.Len(t, pending, 1)
	assert.False(t, items.Finalized, "a pending operation leaves the artifact unfinalized")
	assert.Equal(t, OutcomeSucceeded, items.Items[0].Outcome)
	assert.Empty(t, items.Items[0].Messages)
}

// The overlay only ever raises an outcome, so a capture-time failure survives a
// later successful operation.
func TestApplyOperationsIsMonotone(t *testing.T) {
	items := &ItemOutcomes{
		SchemaVersion: SchemaVersion,
		Items:         []ItemOutcome{row(pvcGR, "ns", "disk1", OutcomeFailed, nil)},
	}

	ApplyOperations(items, []OperationResult{
		operation(pvcGR, "ns", "disk1", OperationSucceeded, ""),
	})

	assert.Equal(t, OutcomeFailed, items.Items[0].Outcome)
}

func TestApplyOperationsHandlesNilArtifact(t *testing.T) {
	assert.Nil(t, ApplyOperations(nil, []OperationResult{
		operation(pvcGR, "ns", "disk1", OperationFailed, "boom"),
	}))
}

// A failed operation on an existing row must not be lost when an earlier
// unmatched operation grows the slice and reallocates its backing array.
func TestApplyOperationsAppendsDoNotInvalidateExistingRows(t *testing.T) {
	items := &ItemOutcomes{
		SchemaVersion: SchemaVersion,
		Items: []ItemOutcome{
			row(pvcGR, "ns", "disk1", OutcomeSucceeded, nil),
		},
	}

	ApplyOperations(items, []OperationResult{
		operation("pods", "ns", "orphan", OperationFailed, "orphan failed"),
		operation(pvcGR, "ns", "disk1", OperationFailed, "snapshot create failed"),
	})

	require.Len(t, items.Items, 2)
	byName := map[string]ItemOutcome{}
	for _, item := range items.Items {
		byName[item.Name] = item
	}
	assert.Equal(t, OutcomeFailed, byName["disk1"].Outcome)
	assert.Equal(t, []string{"snapshot create failed"}, byName["disk1"].Messages)
	assert.Equal(t, OutcomeFailed, byName["orphan"].Outcome)
}

// A row minted by the overlay must not leave the artifact out of order.
func TestApplyOperationsSortsAppendedRows(t *testing.T) {
	items := &ItemOutcomes{
		SchemaVersion: SchemaVersion,
		Items:         []ItemOutcome{row(pvcGR, "ns", "z", OutcomeSucceeded, nil)},
	}

	ApplyOperations(items, []OperationResult{
		operation("configmaps", "ns", "a", OperationFailed, "boom"),
	})

	require.Len(t, items.Items, 2)
	assert.Equal(t, "a", items.Items[0].Name)
	assert.Equal(t, "z", items.Items[1].Name)
}

// A finalizer retry may apply the same operation result again. The row and its
// message must be stable, not duplicated.
func TestApplyOperationsIsIdempotent(t *testing.T) {
	items := &ItemOutcomes{
		SchemaVersion: SchemaVersion,
		Items:         []ItemOutcome{row(pvcGR, "ns", "disk1", OutcomeSucceeded, nil)},
	}
	result := operation(pvcGR, "ns", "disk1", OperationFailed, "snapshot failed")

	ApplyOperations(items, []OperationResult{result})
	ApplyOperations(items, []OperationResult{result})

	require.Len(t, items.Items[0].Messages, 1)
	assert.Equal(t, "snapshot failed", items.Items[0].Messages[0])
}

// The operation error is the reason the row is Failed. It must survive the
// message cap even when the capture-time row was already full.
func TestApplyOperationsKeepsTerminalErrorWhenMessagesAreCapped(t *testing.T) {
	items := &ItemOutcomes{
		SchemaVersion: SchemaVersion,
		Items: []ItemOutcome{{
			GroupResource: pvcGR,
			Namespace:     "ns",
			Name:          "disk1",
			Outcome:       OutcomeSucceeded,
			Messages:      []string{"m1", "m2", "m3", "m4", "m5"},
		}},
	}

	ApplyOperations(items, []OperationResult{
		operation(pvcGR, "ns", "disk1", OperationFailed, "snapshot failed"),
	})

	msgs := items.Items[0].Messages
	require.Len(t, msgs, MaxMessagesPerItem)
	assert.Contains(t, msgs, "snapshot failed")
	assert.Equal(t, "... and 2 more", msgs[len(msgs)-1])
}

func TestApplyOperationsPreservesHiddenCountWhenMessagesAreCapped(t *testing.T) {
	items := &ItemOutcomes{
		SchemaVersion: SchemaVersion,
		Items: []ItemOutcome{{
			GroupResource: pvcGR,
			Namespace:     "ns",
			Name:          "disk1",
			Outcome:       OutcomeSucceeded,
			Messages:      []string{"m1", "m2", "m3", "m4", "... and 8 more"},
		}},
	}

	ApplyOperations(items, []OperationResult{
		operation(pvcGR, "ns", "disk1", OperationFailed, "snapshot failed"),
	})

	assert.Equal(t, []string{"m1", "m2", "m3", "snapshot failed", "... and 9 more"},
		items.Items[0].Messages)
}
