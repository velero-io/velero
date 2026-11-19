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

// OperationState is the settled state of an asynchronous operation that ran for
// one item.
type OperationState string

const (
	// OperationSucceeded means the operation finished, so the item's captured
	// verdict stands.
	OperationSucceeded OperationState = "succeeded"
	// OperationFailed means the operation did not finish successfully and the
	// item must be raised to Failed.
	OperationFailed OperationState = "failed"
	// OperationPending means no verdict was delivered. A backup or restore should
	// not be finalized while one exists.
	OperationPending OperationState = "pending"
)

// OperationResult is the outcome of one asynchronous operation, described in the
// terms the artifact needs. It is declared here rather than reusing a
// backup-specific type so the same overlay can finalize a restore artifact.
type OperationResult struct {
	GroupResource string
	Namespace     string
	Name          string
	State         OperationState
	Error         string
}

// ApplyOperations overlays the results of async operations onto the artifact,
// now that the operations have settled. A failed operation upgrades its item to
// OutcomeFailed with the operation's error appended; a successful operation
// leaves the item unchanged, because the item was processed synchronously and
// the operation finishing only confirms it. Operations with no matching item get
// a row of their own, so the artifact still accounts for them.
//
// The overlay maintains these invariants:
//
//   - A failed operation raises its item to OutcomeFailed and appends the
//     operation's error; a successful operation leaves the captured verdict
//     unchanged because it confirms work already done synchronously.
//   - Pending operations are not applied and leave the artifact unfinalized.
//   - A failed operation with no matching row creates one; a pending operation
//     never invents a row.
//
// ReportedBy is never touched here: it is set once at capture time and carried
// through unchanged on both matched and unmatched rows.
//
// The overlay is monotone: it only ever raises an outcome, so a verdict recorded
// at capture time cannot be lost by the finalize write.
//
// It returns the operations that were not settled. The caller reports them; this
// package does no logging. A finalize pass should not see one, so a non-empty
// result is a signal, not a normal case.
func ApplyOperations(items *ItemOutcomes, operations []OperationResult) []OperationResult {
	if items == nil {
		return nil
	}

	// Index by position, not pointer: appending an unmatched operation row can
	// reallocate the backing array, which would leave every stored pointer
	// writing to the old copy.
	index := make(map[Key]int, len(items.Items))
	for i := range items.Items {
		index[KeyOf(items.Items[i])] = i
	}

	var pending []OperationResult
	appended := false
	for _, operation := range operations {
		switch operation.State {
		case OperationSucceeded:
			continue
		case OperationFailed:
			// Fall through to the failure handling below.
		default:
			pending = append(pending, operation)
			continue
		}

		key := Key{
			GroupResource: operation.GroupResource,
			Namespace:     operation.Namespace,
			Name:          operation.Name,
		}

		idx, ok := index[key]
		if !ok {
			items.Items = append(items.Items, ItemOutcome{
				GroupResource: key.GroupResource,
				Namespace:     key.Namespace,
				Name:          key.Name,
				Outcome:       OutcomeFailed,
			})
			idx = len(items.Items) - 1
			index[key] = idx
			appended = true
		}

		row := &items.Items[idx]
		row.Outcome = OutcomeFailed
		if operation.Error != "" {
			row.Messages = appendTerminalMessage(row.Messages, operation.Error)
		}
	}

	if appended {
		// Result() sorted the captured rows; a row minted here must not leave the
		// artifact out of order.
		sortItems(items.Items)
	}

	// Finalized means no verdict is still outstanding. A pending operation leaves
	// it false so a reader during WaitingForPluginOperations does not mistake the
	// artifact for complete.
	items.Finalized = len(pending) == 0

	return pending
}
