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

package v2

import (
	"fmt"

	"github.com/cockroachdb/errors"

	api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
)

// RestoreItemAction is an actor that performs an operation on an individual item being restored.
type RestoreItemAction interface {
	// Name returns the name of this RIA. Plugins which implement this interface must define Name,
	// but its content is unimportant, as it won't actually be called via RPC. Velero's plugin infrastructure
	// will implement this directly rather than delegating to the RPC plugin in order to return the name
	// that the plugin was registered under. The plugins must implement the method to complete the interface.
	Name() string

	// AppliesTo returns information about which resources this action should be invoked for.
	// A RestoreItemAction's Execute function will only be invoked on items that match the returned
	// selector. A zero-valued ResourceSelector matches all resources.
	AppliesTo() (velero.ResourceSelector, error)

	// Execute allows the ItemAction to perform arbitrary logic with the item being restored,
	// including mutating the item itself prior to restore. The return struct includes:
	// The item (unmodified or modified), an optional slice of ResourceIdentifiers
	// specifying additional related items that should be restored, an optional OperationID,
	// a bool (waitForAdditionalItems) specifying whether Velero should wait until restored additional
	// items are ready before restoring this resource, and an optional timeout for the additional items
	// wait period. An error is returned if the action fails.
	Execute(input *velero.RestoreItemActionExecuteInput) (*velero.RestoreItemActionExecuteOutput, error)

	// Progress allows the RestoreItemAction to report on progress of an asynchronous action.
	// For the passed-in operation, the plugin will return an OperationProgress struct, indicating
	// whether the operation has completed, whether there were any errors, a plugin-specific
	// indication of how much of the operation is done (items completed out of items-to-complete),
	// and started/updated timestamps
	Progress(operationID string, restore *api.Restore) (velero.OperationProgress, error)

	// Cancel allows the RestoreItemAction to cancel an asynchronous action (if possible).
	// Velero will call this if the wait timeout for asynchronous actions has been reached.
	// If operation cancel is not supported, then the plugin just needs to return. No error
	// return is expected in this case, since cancellation is optional here.
	Cancel(operationID string, restore *api.Restore) error

	// AreAdditionalItemsReady allows the ItemAction to communicate whether the passed-in
	// slice of AdditionalItems (previously returned by Execute())
	// are ready. Returns true if all items are ready, and false
	// otherwise. The second return value is to report errors
	AreAdditionalItemsReady(additionalItems []velero.ResourceIdentifier, restore *api.Restore) (bool, error)
}

func AsyncOperationsNotSupportedError() error {
	return errors.New("Plugin does not support asynchronous operations")
}

func InvalidOperationIDError(operationID string) error {
	return fmt.Errorf("operation ID %v is invalid", operationID)
}
