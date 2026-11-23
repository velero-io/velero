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

package v1

import (
	"github.com/velero-io/velero/pkg/plugin/velero"
)

// RestoreItemAction is an actor that performs an operation on an individual item being restored.
type RestoreItemAction interface {
	// AppliesTo returns information about which resources this action should be invoked for.
	// A RestoreItemAction's Execute function will only be invoked on items that match the returned
	// selector. A zero-valued ResourceSelector matches all resources.
	AppliesTo() (velero.ResourceSelector, error)

	// Execute allows the ItemAction to perform arbitrary logic with the item being restored,
	// including mutating the item itself prior to restore. The item (unmodified or modified)
	// should be returned, along with an optional slice of ResourceIdentifiers specifying additional
	// related items that should be restored, a warning (which will be logged but will not prevent
	// the item from being restored) or error (which will be logged and will prevent the item
	// from being restored) if applicable.
	Execute(input *velero.RestoreItemActionExecuteInput) (*velero.RestoreItemActionExecuteOutput, error)
}
