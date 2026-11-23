/*
Copyright 2020 the Velero contributors.

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

package velero

import (
	"k8s.io/apimachinery/pkg/runtime"

	velerov1api "github.com/velero-io/velero/pkg/apis/velero/v1"
)

// DeleteItemAction is an actor that performs an operation on an individual item being restored.
type DeleteItemAction interface {
	// AppliesTo returns information about which resources this action should be invoked for.
	// A DeleteItemAction's Execute function will only be invoked on items that match the returned
	// selector. A zero-valued ResourceSelector matches all resources.
	AppliesTo() (ResourceSelector, error)

	// Execute allows the ItemAction to perform arbitrary logic with the item being deleted.
	// An error should be returned if there were problems with the deletion process, but the
	// overall deletion process cannot be stopped.
	// Returned errors are logged.
	Execute(input *DeleteItemActionExecuteInput) error
}

// DeleteItemActionExecuteInput contains the input parameters for the ItemAction's Execute function.
type DeleteItemActionExecuteInput struct {
	// Item is the item taken from the pristine backed up version of resource.
	Item runtime.Unstructured
	// Backup is the representation of the restore resource processed by Velero.
	Backup *velerov1api.Backup
}
