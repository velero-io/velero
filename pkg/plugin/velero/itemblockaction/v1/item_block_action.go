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
	"k8s.io/apimachinery/pkg/runtime"

	api "github.com/velero-io/velero/pkg/apis/velero/v1"
	"github.com/velero-io/velero/pkg/plugin/velero"
)

// ItemBlockAction is an action that returns a list of related items that must be backed up
// along with the current item (and not in a separate parallel backup thread).
type ItemBlockAction interface {
	// Name returns the name of this IBA. Plugins which implement this interface must define Name,
	// but its content is unimportant, as it won't actually be called via RPC. Velero's plugin infrastructure
	// will implement this directly rather than delegating to the RPC plugin in order to return the name
	// that the plugin was registered under. The plugins must implement the method to complete the interface.
	Name() string

	// AppliesTo returns information about which resources this action should be invoked for.
	// A ItemBlockAction's GetRelatedItems function will only be invoked on items that match the returned
	// selector. A zero-valued ResourceSelector matches all resources.
	AppliesTo() (velero.ResourceSelector, error)

	// GetRelatedItems allows the ItemBlockAction to identify related items which must be backed up
	// along with the current item. In many cases, these will be the same items that a related
	// BackupItemAction's Execute method will return as additionalItems, but there may be differences.
	// For example, items that are newly-created in the BIA Execute and don't yet exist at backup
	// start will *not* be returned here.
	GetRelatedItems(item runtime.Unstructured, backup *api.Backup) ([]velero.ResourceIdentifier, error)
}
