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
	"github.com/cockroachdb/errors"
	"k8s.io/apimachinery/pkg/runtime"

	api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/plugin/clientmgmt/process"
	"github.com/vmware-tanzu/velero/pkg/plugin/framework/common"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	ibav1 "github.com/vmware-tanzu/velero/pkg/plugin/velero/itemblockaction/v1"
)

// AdaptedItemBlockAction is an ItemBlock action adapted to the v1 ItemBlockAction API
type AdaptedItemBlockAction struct {
	Kind common.PluginKind

	// Get returns a restartable ItemBlockAction for the given name and process, wrapping if necessary
	GetRestartable func(name string, restartableProcess process.RestartableProcess) ibav1.ItemBlockAction
}

func AdaptedItemBlockActions() []AdaptedItemBlockAction {
	return []AdaptedItemBlockAction{
		{
			Kind: common.PluginKindItemBlockAction,
			GetRestartable: func(name string, restartableProcess process.RestartableProcess) ibav1.ItemBlockAction {
				return NewRestartableItemBlockAction(name, restartableProcess)
			},
		},
	}
}

// RestartableItemBlockAction is an ItemBlock action for a given implementation (such as "pod"). It is associated with
// a restartableProcess, which may be shared and used to run multiple plugins. At the beginning of each method
// call, the restartableItemBlockAction asks its restartableProcess to restart itself if needed (e.g. if the
// process terminated for any reason), then it proceeds with the actual call.
type RestartableItemBlockAction struct {
	Key                 process.KindAndName
	SharedPluginProcess process.RestartableProcess
}

// NewRestartableItemBlockAction returns a new RestartableItemBlockAction.
func NewRestartableItemBlockAction(name string, sharedPluginProcess process.RestartableProcess) *RestartableItemBlockAction {
	r := &RestartableItemBlockAction{
		Key:                 process.KindAndName{Kind: common.PluginKindItemBlockAction, Name: name},
		SharedPluginProcess: sharedPluginProcess,
	}
	return r
}

// getItemBlockAction returns the ItemBlock action for this restartableItemBlockAction. It does *not* restart the
// plugin process.
func (r *RestartableItemBlockAction) getItemBlockAction() (ibav1.ItemBlockAction, error) {
	plugin, err := r.SharedPluginProcess.GetByKindAndName(r.Key)
	if err != nil {
		return nil, err
	}

	itemBlockAction, ok := plugin.(ibav1.ItemBlockAction)
	if !ok {
		return nil, errors.Errorf("plugin %T is not an ItemBlockAction", plugin)
	}

	return itemBlockAction, nil
}

// getDelegate restarts the plugin process (if needed) and returns the ItemBlock action for this restartableItemBlockAction.
func (r *RestartableItemBlockAction) getDelegate() (ibav1.ItemBlockAction, error) {
	if err := r.SharedPluginProcess.ResetIfNeeded(); err != nil {
		return nil, err
	}

	return r.getItemBlockAction()
}

// Name returns the plugin's name.
func (r *RestartableItemBlockAction) Name() string {
	return r.Key.Name
}

// AppliesTo restarts the plugin's process if needed, then delegates the call.
func (r *RestartableItemBlockAction) AppliesTo() (velero.ResourceSelector, error) {
	delegate, err := r.getDelegate()
	if err != nil {
		return velero.ResourceSelector{}, err
	}

	return delegate.AppliesTo()
}

// GetRelatedItems restarts the plugin's process if needed, then delegates the call.
func (r *RestartableItemBlockAction) GetRelatedItems(item runtime.Unstructured, backup *api.Backup) ([]velero.ResourceIdentifier, error) {
	delegate, err := r.getDelegate()
	if err != nil {
		return nil, err
	}

	return delegate.GetRelatedItems(item, backup)
}
