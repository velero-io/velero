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
	"github.com/cockroachdb/errors"

	api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/plugin/clientmgmt/process"
	riav1cli "github.com/vmware-tanzu/velero/pkg/plugin/clientmgmt/restoreitemaction/v1"
	"github.com/vmware-tanzu/velero/pkg/plugin/framework/common"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	riav2 "github.com/vmware-tanzu/velero/pkg/plugin/velero/restoreitemaction/v2"
)

// AdaptedRestoreItemAction is a v1 RestoreItemAction adapted to implement the v2 API
type AdaptedRestoreItemAction struct {
	Kind common.PluginKind

	// Get returns a restartable RestoreItemAction for the given name and process, wrapping if necessary
	GetRestartable func(name string, restartableProcess process.RestartableProcess) riav2.RestoreItemAction
}

func AdaptedRestoreItemActions() []AdaptedRestoreItemAction {
	return []AdaptedRestoreItemAction{
		{
			Kind: common.PluginKindRestoreItemActionV2,
			GetRestartable: func(name string, restartableProcess process.RestartableProcess) riav2.RestoreItemAction {
				return NewRestartableRestoreItemAction(name, restartableProcess)
			},
		},
		{
			Kind: common.PluginKindRestoreItemAction,
			GetRestartable: func(name string, restartableProcess process.RestartableProcess) riav2.RestoreItemAction {
				return NewAdaptedV1RestartableRestoreItemAction(riav1cli.NewRestartableRestoreItemAction(name, restartableProcess))
			},
		},
	}
}

// RestartableRestoreItemAction is a restore item action for a given implementation (such as "pod"). It is associated with
// a restartableProcess, which may be shared and used to run multiple plugins. At the beginning of each method
// call, the RestartableRestoreItemAction asks its restartableProcess to restart itself if needed (e.g. if the
// process terminated for any reason), then it proceeds with the actual call.
type RestartableRestoreItemAction struct {
	Key                 process.KindAndName
	SharedPluginProcess process.RestartableProcess
}

// NewRestartableRestoreItemAction returns a new RestartableRestoreItemAction.
func NewRestartableRestoreItemAction(name string, sharedPluginProcess process.RestartableProcess) *RestartableRestoreItemAction {
	r := &RestartableRestoreItemAction{
		Key:                 process.KindAndName{Kind: common.PluginKindRestoreItemActionV2, Name: name},
		SharedPluginProcess: sharedPluginProcess,
	}
	return r
}

// getRestoreItemAction returns the restore item action for this RestartableRestoreItemAction. It does *not* restart the
// plugin process.
func (r *RestartableRestoreItemAction) getRestoreItemAction() (riav2.RestoreItemAction, error) {
	plugin, err := r.SharedPluginProcess.GetByKindAndName(r.Key)
	if err != nil {
		return nil, err
	}

	restoreItemAction, ok := plugin.(riav2.RestoreItemAction)
	if !ok {
		return nil, errors.Errorf("plugin %T is not a RestoreItemActionV2", plugin)
	}

	return restoreItemAction, nil
}

// getDelegate restarts the plugin process (if needed) and returns the restore item action for this RestartableRestoreItemAction.
func (r *RestartableRestoreItemAction) getDelegate() (riav2.RestoreItemAction, error) {
	if err := r.SharedPluginProcess.ResetIfNeeded(); err != nil {
		return nil, err
	}

	return r.getRestoreItemAction()
}

// Name returns the plugin's name.
func (r *RestartableRestoreItemAction) Name() string {
	return r.Key.Name
}

// AppliesTo restarts the plugin's process if needed, then delegates the call.
func (r RestartableRestoreItemAction) AppliesTo() (velero.ResourceSelector, error) {
	delegate, err := r.getDelegate()
	if err != nil {
		return velero.ResourceSelector{}, err
	}

	return delegate.AppliesTo()
}

// Execute restarts the plugin's process if needed, then delegates the call.
func (r *RestartableRestoreItemAction) Execute(input *velero.RestoreItemActionExecuteInput) (*velero.RestoreItemActionExecuteOutput, error) {
	delegate, err := r.getDelegate()
	if err != nil {
		return nil, err
	}

	return delegate.Execute(input)
}

// Progress restarts the plugin's process if needed, then delegates the call.
func (r *RestartableRestoreItemAction) Progress(operationID string, restore *api.Restore) (velero.OperationProgress, error) {
	delegate, err := r.getDelegate()
	if err != nil {
		return velero.OperationProgress{}, err
	}

	return delegate.Progress(operationID, restore)
}

// Cancel restarts the plugin's process if needed, then delegates the call.
func (r *RestartableRestoreItemAction) Cancel(operationID string, restore *api.Restore) error {
	delegate, err := r.getDelegate()
	if err != nil {
		return err
	}

	return delegate.Cancel(operationID, restore)
}

// AreAdditionalItemsReady restarts the plugin's process if needed, then delegates the call.
func (r *RestartableRestoreItemAction) AreAdditionalItemsReady(additionalItems []velero.ResourceIdentifier, restore *api.Restore) (bool, error) {
	delegate, err := r.getDelegate()
	if err != nil {
		return false, err
	}

	return delegate.AreAdditionalItemsReady(additionalItems, restore)
}

type AdaptedV1RestartableRestoreItemAction struct {
	V1Restartable *riav1cli.RestartableRestoreItemAction
}

// NewAdaptedV1RestartableRestoreItemAction returns a new v1 RestartableRestoreItemAction adapted to v2
func NewAdaptedV1RestartableRestoreItemAction(v1Restartable *riav1cli.RestartableRestoreItemAction) *AdaptedV1RestartableRestoreItemAction {
	r := &AdaptedV1RestartableRestoreItemAction{
		V1Restartable: v1Restartable,
	}
	return r
}

// Name restarts the plugin's name.
func (r *AdaptedV1RestartableRestoreItemAction) Name() string {
	return r.V1Restartable.Key.Name
}

// AppliesTo delegates to the v1 AppliesTo call.
func (r *AdaptedV1RestartableRestoreItemAction) AppliesTo() (velero.ResourceSelector, error) {
	return r.V1Restartable.AppliesTo()
}

// Execute delegates to the v1 Execute call, returning an empty operationID.
func (r *AdaptedV1RestartableRestoreItemAction) Execute(input *velero.RestoreItemActionExecuteInput) (*velero.RestoreItemActionExecuteOutput, error) {
	return r.V1Restartable.Execute(input)
}

// Progress returns with an error since v1 plugins will never return an operationID, which means that
// any operationID passed in here will be invalid.
func (r *AdaptedV1RestartableRestoreItemAction) Progress(operationID string, restore *api.Restore) (velero.OperationProgress, error) {
	return velero.OperationProgress{}, riav2.AsyncOperationsNotSupportedError()
}

// Cancel just returns without error since v1 plugins don't implement it.
func (r *AdaptedV1RestartableRestoreItemAction) Cancel(operationID string, restore *api.Restore) error {
	return nil
}

// AreAdditionalItemsReady just returns true since v1 plugins don't wait for items.
func (r *AdaptedV1RestartableRestoreItemAction) AreAdditionalItemsReady(additionalItems []velero.ResourceIdentifier, restore *api.Restore) (bool, error) {
	return true, nil
}
