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

package clientmgmt

import (
	"github.com/cockroachdb/errors"

	"github.com/vmware-tanzu/velero/pkg/plugin/clientmgmt/process"
	"github.com/vmware-tanzu/velero/pkg/plugin/framework/common"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
)

// restartableDeleteItemAction is a delete item action for a given implementation (such as "pod"). It is associated with
// a restartableProcess, which may be shared and used to run multiple plugins. At the beginning of each method
// call, the restartableDeleteItemAction asks its restartableProcess to restart itself if needed (e.g. if the
// process terminated for any reason), then it proceeds with the actual call.
type restartableDeleteItemAction struct {
	key                 process.KindAndName
	sharedPluginProcess process.RestartableProcess
}

// NewRestartableDeleteItemAction returns a new restartableDeleteItemAction.
func NewRestartableDeleteItemAction(name string, sharedPluginProcess process.RestartableProcess) *restartableDeleteItemAction {
	r := &restartableDeleteItemAction{
		key:                 process.KindAndName{Kind: common.PluginKindDeleteItemAction, Name: name},
		sharedPluginProcess: sharedPluginProcess,
	}
	return r
}

// getDeleteItemAction returns the delete item action for this restartableDeleteItemAction. It does *not* restart the
// plugin process.
func (r *restartableDeleteItemAction) getDeleteItemAction() (velero.DeleteItemAction, error) {
	plugin, err := r.sharedPluginProcess.GetByKindAndName(r.key)
	if err != nil {
		return nil, err
	}

	deleteItemAction, ok := plugin.(velero.DeleteItemAction)
	if !ok {
		return nil, errors.Errorf("plugin %T is not a DeleteItemAction", plugin)
	}

	return deleteItemAction, nil
}

// getDelegate restarts the plugin process (if needed) and returns the delete item action for this restartableDeleteItemAction.
func (r *restartableDeleteItemAction) getDelegate() (velero.DeleteItemAction, error) {
	if err := r.sharedPluginProcess.ResetIfNeeded(); err != nil {
		return nil, err
	}

	return r.getDeleteItemAction()
}

// AppliesTo restarts the plugin's process if needed, then delegates the call.
func (r *restartableDeleteItemAction) AppliesTo() (velero.ResourceSelector, error) {
	delegate, err := r.getDelegate()
	if err != nil {
		return velero.ResourceSelector{}, err
	}

	return delegate.AppliesTo()
}

// Execute restarts the plugin's process if needed, then delegates the call.
func (r *restartableDeleteItemAction) Execute(input *velero.DeleteItemActionExecuteInput) error {
	delegate, err := r.getDelegate()
	if err != nil {
		return err
	}

	return delegate.Execute(input)
}
