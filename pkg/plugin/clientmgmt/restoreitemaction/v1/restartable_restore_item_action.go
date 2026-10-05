/*
Copyright 2018 the Velero contributors.

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

	"github.com/vmware-tanzu/velero/pkg/plugin/clientmgmt/process"
	"github.com/vmware-tanzu/velero/pkg/plugin/framework/common"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	riav1 "github.com/vmware-tanzu/velero/pkg/plugin/velero/restoreitemaction/v1"
)

// AdaptedRestoreItemAction is a restore item action adapted to the v1 RestoreItemAction API
type AdaptedRestoreItemAction struct {
	Kind common.PluginKind

	// Get returns a restartable RestoreItemAction for the given name and process, wrapping if necessary
	GetRestartable func(name string, restartableProcess process.RestartableProcess) riav1.RestoreItemAction
}

func AdaptedRestoreItemActions() []AdaptedRestoreItemAction {
	return []AdaptedRestoreItemAction{
		{
			Kind: common.PluginKindRestoreItemAction,
			GetRestartable: func(name string, restartableProcess process.RestartableProcess) riav1.RestoreItemAction {
				return NewRestartableRestoreItemAction(name, restartableProcess)
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
		Key:                 process.KindAndName{Kind: common.PluginKindRestoreItemAction, Name: name},
		SharedPluginProcess: sharedPluginProcess,
	}
	return r
}

// getRestoreItemAction returns the restore item action for this RestartableRestoreItemAction. It does *not* restart the
// plugin process.
func (r *RestartableRestoreItemAction) getRestoreItemAction() (riav1.RestoreItemAction, error) {
	plugin, err := r.SharedPluginProcess.GetByKindAndName(r.Key)
	if err != nil {
		return nil, err
	}

	restoreItemAction, ok := plugin.(riav1.RestoreItemAction)
	if !ok {
		return nil, errors.Errorf("plugin %T is not a RestoreItemAction", plugin)
	}

	return restoreItemAction, nil
}

// getDelegate restarts the plugin process (if needed) and returns the restore item action for this RestartableRestoreItemAction.
func (r *RestartableRestoreItemAction) getDelegate() (riav1.RestoreItemAction, error) {
	if err := r.SharedPluginProcess.ResetIfNeeded(); err != nil {
		return nil, err
	}

	return r.getRestoreItemAction()
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
