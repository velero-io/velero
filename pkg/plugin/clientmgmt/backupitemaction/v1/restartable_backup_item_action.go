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
	"k8s.io/apimachinery/pkg/runtime"

	api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/plugin/clientmgmt/process"
	"github.com/vmware-tanzu/velero/pkg/plugin/framework/common"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	biav1 "github.com/vmware-tanzu/velero/pkg/plugin/velero/backupitemaction/v1"
)

// AdaptedBackupItemAction is a backup item action adapted to the v1 BackupItemAction API
type AdaptedBackupItemAction struct {
	Kind common.PluginKind

	// Get returns a restartable BackupItemAction for the given name and process, wrapping if necessary
	GetRestartable func(name string, restartableProcess process.RestartableProcess) biav1.BackupItemAction
}

func AdaptedBackupItemActions() []AdaptedBackupItemAction {
	return []AdaptedBackupItemAction{
		{
			Kind: common.PluginKindBackupItemAction,
			GetRestartable: func(name string, restartableProcess process.RestartableProcess) biav1.BackupItemAction {
				return NewRestartableBackupItemAction(name, restartableProcess)
			},
		},
	}
}

// RestartableBackupItemAction is a backup item action for a given implementation (such as "pod"). It is associated with
// a restartableProcess, which may be shared and used to run multiple plugins. At the beginning of each method
// call, the restartableBackupItemAction asks its restartableProcess to restart itself if needed (e.g. if the
// process terminated for any reason), then it proceeds with the actual call.
type RestartableBackupItemAction struct {
	Key                 process.KindAndName
	SharedPluginProcess process.RestartableProcess
}

// NewRestartableBackupItemAction returns a new RestartableBackupItemAction.
func NewRestartableBackupItemAction(name string, sharedPluginProcess process.RestartableProcess) *RestartableBackupItemAction {
	r := &RestartableBackupItemAction{
		Key:                 process.KindAndName{Kind: common.PluginKindBackupItemAction, Name: name},
		SharedPluginProcess: sharedPluginProcess,
	}
	return r
}

// getBackupItemAction returns the backup item action for this restartableBackupItemAction. It does *not* restart the
// plugin process.
func (r *RestartableBackupItemAction) getBackupItemAction() (biav1.BackupItemAction, error) {
	plugin, err := r.SharedPluginProcess.GetByKindAndName(r.Key)
	if err != nil {
		return nil, err
	}

	backupItemAction, ok := plugin.(biav1.BackupItemAction)
	if !ok {
		return nil, errors.Errorf("plugin %T is not a BackupItemAction", plugin)
	}

	return backupItemAction, nil
}

// getDelegate restarts the plugin process (if needed) and returns the backup item action for this restartableBackupItemAction.
func (r *RestartableBackupItemAction) getDelegate() (biav1.BackupItemAction, error) {
	if err := r.SharedPluginProcess.ResetIfNeeded(); err != nil {
		return nil, err
	}

	return r.getBackupItemAction()
}

// AppliesTo restarts the plugin's process if needed, then delegates the call.
func (r *RestartableBackupItemAction) AppliesTo() (velero.ResourceSelector, error) {
	delegate, err := r.getDelegate()
	if err != nil {
		return velero.ResourceSelector{}, err
	}

	return delegate.AppliesTo()
}

// Execute restarts the plugin's process if needed, then delegates the call.
func (r *RestartableBackupItemAction) Execute(item runtime.Unstructured, backup *api.Backup) (runtime.Unstructured, []velero.ResourceIdentifier, error) {
	delegate, err := r.getDelegate()
	if err != nil {
		return nil, nil, err
	}

	return delegate.Execute(item, backup)
}
