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

package v2

import (
	"github.com/cockroachdb/errors"
	"k8s.io/apimachinery/pkg/runtime"

	api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	biav1cli "github.com/vmware-tanzu/velero/pkg/plugin/clientmgmt/backupitemaction/v1"
	"github.com/vmware-tanzu/velero/pkg/plugin/clientmgmt/process"
	"github.com/vmware-tanzu/velero/pkg/plugin/framework/common"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	biav2 "github.com/vmware-tanzu/velero/pkg/plugin/velero/backupitemaction/v2"
)

// AdaptedBackupItemAction is a v1 BackupItemAction adapted to implement the v2 API
type AdaptedBackupItemAction struct {
	Kind common.PluginKind

	// Get returns a restartable BackupItemAction for the given name and process, wrapping if necessary
	GetRestartable func(name string, restartableProcess process.RestartableProcess) biav2.BackupItemAction
}

func AdaptedBackupItemActions() []AdaptedBackupItemAction {
	return []AdaptedBackupItemAction{
		{
			Kind: common.PluginKindBackupItemActionV2,
			GetRestartable: func(name string, restartableProcess process.RestartableProcess) biav2.BackupItemAction {
				return NewRestartableBackupItemAction(name, restartableProcess)
			},
		},
		{
			Kind: common.PluginKindBackupItemAction,
			GetRestartable: func(name string, restartableProcess process.RestartableProcess) biav2.BackupItemAction {
				return NewAdaptedV1RestartableBackupItemAction(biav1cli.NewRestartableBackupItemAction(name, restartableProcess))
			},
		},
	}
}

// restartableBackupItemAction is a backup item action for a given implementation (such as "pod"). It is associated with
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
		Key:                 process.KindAndName{Kind: common.PluginKindBackupItemActionV2, Name: name},
		SharedPluginProcess: sharedPluginProcess,
	}
	return r
}

// getBackupItemAction returns the backup item action for this restartableBackupItemAction. It does *not* restart the
// plugin process.
func (r *RestartableBackupItemAction) getBackupItemAction() (biav2.BackupItemAction, error) {
	plugin, err := r.SharedPluginProcess.GetByKindAndName(r.Key)
	if err != nil {
		return nil, err
	}

	backupItemAction, ok := plugin.(biav2.BackupItemAction)
	if !ok {
		return nil, errors.Errorf("plugin %T (returned for %v) is not a BackupItemActionV2", plugin, r.Key)
	}

	return backupItemAction, nil
}

// getDelegate restarts the plugin process (if needed) and returns the backup item action for this restartableBackupItemAction.
func (r *RestartableBackupItemAction) getDelegate() (biav2.BackupItemAction, error) {
	if err := r.SharedPluginProcess.ResetIfNeeded(); err != nil {
		return nil, err
	}

	return r.getBackupItemAction()
}

// Name returns the plugin's name.
func (r *RestartableBackupItemAction) Name() string {
	return r.Key.Name
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
func (r *RestartableBackupItemAction) Execute(item runtime.Unstructured, backup *api.Backup) (runtime.Unstructured, []velero.ResourceIdentifier, string, []velero.ResourceIdentifier, error) {
	delegate, err := r.getDelegate()
	if err != nil {
		return nil, nil, "", nil, err
	}

	return delegate.Execute(item, backup)
}

// Progress restarts the plugin's process if needed, then delegates the call.
func (r *RestartableBackupItemAction) Progress(operationID string, backup *api.Backup) (velero.OperationProgress, error) {
	delegate, err := r.getDelegate()
	if err != nil {
		return velero.OperationProgress{}, err
	}

	return delegate.Progress(operationID, backup)
}

// Cancel restarts the plugin's process if needed, then delegates the call.
func (r *RestartableBackupItemAction) Cancel(operationID string, backup *api.Backup) error {
	delegate, err := r.getDelegate()
	if err != nil {
		return err
	}

	return delegate.Cancel(operationID, backup)
}

type AdaptedV1RestartableBackupItemAction struct {
	V1Restartable *biav1cli.RestartableBackupItemAction
}

// NewAdaptedV1RestartableBackupItemAction returns a new v1 RestartableBackupItemAction adapted to v2
func NewAdaptedV1RestartableBackupItemAction(v1Restartable *biav1cli.RestartableBackupItemAction) *AdaptedV1RestartableBackupItemAction {
	r := &AdaptedV1RestartableBackupItemAction{
		V1Restartable: v1Restartable,
	}
	return r
}

// Name restarts the plugin's name.
func (r *AdaptedV1RestartableBackupItemAction) Name() string {
	return r.V1Restartable.Key.Name
}

// AppliesTo delegates to the v1 AppliesTo call.
func (r *AdaptedV1RestartableBackupItemAction) AppliesTo() (velero.ResourceSelector, error) {
	return r.V1Restartable.AppliesTo()
}

// Execute delegates to the v1 Execute call, returning an empty operationID.
func (r *AdaptedV1RestartableBackupItemAction) Execute(item runtime.Unstructured, backup *api.Backup) (runtime.Unstructured, []velero.ResourceIdentifier, string, []velero.ResourceIdentifier, error) {
	updatedItem, additionalItems, err := r.V1Restartable.Execute(item, backup)
	return updatedItem, additionalItems, "", nil, err
}

// Progress returns with an error since v1 plugins will never return an operationID, which means that
// any operationID passed in here will be invalid.
func (r *AdaptedV1RestartableBackupItemAction) Progress(operationID string, backup *api.Backup) (velero.OperationProgress, error) {
	return velero.OperationProgress{}, biav2.AsyncOperationsNotSupportedError()
}

// Cancel just returns without error since v1 plugins don't implement it.
func (r *AdaptedV1RestartableBackupItemAction) Cancel(operationID string, backup *api.Backup) error {
	return nil
}
