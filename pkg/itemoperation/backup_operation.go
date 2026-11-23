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

package itemoperation

import (
	"github.com/velero-io/velero/pkg/plugin/velero"
)

// BackupOperation stores information about an async item operation
// started by a BackupItemAction plugin (v2 or later)
type BackupOperation struct {
	Spec BackupOperationSpec `json:"spec"`

	Status OperationStatus `json:"status"`
}

func (in *BackupOperation) DeepCopy() *BackupOperation {
	if in == nil {
		return nil
	}
	out := new(BackupOperation)
	in.DeepCopyInto(out)
	return out
}

func (in *BackupOperation) DeepCopyInto(out *BackupOperation) {
	*out = *in
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

type BackupOperationSpec struct {
	// BackupName is the name of the Velero backup this item operation
	// is associated with.
	BackupName string `json:"backupName"`

	// BackupUID is the UID of the Velero backup this item operation
	// is associated with.
	BackupUID string `json:"backupUID"`

	// BackupItemAction is the name of the BackupItemAction plugin that started the operation
	BackupItemAction string `json:"backupItemAction"`

	// Kubernetes resource identifier for the item
	ResourceIdentifier velero.ResourceIdentifier `json:"resourceIdentifier"`

	// OperationID returned by the BIA plugin
	OperationID string `json:"operationID"`

	// Items needing to be added to the backup after all async operations have completed
	PostOperationItems []velero.ResourceIdentifier `json:"postOperationItems"`
}

func (in *BackupOperationSpec) DeepCopy() *BackupOperationSpec {
	if in == nil {
		return nil
	}
	out := new(BackupOperationSpec)
	in.DeepCopyInto(out)
	return out
}

func (in *BackupOperationSpec) DeepCopyInto(out *BackupOperationSpec) {
	*out = *in
	in.ResourceIdentifier.DeepCopyInto(&out.ResourceIdentifier)
	if in.PostOperationItems != nil {
		in, out := &in.PostOperationItems, &out.PostOperationItems
		*out = make([]velero.ResourceIdentifier, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}
