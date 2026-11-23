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

// RestoreOperation stores information about an async item operation
// started by a RestoreItemAction plugin (v2 or later)
type RestoreOperation struct {
	Spec RestoreOperationSpec `json:"spec"`

	Status OperationStatus `json:"status"`
}

func (in *RestoreOperation) DeepCopy() *RestoreOperation {
	if in == nil {
		return nil
	}
	out := new(RestoreOperation)
	in.DeepCopyInto(out)
	return out
}

func (in *RestoreOperation) DeepCopyInto(out *RestoreOperation) {
	*out = *in
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

type RestoreOperationSpec struct {
	// RestoreName is the name of the Velero restore this item operation
	// is associated with.
	RestoreName string `json:"restoreName"`

	// RestoreUID is the UID of the Velero restore this item operation
	// is associated with.
	RestoreUID string `json:"restoreUID"`

	// RestoreItemAction is the name of the RestoreItemAction plugin that started the operation
	RestoreItemAction string `json:"restoreItemAction"`

	// Kubernetes resource identifier for the item
	ResourceIdentifier velero.ResourceIdentifier `json:"resourceIdentifier"`

	// OperationID returned by the RIA plugin
	OperationID string `json:"operationID"`
}

func (in *RestoreOperationSpec) DeepCopy() *RestoreOperationSpec {
	if in == nil {
		return nil
	}
	out := new(RestoreOperationSpec)
	in.DeepCopyInto(out)
	return out
}

func (in *RestoreOperationSpec) DeepCopyInto(out *RestoreOperationSpec) {
	*out = *in
	in.ResourceIdentifier.DeepCopyInto(&out.ResourceIdentifier)
}
