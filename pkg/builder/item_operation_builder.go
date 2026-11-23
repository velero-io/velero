/*
Copyright 2023 the Velero contributors.

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

package builder

import (
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/velero-io/velero/pkg/itemoperation"
	"github.com/velero-io/velero/pkg/plugin/velero"
)

// OperationStatusBuilder builds OperationStatus objects
type OperationStatusBuilder struct {
	object *itemoperation.OperationStatus
}

// ForOperationStatus is the constructor for a OperationStatusBuilder.
func ForOperationStatus() *OperationStatusBuilder {
	return &OperationStatusBuilder{
		object: &itemoperation.OperationStatus{},
	}
}

// Result returns the built OperationStatus.
func (osb *OperationStatusBuilder) Result() *itemoperation.OperationStatus {
	return osb.object
}

// Phase sets the OperationStatus's phase.
func (osb *OperationStatusBuilder) Phase(phase itemoperation.OperationPhase) *OperationStatusBuilder {
	osb.object.Phase = phase
	return osb
}

// Error sets the OperationStatus's error.
func (osb *OperationStatusBuilder) Error(err string) *OperationStatusBuilder {
	osb.object.Error = err
	return osb
}

// Progress sets the OperationStatus's progress.
func (osb *OperationStatusBuilder) Progress(nComplete int64, nTotal int64, operationUnits string) *OperationStatusBuilder {
	osb.object.NCompleted = nComplete
	osb.object.NTotal = nTotal
	osb.object.OperationUnits = operationUnits
	return osb
}

// Description sets the OperationStatus's description.
func (osb *OperationStatusBuilder) Description(desc string) *OperationStatusBuilder {
	osb.object.Description = desc
	return osb
}

// Created sets the OperationStatus's creation timestamp.
func (osb *OperationStatusBuilder) Created(t time.Time) *OperationStatusBuilder {
	osb.object.Created = &metav1.Time{Time: t}
	return osb
}

// Updated sets the OperationStatus's last update timestamp.
func (osb *OperationStatusBuilder) Updated(t time.Time) *OperationStatusBuilder {
	osb.object.Updated = &metav1.Time{Time: t}
	return osb
}

// Started sets the OperationStatus's start timestamp.
func (osb *OperationStatusBuilder) Started(t time.Time) *OperationStatusBuilder {
	osb.object.Started = &metav1.Time{Time: t}
	return osb
}

// BackupOperationBuilder builds BackupOperation objects
type BackupOperationBuilder struct {
	object *itemoperation.BackupOperation
}

// ForBackupOperation is the constructor for a BackupOperationBuilder.
func ForBackupOperation() *BackupOperationBuilder {
	return &BackupOperationBuilder{
		object: &itemoperation.BackupOperation{},
	}
}

// Result returns the built BackupOperation.
func (bb *BackupOperationBuilder) Result() *itemoperation.BackupOperation {
	return bb.object
}

// BackupName sets the BackupOperation's backup name.
func (bb *BackupOperationBuilder) BackupName(name string) *BackupOperationBuilder {
	bb.object.Spec.BackupName = name
	return bb
}

// OperationID sets the BackupOperation's operation ID.
func (bb *BackupOperationBuilder) OperationID(id string) *BackupOperationBuilder {
	bb.object.Spec.OperationID = id
	return bb
}

// Status sets the BackupOperation's status.
func (bb *BackupOperationBuilder) Status(status itemoperation.OperationStatus) *BackupOperationBuilder {
	bb.object.Status = status
	return bb
}

// ResourceIdentifier sets the BackupOperation's resource identifier.
func (bb *BackupOperationBuilder) ResourceIdentifier(group, resource, ns, name string) *BackupOperationBuilder {
	bb.object.Spec.ResourceIdentifier = velero.ResourceIdentifier{
		GroupResource: schema.GroupResource{
			Group:    group,
			Resource: resource,
		},
		Namespace: ns,
		Name:      name,
	}
	return bb
}

// BackupItemAction sets the BackupOperation's backup item action.
func (bb *BackupOperationBuilder) BackupItemAction(bia string) *BackupOperationBuilder {
	bb.object.Spec.BackupItemAction = bia
	return bb
}

// PostOperationItem adds a post-operation item to the BackupOperation's list of post-operation items.
func (bb *BackupOperationBuilder) PostOperationItem(group, resource, ns, name string) *BackupOperationBuilder {
	bb.object.Spec.PostOperationItems = append(bb.object.Spec.PostOperationItems, velero.ResourceIdentifier{
		GroupResource: schema.GroupResource{
			Group:    group,
			Resource: resource,
		},
		Namespace: ns,
		Name:      name,
	})
	return bb
}

// RestoreOperationBuilder builds RestoreOperation objects
type RestoreOperationBuilder struct {
	object *itemoperation.RestoreOperation
}

// ForRestoreOperation is the constructor for a RestoreOperationBuilder.
func ForRestoreOperation() *RestoreOperationBuilder {
	return &RestoreOperationBuilder{
		object: &itemoperation.RestoreOperation{},
	}
}

// Result returns the built RestoreOperation.
func (rb *RestoreOperationBuilder) Result() *itemoperation.RestoreOperation {
	return rb.object
}

// RestoreName sets the RestoreOperation's restore name.
func (rb *RestoreOperationBuilder) RestoreName(name string) *RestoreOperationBuilder {
	rb.object.Spec.RestoreName = name
	return rb
}

// OperationID sets the RestoreOperation's operation ID.
func (rb *RestoreOperationBuilder) OperationID(id string) *RestoreOperationBuilder {
	rb.object.Spec.OperationID = id
	return rb
}

// RestoreItemAction sets the RestoreOperation's restore item action.
func (rb *RestoreOperationBuilder) RestoreItemAction(ria string) *RestoreOperationBuilder {
	rb.object.Spec.RestoreItemAction = ria
	return rb
}

// Status sets the RestoreOperation's status.
func (rb *RestoreOperationBuilder) Status(status itemoperation.OperationStatus) *RestoreOperationBuilder {
	rb.object.Status = status
	return rb
}

// ResourceIdentifier sets the RestoreOperation's resource identifier.
func (rb *RestoreOperationBuilder) ResourceIdentifier(group, resource, ns, name string) *RestoreOperationBuilder {
	rb.object.Spec.ResourceIdentifier = velero.ResourceIdentifier{
		GroupResource: schema.GroupResource{
			Group:    group,
			Resource: resource,
		},
		Namespace: ns,
		Name:      name,
	}
	return rb
}
