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
	"encoding/json"

	"context"

	"github.com/pkg/errors"
	"google.golang.org/protobuf/types/known/emptypb"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	timestamppb "google.golang.org/protobuf/types/known/timestamppb"

	api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/plugin/framework/common"
	proto "github.com/vmware-tanzu/velero/pkg/plugin/generated"
	protobiav2 "github.com/vmware-tanzu/velero/pkg/plugin/generated/backupitemaction/v2"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	biav2 "github.com/vmware-tanzu/velero/pkg/plugin/velero/backupitemaction/v2"
)

// BackupItemActionGRPCServer implements the proto-generated BackupItemAction interface, and accepts
// gRPC calls and forwards them to an implementation of the pluggable interface.
type BackupItemActionGRPCServer struct {
	mux *common.ServerMux
}

func (s *BackupItemActionGRPCServer) getImpl(name string) (biav2.BackupItemAction, error) {
	impl, err := s.mux.GetHandler(name)
	if err != nil {
		return nil, err
	}

	itemAction, ok := impl.(biav2.BackupItemAction)
	if !ok {
		return nil, errors.Errorf("%T is not a backup item action", impl)
	}

	return itemAction, nil
}

func (s *BackupItemActionGRPCServer) AppliesTo(
	ctx context.Context, req *protobiav2.BackupItemActionAppliesToRequest) (
	response *protobiav2.BackupItemActionAppliesToResponse, err error) {
	defer func() {
		if recoveredErr := common.HandlePanic(recover()); recoveredErr != nil {
			err = recoveredErr
		}
	}()

	impl, err := s.getImpl(req.Plugin)
	if err != nil {
		return nil, common.NewGRPCError(err)
	}

	resourceSelector, err := impl.AppliesTo()
	if err != nil {
		return nil, common.NewGRPCError(err)
	}

	return &protobiav2.BackupItemActionAppliesToResponse{
		ResourceSelector: &proto.ResourceSelector{
			IncludedNamespaces: resourceSelector.IncludedNamespaces,
			ExcludedNamespaces: resourceSelector.ExcludedNamespaces,
			IncludedResources:  resourceSelector.IncludedResources,
			ExcludedResources:  resourceSelector.ExcludedResources,
			Selector:           resourceSelector.LabelSelector,
		},
	}, nil
}

func (s *BackupItemActionGRPCServer) Execute(
	ctx context.Context, req *protobiav2.ExecuteRequest) (response *protobiav2.ExecuteResponse, err error) {
	defer func() {
		if recoveredErr := common.HandlePanic(recover()); recoveredErr != nil {
			err = recoveredErr
		}
	}()

	impl, err := s.getImpl(req.Plugin)
	if err != nil {
		return nil, common.NewGRPCError(err)
	}

	var item unstructured.Unstructured
	var backup api.Backup

	if err := json.Unmarshal(req.Item, &item); err != nil {
		return nil, common.NewGRPCError(errors.WithStack(err))
	}
	if err := json.Unmarshal(req.Backup, &backup); err != nil {
		return nil, common.NewGRPCError(errors.WithStack(err))
	}

	updatedItem, additionalItems, operationID, postOperationItems, err := impl.Execute(&item, &backup)
	if err != nil {
		return nil, common.NewGRPCError(err)
	}

	// If the plugin implementation returned a nil updatedItem (meaning no modifications), reset updatedItem to the
	// original item.
	var updatedItemJSON []byte
	if updatedItem == nil {
		updatedItemJSON = req.Item
	} else {
		updatedItemJSON, err = json.Marshal(updatedItem.UnstructuredContent())
		if err != nil {
			return nil, common.NewGRPCError(errors.WithStack(err))
		}
	}

	res := &protobiav2.ExecuteResponse{
		Item:        updatedItemJSON,
		OperationID: operationID,
	}

	for _, item := range additionalItems {
		res.AdditionalItems = append(res.AdditionalItems, backupResourceIdentifierToProto(item))
	}
	for _, item := range postOperationItems {
		res.PostOperationItems = append(res.PostOperationItems, backupResourceIdentifierToProto(item))
	}

	return res, nil
}

func (s *BackupItemActionGRPCServer) Progress(
	ctx context.Context, req *protobiav2.BackupItemActionProgressRequest) (
	response *protobiav2.BackupItemActionProgressResponse, err error) {
	defer func() {
		if recoveredErr := common.HandlePanic(recover()); recoveredErr != nil {
			err = recoveredErr
		}
	}()

	impl, err := s.getImpl(req.Plugin)
	if err != nil {
		return nil, common.NewGRPCError(err)
	}

	var backup api.Backup
	if err := json.Unmarshal(req.Backup, &backup); err != nil {
		return nil, common.NewGRPCError(errors.WithStack(err))
	}

	progress, err := impl.Progress(req.OperationID, &backup)
	if err != nil {
		return nil, common.NewGRPCError(err)
	}

	res := &protobiav2.BackupItemActionProgressResponse{
		Progress: &proto.OperationProgress{
			Completed:      progress.Completed,
			Err:            progress.Err,
			NCompleted:     progress.NCompleted,
			NTotal:         progress.NTotal,
			OperationUnits: progress.OperationUnits,
			Description:    progress.Description,
			Started:        timestamppb.New(progress.Started),
			Updated:        timestamppb.New(progress.Updated),
		},
	}
	return res, nil
}

func (s *BackupItemActionGRPCServer) Cancel(
	ctx context.Context, req *protobiav2.BackupItemActionCancelRequest) (
	response *emptypb.Empty, err error) {
	defer func() {
		if recoveredErr := common.HandlePanic(recover()); recoveredErr != nil {
			err = recoveredErr
		}
	}()

	impl, err := s.getImpl(req.Plugin)
	if err != nil {
		return nil, common.NewGRPCError(err)
	}

	var backup api.Backup
	if err := json.Unmarshal(req.Backup, &backup); err != nil {
		return nil, common.NewGRPCError(errors.WithStack(err))
	}

	err = impl.Cancel(req.OperationID, &backup)
	if err != nil {
		return nil, common.NewGRPCError(err)
	}

	return &emptypb.Empty{}, nil
}

func backupResourceIdentifierToProto(id velero.ResourceIdentifier) *proto.ResourceIdentifier {
	return &proto.ResourceIdentifier{
		Group:     id.Group,
		Resource:  id.Resource,
		Namespace: id.Namespace,
		Name:      id.Name,
	}
}

// This shouldn't be called on the GRPC server since the server won't ever receive this request, as
// the RestartableBackupItemAction in Velero won't delegate this to the server
func (s *BackupItemActionGRPCServer) Name() string {
	return ""
}
