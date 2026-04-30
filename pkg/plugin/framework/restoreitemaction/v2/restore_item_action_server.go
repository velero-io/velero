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
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/plugin/framework/common"
	proto "github.com/vmware-tanzu/velero/pkg/plugin/generated"
	protoriav2 "github.com/vmware-tanzu/velero/pkg/plugin/generated/restoreitemaction/v2"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	riav2 "github.com/vmware-tanzu/velero/pkg/plugin/velero/restoreitemaction/v2"
)

// RestoreItemActionGRPCServer implements the proto-generated RestoreItemActionServer interface, and accepts
// gRPC calls and forwards them to an implementation of the pluggable interface.
type RestoreItemActionGRPCServer struct {
	mux *common.ServerMux
}

func (s *RestoreItemActionGRPCServer) getImpl(name string) (riav2.RestoreItemAction, error) {
	impl, err := s.mux.GetHandler(name)
	if err != nil {
		return nil, err
	}

	itemAction, ok := impl.(riav2.RestoreItemAction)
	if !ok {
		return nil, errors.Errorf("%T is not a restore item action (v2)", impl)
	}

	return itemAction, nil
}

func (s *RestoreItemActionGRPCServer) AppliesTo(ctx context.Context, req *protoriav2.RestoreItemActionAppliesToRequest) (response *protoriav2.RestoreItemActionAppliesToResponse, err error) {
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

	return &protoriav2.RestoreItemActionAppliesToResponse{
		ResourceSelector: &proto.ResourceSelector{
			IncludedNamespaces: resourceSelector.IncludedNamespaces,
			ExcludedNamespaces: resourceSelector.ExcludedNamespaces,
			IncludedResources:  resourceSelector.IncludedResources,
			ExcludedResources:  resourceSelector.ExcludedResources,
			Selector:           resourceSelector.LabelSelector,
		},
	}, nil
}

func (s *RestoreItemActionGRPCServer) Execute(ctx context.Context, req *protoriav2.RestoreItemActionExecuteRequest) (response *protoriav2.RestoreItemActionExecuteResponse, err error) {
	defer func() {
		if recoveredErr := common.HandlePanic(recover()); recoveredErr != nil {
			err = recoveredErr
		}
	}()

	impl, err := s.getImpl(req.Plugin)
	if err != nil {
		return nil, common.NewGRPCError(err)
	}

	var (
		item           unstructured.Unstructured
		itemFromBackup unstructured.Unstructured
		restoreObj     api.Restore
	)

	if err := json.Unmarshal(req.Item, &item); err != nil {
		return nil, common.NewGRPCError(errors.WithStack(err))
	}

	if err := json.Unmarshal(req.ItemFromBackup, &itemFromBackup); err != nil {
		return nil, common.NewGRPCError(errors.WithStack(err))
	}

	if err := json.Unmarshal(req.Restore, &restoreObj); err != nil {
		return nil, common.NewGRPCError(errors.WithStack(err))
	}

	executeOutput, err := impl.Execute(&velero.RestoreItemActionExecuteInput{
		Item:           &item,
		ItemFromBackup: &itemFromBackup,
		Restore:        &restoreObj,
	})
	if err != nil {
		return nil, common.NewGRPCError(err)
	}

	// If the plugin implementation returned a nil updateItem (meaning no modifications), reset updatedItem to the
	// original item.
	var updatedItemJSON []byte
	if executeOutput.UpdatedItem == nil {
		updatedItemJSON = req.Item
	} else {
		updatedItemJSON, err = json.Marshal(executeOutput.UpdatedItem.UnstructuredContent())
		if err != nil {
			return nil, common.NewGRPCError(errors.WithStack(err))
		}
	}

	res := &protoriav2.RestoreItemActionExecuteResponse{
		Item:                        updatedItemJSON,
		SkipRestore:                 executeOutput.SkipRestore,
		OperationID:                 executeOutput.OperationID,
		WaitForAdditionalItems:      executeOutput.WaitForAdditionalItems,
		AdditionalItemsReadyTimeout: durationpb.New(executeOutput.AdditionalItemsReadyTimeout),
	}

	for _, item := range executeOutput.AdditionalItems {
		res.AdditionalItems = append(res.AdditionalItems, restoreResourceIdentifierToProto(item))
	}

	return res, nil
}

func (s *RestoreItemActionGRPCServer) Progress(ctx context.Context, req *protoriav2.RestoreItemActionProgressRequest) (
	response *protoriav2.RestoreItemActionProgressResponse, err error) {
	defer func() {
		if recoveredErr := common.HandlePanic(recover()); recoveredErr != nil {
			err = recoveredErr
		}
	}()

	impl, err := s.getImpl(req.Plugin)
	if err != nil {
		return nil, common.NewGRPCError(err)
	}

	var restore api.Restore
	if err := json.Unmarshal(req.Restore, &restore); err != nil {
		return nil, common.NewGRPCError(errors.WithStack(err))
	}

	progress, err := impl.Progress(req.OperationID, &restore)
	if err != nil {
		return nil, common.NewGRPCError(err)
	}

	res := &protoriav2.RestoreItemActionProgressResponse{
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

func (s *RestoreItemActionGRPCServer) Cancel(
	ctx context.Context, req *protoriav2.RestoreItemActionCancelRequest) (
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

	var restore api.Restore
	if err := json.Unmarshal(req.Restore, &restore); err != nil {
		return nil, common.NewGRPCError(errors.WithStack(err))
	}

	err = impl.Cancel(req.OperationID, &restore)
	if err != nil {
		return nil, common.NewGRPCError(err)
	}

	return &emptypb.Empty{}, nil
}

func (s *RestoreItemActionGRPCServer) AreAdditionalItemsReady(ctx context.Context, req *protoriav2.RestoreItemActionItemsReadyRequest) (
	response *protoriav2.RestoreItemActionItemsReadyResponse, err error) {
	defer func() {
		if recoveredErr := common.HandlePanic(recover()); recoveredErr != nil {
			err = recoveredErr
		}
	}()

	impl, err := s.getImpl(req.Plugin)
	if err != nil {
		return nil, common.NewGRPCError(err)
	}

	var restore api.Restore
	if err := json.Unmarshal(req.Restore, &restore); err != nil {
		return nil, common.NewGRPCError(errors.WithStack(err))
	}
	var additionalItems []velero.ResourceIdentifier
	for _, itm := range req.AdditionalItems {
		newItem := velero.ResourceIdentifier{
			GroupResource: schema.GroupResource{
				Group:    itm.Group,
				Resource: itm.Resource,
			},
			Namespace: itm.Namespace,
			Name:      itm.Name,
		}

		additionalItems = append(additionalItems, newItem)
	}
	ready, err := impl.AreAdditionalItemsReady(additionalItems, &restore)
	if err != nil {
		return nil, common.NewGRPCError(err)
	}

	res := &protoriav2.RestoreItemActionItemsReadyResponse{
		Ready: ready,
	}
	return res, nil
}

func restoreResourceIdentifierToProto(id velero.ResourceIdentifier) *proto.ResourceIdentifier {
	return &proto.ResourceIdentifier{
		Group:     id.Group,
		Resource:  id.Resource,
		Namespace: id.Namespace,
		Name:      id.Name,
	}
}

// This shouldn't be called on the GRPC server since the server won't ever receive this request, as
// the RestartableRestoreItemAction in Velero won't delegate this to the server
func (s *RestoreItemActionGRPCServer) Name() string {
	return ""
}
