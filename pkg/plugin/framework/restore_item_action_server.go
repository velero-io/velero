/*
Copyright 2017, 2019 the Velero contributors.

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

package framework

import (
	"encoding/json"

	"context"

	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/plugin/framework/common"
	proto "github.com/vmware-tanzu/velero/pkg/plugin/generated"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	riav1 "github.com/vmware-tanzu/velero/pkg/plugin/velero/restoreitemaction/v1"
)

// RestoreItemActionGRPCServer implements the proto-generated RestoreItemActionServer interface, and accepts
// gRPC calls and forwards them to an implementation of the pluggable interface.
type RestoreItemActionGRPCServer struct {
	mux *common.ServerMux
}

func (s *RestoreItemActionGRPCServer) getImpl(name string) (riav1.RestoreItemAction, error) {
	impl, err := s.mux.GetHandler(name)
	if err != nil {
		return nil, err
	}

	itemAction, ok := impl.(riav1.RestoreItemAction)
	if !ok {
		return nil, errors.Errorf("%T is not a restore item action", impl)
	}

	return itemAction, nil
}

func (s *RestoreItemActionGRPCServer) AppliesTo(ctx context.Context, req *proto.RestoreItemActionAppliesToRequest) (response *proto.RestoreItemActionAppliesToResponse, err error) {
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

	return &proto.RestoreItemActionAppliesToResponse{
		ResourceSelector: &proto.ResourceSelector{
			IncludedNamespaces: resourceSelector.IncludedNamespaces,
			ExcludedNamespaces: resourceSelector.ExcludedNamespaces,
			IncludedResources:  resourceSelector.IncludedResources,
			ExcludedResources:  resourceSelector.ExcludedResources,
			Selector:           resourceSelector.LabelSelector,
		},
	}, nil
}

func (s *RestoreItemActionGRPCServer) Execute(ctx context.Context, req *proto.RestoreItemActionExecuteRequest) (response *proto.RestoreItemActionExecuteResponse, err error) {
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

	res := &proto.RestoreItemActionExecuteResponse{
		Item:        updatedItemJSON,
		SkipRestore: executeOutput.SkipRestore,
	}

	for _, item := range executeOutput.AdditionalItems {
		res.AdditionalItems = append(res.AdditionalItems, restoreResourceIdentifierToProto(item))
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
