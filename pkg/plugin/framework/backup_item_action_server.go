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
	biav1 "github.com/vmware-tanzu/velero/pkg/plugin/velero/backupitemaction/v1"
)

// BackupItemActionGRPCServer implements the proto-generated BackupItemAction interface, and accepts
// gRPC calls and forwards them to an implementation of the pluggable interface.
type BackupItemActionGRPCServer struct {
	mux *common.ServerMux
}

func (s *BackupItemActionGRPCServer) getImpl(name string) (biav1.BackupItemAction, error) {
	impl, err := s.mux.GetHandler(name)
	if err != nil {
		return nil, err
	}

	itemAction, ok := impl.(biav1.BackupItemAction)
	if !ok {
		return nil, errors.Errorf("%T is not a backup item action", impl)
	}

	return itemAction, nil
}

func (s *BackupItemActionGRPCServer) AppliesTo(
	ctx context.Context, req *proto.BackupItemActionAppliesToRequest) (
	response *proto.BackupItemActionAppliesToResponse, err error) {
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

	return &proto.BackupItemActionAppliesToResponse{
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
	ctx context.Context, req *proto.ExecuteRequest) (response *proto.ExecuteResponse, err error) {
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

	updatedItem, additionalItems, err := impl.Execute(&item, &backup)
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

	res := &proto.ExecuteResponse{
		Item: updatedItemJSON,
	}

	for _, item := range additionalItems {
		res.AdditionalItems = append(res.AdditionalItems, backupResourceIdentifierToProto(item))
	}

	return res, nil
}

func backupResourceIdentifierToProto(id velero.ResourceIdentifier) *proto.ResourceIdentifier {
	return &proto.ResourceIdentifier{
		Group:     id.Group,
		Resource:  id.Resource,
		Namespace: id.Namespace,
		Name:      id.Name,
	}
}
