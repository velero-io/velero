/*
Copyright 2020 the Velero contributors.

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
)

// DeleteItemActionGRPCServer implements the proto-generated DeleteItemActionServer interface, and accepts
// gRPC calls and forwards them to an implementation of the pluggable interface.
type DeleteItemActionGRPCServer struct {
	mux *common.ServerMux
}

func (s *DeleteItemActionGRPCServer) getImpl(name string) (velero.DeleteItemAction, error) {
	impl, err := s.mux.GetHandler(name)
	if err != nil {
		return nil, err
	}

	itemAction, ok := impl.(velero.DeleteItemAction)
	if !ok {
		return nil, errors.Errorf("%T is not a delete item action", impl)
	}

	return itemAction, nil
}

func (s *DeleteItemActionGRPCServer) AppliesTo(ctx context.Context, req *proto.DeleteItemActionAppliesToRequest) (response *proto.DeleteItemActionAppliesToResponse, err error) {
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

	return &proto.DeleteItemActionAppliesToResponse{
		ResourceSelector: &proto.ResourceSelector{
			IncludedNamespaces: resourceSelector.IncludedNamespaces,
			ExcludedNamespaces: resourceSelector.ExcludedNamespaces,
			IncludedResources:  resourceSelector.IncludedResources,
			ExcludedResources:  resourceSelector.ExcludedResources,
			Selector:           resourceSelector.LabelSelector,
		},
	}, nil
}

func (s *DeleteItemActionGRPCServer) Execute(ctx context.Context, req *proto.DeleteItemActionExecuteRequest) (_ *proto.Empty, err error) {
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
		item   unstructured.Unstructured
		backup api.Backup
	)

	if err := json.Unmarshal(req.Item, &item); err != nil {
		return nil, common.NewGRPCError(errors.WithStack(err))
	}

	if err = json.Unmarshal(req.Backup, &backup); err != nil {
		return nil, common.NewGRPCError(errors.WithStack(err))
	}

	if err := impl.Execute(&velero.DeleteItemActionExecuteInput{
		Item:   &item,
		Backup: &backup,
	}); err != nil {
		return nil, common.NewGRPCError(err)
	}

	return &proto.Empty{}, nil
}
