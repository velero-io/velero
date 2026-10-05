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

package v1

import (
	"encoding/json"

	"context"

	"github.com/cockroachdb/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/plugin/framework/common"
	proto "github.com/vmware-tanzu/velero/pkg/plugin/generated"
	protoibav1 "github.com/vmware-tanzu/velero/pkg/plugin/generated/itemblockaction/v1"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	ibav1 "github.com/vmware-tanzu/velero/pkg/plugin/velero/itemblockaction/v1"
)

// ItemBlockActionGRPCServer implements the proto-generated ItemBlockAction interface, and accepts
// gRPC calls and forwards them to an implementation of the pluggable interface.
type ItemBlockActionGRPCServer struct {
	mux *common.ServerMux
}

func (s *ItemBlockActionGRPCServer) getImpl(name string) (ibav1.ItemBlockAction, error) {
	impl, err := s.mux.GetHandler(name)
	if err != nil {
		return nil, err
	}

	itemAction, ok := impl.(ibav1.ItemBlockAction)
	if !ok {
		return nil, errors.Errorf("%T is not an ItemBlock action", impl)
	}

	return itemAction, nil
}

func (s *ItemBlockActionGRPCServer) AppliesTo(
	ctx context.Context, req *protoibav1.ItemBlockActionAppliesToRequest) (
	response *protoibav1.ItemBlockActionAppliesToResponse, err error) {
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

	return &protoibav1.ItemBlockActionAppliesToResponse{
		ResourceSelector: &proto.ResourceSelector{
			IncludedNamespaces: resourceSelector.IncludedNamespaces,
			ExcludedNamespaces: resourceSelector.ExcludedNamespaces,
			IncludedResources:  resourceSelector.IncludedResources,
			ExcludedResources:  resourceSelector.ExcludedResources,
			Selector:           resourceSelector.LabelSelector,
		},
	}, nil
}

func (s *ItemBlockActionGRPCServer) GetRelatedItems(
	ctx context.Context, req *protoibav1.ItemBlockActionGetRelatedItemsRequest) (response *protoibav1.ItemBlockActionGetRelatedItemsResponse, err error) {
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

	relatedItems, err := impl.GetRelatedItems(&item, &backup)
	if err != nil {
		return nil, common.NewGRPCError(err)
	}

	res := &protoibav1.ItemBlockActionGetRelatedItemsResponse{}

	for _, item := range relatedItems {
		res.RelatedItems = append(res.RelatedItems, backupResourceIdentifierToProto(item))
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

// This shouldn't be called on the GRPC server since the server won't ever receive this request, as
// the RestartableItemBlockAction in Velero won't delegate this to the server
func (s *ItemBlockActionGRPCServer) Name() string {
	return ""
}
