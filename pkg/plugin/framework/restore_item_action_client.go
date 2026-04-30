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
	"google.golang.org/grpc"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/vmware-tanzu/velero/pkg/plugin/framework/common"
	proto "github.com/vmware-tanzu/velero/pkg/plugin/generated"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	riav1 "github.com/vmware-tanzu/velero/pkg/plugin/velero/restoreitemaction/v1"
)

var _ riav1.RestoreItemAction = &RestoreItemActionGRPCClient{}

// NewRestoreItemActionPlugin constructs a RestoreItemActionPlugin.
func NewRestoreItemActionPlugin(options ...common.PluginOption) *RestoreItemActionPlugin {
	return &RestoreItemActionPlugin{
		PluginBase: common.NewPluginBase(options...),
	}
}

// RestoreItemActionGRPCClient implements the backup/ItemAction interface and uses a
// gRPC client to make calls to the plugin server.
type RestoreItemActionGRPCClient struct {
	*common.ClientBase
	grpcClient proto.RestoreItemActionClient
}

func newRestoreItemActionGRPCClient(base *common.ClientBase, clientConn *grpc.ClientConn) interface{} {
	return &RestoreItemActionGRPCClient{
		ClientBase: base,
		grpcClient: proto.NewRestoreItemActionClient(clientConn),
	}
}

func (c *RestoreItemActionGRPCClient) AppliesTo() (velero.ResourceSelector, error) {
	res, err := c.grpcClient.AppliesTo(context.Background(), &proto.RestoreItemActionAppliesToRequest{Plugin: c.Plugin})
	if err != nil {
		return velero.ResourceSelector{}, common.FromGRPCError(err)
	}

	if res.ResourceSelector == nil {
		return velero.ResourceSelector{}, nil
	}

	return velero.ResourceSelector{
		IncludedNamespaces: res.ResourceSelector.IncludedNamespaces,
		ExcludedNamespaces: res.ResourceSelector.ExcludedNamespaces,
		IncludedResources:  res.ResourceSelector.IncludedResources,
		ExcludedResources:  res.ResourceSelector.ExcludedResources,
		LabelSelector:      res.ResourceSelector.Selector,
	}, nil
}

func (c *RestoreItemActionGRPCClient) Execute(input *velero.RestoreItemActionExecuteInput) (*velero.RestoreItemActionExecuteOutput, error) {
	itemJSON, err := json.Marshal(input.Item.UnstructuredContent())
	if err != nil {
		return nil, errors.WithStack(err)
	}

	itemFromBackupJSON, err := json.Marshal(input.ItemFromBackup.UnstructuredContent())
	if err != nil {
		return nil, errors.WithStack(err)
	}

	restoreJSON, err := json.Marshal(input.Restore)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	req := &proto.RestoreItemActionExecuteRequest{
		Plugin:         c.Plugin,
		Item:           itemJSON,
		ItemFromBackup: itemFromBackupJSON,
		Restore:        restoreJSON,
	}

	res, err := c.grpcClient.Execute(context.Background(), req)
	if err != nil {
		return nil, common.FromGRPCError(err)
	}

	var updatedItem unstructured.Unstructured
	if err := json.Unmarshal(res.Item, &updatedItem); err != nil {
		return nil, errors.WithStack(err)
	}

	var additionalItems []velero.ResourceIdentifier
	for _, itm := range res.AdditionalItems {
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

	return &velero.RestoreItemActionExecuteOutput{
		UpdatedItem:     &updatedItem,
		AdditionalItems: additionalItems,
		SkipRestore:     res.SkipRestore,
	}, nil
}
