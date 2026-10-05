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
	"google.golang.org/grpc"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/plugin/framework/common"
	protoibav1 "github.com/vmware-tanzu/velero/pkg/plugin/generated/itemblockaction/v1"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
)

// NewItemBlockActionPlugin constructs a ItemBlockActionPlugin.
func NewItemBlockActionPlugin(options ...common.PluginOption) *ItemBlockActionPlugin {
	return &ItemBlockActionPlugin{
		PluginBase: common.NewPluginBase(options...),
	}
}

// ItemBlockActionGRPCClient implements the backup/ItemAction interface and uses a
// gRPC client to make calls to the plugin server.
type ItemBlockActionGRPCClient struct {
	*common.ClientBase
	grpcClient protoibav1.ItemBlockActionClient
}

func newItemBlockActionGRPCClient(base *common.ClientBase, clientConn *grpc.ClientConn) any {
	return &ItemBlockActionGRPCClient{
		ClientBase: base,
		grpcClient: protoibav1.NewItemBlockActionClient(clientConn),
	}
}

func (c *ItemBlockActionGRPCClient) AppliesTo() (velero.ResourceSelector, error) {
	req := &protoibav1.ItemBlockActionAppliesToRequest{
		Plugin: c.Plugin,
	}

	res, err := c.grpcClient.AppliesTo(context.Background(), req)
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

func (c *ItemBlockActionGRPCClient) GetRelatedItems(item runtime.Unstructured, backup *api.Backup) ([]velero.ResourceIdentifier, error) {
	itemJSON, err := json.Marshal(item.UnstructuredContent())
	if err != nil {
		return nil, errors.WithStack(err)
	}

	backupJSON, err := json.Marshal(backup)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	req := &protoibav1.ItemBlockActionGetRelatedItemsRequest{
		Plugin: c.Plugin,
		Item:   itemJSON,
		Backup: backupJSON,
	}

	res, err := c.grpcClient.GetRelatedItems(context.Background(), req)
	if err != nil {
		return nil, common.FromGRPCError(err)
	}

	var relatedItems []velero.ResourceIdentifier

	for _, itm := range res.RelatedItems {
		newItem := velero.ResourceIdentifier{
			GroupResource: schema.GroupResource{
				Group:    itm.Group,
				Resource: itm.Resource,
			},
			Namespace: itm.Namespace,
			Name:      itm.Name,
		}

		relatedItems = append(relatedItems, newItem)
	}

	return relatedItems, nil
}

// This shouldn't be called on the GRPC client since the RestartableItemBlockAction won't delegate
// this method
func (c *ItemBlockActionGRPCClient) Name() string {
	return ""
}
