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
	"google.golang.org/grpc"

	"github.com/vmware-tanzu/velero/pkg/plugin/framework/common"
	proto "github.com/vmware-tanzu/velero/pkg/plugin/generated"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
)

var _ velero.DeleteItemAction = &DeleteItemActionGRPCClient{}

// NewDeleteItemActionPlugin constructs a DeleteItemActionPlugin.
func NewDeleteItemActionPlugin(options ...common.PluginOption) *DeleteItemActionPlugin {
	return &DeleteItemActionPlugin{
		PluginBase: common.NewPluginBase(options...),
	}
}

// DeleteItemActionGRPCClient implements the DeleteItemAction interface and uses a
// gRPC client to make calls to the plugin server.
type DeleteItemActionGRPCClient struct {
	*common.ClientBase
	grpcClient proto.DeleteItemActionClient
}

func newDeleteItemActionGRPCClient(base *common.ClientBase, clientConn *grpc.ClientConn) interface{} {
	return &DeleteItemActionGRPCClient{
		ClientBase: base,
		grpcClient: proto.NewDeleteItemActionClient(clientConn),
	}
}

func (c *DeleteItemActionGRPCClient) AppliesTo() (velero.ResourceSelector, error) {
	res, err := c.grpcClient.AppliesTo(context.Background(), &proto.DeleteItemActionAppliesToRequest{Plugin: c.Plugin})
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

func (c *DeleteItemActionGRPCClient) Execute(input *velero.DeleteItemActionExecuteInput) error {
	itemJSON, err := json.Marshal(input.Item.UnstructuredContent())
	if err != nil {
		return errors.WithStack(err)
	}

	backupJSON, err := json.Marshal(input.Backup)
	if err != nil {
		return errors.WithStack(err)
	}

	req := &proto.DeleteItemActionExecuteRequest{
		Plugin: c.Plugin,
		Item:   itemJSON,
		Backup: backupJSON,
	}

	// First return item is just an empty struct no matter what.
	if _, err = c.grpcClient.Execute(context.Background(), req); err != nil {
		return common.FromGRPCError(err)
	}

	return nil
}
