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
	"google.golang.org/grpc"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/plugin/framework/common"
	protoriav2 "github.com/vmware-tanzu/velero/pkg/plugin/generated/restoreitemaction/v2"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	riav2 "github.com/vmware-tanzu/velero/pkg/plugin/velero/restoreitemaction/v2"
)

var _ riav2.RestoreItemAction = &RestoreItemActionGRPCClient{}

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
	grpcClient protoriav2.RestoreItemActionClient
}

func newRestoreItemActionGRPCClient(base *common.ClientBase, clientConn *grpc.ClientConn) interface{} {
	return &RestoreItemActionGRPCClient{
		ClientBase: base,
		grpcClient: protoriav2.NewRestoreItemActionClient(clientConn),
	}
}

func (c *RestoreItemActionGRPCClient) AppliesTo() (velero.ResourceSelector, error) {
	res, err := c.grpcClient.AppliesTo(context.Background(), &protoriav2.RestoreItemActionAppliesToRequest{Plugin: c.Plugin})
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

	req := &protoriav2.RestoreItemActionExecuteRequest{
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
		UpdatedItem:                 &updatedItem,
		AdditionalItems:             additionalItems,
		SkipRestore:                 res.SkipRestore,
		OperationID:                 res.OperationID,
		WaitForAdditionalItems:      res.WaitForAdditionalItems,
		AdditionalItemsReadyTimeout: res.AdditionalItemsReadyTimeout.AsDuration(),
	}, nil
}

func (c *RestoreItemActionGRPCClient) Progress(operationID string, restore *api.Restore) (velero.OperationProgress, error) {
	restoreJSON, err := json.Marshal(restore)
	if err != nil {
		return velero.OperationProgress{}, errors.WithStack(err)
	}
	req := &protoriav2.RestoreItemActionProgressRequest{
		Plugin:      c.Plugin,
		OperationID: operationID,
		Restore:     restoreJSON,
	}

	res, err := c.grpcClient.Progress(context.Background(), req)
	if err != nil {
		return velero.OperationProgress{}, common.FromGRPCError(err)
	}

	return velero.OperationProgress{
		Completed:      res.Progress.Completed,
		Err:            res.Progress.Err,
		NCompleted:     res.Progress.NCompleted,
		NTotal:         res.Progress.NTotal,
		OperationUnits: res.Progress.OperationUnits,
		Description:    res.Progress.Description,
		Started:        res.Progress.Started.AsTime(),
		Updated:        res.Progress.Updated.AsTime(),
	}, nil
}

func (c *RestoreItemActionGRPCClient) Cancel(operationID string, restore *api.Restore) error {
	restoreJSON, err := json.Marshal(restore)
	if err != nil {
		return errors.WithStack(err)
	}
	req := &protoriav2.RestoreItemActionCancelRequest{
		Plugin:      c.Plugin,
		OperationID: operationID,
		Restore:     restoreJSON,
	}

	_, err = c.grpcClient.Cancel(context.Background(), req)
	if err != nil {
		return common.FromGRPCError(err)
	}

	return nil
}

func (c *RestoreItemActionGRPCClient) AreAdditionalItemsReady(additionalItems []velero.ResourceIdentifier, restore *api.Restore) (bool, error) {
	restoreJSON, err := json.Marshal(restore)
	if err != nil {
		return false, errors.WithStack(err)
	}

	req := &protoriav2.RestoreItemActionItemsReadyRequest{
		Plugin:  c.Plugin,
		Restore: restoreJSON,
	}
	for _, item := range additionalItems {
		req.AdditionalItems = append(req.AdditionalItems, restoreResourceIdentifierToProto(item))
	}

	res, err := c.grpcClient.AreAdditionalItemsReady(context.Background(), req)
	if err != nil {
		return false, common.FromGRPCError(err)
	}

	return res.Ready, nil
}

// This shouldn't be called on the GRPC client since the RestartableRestoreItemAction won't delegate
// this method
func (c *RestoreItemActionGRPCClient) Name() string {
	return ""
}
