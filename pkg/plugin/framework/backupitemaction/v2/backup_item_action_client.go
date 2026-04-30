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

package v2

import (
	"encoding/json"

	"context"

	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/plugin/framework/common"
	protobiav2 "github.com/vmware-tanzu/velero/pkg/plugin/generated/backupitemaction/v2"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
)

// NewBackupItemActionPlugin constructs a BackupItemActionPlugin.
func NewBackupItemActionPlugin(options ...common.PluginOption) *BackupItemActionPlugin {
	return &BackupItemActionPlugin{
		PluginBase: common.NewPluginBase(options...),
	}
}

// BackupItemActionGRPCClient implements the backup/ItemAction interface and uses a
// gRPC client to make calls to the plugin server.
type BackupItemActionGRPCClient struct {
	*common.ClientBase
	grpcClient protobiav2.BackupItemActionClient
}

func newBackupItemActionGRPCClient(base *common.ClientBase, clientConn *grpc.ClientConn) interface{} {
	return &BackupItemActionGRPCClient{
		ClientBase: base,
		grpcClient: protobiav2.NewBackupItemActionClient(clientConn),
	}
}

func (c *BackupItemActionGRPCClient) AppliesTo() (velero.ResourceSelector, error) {
	req := &protobiav2.BackupItemActionAppliesToRequest{
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

func (c *BackupItemActionGRPCClient) Execute(item runtime.Unstructured, backup *api.Backup) (runtime.Unstructured, []velero.ResourceIdentifier, string, []velero.ResourceIdentifier, error) {
	itemJSON, err := json.Marshal(item.UnstructuredContent())
	if err != nil {
		return nil, nil, "", nil, errors.WithStack(err)
	}

	backupJSON, err := json.Marshal(backup)
	if err != nil {
		return nil, nil, "", nil, errors.WithStack(err)
	}

	req := &protobiav2.ExecuteRequest{
		Plugin: c.Plugin,
		Item:   itemJSON,
		Backup: backupJSON,
	}

	res, err := c.grpcClient.Execute(context.Background(), req)
	if err != nil {
		return nil, nil, "", nil, common.FromGRPCError(err)
	}

	var updatedItem unstructured.Unstructured
	if err := json.Unmarshal(res.Item, &updatedItem); err != nil {
		return nil, nil, "", nil, errors.WithStack(err)
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

	var postOperationItems []velero.ResourceIdentifier

	for _, itm := range res.PostOperationItems {
		newItem := velero.ResourceIdentifier{
			GroupResource: schema.GroupResource{
				Group:    itm.Group,
				Resource: itm.Resource,
			},
			Namespace: itm.Namespace,
			Name:      itm.Name,
		}

		postOperationItems = append(postOperationItems, newItem)
	}

	return &updatedItem, additionalItems, res.OperationID, postOperationItems, nil
}

func (c *BackupItemActionGRPCClient) Progress(operationID string, backup *api.Backup) (velero.OperationProgress, error) {
	backupJSON, err := json.Marshal(backup)
	if err != nil {
		return velero.OperationProgress{}, errors.WithStack(err)
	}
	req := &protobiav2.BackupItemActionProgressRequest{
		Plugin:      c.Plugin,
		OperationID: operationID,
		Backup:      backupJSON,
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

func (c *BackupItemActionGRPCClient) Cancel(operationID string, backup *api.Backup) error {
	backupJSON, err := json.Marshal(backup)
	if err != nil {
		return errors.WithStack(err)
	}
	req := &protobiav2.BackupItemActionCancelRequest{
		Plugin:      c.Plugin,
		OperationID: operationID,
		Backup:      backupJSON,
	}

	_, err = c.grpcClient.Cancel(context.Background(), req)
	if err != nil {
		return common.FromGRPCError(err)
	}

	return nil
}

// This shouldn't be called on the GRPC client since the RestartableBackupItemAction won't delegate
// this method
func (c *BackupItemActionGRPCClient) Name() string {
	return ""
}
