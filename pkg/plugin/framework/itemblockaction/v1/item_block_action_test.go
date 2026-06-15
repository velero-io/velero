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
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	v1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/plugin/framework/common"
	proto "github.com/vmware-tanzu/velero/pkg/plugin/generated"
	protoibav1 "github.com/vmware-tanzu/velero/pkg/plugin/generated/itemblockaction/v1"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	mocks "github.com/vmware-tanzu/velero/pkg/plugin/velero/mocks/itemblockaction/v1"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
)

func TestItemBlockActionGRPCServerGetRelatedItems(t *testing.T) {
	invalidItem := []byte("this is gibberish json")
	validItem := []byte(`
	{
		"apiVersion": "v1",
		"kind": "ConfigMap",
		"metadata": {
			"namespace": "myns",
			"name": "myconfigmap"
		},
		"data": {
			"key": "value"
		}
	}`)
	var validItemObject unstructured.Unstructured
	err := json.Unmarshal(validItem, &validItemObject)
	require.NoError(t, err)

	invalidBackup := []byte("this is gibberish json")
	validBackup := []byte(`
	{
		"apiVersion": "velero.io/v1",
		"kind": "Backup",
		"metadata": {
			"namespace": "myns",
			"name": "mybackup"
		},
		"spec": {
			"includedNamespaces": ["*"],
			"includedResources": ["*"],
			"ttl": "60m"
		}
	}`)
	var validBackupObject v1.Backup
	err = json.Unmarshal(validBackup, &validBackupObject)
	require.NoError(t, err)

	tests := []struct {
		name             string
		backup           []byte
		item             []byte
		implRelatedItems []velero.ResourceIdentifier
		implError        error
		expectError      bool
		skipMock         bool
	}{
		{
			name:        "error unmarshaling item",
			item:        invalidItem,
			backup:      validBackup,
			expectError: true,
			skipMock:    true,
		},
		{
			name:        "error unmarshaling backup",
			item:        validItem,
			backup:      invalidBackup,
			expectError: true,
			skipMock:    true,
		},
		{
			name:        "error running impl",
			item:        validItem,
			backup:      validBackup,
			implError:   errors.New("impl error"),
			expectError: true,
		},
		{
			name:   "no relatedItems",
			item:   validItem,
			backup: validBackup,
		},
		{
			name:   "some relatedItems",
			item:   validItem,
			backup: validBackup,
			implRelatedItems: []velero.ResourceIdentifier{
				{
					GroupResource: schema.GroupResource{Group: "v1", Resource: "pods"},
					Namespace:     "myns",
					Name:          "mypod",
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			itemAction := &mocks.ItemBlockAction{}
			defer itemAction.AssertExpectations(t)

			if !test.skipMock {
				itemAction.On("GetRelatedItems", &validItemObject, &validBackupObject).Return(test.implRelatedItems, test.implError)
			}

			s := &ItemBlockActionGRPCServer{mux: &common.ServerMux{
				ServerLog: velerotest.NewLogger(),
				Handlers: map[string]any{
					"xyz": itemAction,
				},
			}}

			req := &protoibav1.ItemBlockActionGetRelatedItemsRequest{
				Plugin: "xyz",
				Item:   test.item,
				Backup: test.backup,
			}

			resp, err := s.GetRelatedItems(t.Context(), req)

			// Verify error
			assert.Equal(t, test.expectError, err != nil)
			if err != nil {
				return
			}
			require.NotNil(t, resp)

			// Verify related items
			var expectedRelatedItems []*proto.ResourceIdentifier
			for _, item := range test.implRelatedItems {
				expectedRelatedItems = append(expectedRelatedItems, backupResourceIdentifierToProto(item))
			}
			assert.Equal(t, expectedRelatedItems, resp.RelatedItems)
		})
	}
}
