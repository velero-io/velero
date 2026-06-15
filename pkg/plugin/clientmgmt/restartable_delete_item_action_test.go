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

package clientmgmt

import (
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/vmware-tanzu/velero/internal/restartabletest"
	api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/plugin/clientmgmt/process"
	"github.com/vmware-tanzu/velero/pkg/plugin/framework/common"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero/mocks"
)

func TestRestartableGetDeleteItemAction(t *testing.T) {
	tests := []struct {
		name          string
		plugin        any
		getError      error
		expectedError string
	}{
		{
			name:          "error getting by kind and name",
			getError:      errors.Errorf("get error"),
			expectedError: "get error",
		},
		{
			name:          "wrong type",
			plugin:        3,
			expectedError: "plugin int is not a DeleteItemAction",
		},
		{
			name:   "happy path",
			plugin: new(mocks.DeleteItemAction),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := new(restartabletest.MockRestartableProcess)
			defer p.AssertExpectations(t)

			name := "pod"
			key := process.KindAndName{Kind: common.PluginKindDeleteItemAction, Name: name}
			p.On("GetByKindAndName", key).Return(tc.plugin, tc.getError)

			r := NewRestartableDeleteItemAction(name, p)
			a, err := r.getDeleteItemAction()
			if tc.expectedError != "" {
				assert.EqualError(t, err, tc.expectedError)
				return
			}
			require.NoError(t, err)

			assert.Equal(t, tc.plugin, a)
		})
	}
}

func TestRestartableDeleteItemActionGetDelegate(t *testing.T) {
	p := new(restartabletest.MockRestartableProcess)
	defer p.AssertExpectations(t)

	// Reset error
	p.On("ResetIfNeeded").Return(errors.Errorf("reset error")).Once()
	name := "pod"
	r := NewRestartableDeleteItemAction(name, p)
	a, err := r.getDelegate()
	assert.Nil(t, a)
	require.EqualError(t, err, "reset error")

	// Happy path
	// Currently broken since this mocks out the restore item action interface
	p.On("ResetIfNeeded").Return(nil)
	expected := new(mocks.DeleteItemAction)
	key := process.KindAndName{Kind: common.PluginKindDeleteItemAction, Name: name}
	p.On("GetByKindAndName", key).Return(expected, nil)

	a, err = r.getDelegate()
	require.NoError(t, err)
	assert.Equal(t, expected, a)
}

func TestRestartableDeleteItemActionDelegatedFunctions(t *testing.T) {
	pv := &unstructured.Unstructured{
		Object: map[string]any{
			"color": "blue",
		},
	}

	backup := &api.Backup{}

	input := &velero.DeleteItemActionExecuteInput{
		Item:   pv,
		Backup: backup,
	}

	restartabletest.RunRestartableDelegateTests(
		t,
		common.PluginKindDeleteItemAction,
		func(key process.KindAndName, p process.RestartableProcess) any {
			return &restartableDeleteItemAction{
				key:                 key,
				sharedPluginProcess: p,
			}
		},
		func() restartabletest.Mockable {
			// Currently broken because this mocks the restore item action interface
			return new(mocks.DeleteItemAction)
		},
		restartabletest.RestartableDelegateTest{
			Function:                "AppliesTo",
			Inputs:                  []any{},
			ExpectedErrorOutputs:    []any{velero.ResourceSelector{}, errors.Errorf("reset error")},
			ExpectedDelegateOutputs: []any{velero.ResourceSelector{IncludedNamespaces: []string{"a"}}, errors.Errorf("delegate error")},
		},
		restartabletest.RestartableDelegateTest{
			Function:                "Execute",
			Inputs:                  []any{input},
			ExpectedErrorOutputs:    []any{errors.Errorf("reset error")},
			ExpectedDelegateOutputs: []any{errors.Errorf("delegate error")},
		},
	)
}
