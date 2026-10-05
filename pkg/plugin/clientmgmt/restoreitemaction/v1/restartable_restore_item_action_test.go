/*
Copyright 2018, 2019 the Velero contributors.

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
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/vmware-tanzu/velero/internal/restartabletest"
	v1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/plugin/clientmgmt/process"
	"github.com/vmware-tanzu/velero/pkg/plugin/framework/common"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	mocks "github.com/vmware-tanzu/velero/pkg/plugin/velero/mocks/restoreitemaction/v1"
)

func TestRestartableGetRestoreItemAction(t *testing.T) {
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
			expectedError: "plugin int is not a RestoreItemAction",
		},
		{
			name:   "happy path",
			plugin: new(mocks.RestoreItemAction),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := new(restartabletest.MockRestartableProcess)
			defer p.AssertExpectations(t)

			name := "pod"
			key := process.KindAndName{Kind: common.PluginKindRestoreItemAction, Name: name}
			p.On("GetByKindAndName", key).Return(tc.plugin, tc.getError)

			r := NewRestartableRestoreItemAction(name, p)
			a, err := r.getRestoreItemAction()
			if tc.expectedError != "" {
				assert.EqualError(t, err, tc.expectedError)
				return
			}
			require.NoError(t, err)

			assert.Equal(t, tc.plugin, a)
		})
	}
}

func TestRestartableRestoreItemActionGetDelegate(t *testing.T) {
	p := new(restartabletest.MockRestartableProcess)
	defer p.AssertExpectations(t)

	// Reset error
	p.On("ResetIfNeeded").Return(errors.Errorf("reset error")).Once()
	name := "pod"
	r := NewRestartableRestoreItemAction(name, p)
	a, err := r.getDelegate()
	assert.Nil(t, a)
	require.EqualError(t, err, "reset error")

	// Happy path
	p.On("ResetIfNeeded").Return(nil)
	expected := new(mocks.RestoreItemAction)
	key := process.KindAndName{Kind: common.PluginKindRestoreItemAction, Name: name}
	p.On("GetByKindAndName", key).Return(expected, nil)

	a, err = r.getDelegate()
	require.NoError(t, err)
	assert.Equal(t, expected, a)
}

func TestRestartableRestoreItemActionDelegatedFunctions(t *testing.T) {
	pv := &unstructured.Unstructured{
		Object: map[string]any{
			"color": "blue",
		},
	}

	input := &velero.RestoreItemActionExecuteInput{
		Item:           pv,
		ItemFromBackup: pv,
		Restore:        new(v1.Restore),
	}

	output := &velero.RestoreItemActionExecuteOutput{
		UpdatedItem: &unstructured.Unstructured{
			Object: map[string]any{
				"color": "green",
			},
		},
	}

	restartabletest.RunRestartableDelegateTests(
		t,
		common.PluginKindRestoreItemAction,
		func(key process.KindAndName, p process.RestartableProcess) any {
			return &RestartableRestoreItemAction{
				Key:                 key,
				SharedPluginProcess: p,
			}
		},
		func() restartabletest.Mockable {
			return new(mocks.RestoreItemAction)
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
			ExpectedErrorOutputs:    []any{nil, errors.Errorf("reset error")},
			ExpectedDelegateOutputs: []any{output, errors.Errorf("delegate error")},
		},
	)
}
