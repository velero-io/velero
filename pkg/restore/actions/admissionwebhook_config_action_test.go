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

package actions

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/velero-io/velero/pkg/plugin/velero"
	velerotest "github.com/velero-io/velero/pkg/test"
)

func TestNewAdmissionWebhookConfigurationActionExecute(t *testing.T) {
	action := NewAdmissionWebhookConfigurationAction(velerotest.NewLogger())
	cases := []struct {
		name                    string
		itemJSON                string
		wantErr                 bool
		NoneSideEffectsIndex    []int // the indexes with sideEffects that arereset to None
		NotNoneSideEffectsIndex []int // the indexes with sideEffects that are not reset to None
	}{
		{
			name: "v1 mutatingwebhookconfiguration with sideEffects as Unknown",
			itemJSON: `{
				 "apiVersion": "admissionregistration.k8s.io/v1",
				 "kind": "MutatingWebhookConfiguration",
				 "metadata": {
					  "name": "my-test-mutating"
				 },
				 "webhooks": [
					  {
						  "clientConfig": {
							   "url": "https://mytest.org"
						  },
						  "rules": [
							   {
									"apiGroups": [
										""
									],
									"apiVersions": [
										"v1"
									],
									"operations": [
										"CREATE"
									],
									"resources": [
										"pods"
									],
									"scope": "Namespaced"
							   }
						  ],
						  "sideEffects": "Unknown"
					  }
				 ]
			}`,
			wantErr:              false,
			NoneSideEffectsIndex: []int{0},
		},
		{
			name: "v1 validatingwebhookconfiguration with sideEffects as Some",
			itemJSON: `{
				 "apiVersion": "admissionregistration.k8s.io/v1",
				 "kind": "ValidatingWebhookConfiguration",
				 "metadata": {
					  "name": "my-test-validating"
				 },
				 "webhooks": [
					  {
						  "clientConfig": {
							   "url": "https://mytest.org"
						  },
						  "rules": [
							   {
									"apiGroups": [
										""
									],
									"apiVersions": [
										"v1"
									],
									"operations": [
										"CREATE"
									],
									"resources": [
										"pods"
									],
									"scope": "Namespaced"
							   }
						  ],
						  "sideEffects": "Some"
					  }
				 ]
			}`,
			wantErr:              false,
			NoneSideEffectsIndex: []int{0},
		},
		{
			name: "v1beta1 validatingwebhookconfiguration with sideEffects as Some, nothing should change",
			itemJSON: `{
				 "apiVersion": "admissionregistration.k8s.io/v1beta1",
				 "kind": "ValidatingWebhookConfiguration",
				 "metadata": {
					  "name": "my-test-validating"
				 },
				 "webhooks": [
					  {
						  "clientConfig": {
							   "url": "https://mytest.org"
						  },
						  "rules": [
							   {
									"apiGroups": [
										""
									],
									"apiVersions": [
										"v1"
									],
									"operations": [
										"CREATE"
									],
									"resources": [
										"pods"
									],
									"scope": "Namespaced"
							   }
						  ],
						  "sideEffects": "Some"
					  }
				 ]
			}`,
			wantErr:                 false,
			NotNoneSideEffectsIndex: []int{0},
		},
		{
			name: "v1 validatingwebhookconfiguration with multiple invalid sideEffects",
			itemJSON: `{
				 "apiVersion": "admissionregistration.k8s.io/v1",
				 "kind": "ValidatingWebhookConfiguration",
				 "metadata": {
					  "name": "my-test-validating"
				 },
				 "webhooks": [
					  {
						  "clientConfig": {
							   "url": "https://mytest.org"
						  },
						  "sideEffects": "Some"
					  },
					  {
						  "clientConfig": {
							   "url": "https://mytest2.org"
						  },
						  "sideEffects": "Some"
					  }
				 ]
			}`,
			wantErr:              false,
			NoneSideEffectsIndex: []int{0, 1},
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			o := map[string]any{}
			json.Unmarshal([]byte(tt.itemJSON), &o)
			input := &velero.RestoreItemActionExecuteInput{
				Item: &unstructured.Unstructured{
					Object: o,
				},
			}
			output, err := action.Execute(input)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			if tt.NoneSideEffectsIndex != nil {
				wb, _, err := unstructured.NestedSlice(output.UpdatedItem.UnstructuredContent(), "webhooks")
				require.NoError(t, err)
				for _, i := range tt.NoneSideEffectsIndex {
					it, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&wb[i])
					require.NoError(t, err)
					s := it["sideEffects"].(string)
					assert.Equal(t, "None", s)
				}
			}
			if tt.NotNoneSideEffectsIndex != nil {
				wb, _, err := unstructured.NestedSlice(output.UpdatedItem.UnstructuredContent(), "webhooks")
				require.NoError(t, err)
				for _, i := range tt.NotNoneSideEffectsIndex {
					it, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&wb[i])
					require.NoError(t, err)
					s := it["sideEffects"].(string)
					assert.NotEqual(t, "None", s)
				}
			}
		})
	}
}
