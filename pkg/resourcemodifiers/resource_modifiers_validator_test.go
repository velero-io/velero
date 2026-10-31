/*
Copyright The Velero Contributors.

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
package resourcemodifiers

import (
	"testing"
)

func TestResourceModifiers_Validate(t *testing.T) {
	type fields struct {
		Version               string
		ResourceModifierRules []ResourceModifierRule
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "correct version, non 0 length ResourceModifierRules",
			fields: fields{
				Version: "v1",
				ResourceModifierRules: []ResourceModifierRule{
					{
						Conditions: Conditions{
							GroupResource:     "persistentvolumeclaims",
							ResourceNameRegex: ".*",
							Namespaces:        []string{"bar", "foo"},
						},
						Patches: []JSONPatch{
							{
								Operation: "replace",
								Path:      "/spec/storageClassName",
								Value:     "premium",
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "incorrect version, non 0 length ResourceModifierRules",
			fields: fields{
				Version: "v2",
				ResourceModifierRules: []ResourceModifierRule{
					{
						Conditions: Conditions{
							GroupResource:     "persistentvolumeclaims",
							ResourceNameRegex: ".*",
							Namespaces:        []string{"bar", "foo"},
						},
						Patches: []JSONPatch{
							{
								Operation: "replace",
								Path:      "/spec/storageClassName",
								Value:     "premium",
							},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "correct version, 0 length ResourceModifierRules",
			fields: fields{
				Version:               "v1",
				ResourceModifierRules: []ResourceModifierRule{},
			},
			wantErr: true,
		},
		{
			name: "patch has invalid operation",
			fields: fields{
				Version: "v1",
				ResourceModifierRules: []ResourceModifierRule{
					{
						Conditions: Conditions{
							GroupResource:     "persistentvolumeclaims",
							ResourceNameRegex: ".*",
							Namespaces:        []string{"bar", "foo"},
						},
						Patches: []JSONPatch{
							{
								Operation: "invalid",
								Path:      "/spec/storageClassName",
								Value:     "premium",
							},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "Condition has empty GroupResource",
			fields: fields{
				Version: "v1",
				ResourceModifierRules: []ResourceModifierRule{
					{
						Conditions: Conditions{
							GroupResource:     "",
							ResourceNameRegex: ".*",
							Namespaces:        []string{"bar", "foo"},
						},
						Patches: []JSONPatch{
							{
								Operation: "invalid",
								Path:      "/spec/storageClassName",
								Value:     "premium",
							},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "More than one patch type in a rule",
			fields: fields{
				Version: "v1",
				ResourceModifierRules: []ResourceModifierRule{
					{
						Conditions: Conditions{
							GroupResource: "*",
						},
						Patches: []JSONPatch{
							{
								Operation: "test",
								Path:      "/spec/storageClassName",
								Value:     "premium",
							},
						},
						MergePatches: []JSONMergePatch{
							{
								PatchData: `{"metadata":{"labels":{"a":null}}}`,
							},
						},
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &ResourceModifiers{
				Version:               tt.fields.Version,
				ResourceModifierRules: tt.fields.ResourceModifierRules,
			}
			if err := p.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("ResourceModifiers.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestJsonPatch_Validate(t *testing.T) {
	type fields struct {
		Operation string
		Path      string
		Value     string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "not empty operation, path, and new value, valid scenario",
			fields: fields{
				Operation: "replace",
				Path:      "/spec/storageClassName",
				Value:     "premium",
			},
			wantErr: false,
		},
		{
			name: "empty operation throws error",
			fields: fields{
				Operation: "",
				Path:      "/spec/storageClassName",
				Value:     "premium",
			},
			wantErr: true,
		},
		{
			name: "empty path throws error",
			fields: fields{
				Operation: "replace",
				Path:      "",
				Value:     "premium",
			},
			wantErr: true,
		},
		{
			name: "invalid operation throws error",
			fields: fields{
				Operation: "invalid",
				Path:      "/spec/storageClassName",
				Value:     "premium",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &JSONPatch{
				Operation: tt.fields.Operation,
				Path:      tt.fields.Path,
				Value:     tt.fields.Value,
			}
			if err := p.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("JsonPatch.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
