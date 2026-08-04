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
package resourcepolicies

import (
	"testing"

	"k8s.io/apimachinery/pkg/api/resource"
)

func TestCapacityConditionValidate(t *testing.T) {
	testCases := []struct {
		name     string
		capacity *capacity
		wantErr  bool
	}{
		{
			name:     "lower and upper are both zero",
			capacity: &capacity{lower: *resource.NewQuantity(0, resource.DecimalSI), upper: *resource.NewQuantity(0, resource.DecimalSI)},
			wantErr:  false,
		},
		{
			name:     "lower is zero and upper is greater than zero",
			capacity: &capacity{lower: *resource.NewQuantity(0, resource.DecimalSI), upper: *resource.NewQuantity(100, resource.DecimalSI)},
			wantErr:  false,
		},
		{
			name:     "lower is greater than upper",
			capacity: &capacity{lower: *resource.NewQuantity(100, resource.DecimalSI), upper: *resource.NewQuantity(50, resource.DecimalSI)},
			wantErr:  true,
		},
		{
			name:     "lower and upper are equal",
			capacity: &capacity{lower: *resource.NewQuantity(100, resource.DecimalSI), upper: *resource.NewQuantity(100, resource.DecimalSI)},
			wantErr:  false,
		},
		{
			name:     "lower is greater than zero and upper is zero",
			capacity: &capacity{lower: *resource.NewQuantity(100, resource.DecimalSI), upper: *resource.NewQuantity(0, resource.DecimalSI)},
			wantErr:  false,
		},
		{
			name:     "lower and upper are both not zero and lower is less than upper",
			capacity: &capacity{lower: *resource.NewQuantity(100, resource.DecimalSI), upper: *resource.NewQuantity(200, resource.DecimalSI)},
			wantErr:  false,
		},
		{
			name:     "lower and upper are both not zero and lower is equal to upper",
			capacity: &capacity{lower: *resource.NewQuantity(100, resource.DecimalSI), upper: *resource.NewQuantity(100, resource.DecimalSI)},
			wantErr:  false,
		},
		{
			name:     "lower and upper are both not zero and lower is greater than upper",
			capacity: &capacity{lower: *resource.NewQuantity(200, resource.DecimalSI), upper: *resource.NewQuantity(100, resource.DecimalSI)},
			wantErr:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c := &capacityCondition{capacity: *tc.capacity}
			err := c.validate()

			if (err != nil) != tc.wantErr {
				t.Fatalf("Expected error %v, but got error %v", tc.wantErr, err)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	testCases := []struct {
		name    string
		res     *ResourcePolicies
		wantErr bool
	}{
		{
			name: "unknown key in yaml",
			res: &ResourcePolicies{
				Version: "v1",
				VolumePolicies: []VolumePolicy{
					{
						Action: Action{Type: "skip"},
						Conditions: map[string]any{
							"capacity":     "0,10Gi",
							"unknown":      "",
							"storageClass": []string{"gp2", "ebs-sc"},
							"csi": any(
								map[string]any{
									"driver": "aws.efs.csi.driver",
								}),
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "error format of capacity",
			res: &ResourcePolicies{
				Version: "v1",
				VolumePolicies: []VolumePolicy{
					{
						Action: Action{Type: "skip"},
						Conditions: map[string]any{
							"capacity":     "10Gi",
							"storageClass": []string{"gp2", "ebs-sc"},
							"csi": any(
								map[string]any{
									"driver": "aws.efs.csi.driver",
								}),
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "error format of storageClass",
			res: &ResourcePolicies{
				Version: "v1",
				VolumePolicies: []VolumePolicy{
					{
						Action: Action{Type: "skip"},
						Conditions: map[string]any{
							"capacity":     "0,10Gi",
							"storageClass": "ebs-sc",
							"csi": any(
								map[string]any{
									"driver": "aws.efs.csi.driver",
								}),
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "error format of csi",
			res: &ResourcePolicies{
				Version: "v1",
				VolumePolicies: []VolumePolicy{
					{
						Action: Action{Type: "skip"},
						Conditions: map[string]any{
							"capacity":     "0,10Gi",
							"storageClass": []string{"gp2", "ebs-sc"},
							"csi":          "aws.efs.csi.driver",
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "error format of csi driver",
			res: &ResourcePolicies{
				Version: "v1",
				VolumePolicies: []VolumePolicy{
					{
						Action: Action{Type: "skip"},
						Conditions: map[string]any{
							"capacity":     "0,10Gi",
							"storageClass": []string{"gp2", "ebs-sc"},
							"csi": any(
								map[string]any{
									"driver": []string{"aws.efs.csi.driver"},
								}),
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "error format of csi driver volumeAttributes",
			res: &ResourcePolicies{
				Version: "v1",
				VolumePolicies: []VolumePolicy{
					{
						Action: Action{Type: "skip"},
						Conditions: map[string]any{
							"capacity":     "0,10Gi",
							"storageClass": []string{"gp2", "ebs-sc"},
							"csi": any(
								map[string]any{
									"driver":           "aws.efs.csi.driver",
									"volumeAttributes": "test",
								}),
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "unsupported version",
			res: &ResourcePolicies{
				Version: "v2",
				VolumePolicies: []VolumePolicy{
					{
						Action: Action{Type: "skip"},
						Conditions: map[string]any{
							"capacity": "0,10Gi",
							"csi": any(
								map[string]any{
									"driver": "aws.efs.csi.driver",
								}),
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "unsupported action",
			res: &ResourcePolicies{
				Version: "v1",
				VolumePolicies: []VolumePolicy{
					{
						Action: Action{Type: "unsupported"},
						Conditions: map[string]any{
							"capacity": "0,10Gi",
							"csi": any(
								map[string]any{
									"driver": "aws.efs.csi.driver",
								}),
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "error format of nfs",
			res: &ResourcePolicies{
				Version: "v1",
				VolumePolicies: []VolumePolicy{
					{
						Action: Action{Type: "skip"},
						Conditions: map[string]any{
							"capacity":     "0,10Gi",
							"storageClass": []string{"gp2", "ebs-sc"},
							"nfs":          "aws.efs.csi.driver",
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "supported format volume policies only csi driver",
			res: &ResourcePolicies{
				Version: "v1",
				VolumePolicies: []VolumePolicy{
					{
						Action: Action{Type: "skip"},
						Conditions: map[string]any{
							"csi": any(
								map[string]any{
									"driver": "aws.efs.csi.driver",
								}),
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "unsupported format volume policies only csi volumeattributes",
			res: &ResourcePolicies{
				Version: "v1",
				VolumePolicies: []VolumePolicy{
					{
						Action: Action{Type: "skip"},
						Conditions: map[string]any{
							"csi": any(
								map[string]any{
									"volumeAttributes": map[string]string{
										"key1": "value1",
									},
								}),
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "supported format volume policies with csi driver and volumeattributes",
			res: &ResourcePolicies{
				Version: "v1",
				VolumePolicies: []VolumePolicy{
					{
						Action: Action{Type: "skip"},
						Conditions: map[string]any{
							"csi": any(
								map[string]any{
									"driver": "aws.efs.csi.driver",
									"volumeAttributes": map[string]string{
										"key1": "value1",
									},
								}),
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "supported format volume policies",
			res: &ResourcePolicies{
				Version: "v1",
				VolumePolicies: []VolumePolicy{
					{
						Action: Action{Type: "skip"},
						Conditions: map[string]any{
							"capacity":     "0,10Gi",
							"storageClass": []string{"gp2", "ebs-sc"},
							"csi": any(
								map[string]any{
									"driver": "aws.efs.csi.driver",
								}),
							"nfs": any(
								map[string]any{
									"server": "192.168.20.90",
									"path":   "/mnt/data/",
								}),
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "supported format volume policies, action type snapshot",
			res: &ResourcePolicies{
				Version: "v1",
				VolumePolicies: []VolumePolicy{
					{
						Action: Action{Type: "snapshot"},
						Conditions: map[string]any{
							"capacity":     "0,10Gi",
							"storageClass": []string{"gp2", "ebs-sc"},
							"csi": any(
								map[string]any{
									"driver": "aws.efs.csi.driver",
								}),
							"nfs": any(
								map[string]any{
									"server": "192.168.20.90",
									"path":   "/mnt/data/",
								}),
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "supported format volume policies, action type fs-backup",
			res: &ResourcePolicies{
				Version: "v1",
				VolumePolicies: []VolumePolicy{
					{
						Action: Action{Type: "fs-backup"},
						Conditions: map[string]any{
							"capacity":     "0,10Gi",
							"storageClass": []string{"gp2", "ebs-sc"},
							"csi": any(
								map[string]any{
									"driver": "aws.efs.csi.driver",
								}),
							"nfs": any(
								map[string]any{
									"server": "192.168.20.90",
									"path":   "/mnt/data/",
								}),
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "supported format volume policies, action type fs-backup and snapshot",
			res: &ResourcePolicies{
				Version: "v1",
				VolumePolicies: []VolumePolicy{
					{
						Action: Action{Type: Snapshot},
						Conditions: map[string]any{
							"storageClass": []string{"gp2"},
						},
					},
					{
						Action: Action{Type: FSBackup},
						Conditions: map[string]any{
							"nfs": any(
								map[string]any{
									"server": "192.168.20.90",
									"path":   "/mnt/data/",
								}),
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "supported format volume policies with pvcLabels (valid map)",
			res: &ResourcePolicies{
				Version: "v1",
				VolumePolicies: []VolumePolicy{
					{
						Action: Action{Type: "skip"},
						Conditions: map[string]any{
							"pvcLabels": map[string]string{
								"environment": "production",
								"app":         "database",
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "error format volume policies with pvcLabels (not a map)",
			res: &ResourcePolicies{
				Version: "v1",
				VolumePolicies: []VolumePolicy{
					{
						Action: Action{Type: "skip"},
						Conditions: map[string]any{
							"pvcLabels": "production",
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: " '*' in the filters of include exclude policy - 1",
			res: &ResourcePolicies{
				Version: "v1",
				VolumePolicies: []VolumePolicy{
					{
						Action: Action{Type: "skip"},
						Conditions: map[string]any{
							"pvcLabels": map[string]string{
								"environment": "production",
								"app":         "database",
							},
						},
					},
				},
				IncludeExcludePolicy: &IncludeExcludePolicy{
					IncludedClusterScopedResources:   []string{"*"},
					ExcludedClusterScopedResources:   []string{"crds"},
					IncludedNamespaceScopedResources: []string{"pods"},
					ExcludedNamespaceScopedResources: []string{"secrets"},
				},
			},
			wantErr: true,
		},
		{
			name: " '*' in the filters of include exclude policy - 2",
			res: &ResourcePolicies{
				Version: "v1",
				VolumePolicies: []VolumePolicy{
					{
						Action: Action{Type: "skip"},
						Conditions: map[string]any{
							"pvcLabels": map[string]string{
								"environment": "production",
								"app":         "database",
							},
						},
					},
				},
				IncludeExcludePolicy: &IncludeExcludePolicy{
					IncludedClusterScopedResources:   []string{"persistentvolumes"},
					ExcludedClusterScopedResources:   []string{"crds"},
					IncludedNamespaceScopedResources: []string{"pods"},
					ExcludedNamespaceScopedResources: []string{"*"},
				},
			},
			wantErr: true,
		},
		{
			name: " dup item in both the include and exclude filters of include exclude policy",
			res: &ResourcePolicies{
				Version: "v1",
				VolumePolicies: []VolumePolicy{
					{
						Action: Action{Type: "skip"},
						Conditions: map[string]any{
							"pvcLabels": map[string]string{
								"environment": "production",
								"app":         "database",
							},
						},
					},
				},
				IncludeExcludePolicy: &IncludeExcludePolicy{
					IncludedClusterScopedResources:   []string{"persistentvolumes"},
					ExcludedClusterScopedResources:   []string{"crds"},
					IncludedNamespaceScopedResources: []string{"pods", "configmaps"},
					ExcludedNamespaceScopedResources: []string{"secrets", "pods"},
				},
			},
			wantErr: true,
		},
		{
			name: " valid volume policies and valid include/exclude policy",
			res: &ResourcePolicies{
				Version: "v1",
				VolumePolicies: []VolumePolicy{
					{
						Action: Action{Type: "skip"},
						Conditions: map[string]any{
							"pvcLabels": map[string]string{
								"environment": "production",
								"app":         "database",
							},
						},
					},
				},
				IncludeExcludePolicy: &IncludeExcludePolicy{
					IncludedClusterScopedResources:   []string{"persistentvolumes"},
					ExcludedClusterScopedResources:   []string{"crds"},
					IncludedNamespaceScopedResources: []string{"pods", "configmaps"},
					ExcludedNamespaceScopedResources: []string{"secrets"},
				},
			},
			wantErr: false,
		},
		{
			name: "snapshot action with valid dataMover velero-fs",
			res: &ResourcePolicies{
				Version: "v1",
				VolumePolicies: []VolumePolicy{
					{
						Action: Action{
							Type:       Snapshot,
							Parameters: map[string]any{"dataMover": "velero-fs"},
						},
						Conditions: map[string]any{"storageClass": []string{"gp2"}},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "snapshot action with valid dataMover velero-block",
			res: &ResourcePolicies{
				Version: "v1",
				VolumePolicies: []VolumePolicy{
					{
						Action: Action{
							Type:       Snapshot,
							Parameters: map[string]any{"dataMover": "velero-block"},
						},
						Conditions: map[string]any{"storageClass": []string{"gp2"}},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "snapshot action with valid dataMover velero",
			res: &ResourcePolicies{
				Version: "v1",
				VolumePolicies: []VolumePolicy{
					{
						Action: Action{
							Type:       Snapshot,
							Parameters: map[string]any{"dataMover": "velero"},
						},
						Conditions: map[string]any{"storageClass": []string{"gp2"}},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "snapshot action with invalid dataMover value",
			res: &ResourcePolicies{
				Version: "v1",
				VolumePolicies: []VolumePolicy{
					{
						Action: Action{
							Type:       Snapshot,
							Parameters: map[string]any{"dataMover": "unknown-mover"},
						},
						Conditions: map[string]any{"storageClass": []string{"gp2"}},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "snapshot action with non-string dataMover value",
			res: &ResourcePolicies{
				Version: "v1",
				VolumePolicies: []VolumePolicy{
					{
						Action: Action{
							Type:       Snapshot,
							Parameters: map[string]any{"dataMover": 123},
						},
						Conditions: map[string]any{"storageClass": []string{"gp2"}},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "dataMover parameter on non-snapshot action is rejected",
			res: &ResourcePolicies{
				Version: "v1",
				VolumePolicies: []VolumePolicy{
					{
						Action: Action{
							Type:       FSBackup,
							Parameters: map[string]any{"dataMover": "velero-fs"},
						},
						Conditions: map[string]any{"storageClass": []string{"gp2"}},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "snapshot action without parameters still valid",
			res: &ResourcePolicies{
				Version: "v1",
				VolumePolicies: []VolumePolicy{
					{
						Action:     Action{Type: Snapshot},
						Conditions: map[string]any{"storageClass": []string{"gp2"}},
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			policies := &Policies{}
			err1 := policies.BuildPolicy(tc.res)
			err2 := policies.Validate()

			if tc.wantErr {
				if err1 == nil && err2 == nil {
					t.Fatalf("Expected error %v, but not get error", tc.wantErr)
				}
			} else {
				if err1 != nil || err2 != nil {
					t.Fatalf("Expected error %v, but got error %v %v", tc.wantErr, err1, err2)
				}
			}
		})
	}
}

func TestValidateForRestore(t *testing.T) {
	testCases := []struct {
		name    string
		res     *ResourcePolicies
		wantErr bool
	}{
		{
			name: "valid restore policies",
			res: &ResourcePolicies{
				Version: "v1",
				ClusterScopedFilterPolicy: &ClusterScopedFilterPolicy{
					ResourceFilters: []ResourceFilter{
						{
							Kinds: []string{"ClusterRole"},
						},
					},
				},
				NamespacedFilterPolicies: []NamespacedFilterPolicy{
					{
						Namespaces: []string{"default"},
						ResourceFilters: []ResourceFilter{
							{
								Kinds: []string{"Pod"},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "unsupported volumePolicies for restore",
			res: &ResourcePolicies{
				Version: "v1",
				VolumePolicies: []VolumePolicy{
					{
						Action: Action{Type: "skip"},
						Conditions: map[string]any{
							"capacity": "10Gi",
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "unsupported includeExcludePolicy for restore",
			res: &ResourcePolicies{
				Version: "v1",
				IncludeExcludePolicy: &IncludeExcludePolicy{
					IncludedClusterScopedResources: []string{"persistentvolumes"},
				},
			},
			wantErr: true,
		},
		{
			name: "wrong version",
			res: &ResourcePolicies{
				Version: "v2",
			},
			wantErr: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			policies := &Policies{}
			err1 := policies.BuildPolicy(tc.res)
			err2 := policies.ValidateForRestore()

			if tc.wantErr {
				if err1 == nil && err2 == nil {
					t.Fatalf("Expected error %v, but not get error", tc.wantErr)
				}
			} else {
				if err1 != nil || err2 != nil {
					t.Fatalf("Expected error %v, but got error %v %v", tc.wantErr, err1, err2)
				}
			}
		})
	}
}
