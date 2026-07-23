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

package volumehelper

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/ptr"

	"github.com/vmware-tanzu/velero/internal/resourcepolicies"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/kuberesource"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
	podvolumeutil "github.com/vmware-tanzu/velero/pkg/util/podvolume"
)

func TestVolumeHelperImpl_ShouldPerformSnapshot(t *testing.T) {
	testCases := []struct {
		name                     string
		inputObj                 runtime.Object
		groupResource            schema.GroupResource
		pod                      *corev1api.Pod
		resourcePolicies         *resourcepolicies.ResourcePolicies
		snapshotVolumesFlag      *bool
		defaultVolumesToFSBackup bool
		shouldSnapshot           bool
		expectedErr              bool
	}{
		{
			name:          "VolumePolicy match, returns true and no error",
			inputObj:      builder.ForPersistentVolume("example-pv").StorageClass("gp2-csi").ClaimRef("ns", "pvc-1").Result(),
			groupResource: kuberesource.PersistentVolumes,
			resourcePolicies: &resourcepolicies.ResourcePolicies{
				Version: "v1",
				VolumePolicies: []resourcepolicies.VolumePolicy{
					{
						Conditions: map[string]any{
							"storageClass": []string{"gp2-csi"},
						},
						Action: resourcepolicies.Action{
							Type: resourcepolicies.Snapshot,
						},
					},
				},
			},
			snapshotVolumesFlag: ptr.To(true),
			shouldSnapshot:      true,
			expectedErr:         false,
		},
		{
			name:          "VolumePolicy match, snapshotVolumes is false, return true and no error",
			inputObj:      builder.ForPersistentVolume("example-pv").StorageClass("gp2-csi").ClaimRef("ns", "pvc-1").Result(),
			groupResource: kuberesource.PersistentVolumes,
			resourcePolicies: &resourcepolicies.ResourcePolicies{
				Version: "v1",
				VolumePolicies: []resourcepolicies.VolumePolicy{
					{
						Conditions: map[string]any{
							"storageClass": []string{"gp2-csi"},
						},
						Action: resourcepolicies.Action{
							Type: resourcepolicies.Snapshot,
						},
					},
				},
			},
			snapshotVolumesFlag: ptr.To(false),
			shouldSnapshot:      true,
			expectedErr:         false,
		},
		{
			name:          "VolumePolicy match but action is unexpected, return false and no error",
			inputObj:      builder.ForPersistentVolume("example-pv").StorageClass("gp2-csi").ClaimRef("ns", "pvc-1").Result(),
			groupResource: kuberesource.PersistentVolumes,
			resourcePolicies: &resourcepolicies.ResourcePolicies{
				Version: "v1",
				VolumePolicies: []resourcepolicies.VolumePolicy{
					{
						Conditions: map[string]any{
							"storageClass": []string{"gp2-csi"},
						},
						Action: resourcepolicies.Action{
							Type: resourcepolicies.FSBackup,
						},
					},
				},
			},
			snapshotVolumesFlag: ptr.To(true),
			shouldSnapshot:      false,
			expectedErr:         false,
		},
		{
			name:          "VolumePolicy not match, not selected by fs-backup as opt-out way, snapshotVolumes is true, returns true and no error",
			inputObj:      builder.ForPersistentVolume("example-pv").StorageClass("gp3-csi").ClaimRef("ns", "pvc-1").Result(),
			groupResource: kuberesource.PersistentVolumes,
			pod:           builder.ForPod("ns", "pod-1").Result(),
			resourcePolicies: &resourcepolicies.ResourcePolicies{
				Version: "v1",
				VolumePolicies: []resourcepolicies.VolumePolicy{
					{
						Conditions: map[string]any{
							"storageClass": []string{"gp2-csi"},
						},
						Action: resourcepolicies.Action{
							Type: resourcepolicies.Snapshot,
						},
					},
				},
			},
			snapshotVolumesFlag: ptr.To(true),
			shouldSnapshot:      true,
			expectedErr:         false,
		},
		{
			name:          "VolumePolicy not match, selected by fs-backup as opt-out way, snapshotVolumes is true, returns false and no error",
			inputObj:      builder.ForPersistentVolume("example-pv").StorageClass("gp3-csi").ClaimRef("ns", "pvc-1").Result(),
			groupResource: kuberesource.PersistentVolumes,
			pod: builder.ForPod("ns", "pod-1").Volumes(
				&corev1api.Volume{
					Name: "volume",
					VolumeSource: corev1api.VolumeSource{
						PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
							ClaimName: "pvc-1",
						},
					},
				},
			).Result(),
			resourcePolicies: &resourcepolicies.ResourcePolicies{
				Version: "v1",
				VolumePolicies: []resourcepolicies.VolumePolicy{
					{
						Conditions: map[string]any{
							"storageClass": []string{"gp2-csi"},
						},
						Action: resourcepolicies.Action{
							Type: resourcepolicies.Snapshot,
						},
					},
				},
			},
			snapshotVolumesFlag:      ptr.To(true),
			defaultVolumesToFSBackup: true,
			shouldSnapshot:           false,
			expectedErr:              false,
		},
		{
			name:          "VolumePolicy not match, selected by fs-backup as opt-out way, snapshotVolumes is true, returns false and no error",
			inputObj:      builder.ForPersistentVolume("example-pv").StorageClass("gp3-csi").ClaimRef("ns", "pvc-1").Result(),
			groupResource: kuberesource.PersistentVolumes,
			pod: builder.ForPod("ns", "pod-1").
				ObjectMeta(builder.WithAnnotations(velerov1api.VolumesToExcludeAnnotation, "volume")).
				Volumes(
					&corev1api.Volume{
						Name: "volume",
						VolumeSource: corev1api.VolumeSource{
							PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
								ClaimName: "pvc-1",
							},
						},
					},
				).Result(),
			resourcePolicies: &resourcepolicies.ResourcePolicies{
				Version: "v1",
				VolumePolicies: []resourcepolicies.VolumePolicy{
					{
						Conditions: map[string]any{
							"storageClass": []string{"gp2-csi"},
						},
						Action: resourcepolicies.Action{
							Type: resourcepolicies.Snapshot,
						},
					},
				},
			},
			snapshotVolumesFlag:      ptr.To(true),
			defaultVolumesToFSBackup: true,
			shouldSnapshot:           true,
			expectedErr:              false,
		},
		{
			name:          "VolumePolicy not match, not selected by fs-backup as opt-in way, snapshotVolumes is true, returns false and no error",
			inputObj:      builder.ForPersistentVolume("example-pv").StorageClass("gp3-csi").ClaimRef("ns", "pvc-1").Result(),
			groupResource: kuberesource.PersistentVolumes,
			pod: builder.ForPod("ns", "pod-1").
				ObjectMeta(builder.WithAnnotations(velerov1api.VolumesToBackupAnnotation, "volume")).
				Volumes(
					&corev1api.Volume{
						Name: "volume",
						VolumeSource: corev1api.VolumeSource{
							PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
								ClaimName: "pvc-1",
							},
						},
					},
				).Result(),
			resourcePolicies: &resourcepolicies.ResourcePolicies{
				Version: "v1",
				VolumePolicies: []resourcepolicies.VolumePolicy{
					{
						Conditions: map[string]any{
							"storageClass": []string{"gp2-csi"},
						},
						Action: resourcepolicies.Action{
							Type: resourcepolicies.Snapshot,
						},
					},
				},
			},
			snapshotVolumesFlag:      ptr.To(true),
			defaultVolumesToFSBackup: false,
			shouldSnapshot:           false,
			expectedErr:              false,
		},
		{
			name:          "VolumePolicy not match, not selected by fs-backup as opt-in way, snapshotVolumes is true, returns true and no error",
			inputObj:      builder.ForPersistentVolume("example-pv").StorageClass("gp3-csi").ClaimRef("ns", "pvc-1").Result(),
			groupResource: kuberesource.PersistentVolumes,
			pod: builder.ForPod("ns", "pod-1").
				Volumes(
					&corev1api.Volume{
						Name: "volume",
						VolumeSource: corev1api.VolumeSource{
							PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
								ClaimName: "pvc-1",
							},
						},
					},
				).Result(),
			resourcePolicies: &resourcepolicies.ResourcePolicies{
				Version: "v1",
				VolumePolicies: []resourcepolicies.VolumePolicy{
					{
						Conditions: map[string]any{
							"storageClass": []string{"gp2-csi"},
						},
						Action: resourcepolicies.Action{
							Type: resourcepolicies.Snapshot,
						},
					},
				},
			},
			snapshotVolumesFlag:      ptr.To(true),
			defaultVolumesToFSBackup: false,
			shouldSnapshot:           true,
			expectedErr:              false,
		},
		{
			name:                "No VolumePolicy, not selected by fs-backup, snapshotVolumes is true, returns true and no error",
			inputObj:            builder.ForPersistentVolume("example-pv").StorageClass("gp3-csi").ClaimRef("ns", "pvc-1").Result(),
			groupResource:       kuberesource.PersistentVolumes,
			resourcePolicies:    nil,
			snapshotVolumesFlag: ptr.To(true),
			shouldSnapshot:      true,
			expectedErr:         false,
		},
		{
			name:                "No VolumePolicy, not selected by fs-backup, snapshotVolumes is false, returns false and no error",
			inputObj:            builder.ForPersistentVolume("example-pv").StorageClass("gp3-csi").ClaimRef("ns", "pvc-1").Result(),
			groupResource:       kuberesource.PersistentVolumes,
			resourcePolicies:    nil,
			snapshotVolumesFlag: ptr.To(false),
			shouldSnapshot:      false,
			expectedErr:         false,
		},
		{
			name:          "PVC not having PV, return false and error when no matching policy",
			inputObj:      builder.ForPersistentVolumeClaim("default", "example-pvc").StorageClass("gp2-csi").Result(),
			groupResource: kuberesource.PersistentVolumeClaims,
			resourcePolicies: &resourcepolicies.ResourcePolicies{
				Version: "v1",
			},
			snapshotVolumesFlag: ptr.To(true),
			shouldSnapshot:      false,
			expectedErr:         true,
		},
	}

	objs := []runtime.Object{
		&corev1api.PersistentVolumeClaim{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "ns",
				Name:      "pvc-1",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fakeClient := velerotest.NewFakeControllerRuntimeClient(t, objs...)
			if tc.pod != nil {
				fakeClient.Create(t.Context(), tc.pod)
			}

			var p *resourcepolicies.Policies
			if tc.resourcePolicies != nil {
				p = &resourcepolicies.Policies{}
				err := p.BuildPolicy(tc.resourcePolicies)
				if err != nil {
					t.Fatalf("failed to build policy with error %v", err)
				}
			}
			vh := NewVolumeHelperImpl(
				p,
				tc.snapshotVolumesFlag,
				logrus.StandardLogger(),
				fakeClient,
				tc.defaultVolumesToFSBackup,
				false,
			)

			obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(tc.inputObj)
			require.NoError(t, err)

			actualShouldSnapshot, actualError := vh.ShouldPerformSnapshot(&unstructured.Unstructured{Object: obj}, tc.groupResource)
			if tc.expectedErr {
				require.Error(t, actualError, "Want error; Got nil error")
				return
			}

			require.Equalf(t, tc.shouldSnapshot, actualShouldSnapshot, "Want shouldSnapshot as %t; Got shouldSnapshot as %t", tc.shouldSnapshot, actualShouldSnapshot)
		})
	}
}

func TestVolumeHelperImpl_ShouldIncludeVolumeInBackup(t *testing.T) {
	testCases := []struct {
		name             string
		vol              corev1api.Volume
		backupExcludePVC bool
		shouldInclude    bool
	}{
		{
			name: "volume has host path so do not include",
			vol: corev1api.Volume{
				Name: "sample-volume",
				VolumeSource: corev1api.VolumeSource{
					HostPath: &corev1api.HostPathVolumeSource{
						Path: "some-path",
					},
				},
			},
			backupExcludePVC: false,
			shouldInclude:    false,
		},
		{
			name: "volume has secret mounted so do not include",
			vol: corev1api.Volume{
				Name: "sample-volume",
				VolumeSource: corev1api.VolumeSource{
					Secret: &corev1api.SecretVolumeSource{
						SecretName: "sample-secret",
						Items: []corev1api.KeyToPath{
							{
								Key:  "username",
								Path: "my-username",
							},
						},
					},
				},
			},
			backupExcludePVC: false,
			shouldInclude:    false,
		},
		{
			name: "volume has configmap so do not include",
			vol: corev1api.Volume{
				Name: "sample-volume",
				VolumeSource: corev1api.VolumeSource{
					ConfigMap: &corev1api.ConfigMapVolumeSource{
						LocalObjectReference: corev1api.LocalObjectReference{
							Name: "sample-cm",
						},
					},
				},
			},
			backupExcludePVC: false,
			shouldInclude:    false,
		},
		{
			name: "volume is mounted as project volume so do not include",
			vol: corev1api.Volume{
				Name: "sample-volume",
				VolumeSource: corev1api.VolumeSource{
					Projected: &corev1api.ProjectedVolumeSource{
						Sources: []corev1api.VolumeProjection{},
					},
				},
			},
			backupExcludePVC: false,
			shouldInclude:    false,
		},
		{
			name: "volume has downwardAPI so do not include",
			vol: corev1api.Volume{
				Name: "sample-volume",
				VolumeSource: corev1api.VolumeSource{
					DownwardAPI: &corev1api.DownwardAPIVolumeSource{
						Items: []corev1api.DownwardAPIVolumeFile{
							{
								Path: "labels",
								FieldRef: &corev1api.ObjectFieldSelector{
									FieldPath: "metadata.labels",
								},
							},
						},
					},
				},
			},
			backupExcludePVC: false,
			shouldInclude:    false,
		},
		{
			name: "volume has pvc and backupExcludePVC is true so do not include",
			vol: corev1api.Volume{
				Name: "sample-volume",
				VolumeSource: corev1api.VolumeSource{
					PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
						ClaimName: "sample-pvc",
					},
				},
			},
			backupExcludePVC: true,
			shouldInclude:    false,
		},
		{
			name: "volume name has prefix default-token so do not include",
			vol: corev1api.Volume{
				Name: "default-token-vol-name",
				VolumeSource: corev1api.VolumeSource{
					PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
						ClaimName: "sample-pvc",
					},
				},
			},
			backupExcludePVC: false,
			shouldInclude:    false,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resourcePolicies := resourcepolicies.ResourcePolicies{
				Version: "v1",
				VolumePolicies: []resourcepolicies.VolumePolicy{
					{
						Conditions: map[string]any{
							"storageClass": []string{"gp2-csi"},
						},
						Action: resourcepolicies.Action{
							Type: resourcepolicies.Snapshot,
						},
					},
				},
			}
			policies := resourcePolicies
			p := &resourcepolicies.Policies{}
			err := p.BuildPolicy(&policies)
			if err != nil {
				t.Fatalf("failed to build policy with error %v", err)
			}
			vh := &volumeHelperImpl{
				volumePolicy:     p,
				snapshotVolumes:  ptr.To(true),
				logger:           velerotest.NewLogger(),
				backupExcludePVC: tc.backupExcludePVC,
			}
			actualShouldInclude := vh.shouldIncludeVolumeInBackup(tc.vol)
			assert.Equalf(t, actualShouldInclude, tc.shouldInclude, "Want shouldInclude as %v; Got actualShouldInclude as %v", tc.shouldInclude, actualShouldInclude)
		})
	}
}

func TestVolumeHelperImpl_ShouldPerformFSBackup(t *testing.T) {
	testCases := []struct {
		name                     string
		pod                      *corev1api.Pod
		resources                []runtime.Object
		resourcePolicies         *resourcepolicies.ResourcePolicies
		snapshotVolumesFlag      *bool
		defaultVolumesToFSBackup bool
		shouldFSBackup           bool
		expectedErr              bool
	}{
		{
			name: "HostPath volume should be skipped.",
			pod: builder.ForPod("ns", "pod-1").
				Volumes(
					&corev1api.Volume{
						Name: "",
						VolumeSource: corev1api.VolumeSource{
							HostPath: &corev1api.HostPathVolumeSource{
								Path: "/mnt/test",
							},
						},
					}).Result(),
			shouldFSBackup: false,
			expectedErr:    false,
		},
		{
			name: "VolumePolicy match, return true and no error",
			pod: builder.ForPod("ns", "pod-1").
				Volumes(
					&corev1api.Volume{
						Name: "",
						VolumeSource: corev1api.VolumeSource{
							PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
								ClaimName: "pvc-1",
							},
						},
					}).Result(),
			resources: []runtime.Object{
				builder.ForPersistentVolumeClaim("ns", "pvc-1").
					VolumeName("pv-1").
					StorageClass("gp2-csi").Phase(corev1api.ClaimBound).Result(),
				builder.ForPersistentVolume("pv-1").StorageClass("gp2-csi").Result(),
			},
			resourcePolicies: &resourcepolicies.ResourcePolicies{
				Version: "v1",
				VolumePolicies: []resourcepolicies.VolumePolicy{
					{
						Conditions: map[string]any{
							"storageClass": []string{"gp2-csi"},
						},
						Action: resourcepolicies.Action{
							Type: resourcepolicies.FSBackup,
						},
					},
				},
			},
			shouldFSBackup: true,
			expectedErr:    false,
		},
		{
			name: "Volume source is emptyDir, VolumePolicy match, return true and no error",
			pod: builder.ForPod("ns", "pod-1").
				Volumes(
					&corev1api.Volume{
						Name: "",
						VolumeSource: corev1api.VolumeSource{
							EmptyDir: &corev1api.EmptyDirVolumeSource{},
						},
					}).Result(),
			resourcePolicies: &resourcepolicies.ResourcePolicies{
				Version: "v1",
				VolumePolicies: []resourcepolicies.VolumePolicy{
					{
						Conditions: map[string]any{
							"volumeTypes": []string{"emptyDir"},
						},
						Action: resourcepolicies.Action{
							Type: resourcepolicies.FSBackup,
						},
					},
				},
			},
			shouldFSBackup: true,
			expectedErr:    false,
		},
		{
			name: "VolumePolicy match, action type is not fs-backup, return false and no error",
			pod: builder.ForPod("ns", "pod-1").
				Volumes(
					&corev1api.Volume{
						Name: "",
						VolumeSource: corev1api.VolumeSource{
							PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
								ClaimName: "pvc-1",
							},
						},
					}).Result(),
			resources: []runtime.Object{
				builder.ForPersistentVolumeClaim("ns", "pvc-1").
					VolumeName("pv-1").
					StorageClass("gp2-csi").Phase(corev1api.ClaimBound).Result(),
				builder.ForPersistentVolume("pv-1").StorageClass("gp2-csi").Result(),
			},
			resourcePolicies: &resourcepolicies.ResourcePolicies{
				Version: "v1",
				VolumePolicies: []resourcepolicies.VolumePolicy{
					{
						Conditions: map[string]any{
							"storageClass": []string{"gp2-csi"},
						},
						Action: resourcepolicies.Action{
							Type: resourcepolicies.Snapshot,
						},
					},
				},
			},
			shouldFSBackup: false,
			expectedErr:    false,
		},
		{
			name: "VolumePolicy not match, selected by opt-in way, return true and no error",
			pod: builder.ForPod("ns", "pod-1").
				ObjectMeta(builder.WithAnnotations(velerov1api.VolumesToBackupAnnotation, "pvc-1")).
				Volumes(
					&corev1api.Volume{
						Name: "pvc-1",
						VolumeSource: corev1api.VolumeSource{
							PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
								ClaimName: "pvc-1",
							},
						},
					}).Result(),
			resources: []runtime.Object{
				builder.ForPersistentVolumeClaim("ns", "pvc-1").
					VolumeName("pv-1").
					StorageClass("gp2-csi").Phase(corev1api.ClaimBound).Result(),
				builder.ForPersistentVolume("pv-1").StorageClass("gp2-csi").Result(),
			},
			resourcePolicies: &resourcepolicies.ResourcePolicies{
				Version: "v1",
				VolumePolicies: []resourcepolicies.VolumePolicy{
					{
						Conditions: map[string]any{
							"storageClass": []string{"gp3-csi"},
						},
						Action: resourcepolicies.Action{
							Type: resourcepolicies.FSBackup,
						},
					},
				},
			},
			shouldFSBackup: true,
			expectedErr:    false,
		},
		{
			name: "No VolumePolicy, not selected by opt-out way, return false and no error",
			pod: builder.ForPod("ns", "pod-1").
				ObjectMeta(builder.WithAnnotations(velerov1api.VolumesToExcludeAnnotation, "pvc-1")).
				Volumes(
					&corev1api.Volume{
						Name: "pvc-1",
						VolumeSource: corev1api.VolumeSource{
							PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
								ClaimName: "pvc-1",
							},
						},
					}).Result(),
			resources: []runtime.Object{
				builder.ForPersistentVolumeClaim("ns", "pvc-1").
					VolumeName("pv-1").
					StorageClass("gp2-csi").Phase(corev1api.ClaimBound).Result(),
				builder.ForPersistentVolume("pv-1").StorageClass("gp2-csi").Result(),
			},
			defaultVolumesToFSBackup: true,
			shouldFSBackup:           false,
			expectedErr:              false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fakeClient := velerotest.NewFakeControllerRuntimeClient(t, tc.resources...)
			if tc.pod != nil {
				fakeClient.Create(t.Context(), tc.pod)
			}

			var p *resourcepolicies.Policies
			if tc.resourcePolicies != nil {
				p = &resourcepolicies.Policies{}
				err := p.BuildPolicy(tc.resourcePolicies)
				if err != nil {
					t.Fatalf("failed to build policy with error %v", err)
				}
			}
			vh := NewVolumeHelperImpl(
				p,
				tc.snapshotVolumesFlag,
				logrus.StandardLogger(),
				fakeClient,
				tc.defaultVolumesToFSBackup,
				false,
			)

			actualShouldFSBackup, actualError := vh.ShouldPerformFSBackup(tc.pod.Spec.Volumes[0], *tc.pod)
			if tc.expectedErr {
				require.Error(t, actualError, "Want error; Got nil error")
				return
			}

			require.Equalf(t, tc.shouldFSBackup, actualShouldFSBackup, "Want shouldFSBackup as %t; Got shouldFSBackup as %t", tc.shouldFSBackup, actualShouldFSBackup)
		})
	}
}

func TestGetVolumeFromResource(t *testing.T) {
	helper := &volumeHelperImpl{}

	t.Run("PersistentVolume input", func(t *testing.T) {
		pv := &corev1api.PersistentVolume{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-pv",
			},
		}
		outPV, outPod, err := helper.getVolumeFromResource(pv)
		require.NoError(t, err)
		assert.NotNil(t, outPV)
		assert.Nil(t, outPod)
		assert.Equal(t, "test-pv", outPV.Name)
	})

	t.Run("Volume input", func(t *testing.T) {
		vol := &corev1api.Volume{
			Name: "test-volume",
		}
		outPV, outPod, err := helper.getVolumeFromResource(vol)
		require.NoError(t, err)
		assert.Nil(t, outPV)
		assert.NotNil(t, outPod)
		assert.Equal(t, "test-volume", outPod.Name)
	})

	t.Run("Invalid input", func(t *testing.T) {
		_, _, err := helper.getVolumeFromResource("invalid")
		assert.ErrorContains(t, err, "resource is not a PersistentVolume or Volume")
	})
}

func TestVolumeHelperImplWithCache_ShouldPerformSnapshot(t *testing.T) {
	testCases := []struct {
		name                     string
		inputObj                 runtime.Object
		groupResource            schema.GroupResource
		pod                      *corev1api.Pod
		resourcePolicies         *resourcepolicies.ResourcePolicies
		snapshotVolumesFlag      *bool
		defaultVolumesToFSBackup bool
		buildCache               bool
		shouldSnapshot           bool
		expectedErr              bool
	}{
		{
			name:          "VolumePolicy match with cache, returns true",
			inputObj:      builder.ForPersistentVolume("example-pv").StorageClass("gp2-csi").ClaimRef("ns", "pvc-1").Result(),
			groupResource: kuberesource.PersistentVolumes,
			resourcePolicies: &resourcepolicies.ResourcePolicies{
				Version: "v1",
				VolumePolicies: []resourcepolicies.VolumePolicy{
					{
						Conditions: map[string]any{
							"storageClass": []string{"gp2-csi"},
						},
						Action: resourcepolicies.Action{
							Type: resourcepolicies.Snapshot,
						},
					},
				},
			},
			snapshotVolumesFlag: ptr.To(true),
			buildCache:          true,
			shouldSnapshot:      true,
			expectedErr:         false,
		},
		{
			name:          "VolumePolicy not match, fs-backup via opt-out with cache, skips snapshot",
			inputObj:      builder.ForPersistentVolume("example-pv").StorageClass("gp3-csi").ClaimRef("ns", "pvc-1").Result(),
			groupResource: kuberesource.PersistentVolumes,
			pod: builder.ForPod("ns", "pod-1").Volumes(
				&corev1api.Volume{
					Name: "volume",
					VolumeSource: corev1api.VolumeSource{
						PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
							ClaimName: "pvc-1",
						},
					},
				},
			).Result(),
			resourcePolicies: &resourcepolicies.ResourcePolicies{
				Version: "v1",
				VolumePolicies: []resourcepolicies.VolumePolicy{
					{
						Conditions: map[string]any{
							"storageClass": []string{"gp2-csi"},
						},
						Action: resourcepolicies.Action{
							Type: resourcepolicies.Snapshot,
						},
					},
				},
			},
			snapshotVolumesFlag:      ptr.To(true),
			defaultVolumesToFSBackup: true,
			buildCache:               true,
			shouldSnapshot:           false,
			expectedErr:              false,
		},
		{
			name:          "Cache not built, falls back to direct lookup",
			inputObj:      builder.ForPersistentVolume("example-pv").StorageClass("gp2-csi").ClaimRef("ns", "pvc-1").Result(),
			groupResource: kuberesource.PersistentVolumes,
			resourcePolicies: &resourcepolicies.ResourcePolicies{
				Version: "v1",
				VolumePolicies: []resourcepolicies.VolumePolicy{
					{
						Conditions: map[string]any{
							"storageClass": []string{"gp2-csi"},
						},
						Action: resourcepolicies.Action{
							Type: resourcepolicies.Snapshot,
						},
					},
				},
			},
			snapshotVolumesFlag: ptr.To(true),
			buildCache:          false,
			shouldSnapshot:      true,
			expectedErr:         false,
		},
		{
			name:          "No volume policy, defaultVolumesToFSBackup with cache, skips snapshot",
			inputObj:      builder.ForPersistentVolume("example-pv").StorageClass("gp2-csi").ClaimRef("ns", "pvc-1").Result(),
			groupResource: kuberesource.PersistentVolumes,
			pod: builder.ForPod("ns", "pod-1").Volumes(
				&corev1api.Volume{
					Name: "volume",
					VolumeSource: corev1api.VolumeSource{
						PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
							ClaimName: "pvc-1",
						},
					},
				},
			).Result(),
			resourcePolicies:         nil,
			snapshotVolumesFlag:      ptr.To(true),
			defaultVolumesToFSBackup: true,
			buildCache:               true,
			shouldSnapshot:           false,
			expectedErr:              false,
		},
	}

	objs := []runtime.Object{
		&corev1api.PersistentVolumeClaim{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "ns",
				Name:      "pvc-1",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fakeClient := velerotest.NewFakeControllerRuntimeClient(t, objs...)
			if tc.pod != nil {
				require.NoError(t, fakeClient.Create(t.Context(), tc.pod))
			}

			var p *resourcepolicies.Policies
			if tc.resourcePolicies != nil {
				p = &resourcepolicies.Policies{}
				err := p.BuildPolicy(tc.resourcePolicies)
				require.NoError(t, err)
			}

			var namespaces []string
			if tc.buildCache {
				namespaces = []string{"ns"}
			}

			vh, err := NewVolumeHelperImplWithNamespaces(
				p,
				tc.snapshotVolumesFlag,
				logrus.StandardLogger(),
				fakeClient,
				tc.defaultVolumesToFSBackup,
				false,
				namespaces,
			)
			require.NoError(t, err)

			obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(tc.inputObj)
			require.NoError(t, err)

			actualShouldSnapshot, actualError := vh.ShouldPerformSnapshot(&unstructured.Unstructured{Object: obj}, tc.groupResource)
			if tc.expectedErr {
				require.Error(t, actualError)
				return
			}
			require.NoError(t, actualError)
			require.Equalf(t, tc.shouldSnapshot, actualShouldSnapshot, "Want shouldSnapshot as %t; Got shouldSnapshot as %t", tc.shouldSnapshot, actualShouldSnapshot)
		})
	}
}

func TestVolumeHelperImplWithCache_ShouldPerformFSBackup(t *testing.T) {
	testCases := []struct {
		name                     string
		pod                      *corev1api.Pod
		resources                []runtime.Object
		resourcePolicies         *resourcepolicies.ResourcePolicies
		snapshotVolumesFlag      *bool
		defaultVolumesToFSBackup bool
		buildCache               bool
		shouldFSBackup           bool
		expectedErr              bool
	}{
		{
			name: "VolumePolicy match with cache, return true",
			pod: builder.ForPod("ns", "pod-1").
				Volumes(
					&corev1api.Volume{
						Name: "vol-1",
						VolumeSource: corev1api.VolumeSource{
							PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
								ClaimName: "pvc-1",
							},
						},
					}).Result(),
			resources: []runtime.Object{
				builder.ForPersistentVolumeClaim("ns", "pvc-1").
					VolumeName("pv-1").
					StorageClass("gp2-csi").Phase(corev1api.ClaimBound).Result(),
				builder.ForPersistentVolume("pv-1").StorageClass("gp2-csi").Result(),
			},
			resourcePolicies: &resourcepolicies.ResourcePolicies{
				Version: "v1",
				VolumePolicies: []resourcepolicies.VolumePolicy{
					{
						Conditions: map[string]any{
							"storageClass": []string{"gp2-csi"},
						},
						Action: resourcepolicies.Action{
							Type: resourcepolicies.FSBackup,
						},
					},
				},
			},
			buildCache:     true,
			shouldFSBackup: true,
			expectedErr:    false,
		},
		{
			name: "VolumePolicy match with cache, action is snapshot, return false",
			pod: builder.ForPod("ns", "pod-1").
				Volumes(
					&corev1api.Volume{
						Name: "vol-1",
						VolumeSource: corev1api.VolumeSource{
							PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
								ClaimName: "pvc-1",
							},
						},
					}).Result(),
			resources: []runtime.Object{
				builder.ForPersistentVolumeClaim("ns", "pvc-1").
					VolumeName("pv-1").
					StorageClass("gp2-csi").Phase(corev1api.ClaimBound).Result(),
				builder.ForPersistentVolume("pv-1").StorageClass("gp2-csi").Result(),
			},
			resourcePolicies: &resourcepolicies.ResourcePolicies{
				Version: "v1",
				VolumePolicies: []resourcepolicies.VolumePolicy{
					{
						Conditions: map[string]any{
							"storageClass": []string{"gp2-csi"},
						},
						Action: resourcepolicies.Action{
							Type: resourcepolicies.Snapshot,
						},
					},
				},
			},
			buildCache:     true,
			shouldFSBackup: false,
			expectedErr:    false,
		},
		{
			name: "Cache not built, falls back to direct lookup, opt-in annotation",
			pod: builder.ForPod("ns", "pod-1").
				ObjectMeta(builder.WithAnnotations(velerov1api.VolumesToBackupAnnotation, "vol-1")).
				Volumes(
					&corev1api.Volume{
						Name: "vol-1",
						VolumeSource: corev1api.VolumeSource{
							PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
								ClaimName: "pvc-1",
							},
						},
					}).Result(),
			resources: []runtime.Object{
				builder.ForPersistentVolumeClaim("ns", "pvc-1").
					VolumeName("pv-1").
					StorageClass("gp2-csi").Phase(corev1api.ClaimBound).Result(),
				builder.ForPersistentVolume("pv-1").StorageClass("gp2-csi").Result(),
			},
			buildCache:               false,
			defaultVolumesToFSBackup: false,
			shouldFSBackup:           true,
			expectedErr:              false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fakeClient := velerotest.NewFakeControllerRuntimeClient(t, tc.resources...)
			if tc.pod != nil {
				require.NoError(t, fakeClient.Create(t.Context(), tc.pod))
			}

			var p *resourcepolicies.Policies
			if tc.resourcePolicies != nil {
				p = &resourcepolicies.Policies{}
				err := p.BuildPolicy(tc.resourcePolicies)
				require.NoError(t, err)
			}

			var namespaces []string
			if tc.buildCache {
				namespaces = []string{"ns"}
			}

			vh, err := NewVolumeHelperImplWithNamespaces(
				p,
				tc.snapshotVolumesFlag,
				logrus.StandardLogger(),
				fakeClient,
				tc.defaultVolumesToFSBackup,
				false,
				namespaces,
			)
			require.NoError(t, err)

			actualShouldFSBackup, actualError := vh.ShouldPerformFSBackup(tc.pod.Spec.Volumes[0], *tc.pod)
			if tc.expectedErr {
				require.Error(t, actualError)
				return
			}
			require.NoError(t, actualError)
			require.Equalf(t, tc.shouldFSBackup, actualShouldFSBackup, "Want shouldFSBackup as %t; Got shouldFSBackup as %t", tc.shouldFSBackup, actualShouldFSBackup)
		})
	}
}

// TestNewVolumeHelperImplWithCache tests the NewVolumeHelperImplWithCache constructor
// which is used by plugins that build the cache lazily per-namespace.
func TestNewVolumeHelperImplWithCache(t *testing.T) {
	testCases := []struct {
		name                    string
		backup                  velerov1api.Backup
		resourcePolicyConfigMap *corev1api.ConfigMap
		pvcPodCache             bool // whether to pass a cache
		expectError             bool
	}{
		{
			name: "creates VolumeHelper with nil cache",
			backup: velerov1api.Backup{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-backup",
					Namespace: "velero",
				},
				Spec: velerov1api.BackupSpec{
					SnapshotVolumes:          ptr.To(true),
					DefaultVolumesToFsBackup: ptr.To(false),
				},
			},
			pvcPodCache: false,
			expectError: false,
		},
		{
			name: "creates VolumeHelper with non-nil cache",
			backup: velerov1api.Backup{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-backup",
					Namespace: "velero",
				},
				Spec: velerov1api.BackupSpec{
					SnapshotVolumes:          ptr.To(true),
					DefaultVolumesToFsBackup: ptr.To(true),
					SnapshotMoveData:         ptr.To(true),
				},
			},
			pvcPodCache: true,
			expectError: false,
		},
		{
			name: "creates VolumeHelper with resource policies",
			backup: velerov1api.Backup{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-backup",
					Namespace: "velero",
				},
				Spec: velerov1api.BackupSpec{
					SnapshotVolumes: ptr.To(true),
					ResourcePolicy: &corev1api.TypedLocalObjectReference{
						Kind: "ConfigMap",
						Name: "resource-policy",
					},
				},
			},
			resourcePolicyConfigMap: &corev1api.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "resource-policy",
					Namespace: "velero",
				},
				Data: map[string]string{
					"policy": `version: v1
volumePolicies:
- conditions:
    storageClass:
    - gp2-csi
  action:
    type: snapshot`,
				},
			},
			pvcPodCache: true,
			expectError: false,
		},
		{
			name: "fails when resource policy ConfigMap not found",
			backup: velerov1api.Backup{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-backup",
					Namespace: "velero",
				},
				Spec: velerov1api.BackupSpec{
					ResourcePolicy: &corev1api.TypedLocalObjectReference{
						Kind: "ConfigMap",
						Name: "non-existent-policy",
					},
				},
			},
			pvcPodCache: false,
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var objs []runtime.Object
			if tc.resourcePolicyConfigMap != nil {
				objs = append(objs, tc.resourcePolicyConfigMap)
			}
			fakeClient := velerotest.NewFakeControllerRuntimeClient(t, objs...)

			var cache *podvolumeutil.PVCPodCache
			if tc.pvcPodCache {
				cache = podvolumeutil.NewPVCPodCache()
			}

			vh, err := NewVolumeHelperImplWithCache(
				tc.backup,
				fakeClient,
				logrus.StandardLogger(),
				cache,
			)

			if tc.expectError {
				require.Error(t, err)
				require.Nil(t, vh)
			} else {
				require.NoError(t, err)
				require.NotNil(t, vh)
			}
		})
	}
}

// TestNewVolumeHelperImplWithCache_UsesCache verifies that the VolumeHelper created
// via NewVolumeHelperImplWithCache actually uses the provided cache for lookups.
func TestNewVolumeHelperImplWithCache_UsesCache(t *testing.T) {
	// Create a pod that uses a PVC via opt-out (defaultVolumesToFsBackup=true)
	pod := builder.ForPod("ns", "pod-1").Volumes(
		&corev1api.Volume{
			Name: "volume",
			VolumeSource: corev1api.VolumeSource{
				PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
					ClaimName: "pvc-1",
				},
			},
		},
	).Result()

	pvc := &corev1api.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "ns",
			Name:      "pvc-1",
		},
	}

	pv := builder.ForPersistentVolume("example-pv").StorageClass("gp2-csi").ClaimRef("ns", "pvc-1").Result()

	fakeClient := velerotest.NewFakeControllerRuntimeClient(t, pvc, pv, pod)

	// Build cache for the namespace
	cache := podvolumeutil.NewPVCPodCache()
	err := cache.BuildCacheForNamespace(t.Context(), "ns", fakeClient)
	require.NoError(t, err)

	backup := velerov1api.Backup{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backup",
			Namespace: "velero",
		},
		Spec: velerov1api.BackupSpec{
			SnapshotVolumes:          ptr.To(true),
			DefaultVolumesToFsBackup: ptr.To(true), // opt-out mode
		},
	}

	vh, err := NewVolumeHelperImplWithCache(backup, fakeClient, logrus.StandardLogger(), cache)
	require.NoError(t, err)

	// Convert PV to unstructured
	obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(pv)
	require.NoError(t, err)

	// ShouldPerformSnapshot should return false because the volume is selected for fs-backup
	// This relies on the cache to find the pod using the PVC
	shouldSnapshot, err := vh.ShouldPerformSnapshot(&unstructured.Unstructured{Object: obj}, kuberesource.PersistentVolumes)
	require.NoError(t, err)
	require.False(t, shouldSnapshot, "Expected snapshot to be skipped due to fs-backup selection via cache")
}

// TestVolumeHelperImpl_ShouldPerformSnapshot_UnboundPVC tests that Pending and Lost PVCs with
// phase-based skip policies don't cause errors when GetPVForPVC would fail.
func TestVolumeHelperImpl_ShouldPerformSnapshot_UnboundPVC(t *testing.T) {
	testCases := []struct {
		name             string
		inputPVC         *corev1api.PersistentVolumeClaim
		resourcePolicies *resourcepolicies.ResourcePolicies
		shouldSnapshot   bool
		expectedErr      bool
	}{
		{
			name: "Pending PVC with phase-based skip policy should not error and return false",
			inputPVC: builder.ForPersistentVolumeClaim("ns", "pvc-pending").
				StorageClass("non-existent-class").
				Phase(corev1api.ClaimPending).
				Result(),
			resourcePolicies: &resourcepolicies.ResourcePolicies{
				Version: "v1",
				VolumePolicies: []resourcepolicies.VolumePolicy{
					{
						Conditions: map[string]any{
							"pvcPhase": []string{"Pending"},
						},
						Action: resourcepolicies.Action{
							Type: resourcepolicies.Skip,
						},
					},
				},
			},
			shouldSnapshot: false,
			expectedErr:    false,
		},
		{
			name: "Pending PVC without matching skip policy should error (no PV)",
			inputPVC: builder.ForPersistentVolumeClaim("ns", "pvc-pending-no-policy").
				StorageClass("non-existent-class").
				Phase(corev1api.ClaimPending).
				Result(),
			resourcePolicies: &resourcepolicies.ResourcePolicies{
				Version: "v1",
				VolumePolicies: []resourcepolicies.VolumePolicy{
					{
						Conditions: map[string]any{
							"storageClass": []string{"gp2-csi"},
						},
						Action: resourcepolicies.Action{
							Type: resourcepolicies.Skip,
						},
					},
				},
			},
			shouldSnapshot: false,
			expectedErr:    true,
		},
		{
			name: "Lost PVC with phase-based skip policy should not error and return false",
			inputPVC: builder.ForPersistentVolumeClaim("ns", "pvc-lost").
				StorageClass("some-class").
				Phase(corev1api.ClaimLost).
				Result(),
			resourcePolicies: &resourcepolicies.ResourcePolicies{
				Version: "v1",
				VolumePolicies: []resourcepolicies.VolumePolicy{
					{
						Conditions: map[string]any{
							"pvcPhase": []string{"Lost"},
						},
						Action: resourcepolicies.Action{
							Type: resourcepolicies.Skip,
						},
					},
				},
			},
			shouldSnapshot: false,
			expectedErr:    false,
		},
		{
			name: "Lost PVC with policy for Pending and Lost should not error and return false",
			inputPVC: builder.ForPersistentVolumeClaim("ns", "pvc-lost").
				StorageClass("some-class").
				Phase(corev1api.ClaimLost).
				Result(),
			resourcePolicies: &resourcepolicies.ResourcePolicies{
				Version: "v1",
				VolumePolicies: []resourcepolicies.VolumePolicy{
					{
						Conditions: map[string]any{
							"pvcPhase": []string{"Pending", "Lost"},
						},
						Action: resourcepolicies.Action{
							Type: resourcepolicies.Skip,
						},
					},
				},
			},
			shouldSnapshot: false,
			expectedErr:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fakeClient := velerotest.NewFakeControllerRuntimeClient(t)

			var p *resourcepolicies.Policies
			if tc.resourcePolicies != nil {
				p = &resourcepolicies.Policies{}
				err := p.BuildPolicy(tc.resourcePolicies)
				require.NoError(t, err)
			}

			vh := NewVolumeHelperImpl(
				p,
				ptr.To(true),
				logrus.StandardLogger(),
				fakeClient,
				false,
				false,
			)

			obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(tc.inputPVC)
			require.NoError(t, err)

			actualShouldSnapshot, actualError := vh.ShouldPerformSnapshot(&unstructured.Unstructured{Object: obj}, kuberesource.PersistentVolumeClaims)
			if tc.expectedErr {
				require.Error(t, actualError, "Want error; Got nil error")
				return
			}

			require.NoError(t, actualError)
			require.Equalf(t, tc.shouldSnapshot, actualShouldSnapshot, "Want shouldSnapshot as %t; Got shouldSnapshot as %t", tc.shouldSnapshot, actualShouldSnapshot)
		})
	}
}

// TestVolumeHelperImpl_ShouldPerformFSBackup_UnboundPVC tests that Pending and Lost PVCs with
// phase-based skip policies don't cause errors when GetPVForPVC would fail.
func TestVolumeHelperImpl_ShouldPerformFSBackup_UnboundPVC(t *testing.T) {
	testCases := []struct {
		name             string
		pod              *corev1api.Pod
		pvc              *corev1api.PersistentVolumeClaim
		resourcePolicies *resourcepolicies.ResourcePolicies
		shouldFSBackup   bool
		expectedErr      bool
	}{
		{
			name: "Pending PVC with phase-based skip policy should not error and return false",
			pod: builder.ForPod("ns", "pod-1").
				Volumes(
					&corev1api.Volume{
						Name: "vol-pending",
						VolumeSource: corev1api.VolumeSource{
							PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
								ClaimName: "pvc-pending",
							},
						},
					}).Result(),
			pvc: builder.ForPersistentVolumeClaim("ns", "pvc-pending").
				StorageClass("non-existent-class").
				Phase(corev1api.ClaimPending).
				Result(),
			resourcePolicies: &resourcepolicies.ResourcePolicies{
				Version: "v1",
				VolumePolicies: []resourcepolicies.VolumePolicy{
					{
						Conditions: map[string]any{
							"pvcPhase": []string{"Pending"},
						},
						Action: resourcepolicies.Action{
							Type: resourcepolicies.Skip,
						},
					},
				},
			},
			shouldFSBackup: false,
			expectedErr:    false,
		},
		{
			name: "Pending PVC without matching skip policy should error (no PV)",
			pod: builder.ForPod("ns", "pod-1").
				Volumes(
					&corev1api.Volume{
						Name: "vol-pending",
						VolumeSource: corev1api.VolumeSource{
							PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
								ClaimName: "pvc-pending-no-policy",
							},
						},
					}).Result(),
			pvc: builder.ForPersistentVolumeClaim("ns", "pvc-pending-no-policy").
				StorageClass("non-existent-class").
				Phase(corev1api.ClaimPending).
				Result(),
			resourcePolicies: &resourcepolicies.ResourcePolicies{
				Version: "v1",
				VolumePolicies: []resourcepolicies.VolumePolicy{
					{
						Conditions: map[string]any{
							"storageClass": []string{"gp2-csi"},
						},
						Action: resourcepolicies.Action{
							Type: resourcepolicies.Skip,
						},
					},
				},
			},
			shouldFSBackup: false,
			expectedErr:    true,
		},
		{
			name: "Lost PVC with phase-based skip policy should not error and return false",
			pod: builder.ForPod("ns", "pod-1").
				Volumes(
					&corev1api.Volume{
						Name: "vol-lost",
						VolumeSource: corev1api.VolumeSource{
							PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
								ClaimName: "pvc-lost",
							},
						},
					}).Result(),
			pvc: builder.ForPersistentVolumeClaim("ns", "pvc-lost").
				StorageClass("some-class").
				Phase(corev1api.ClaimLost).
				Result(),
			resourcePolicies: &resourcepolicies.ResourcePolicies{
				Version: "v1",
				VolumePolicies: []resourcepolicies.VolumePolicy{
					{
						Conditions: map[string]any{
							"pvcPhase": []string{"Lost"},
						},
						Action: resourcepolicies.Action{
							Type: resourcepolicies.Skip,
						},
					},
				},
			},
			shouldFSBackup: false,
			expectedErr:    false,
		},
		{
			name: "Lost PVC with policy for Pending and Lost should not error and return false",
			pod: builder.ForPod("ns", "pod-1").
				Volumes(
					&corev1api.Volume{
						Name: "vol-lost",
						VolumeSource: corev1api.VolumeSource{
							PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
								ClaimName: "pvc-lost",
							},
						},
					}).Result(),
			pvc: builder.ForPersistentVolumeClaim("ns", "pvc-lost").
				StorageClass("some-class").
				Phase(corev1api.ClaimLost).
				Result(),
			resourcePolicies: &resourcepolicies.ResourcePolicies{
				Version: "v1",
				VolumePolicies: []resourcepolicies.VolumePolicy{
					{
						Conditions: map[string]any{
							"pvcPhase": []string{"Pending", "Lost"},
						},
						Action: resourcepolicies.Action{
							Type: resourcepolicies.Skip,
						},
					},
				},
			},
			shouldFSBackup: false,
			expectedErr:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fakeClient := velerotest.NewFakeControllerRuntimeClient(t, tc.pvc)
			require.NoError(t, fakeClient.Create(t.Context(), tc.pod))

			var p *resourcepolicies.Policies
			if tc.resourcePolicies != nil {
				p = &resourcepolicies.Policies{}
				err := p.BuildPolicy(tc.resourcePolicies)
				require.NoError(t, err)
			}

			vh := NewVolumeHelperImpl(
				p,
				ptr.To(true),
				logrus.StandardLogger(),
				fakeClient,
				false,
				false,
			)

			actualShouldFSBackup, actualError := vh.ShouldPerformFSBackup(tc.pod.Spec.Volumes[0], *tc.pod)
			if tc.expectedErr {
				require.Error(t, actualError, "Want error; Got nil error")
				return
			}

			require.NoError(t, actualError)
			require.Equalf(t, tc.shouldFSBackup, actualShouldFSBackup, "Want shouldFSBackup as %t; Got shouldFSBackup as %t", tc.shouldFSBackup, actualShouldFSBackup)
		})
	}
}
