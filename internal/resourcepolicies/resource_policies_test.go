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
	"context"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
)

func pvcVolumeMode(mode corev1api.PersistentVolumeMode) *corev1api.PersistentVolumeMode {
	return &mode
}

func TestLoadResourcePolicies(t *testing.T) {
	testCases := []struct {
		name     string
		yamlData string
		wantErr  bool
	}{
		{
			name: "unknown key in yaml",
			yamlData: `version: v1
	volumePolicies:
	- conditions:
		capacity: "0,100Gi"
		unknown: {}
		storageClass:
		- gp2
		- ebs-sc
	  action:
		type: skip`,
			wantErr: true,
		},
		{
			name: "reduplicated key in yaml",
			yamlData: `version: v1
	volumePolicies:
	- conditions:
		capacity: "0,100Gi"
		capacity: "0,100Gi"
		storageClass:
		- gp2
		- ebs-sc
	  action:
		type: skip`,
			wantErr: true,
		},
		{
			name: "error format of storageClass",
			yamlData: `version: v1
	volumePolicies:
	- conditions:
		capacity: "0,100Gi"
		storageClass: gp2
	  action:
		type: skip`,
			wantErr: true,
		},
		{
			name: "error format of csi",
			yamlData: `version: v1
	volumePolicies:
	- conditions:
		capacity: "0,100Gi"
		csi: gp2
	  action:
		type: skip`,
			wantErr: true,
		},
		{
			name: "error format of nfs",
			yamlData: `version: v1
	volumePolicies:
	- conditions:
		capacity: "0,100Gi"
		csi: {}
		nfs: abc
	  action:
		type: skip`,
			wantErr: true,
		},
		{
			name: "supported format volume policies",
			yamlData: `version: v1
volumePolicies:
  - conditions:
      capacity: '0,100Gi'
      csi:
        driver: aws.efs.csi.driver
    action:
      type: skip
`,
			wantErr: false,
		},
		{
			name: "supported format csi driver with volumeAttributes for volume policies",
			yamlData: `version: v1
volumePolicies:
  - conditions:
      capacity: '0,100Gi'
      csi:
        driver: aws.efs.csi.driver
        volumeAttributes:
          key1: value1
    action:
      type: skip
`,
			wantErr: false,
		},
		{
			name: "supported format pvcLabels",
			yamlData: `version: v1
volumePolicies:
  - conditions:
      pvcLabels:
        environment: production
        app: database
    action:
      type: skip
`,
			wantErr: false,
		},
		{
			name: "error format of pvcLabels (not a map)",
			yamlData: `version: v1
volumePolicies:
  - conditions:
      pvcLabels: "production"
    action:
      type: skip
`,
			wantErr: true,
		},
		{
			name: "supported format pvcLabels with extra keys",
			yamlData: `version: v1
volumePolicies:
  - conditions:
      pvcLabels:
        environment: production
        region: us-west
    action:
      type: skip
`,
			wantErr: false,
		},
		{
			name: "supported format pvcVolumeMode",
			yamlData: `version: v1
volumePolicies:
  - conditions:
      pvcVolumeMode: Block
    action:
      type: skip
`,
			wantErr: false,
		},
		{
			name: "error format of pvcVolumeMode (not a string)",
			yamlData: `version: v1
volumePolicies:
  - conditions:
      pvcVolumeMode:
        - Block
    action:
      type: skip
`,
			wantErr: true,
		},
		{
			name: "supported format pvcAccessModes",
			yamlData: `version: v1
volumePolicies:
  - conditions:
      pvcAccessModes:
        - ReadWriteOnce
    action:
      type: skip
`,
			wantErr: false,
		},
		{
			name: "error format of pvcAccessModes (not a list)",
			yamlData: `version: v1
volumePolicies:
  - conditions:
      pvcAccessModes: ReadWriteOnce
    action:
      type: skip
`,
			wantErr: true,
		},
		{
			name: "error format of pvcAccessModes (list with non-string)",
			yamlData: `version: v1
volumePolicies:
  - conditions:
      pvcAccessModes:
        - 123
    action:
      type: skip
`,
			wantErr: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := unmarshalResourcePolicies(&tc.yamlData)

			if (err != nil) != tc.wantErr {
				t.Fatalf("Expected error %v, but got error %v", tc.wantErr, err)
			}
		})
	}
}

func TestGetResourceMatchedAction(t *testing.T) {
	resPolicies := &ResourcePolicies{
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
				},
			},
			{
				Action: Action{Type: "skip"},
				Conditions: map[string]any{
					"csi": any(
						map[string]any{
							"driver":           "files.csi.driver",
							"volumeAttributes": map[string]string{"protocol": "nfs"},
						}),
				},
			},
			{
				Action: Action{Type: "snapshot"},
				Conditions: map[string]any{
					"capacity":     "10,100Gi",
					"storageClass": []string{"gp2", "ebs-sc"},
					"csi": any(
						map[string]any{
							"driver": "aws.efs.csi.driver",
						}),
				},
			},
			{
				Action: Action{Type: "fs-backup"},
				Conditions: map[string]any{
					"storageClass": []string{"gp2", "ebs-sc"},
					"csi": any(
						map[string]any{
							"driver": "aws.efs.csi.driver",
						}),
				},
			},
			{
				Action: Action{Type: "snapshot"},
				Conditions: map[string]any{
					"pvcLabels": map[string]string{
						"environment": "production",
					},
				},
			},
		},
	}
	testCases := []struct {
		name             string
		volume           *structuredVolume
		expectedAction   *Action
		resourcePolicies *ResourcePolicies
	}{
		{
			name: "match policy",
			volume: &structuredVolume{
				capacity:     *resource.NewQuantity(5<<30, resource.BinarySI),
				storageClass: "ebs-sc",
				csi:          &csiVolumeSource{Driver: "aws.efs.csi.driver"},
			},
			expectedAction: &Action{Type: "skip"},
		},
		{
			name: "match policy AFS NFS",
			volume: &structuredVolume{
				capacity:     *resource.NewQuantity(5<<30, resource.BinarySI),
				storageClass: "afs-nfs",
				csi:          &csiVolumeSource{Driver: "files.csi.driver", VolumeAttributes: map[string]string{"protocol": "nfs"}},
			},
			expectedAction: &Action{Type: "skip"},
		},
		{
			name: "match policy AFS SMB",
			volume: &structuredVolume{
				capacity:     *resource.NewQuantity(5<<30, resource.BinarySI),
				storageClass: "afs-smb",
				csi:          &csiVolumeSource{Driver: "files.csi.driver"},
			},
			expectedAction: nil,
		},
		{
			name: "both matches return the first policy",
			volume: &structuredVolume{
				capacity:     *resource.NewQuantity(50<<30, resource.BinarySI),
				storageClass: "ebs-sc",
				csi:          &csiVolumeSource{Driver: "aws.efs.csi.driver"},
			},
			expectedAction: &Action{Type: "snapshot"},
		},
		{
			name: "mismatch all policies",
			volume: &structuredVolume{
				capacity:     *resource.NewQuantity(50<<30, resource.BinarySI),
				storageClass: "ebs-sc",
				nfs:          &nFSVolumeSource{},
			},
			expectedAction: nil,
		},
		{
			name: "match pvcLabels condition",
			volume: &structuredVolume{
				capacity:     *resource.NewQuantity(5<<30, resource.BinarySI),
				storageClass: "some-class",
				pvcLabels: map[string]string{
					"environment": "production",
					"team":        "backend",
				},
			},
			expectedAction: &Action{Type: "snapshot"},
		},
		{
			name: "mismatch pvcLabels condition",
			volume: &structuredVolume{
				capacity:     *resource.NewQuantity(5<<30, resource.BinarySI),
				storageClass: "some-class",
				pvcLabels: map[string]string{
					"environment": "staging",
				},
			},
			expectedAction: nil,
		},
		{
			name: "nil condition always match the action",
			volume: &structuredVolume{
				capacity:     *resource.NewQuantity(5<<30, resource.BinarySI),
				storageClass: "some-class",
				pvcLabels: map[string]string{
					"environment": "staging",
				},
			},
			resourcePolicies: &ResourcePolicies{
				Version: "v1",
				VolumePolicies: []VolumePolicy{
					{
						Action:     Action{Type: "skip"},
						Conditions: map[string]any{},
					},
				},
			},
			expectedAction: &Action{Type: "skip"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			policies := &Policies{}
			currentResourcePolicy := resPolicies
			if tc.resourcePolicies != nil {
				currentResourcePolicy = tc.resourcePolicies
			}
			err := policies.BuildPolicy(currentResourcePolicy)
			if err != nil {
				t.Errorf("Failed to build policy with error %v", err)
			}

			action := policies.match(tc.volume)
			if action == nil {
				if tc.expectedAction != nil {
					t.Errorf("Expected action %v, but got result nil", tc.expectedAction.Type)
				}
			} else {
				if tc.expectedAction != nil {
					if action.Type != tc.expectedAction.Type {
						t.Errorf("Expected action %v, but got result %v", tc.expectedAction.Type, action.Type)
					}
				} else {
					t.Errorf("Expected action nil, but got result %v", action.Type)
				}
			}
		})
	}
}

func TestGetResourcePoliciesFromConfig(t *testing.T) {
	testCases := []struct {
		name        string
		cm          *corev1api.ConfigMap
		expectedErr string
	}{
		{
			name: "valid configmap",
			cm: &corev1api.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-configmap",
					Namespace: "test-namespace",
				},
				Data: map[string]string{
					"test-data": `version: v1
volumePolicies:
  - conditions:
      capacity: '0,10Gi'
      csi:
        driver: disks.csi.driver
    action:
      type: skip
  - conditions:
      csi:
        driver: files.csi.driver
        volumeAttributes:
          protocol: nfs
    action:
      type: skip
  - conditions:
      pvcLabels:
        environment: production
    action:
      type: skip
`,
				},
			},
			expectedErr: "",
		},
		{
			name:        "nil configmap",
			cm:          nil,
			expectedErr: "could not parse config from nil configmap",
		},
		{
			name: "empty data configmap",
			cm: &corev1api.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-configmap",
					Namespace: "test-namespace",
				},
				Data: map[string]string{},
			},
			expectedErr: "illegal resource policies test-namespace/test-configmap configmap",
		},
		{
			name: "multiple data configmap",
			cm: &corev1api.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-configmap",
					Namespace: "test-namespace",
				},
				Data: map[string]string{
					"data1": "value1",
					"data2": "value2",
				},
			},
			expectedErr: "illegal resource policies test-namespace/test-configmap configmap",
		},
		{
			name: "invalid yaml data",
			cm: &corev1api.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-configmap",
					Namespace: "test-namespace",
				},
				Data: map[string]string{
					"test-data": `version: v1
volumePolicies:
  - conditions:
      capacity: '0,10Gi'
      csi:
        driver: disks.csi.driver
    action:
      type: skip
    invalid-key: value
`,
				},
			},
			expectedErr: "failed to decode yaml data into resource policies",
		},
		{
			name: "build policy error",
			cm: &corev1api.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-configmap",
					Namespace: "test-namespace",
				},
				Data: map[string]string{
					"test-data": `version: v1
volumePolicies:
  - conditions:
      capacity: 'invalid-capacity'
      csi:
        driver: disks.csi.driver
    action:
      type: skip
`,
				},
			},
			expectedErr: "wrong format of Capacity invalid-capacity",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resPolicies, err := getResourcePoliciesFromConfig(tc.cm)
			if tc.expectedErr == "" {
				require.NoError(t, err)
				assert.Equal(t, "v1", resPolicies.version)
				assert.Len(t, resPolicies.volumePolicies, 3)
			} else {
				require.ErrorContains(t, err, tc.expectedErr)
				assert.Nil(t, resPolicies)
			}
		})
	}
}

func TestGetResourcePoliciesFromBackup(t *testing.T) {
	validCM := &corev1api.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-configmap",
			Namespace: "test-namespace",
		},
		Data: map[string]string{
			"test-data": `version: v1
volumePolicies:
  - conditions:
      capacity: '0,10Gi'
      csi:
        driver: disks.csi.driver
    action:
      type: skip
`,
		},
	}

	invalidActionCM := &corev1api.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "invalid-action-configmap",
			Namespace: "test-namespace",
		},
		Data: map[string]string{
			"test-data": `version: v1
volumePolicies:
  - conditions:
      capacity: '0,10Gi'
      csi:
        driver: disks.csi.driver
    action:
      type: invalid-action
`,
		},
	}

	invalidVersionCM := &corev1api.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "invalid-version-configmap",
			Namespace: "test-namespace",
		},
		Data: map[string]string{
			"test-data": `version: v2
volumePolicies:
  - conditions:
      capacity: '0,10Gi'
      csi:
        driver: disks.csi.driver
    action:
      type: skip
`,
		},
	}

	emptyCM := &corev1api.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "empty-configmap",
			Namespace: "test-namespace",
		},
	}

	client := fake.NewClientBuilder().WithScheme(scheme.Scheme).WithObjects(validCM, invalidActionCM, invalidVersionCM, emptyCM).Build()
	logger := logrus.New()

	testCases := []struct {
		name        string
		backup      velerov1api.Backup
		expectedErr string
	}{
		{
			name: "valid configmap",
			backup: velerov1api.Backup{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-namespace",
					Name:      "test-backup",
				},
				Spec: velerov1api.BackupSpec{
					ResourcePolicy: &corev1api.TypedLocalObjectReference{
						Kind: ConfigmapRefType,
						Name: "test-configmap",
					},
				},
			},
			expectedErr: "",
		},
		{
			name: "invalid kind",
			backup: velerov1api.Backup{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-namespace",
					Name:      "test-backup",
				},
				Spec: velerov1api.BackupSpec{
					ResourcePolicy: &corev1api.TypedLocalObjectReference{
						Kind: "Secret",
						Name: "test-configmap",
					},
				},
			},
			expectedErr: "",
		},
		{
			name: "configmap not found",
			backup: velerov1api.Backup{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-namespace",
					Name:      "test-backup",
				},
				Spec: velerov1api.BackupSpec{
					ResourcePolicy: &corev1api.TypedLocalObjectReference{
						Kind: ConfigmapRefType,
						Name: "non-existent-configmap",
					},
				},
			},
			expectedErr: "fail to get ResourcePolicies test-namespace/non-existent-configmap ConfigMap",
		},
		{
			name: "invalid action configmap",
			backup: velerov1api.Backup{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-namespace",
					Name:      "test-backup",
				},
				Spec: velerov1api.BackupSpec{
					ResourcePolicy: &corev1api.TypedLocalObjectReference{
						Kind: ConfigmapRefType,
						Name: "invalid-action-configmap",
					},
				},
			},
			expectedErr: "fail to validate ResourcePolicies in ConfigMap test-namespace/test-backup",
		},
		{
			name: "invalid version configmap",
			backup: velerov1api.Backup{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-namespace",
					Name:      "test-backup",
				},
				Spec: velerov1api.BackupSpec{
					ResourcePolicy: &corev1api.TypedLocalObjectReference{
						Kind: ConfigmapRefType,
						Name: "invalid-version-configmap",
					},
				},
			},
			expectedErr: "fail to validate ResourcePolicies in ConfigMap test-namespace/test-backup",
		},
		{
			name: "empty configmap",
			backup: velerov1api.Backup{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-namespace",
					Name:      "test-backup",
				},
				Spec: velerov1api.BackupSpec{
					ResourcePolicy: &corev1api.TypedLocalObjectReference{
						Kind: ConfigmapRefType,
						Name: "empty-configmap",
					},
				},
			},
			expectedErr: "fail to read the ResourcePolicies from ConfigMap test-namespace/test-backup",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resPolicies, err := GetResourcePoliciesFromBackup(tc.backup, client, logger)
			if tc.expectedErr == "" {
				require.NoError(t, err)
				if tc.backup.Spec.ResourcePolicy != nil && tc.backup.Spec.ResourcePolicy.Kind == ConfigmapRefType {
					assert.NotNil(t, resPolicies)
				} else {
					assert.Nil(t, resPolicies)
				}
			} else {
				require.ErrorContains(t, err, tc.expectedErr)
				assert.Nil(t, resPolicies)
			}
		})
	}
}

func TestGetResourcePoliciesFromRestore(t *testing.T) {
	validCM := &corev1api.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-configmap",
			Namespace: "test-namespace",
		},
		Data: map[string]string{
			"test-data": `version: v1
namespacedFilterPolicies:
  - namespaces: ["default"]
    resourceFilters:
      - kinds: ["Pod"]
`,
		},
	}

	invalidNfpCM := &corev1api.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "invalid-action-configmap",
			Namespace: "test-namespace",
		},
		Data: map[string]string{
			"test-data": `version: v1
namespacedFilterPolicies:
  - namespaces: []
    resourceFilters:
      - kinds: ["Pod"]
`,
		},
	}

	invalidVersionCM := &corev1api.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "invalid-version-configmap",
			Namespace: "test-namespace",
		},
		Data: map[string]string{
			"test-data": `version: v2
namespacedFilterPolicies:
  - namespaces: ["default"]
    resourceFilters:
      - kinds: ["Pod"]
`,
		},
	}

	emptyCM := &corev1api.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "empty-configmap",
			Namespace: "test-namespace",
		},
	}

	client := fake.NewClientBuilder().WithScheme(scheme.Scheme).WithObjects(validCM, invalidNfpCM, invalidVersionCM, emptyCM).Build()
	logger := logrus.New()

	testCases := []struct {
		name        string
		restore     *velerov1api.Restore
		expectedErr string
	}{
		{
			name: "valid configmap",
			restore: &velerov1api.Restore{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-namespace",
					Name:      "test-restore",
				},
				Spec: velerov1api.RestoreSpec{
					ResourcePolicy: &corev1api.TypedLocalObjectReference{
						Kind: ConfigmapRefType,
						Name: "test-configmap",
					},
				},
			},
			expectedErr: "",
		},
		{
			name: "invalid kind",
			restore: &velerov1api.Restore{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-namespace",
					Name:      "test-restore",
				},
				Spec: velerov1api.RestoreSpec{
					ResourcePolicy: &corev1api.TypedLocalObjectReference{
						Kind: "Secret",
						Name: "test-configmap",
					},
				},
			},
			expectedErr: "invalid ResourcePolicy kind \"Secret\", only \"configmap\" is supported",
		},
		{
			name: "configmap not found",
			restore: &velerov1api.Restore{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-namespace",
					Name:      "test-restore",
				},
				Spec: velerov1api.RestoreSpec{
					ResourcePolicy: &corev1api.TypedLocalObjectReference{
						Kind: ConfigmapRefType,
						Name: "non-existent-configmap",
					},
				},
			},
			expectedErr: "fail to get ResourcePolicies test-namespace/non-existent-configmap ConfigMap",
		},
		{
			name: "invalid action configmap",
			restore: &velerov1api.Restore{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-namespace",
					Name:      "test-restore",
				},
				Spec: velerov1api.RestoreSpec{
					ResourcePolicy: &corev1api.TypedLocalObjectReference{
						Kind: ConfigmapRefType,
						Name: "invalid-action-configmap",
					},
				},
			},
			expectedErr: "fail to validate ResourcePolicies in ConfigMap test-namespace/invalid-action-configmap",
		},
		{
			name: "invalid version configmap",
			restore: &velerov1api.Restore{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-namespace",
					Name:      "test-restore",
				},
				Spec: velerov1api.RestoreSpec{
					ResourcePolicy: &corev1api.TypedLocalObjectReference{
						Kind: ConfigmapRefType,
						Name: "invalid-version-configmap",
					},
				},
			},
			expectedErr: "fail to validate ResourcePolicies in ConfigMap test-namespace/invalid-version-configmap",
		},
		{
			name: "empty configmap",
			restore: &velerov1api.Restore{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-namespace",
					Name:      "test-restore",
				},
				Spec: velerov1api.RestoreSpec{
					ResourcePolicy: &corev1api.TypedLocalObjectReference{
						Kind: ConfigmapRefType,
						Name: "empty-configmap",
					},
				},
			},
			expectedErr: "fail to read the ResourcePolicies from ConfigMap test-namespace/empty-configmap",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resPolicies, err := GetResourcePoliciesFromRestore(context.Background(), tc.restore, client, logger)
			if tc.expectedErr == "" {
				require.NoError(t, err)
				assert.NotNil(t, resPolicies)
			} else {
				require.ErrorContains(t, err, tc.expectedErr)
				assert.Nil(t, resPolicies)
			}
		})
	}
}

func TestGetMatchAction(t *testing.T) {
	testCases := []struct {
		name     string
		yamlData string
		vol      *corev1api.PersistentVolume
		podVol   *corev1api.Volume
		pvc      *corev1api.PersistentVolumeClaim
		skip     bool
	}{
		{
			name: "empty csi",
			yamlData: `version: v1
volumePolicies:
- conditions:
   csi: {}
  action:
    type: skip`,
			vol: &corev1api.PersistentVolume{
				Spec: corev1api.PersistentVolumeSpec{
					PersistentVolumeSource: corev1api.PersistentVolumeSource{
						CSI: &corev1api.CSIPersistentVolumeSource{Driver: "ebs.csi.aws.com"},
					}},
			},
			skip: true,
		},
		{
			name: "empty csi with pv no csi driver",
			yamlData: `version: v1
volumePolicies:
- conditions:
   csi: {}
  action:
    type: skip`,
			vol: &corev1api.PersistentVolume{
				Spec: corev1api.PersistentVolumeSpec{
					Capacity: corev1api.ResourceList{
						corev1api.ResourceStorage: resource.MustParse("1Gi"),
					}},
			},
			skip: false,
		},
		{
			name: "Skip AFS CSI condition with Disk volumes",
			yamlData: `version: v1
volumePolicies:
  - conditions:
      csi:
        driver: files.csi.driver
    action:
      type: skip`,
			vol: &corev1api.PersistentVolume{
				Spec: corev1api.PersistentVolumeSpec{
					PersistentVolumeSource: corev1api.PersistentVolumeSource{
						CSI: &corev1api.CSIPersistentVolumeSource{Driver: "disks.csi.driver"},
					}},
			},
			skip: false,
		},
		{
			name: "Skip AFS CSI condition with AFS volumes",
			yamlData: `version: v1
volumePolicies:
  - conditions:
      csi:
        driver: files.csi.driver
    action:
      type: skip`,
			vol: &corev1api.PersistentVolume{
				Spec: corev1api.PersistentVolumeSpec{
					PersistentVolumeSource: corev1api.PersistentVolumeSource{
						CSI: &corev1api.CSIPersistentVolumeSource{Driver: "files.csi.driver"},
					}},
			},
			skip: true,
		},
		{
			name: "Skip AFS NFS CSI condition with Disk volumes",
			yamlData: `version: v1
volumePolicies:
  - conditions:
      csi:
        driver: files.csi.driver
        volumeAttributes:
          protocol: nfs
    action:
      type: skip
`,
			vol: &corev1api.PersistentVolume{
				Spec: corev1api.PersistentVolumeSpec{
					PersistentVolumeSource: corev1api.PersistentVolumeSource{
						CSI: &corev1api.CSIPersistentVolumeSource{Driver: "disks.csi.driver"},
					}},
			},
			skip: false,
		},
		{
			name: "Skip AFS NFS CSI condition with AFS SMB volumes",
			yamlData: `version: v1
volumePolicies:
  - conditions:
      csi:
        driver: files.csi.driver
        volumeAttributes:
          protocol: nfs
    action:
      type: skip
`,
			vol: &corev1api.PersistentVolume{
				Spec: corev1api.PersistentVolumeSpec{
					PersistentVolumeSource: corev1api.PersistentVolumeSource{
						CSI: &corev1api.CSIPersistentVolumeSource{Driver: "files.csi.driver", VolumeAttributes: map[string]string{"key1": "val1"}},
					}},
			},
			skip: false,
		},
		{
			name: "Skip AFS NFS CSI condition with AFS NFS volumes",
			yamlData: `version: v1
volumePolicies:
  - conditions:
      csi:
        driver: files.csi.driver
        volumeAttributes:
          protocol: nfs
    action:
      type: skip
`,
			vol: &corev1api.PersistentVolume{
				Spec: corev1api.PersistentVolumeSpec{
					PersistentVolumeSource: corev1api.PersistentVolumeSource{
						CSI: &corev1api.CSIPersistentVolumeSource{Driver: "files.csi.driver", VolumeAttributes: map[string]string{"protocol": "nfs"}},
					}},
			},
			skip: true,
		},
		{
			name: "Skip Disk and AFS NFS CSI condition with Disk volumes",
			yamlData: `version: v1
volumePolicies:
  - conditions:
      csi:
        driver: disks.csi.driver
    action:
      type: skip
  - conditions:
      csi:
        driver: files.csi.driver
        volumeAttributes:
          protocol: nfs
    action:
      type: skip`,
			vol: &corev1api.PersistentVolume{
				Spec: corev1api.PersistentVolumeSpec{
					PersistentVolumeSource: corev1api.PersistentVolumeSource{
						CSI: &corev1api.CSIPersistentVolumeSource{Driver: "disks.csi.driver", VolumeAttributes: map[string]string{"key1": "val1"}},
					}},
			},
			skip: true,
		},
		{
			name: "Skip Disk and AFS NFS CSI condition with AFS SMB volumes",
			yamlData: `version: v1
volumePolicies:
  - conditions:
      csi:
        driver: disks.csi.driver
    action:
      type: skip
  - conditions:
      csi:
        driver: files.csi.driver
        volumeAttributes:
          protocol: nfs
    action:
      type: skip`,
			vol: &corev1api.PersistentVolume{
				Spec: corev1api.PersistentVolumeSpec{
					PersistentVolumeSource: corev1api.PersistentVolumeSource{
						CSI: &corev1api.CSIPersistentVolumeSource{Driver: "files.csi.driver", VolumeAttributes: map[string]string{"key1": "val1"}},
					}},
			},
			skip: false,
		},
		{
			name: "Skip Disk and AFS NFS CSI condition with AFS NFS volumes",
			yamlData: `version: v1
volumePolicies:
  - conditions:
      csi:
        driver: disks.csi.driver
    action:
      type: skip
  - conditions:
      csi:
        driver: files.csi.driver
        volumeAttributes:
          protocol: nfs
    action:
      type: skip`,
			vol: &corev1api.PersistentVolume{
				Spec: corev1api.PersistentVolumeSpec{
					PersistentVolumeSource: corev1api.PersistentVolumeSource{
						CSI: &corev1api.CSIPersistentVolumeSource{Driver: "files.csi.driver", VolumeAttributes: map[string]string{"key1": "val1", "protocol": "nfs"}},
					}},
			},
			skip: true,
		},
		{
			name: "csi not configured and testing capacity condition",
			yamlData: `version: v1
volumePolicies:
- conditions:
    capacity: "0,100Gi"
  action:
    type: skip`,
			vol: &corev1api.PersistentVolume{
				Spec: corev1api.PersistentVolumeSpec{
					Capacity: corev1api.ResourceList{
						corev1api.ResourceStorage: resource.MustParse("1Gi"),
					},
					PersistentVolumeSource: corev1api.PersistentVolumeSource{
						CSI: &corev1api.CSIPersistentVolumeSource{Driver: "ebs.csi.aws.com"},
					}},
			},
			skip: true,
		},
		{
			name: "empty nfs",
			yamlData: `version: v1
volumePolicies:
- conditions:
    nfs: {}
  action:
    type: skip`,
			vol: &corev1api.PersistentVolume{
				Spec: corev1api.PersistentVolumeSpec{
					PersistentVolumeSource: corev1api.PersistentVolumeSource{
						NFS: &corev1api.NFSVolumeSource{Server: "192.168.1.20"},
					}},
			},
			skip: true,
		},
		{
			name: "nfs not configured",
			yamlData: `version: v1
volumePolicies:
- conditions:
    capacity: "0,100Gi"
  action:
    type: skip`,
			vol: &corev1api.PersistentVolume{
				Spec: corev1api.PersistentVolumeSpec{
					Capacity: corev1api.ResourceList{
						corev1api.ResourceStorage: resource.MustParse("1Gi"),
					},
					PersistentVolumeSource: corev1api.PersistentVolumeSource{
						NFS: &corev1api.NFSVolumeSource{Server: "192.168.1.20"},
					},
				},
			},
			skip: true,
		},
		{
			name: "empty nfs with pv no nfs volume source",
			yamlData: `version: v1
volumePolicies:
- conditions:
    capacity: "0,100Gi"
    nfs: {}
  action:
    type: skip`,
			vol: &corev1api.PersistentVolume{
				Spec: corev1api.PersistentVolumeSpec{
					Capacity: corev1api.ResourceList{
						corev1api.ResourceStorage: resource.MustParse("1Gi"),
					},
				},
			},
			skip: false,
		},
		{
			name: "match volume by types",
			yamlData: `version: v1
volumePolicies:
- conditions:
    capacity: "0,100Gi"
    volumeTypes:
      - local
      - hostPath
  action:
    type: skip`,
			vol: &corev1api.PersistentVolume{
				Spec: corev1api.PersistentVolumeSpec{
					Capacity: corev1api.ResourceList{
						corev1api.ResourceStorage: resource.MustParse("1Gi"),
					},
					PersistentVolumeSource: corev1api.PersistentVolumeSource{
						HostPath: &corev1api.HostPathVolumeSource{Path: "/mnt/data"},
					},
				},
			},
			skip: true,
		},
		{
			name: "mismatch volume by types",
			yamlData: `version: v1
volumePolicies:
- conditions:
    capacity: "0,100Gi"
    volumeTypes:
      - local
  action:
    type: skip`,
			vol: &corev1api.PersistentVolume{
				Spec: corev1api.PersistentVolumeSpec{
					Capacity: corev1api.ResourceList{
						corev1api.ResourceStorage: resource.MustParse("1Gi"),
					},
					PersistentVolumeSource: corev1api.PersistentVolumeSource{
						HostPath: &corev1api.HostPathVolumeSource{Path: "/mnt/data"},
					},
				},
			},
			skip: false,
		},
		{
			name: "PVC labels match",
			yamlData: `version: v1
volumePolicies:
- conditions:
    capacity: "0,100Gi"
    pvcLabels:
      environment: production
  action:
    type: skip`,
			vol: &corev1api.PersistentVolume{
				ObjectMeta: metav1.ObjectMeta{
					Name: "pv-1",
				},
				Spec: corev1api.PersistentVolumeSpec{
					Capacity: corev1api.ResourceList{
						corev1api.ResourceStorage: resource.MustParse("1Gi"),
					},
					PersistentVolumeSource: corev1api.PersistentVolumeSource{},
					ClaimRef: &corev1api.ObjectReference{
						Namespace: "default",
						Name:      "pvc-1",
					},
				},
			},
			pvc: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "pvc-1",
					Labels:    map[string]string{"environment": "production"},
				},
			},
			skip: true,
		},
		{
			name: "PVC labels match, criteria label is a subset of the pvc labels",
			yamlData: `version: v1
volumePolicies:
- conditions:
    capacity: "0,100Gi"
    pvcLabels:
      environment: production
  action:
    type: skip`,
			vol: &corev1api.PersistentVolume{
				ObjectMeta: metav1.ObjectMeta{
					Name: "pv-1",
				},
				Spec: corev1api.PersistentVolumeSpec{
					Capacity: corev1api.ResourceList{
						corev1api.ResourceStorage: resource.MustParse("1Gi"),
					},
					PersistentVolumeSource: corev1api.PersistentVolumeSource{},
					ClaimRef: &corev1api.ObjectReference{
						Namespace: "default",
						Name:      "pvc-1",
					},
				},
			},
			pvc: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "pvc-1",
					Labels:    map[string]string{"environment": "production", "app": "backend"},
				},
			},
			skip: true,
		},
		{
			name: "PVC labels match don't match exactly",
			yamlData: `version: v1
volumePolicies:
- conditions:
    capacity: "0,100Gi"
    pvcLabels:
      environment: production
      app: frontend
  action:
    type: skip`,
			vol: &corev1api.PersistentVolume{
				ObjectMeta: metav1.ObjectMeta{
					Name: "pv-1",
				},
				Spec: corev1api.PersistentVolumeSpec{
					Capacity: corev1api.ResourceList{
						corev1api.ResourceStorage: resource.MustParse("1Gi"),
					},
					PersistentVolumeSource: corev1api.PersistentVolumeSource{},
					ClaimRef: &corev1api.ObjectReference{
						Namespace: "default",
						Name:      "pvc-1",
					},
				},
			},
			pvc: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "pvc-1",
					Labels:    map[string]string{"environment": "production"},
				},
			},
			skip: false,
		},
		{
			name: "PVC labels mismatch",
			yamlData: `version: v1
volumePolicies:
- conditions:
    capacity: "0,100Gi"
    pvcLabels:
      environment: production
  action:
    type: skip`,
			vol: &corev1api.PersistentVolume{
				ObjectMeta: metav1.ObjectMeta{
					Name: "pv-2",
				},
				Spec: corev1api.PersistentVolumeSpec{
					Capacity: corev1api.ResourceList{
						corev1api.ResourceStorage: resource.MustParse("1Gi"),
					},
					PersistentVolumeSource: corev1api.PersistentVolumeSource{},
					ClaimRef: &corev1api.ObjectReference{
						Namespace: "default",
						Name:      "pvc-2",
					},
				},
			},
			pvc: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "pvc-1",
					Labels:    map[string]string{"environment": "staging"},
				},
			},
			skip: false,
		},
		{
			name: "PodVolume case with PVC labels match",
			yamlData: `version: v1
volumePolicies:
- conditions:
    pvcLabels:
      environment: production
  action:
    type: skip`,
			vol:    nil,
			podVol: &corev1api.Volume{Name: "pod-vol-1"},
			pvc: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "pvc-1",
					Labels:    map[string]string{"environment": "production"},
				},
			},
			skip: true,
		},
		{
			name: "PodVolume case with PVC labels mismatch",
			yamlData: `version: v1
volumePolicies:
- conditions:
    pvcLabels:
      environment: production
  action:
    type: skip`,
			vol:    nil,
			podVol: &corev1api.Volume{Name: "pod-vol-2"},
			pvc: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "pvc-2",
					Labels:    map[string]string{"environment": "staging"},
				},
			},
			skip: false,
		},
		{
			name: "PodVolume case with PVC labels match with extra keys on PVC",
			yamlData: `version: v1
volumePolicies:
- conditions:
    pvcLabels:
      environment: production
  action:
    type: skip`,
			vol:    nil,
			podVol: &corev1api.Volume{Name: "pod-vol-3"},
			pvc: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "pvc-3",
					Labels:    map[string]string{"environment": "production", "app": "backend"},
				},
			},
			skip: true,
		},
		{
			name: "PodVolume case with PVC labels don't match exactly",
			yamlData: `version: v1
volumePolicies:
- conditions:
    pvcLabels:
      environment: production
      app: frontend
  action:
    type: skip`,
			vol:    nil,
			podVol: &corev1api.Volume{Name: "pod-vol-4"},
			pvc: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "pvc-4",
					Labels:    map[string]string{"environment": "production"},
				},
			},
			skip: false,
		},
		{
			name: "PVC phase matching - Pending phase should skip",
			yamlData: `version: v1
volumePolicies:
- conditions:
   pvcPhase: ["Pending"]
  action:
    type: skip`,
			vol:    nil,
			podVol: nil,
			pvc: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "pvc-pending",
				},
				Status: corev1api.PersistentVolumeClaimStatus{
					Phase: corev1api.ClaimPending,
				},
			},
			skip: true,
		},
		{
			name: "PVC phase matching - Bound phase should not skip",
			yamlData: `version: v1
volumePolicies:
- conditions:
   pvcPhase: ["Pending"]
  action:
    type: skip`,
			vol:    nil,
			podVol: nil,
			pvc: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "pvc-bound",
				},
				Status: corev1api.PersistentVolumeClaimStatus{
					Phase: corev1api.ClaimBound,
				},
			},
			skip: false,
		},
		{
			name: "PVC phase matching - Multiple phases (Pending, Lost)",
			yamlData: `version: v1
volumePolicies:
- conditions:
   pvcPhase: ["Pending", "Lost"]
  action:
    type: skip`,
			vol:    nil,
			podVol: nil,
			pvc: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "pvc-lost",
				},
				Status: corev1api.PersistentVolumeClaimStatus{
					Phase: corev1api.ClaimLost,
				},
			},
			skip: true,
		},
		{
			name: "PVC volume mode matching - Block volume mode should skip",
			yamlData: `version: v1
volumePolicies:
- conditions:
   pvcVolumeMode: Block
  action:
    type: skip`,
			vol:    nil,
			podVol: nil,
			pvc: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "pvc-block",
				},
				Spec: corev1api.PersistentVolumeClaimSpec{
					VolumeMode: pvcVolumeMode(corev1api.PersistentVolumeBlock),
				},
			},
			skip: true,
		},
		{
			name: "PVC volume mode matching - Filesystem volume mode should not skip",
			yamlData: `version: v1
volumePolicies:
- conditions:
   pvcVolumeMode: Block
  action:
    type: skip`,
			vol:    nil,
			podVol: nil,
			pvc: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "pvc-filesystem",
				},
				Spec: corev1api.PersistentVolumeClaimSpec{
					VolumeMode: pvcVolumeMode(corev1api.PersistentVolumeFilesystem),
				},
			},
			skip: false,
		},
		{
			name: "PVC volume mode matching - nil volume mode should not match Filesystem",
			yamlData: `version: v1
volumePolicies:
- conditions:
   pvcVolumeMode: Filesystem
  action:
    type: skip`,
			vol:    nil,
			podVol: nil,
			pvc: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "pvc-without-volume-mode",
				},
			},
			skip: false,
		},
		{
			name: "PVC volume mode matching - unknown condition value should not match empty volume mode",
			yamlData: `version: v1
volumePolicies:
- conditions:
   pvcVolumeMode: foo
  action:
    type: skip`,
			vol:    nil,
			podVol: nil,
			pvc: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "pvc-without-volume-mode",
				},
			},
			skip: false,
		},
		{
			name: "PVC volume mode matching - omitted condition should not restrict volume mode",
			yamlData: `version: v1
volumePolicies:
- conditions:
   pvcAccessModes: ["ReadWriteOnce"]
  action:
    type: skip`,
			vol:    nil,
			podVol: nil,
			pvc: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "pvc-block-rwo",
				},
				Spec: corev1api.PersistentVolumeClaimSpec{
					VolumeMode:  pvcVolumeMode(corev1api.PersistentVolumeBlock),
					AccessModes: []corev1api.PersistentVolumeAccessMode{corev1api.ReadWriteOnce},
				},
			},
			skip: true,
		},
		{
			name: "PVC volume mode matching - non-PVC volume should not match",
			yamlData: `version: v1
volumePolicies:
- conditions:
   pvcVolumeMode: Filesystem
  action:
    type: skip`,
			vol: nil,
			podVol: &corev1api.Volume{
				Name: "empty-dir-volume",
				VolumeSource: corev1api.VolumeSource{
					EmptyDir: &corev1api.EmptyDirVolumeSource{},
				},
			},
			pvc:  nil,
			skip: false,
		},
		{
			name: "PVC access modes matching - non-PVC volume should not match",
			yamlData: `version: v1
volumePolicies:
- conditions:
   pvcAccessModes: ["ReadWriteOnce"]
  action:
    type: skip`,
			vol: nil,
			podVol: &corev1api.Volume{
				Name: "configmap-volume",
				VolumeSource: corev1api.VolumeSource{
					ConfigMap: &corev1api.ConfigMapVolumeSource{},
				},
			},
			pvc:  nil,
			skip: false,
		},

		{
			name: "PVC access modes matching - ReadWriteOnce should skip",
			yamlData: `version: v1
volumePolicies:
- conditions:
   pvcAccessModes: ["ReadWriteOnce"]
  action:
    type: skip`,
			vol:    nil,
			podVol: nil,
			pvc: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "pvc-rwo",
				},
				Spec: corev1api.PersistentVolumeClaimSpec{
					AccessModes: []corev1api.PersistentVolumeAccessMode{corev1api.ReadWriteOnce},
				},
			},
			skip: true,
		},
		{
			name: "PVC access modes matching - extra PVC access mode should not skip",
			yamlData: `version: v1
volumePolicies:
- conditions:
   pvcAccessModes: ["ReadWriteOnce"]
  action:
    type: skip`,
			vol:    nil,
			podVol: nil,
			pvc: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "pvc-rwo-rom",
				},
				Spec: corev1api.PersistentVolumeClaimSpec{
					AccessModes: []corev1api.PersistentVolumeAccessMode{corev1api.ReadWriteOnce, corev1api.ReadOnlyMany},
				},
			},
			skip: false,
		},
		{
			name: "PVC access modes matching - ReadWriteMany should not skip",
			yamlData: `version: v1
volumePolicies:
- conditions:
   pvcAccessModes: ["ReadWriteOnce"]
  action:
    type: skip`,
			vol:    nil,
			podVol: nil,
			pvc: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "pvc-rwx",
				},
				Spec: corev1api.PersistentVolumeClaimSpec{
					AccessModes: []corev1api.PersistentVolumeAccessMode{corev1api.ReadWriteMany},
				},
			},
			skip: false,
		},
		{
			name: "PVC access modes matching - exact access mode set should match regardless of order",
			yamlData: `version: v1
volumePolicies:
- conditions:
   pvcAccessModes: ["ReadWriteMany", "ReadOnlyMany"]
  action:
    type: skip`,
			vol:    nil,
			podVol: nil,
			pvc: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "pvc-rom-rwx",
				},
				Spec: corev1api.PersistentVolumeClaimSpec{
					AccessModes: []corev1api.PersistentVolumeAccessMode{corev1api.ReadOnlyMany, corev1api.ReadWriteMany},
				},
			},
			skip: true,
		},
		{
			name: "PVC access modes matching - missing one configured access mode should not skip",
			yamlData: `version: v1
volumePolicies:
- conditions:
   pvcAccessModes: ["ReadOnlyMany", "ReadWriteMany"]
  action:
    type: skip`,
			vol:    nil,
			podVol: nil,
			pvc: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "pvc-rwx",
				},
				Spec: corev1api.PersistentVolumeClaimSpec{
					AccessModes: []corev1api.PersistentVolumeAccessMode{corev1api.ReadWriteMany},
				},
			},
			skip: false,
		},
		{
			name: "PVC access modes matching - Combined with volume mode",
			yamlData: `version: v1
volumePolicies:
- conditions:
   pvcVolumeMode: Block
   pvcAccessModes: ["ReadWriteOnce"]
  action:
    type: skip`,
			vol:    nil,
			podVol: nil,
			pvc: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
					Name:      "pvc-block-rwo",
				},
				Spec: corev1api.PersistentVolumeClaimSpec{
					VolumeMode:  pvcVolumeMode(corev1api.PersistentVolumeBlock),
					AccessModes: []corev1api.PersistentVolumeAccessMode{corev1api.ReadWriteOnce},
				},
			},
			skip: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resPolicies, err := unmarshalResourcePolicies(&tc.yamlData)
			if err != nil {
				t.Fatalf("got error when get match action %v", err)
			}
			require.NoError(t, err)
			policies := &Policies{}
			err = policies.BuildPolicy(resPolicies)
			require.NoError(t, err)
			vfd := VolumeFilterData{}
			if tc.pvc != nil {
				vfd.PVC = tc.pvc
			}

			if tc.vol != nil {
				vfd.PersistentVolume = tc.vol
			}

			if tc.podVol != nil {
				vfd.PodVolume = tc.podVol
			}

			action, err := policies.GetMatchAction(vfd)
			require.NoError(t, err)

			if tc.skip {
				if action.Type != Skip {
					t.Fatalf("Expected action skip but is %v", action.Type)
				}
			} else if action != nil && action.Type == Skip {
				t.Fatalf("Expected action not skip but is %v", action.Type)
			}
		})
	}
}

func TestGetMatchAction_Errors(t *testing.T) {
	p := &Policies{}

	testCases := []struct {
		name        string
		input       any
		expectedErr string
	}{
		{
			name:        "invalid input type",
			input:       "invalid input",
			expectedErr: "failed to convert input to VolumeFilterData",
		},
		{
			name: "no volume provided",
			input: VolumeFilterData{
				PersistentVolume: nil,
				PodVolume:        nil,
				PVC:              nil,
			},
			expectedErr: "failed to convert object",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			action, err := p.GetMatchAction(tc.input)
			require.ErrorContains(t, err, tc.expectedErr)
			assert.Nil(t, action)
		})
	}
}

func TestParsePVC(t *testing.T) {
	tests := []struct {
		name                string
		pvc                 *corev1api.PersistentVolumeClaim
		expectedLabels      map[string]string
		expectedPhase       string
		expectedVolumeMode  string
		expectedAccessModes []string
		expectErr           bool
	}{
		{
			name: "valid PVC with labels, Pending phase, Block volume mode, and access modes",
			pvc: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"env": "prod"},
				},
				Spec: corev1api.PersistentVolumeClaimSpec{
					VolumeMode:  pvcVolumeMode(corev1api.PersistentVolumeBlock),
					AccessModes: []corev1api.PersistentVolumeAccessMode{corev1api.ReadWriteOnce, corev1api.ReadOnlyMany},
				},
				Status: corev1api.PersistentVolumeClaimStatus{
					Phase: corev1api.ClaimPending,
				},
			},
			expectedLabels:      map[string]string{"env": "prod"},
			expectedPhase:       "Pending",
			expectedVolumeMode:  "Block",
			expectedAccessModes: []string{"ReadWriteOnce", "ReadOnlyMany"},
			expectErr:           false,
		},
		{
			name: "valid PVC with Bound phase and nil volume mode",
			pvc: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{},
				},
				Status: corev1api.PersistentVolumeClaimStatus{
					Phase: corev1api.ClaimBound,
				},
			},
			expectedLabels:      nil,
			expectedPhase:       "Bound",
			expectedVolumeMode:  "",
			expectedAccessModes: nil,
			expectErr:           false,
		},
		{
			name: "valid PVC with Lost phase and Filesystem volume mode",
			pvc: &corev1api.PersistentVolumeClaim{
				Spec: corev1api.PersistentVolumeClaimSpec{
					VolumeMode: pvcVolumeMode(corev1api.PersistentVolumeFilesystem),
				},
				Status: corev1api.PersistentVolumeClaimStatus{
					Phase: corev1api.ClaimLost,
				},
			},
			expectedLabels:      nil,
			expectedPhase:       "Lost",
			expectedVolumeMode:  "Filesystem",
			expectedAccessModes: nil,
			expectErr:           false,
		},
		{
			name: "valid PVC with unknown non-nil volume mode",
			pvc: &corev1api.PersistentVolumeClaim{
				Spec: corev1api.PersistentVolumeClaimSpec{
					VolumeMode: pvcVolumeMode(corev1api.PersistentVolumeMode("foo")),
				},
				Status: corev1api.PersistentVolumeClaimStatus{
					Phase: corev1api.ClaimBound,
				},
			},
			expectedLabels:      nil,
			expectedPhase:       "Bound",
			expectedVolumeMode:  "foo",
			expectedAccessModes: nil,
			expectErr:           false,
		},
		{
			name:                "nil PVC pointer",
			pvc:                 (*corev1api.PersistentVolumeClaim)(nil),
			expectedLabels:      nil,
			expectedPhase:       "",
			expectedVolumeMode:  "",
			expectedAccessModes: nil,
			expectErr:           false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &structuredVolume{}
			s.parsePVC(tc.pvc)

			assert.Equal(t, tc.expectedLabels, s.pvcLabels)
			assert.Equal(t, tc.expectedPhase, s.pvcPhase)
			assert.Equal(t, tc.expectedVolumeMode, s.pvcVolumeMode)
			assert.Equal(t, tc.expectedAccessModes, s.pvcAccessModes)
		})
	}
}

func TestPVCPhaseMatch(t *testing.T) {
	tests := []struct {
		name          string
		condition     *pvcPhaseCondition
		volume        *structuredVolume
		expectedMatch bool
	}{
		{
			name:          "match Pending phase",
			condition:     &pvcPhaseCondition{phases: []string{"Pending"}},
			volume:        &structuredVolume{pvcPhase: "Pending"},
			expectedMatch: true,
		},
		{
			name:          "match multiple phases - Pending matches",
			condition:     &pvcPhaseCondition{phases: []string{"Pending", "Bound"}},
			volume:        &structuredVolume{pvcPhase: "Pending"},
			expectedMatch: true,
		},
		{
			name:          "match multiple phases - Bound matches",
			condition:     &pvcPhaseCondition{phases: []string{"Pending", "Bound"}},
			volume:        &structuredVolume{pvcPhase: "Bound"},
			expectedMatch: true,
		},
		{
			name:          "no match for different phase",
			condition:     &pvcPhaseCondition{phases: []string{"Pending"}},
			volume:        &structuredVolume{pvcPhase: "Bound"},
			expectedMatch: false,
		},
		{
			name:          "no match for empty phase",
			condition:     &pvcPhaseCondition{phases: []string{"Pending"}},
			volume:        &structuredVolume{pvcPhase: ""},
			expectedMatch: false,
		},
		{
			name:          "match with empty phases list (always match)",
			condition:     &pvcPhaseCondition{phases: []string{}},
			volume:        &structuredVolume{pvcPhase: "Pending"},
			expectedMatch: true,
		},
		{
			name:          "match with nil phases list (always match)",
			condition:     &pvcPhaseCondition{phases: nil},
			volume:        &structuredVolume{pvcPhase: "Pending"},
			expectedMatch: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.condition.match(tc.volume)
			assert.Equal(t, tc.expectedMatch, result)
		})
	}
}

func TestNamespacedFilterPolicies(t *testing.T) {
	testCases := []struct {
		name     string
		yamlData string
		wantErr  bool
		errMsg   string
	}{
		{
			name: "valid namespacedFilterPolicies with multiple kinds",
			yamlData: `version: v1
namespacedFilterPolicies:
- namespaces: ["frontend", "backend"]
  resourceFilters:
  - kinds: ["Pod", "ConfigMap"]
    labelSelector:
      app: web
    names: ["app-*"]
  - kinds: ["Secret"]
    excludedNames: ["temp-*"]`,
			wantErr: false,
		},
		{
			name: "valid namespacedFilterPolicies with glob patterns",
			yamlData: `version: v1
namespacedFilterPolicies:
- namespaces: ["team-*"]
  resourceFilters:
  - kinds: ["Pod"]
    orLabelSelectors:
    - env: prod
    - env: staging`,
			wantErr: false,
		},
		{
			name: "valid - overlapping patterns allowed (first-match semantics)",
			yamlData: `version: v1
namespacedFilterPolicies:
- namespaces: ["team-frontend-*"]
  resourceFilters:
  - kinds: ["Pod", "ConfigMap", "Secret"]
- namespaces: ["team-*"]
  resourceFilters:
  - kinds: ["Deployment", "Service"]`,
			wantErr: false,
		},
		{
			name: "invalid - no namespaces",
			yamlData: `version: v1
namespacedFilterPolicies:
- namespaces: []
  resourceFilters:
  - kinds: ["Pod"]`,
			wantErr: true,
			errMsg:  "at least one namespace must be specified",
		},
		{
			name: "invalid - no resourceFilters",
			yamlData: `version: v1
namespacedFilterPolicies:
- namespaces: ["test"]
  resourceFilters: []`,
			wantErr: true,
			errMsg:  "at least one resourceFilter must be specified",
		},
		{
			name: "valid - asterisk catch-all",
			yamlData: `version: v1
namespacedFilterPolicies:
- namespaces: ["test"]
  resourceFilters:
  - kinds: ["*"]
    labelSelector:
      app: web`,
			wantErr: false,
		},
		{
			name: "invalid - multiple asterisk kinds",
			yamlData: `version: v1
namespacedFilterPolicies:
- namespaces: ["test"]
  resourceFilters:
  - kinds: ["*"]
    labelSelector:
      app: web
  - kinds: ["*"]
    labelSelector:
      app: db`,
			wantErr: true,
			errMsg:  "only one catch-all resource filter is allowed",
		},
		{
			name: "invalid - empty and asterisk kinds",
			yamlData: `version: v1
namespacedFilterPolicies:
- namespaces: ["test"]
  resourceFilters:
  - kinds: []
    labelSelector:
      app: web
  - kinds: ["*"]
    labelSelector:
      app: db`,
			wantErr: true,
			errMsg:  "only one catch-all resource filter is allowed",
		},
		{
			name: "invalid - multiple empty kinds",
			yamlData: `version: v1
namespacedFilterPolicies:
- namespaces: ["test"]
  resourceFilters:
  - kinds: []
    labelSelector:
      app: web
  - kinds: []
    labelSelector:
      app: db`,
			wantErr: true,
			errMsg:  "only one catch-all resource filter is allowed",
		},
		{
			name: "invalid - names with empty kinds",
			yamlData: `version: v1
namespacedFilterPolicies:
- namespaces: ["test"]
  resourceFilters:
  - kinds: []
    names: ["app-*"]
    labelSelector:
      app: web`,
			wantErr: true,
			errMsg:  "names or excludedNames cannot be specified for catch-all filters",
		},
		{
			name: "invalid - excludedNames with empty kinds",
			yamlData: `version: v1
namespacedFilterPolicies:
- namespaces: ["test"]
  resourceFilters:
  - kinds: []
    excludedNames: ["app-*"]
    labelSelector:
      app: web`,
			wantErr: true,
			errMsg:  "names or excludedNames cannot be specified for catch-all filters",
		},
		{
			name: "valid - no label selectors with catch-all",
			yamlData: `version: v1
namespacedFilterPolicies:
- namespaces: ["test"]
  resourceFilters:
  - kinds: ["*"]`,
			wantErr: false,
		},
		{
			name: "invalid - duplicate kinds",
			yamlData: `version: v1
namespacedFilterPolicies:
- namespaces: ["test"]
  resourceFilters:
  - kinds: ["Pod"]
  - kinds: ["Pod", "ConfigMap"]`,
			wantErr: true,
			errMsg:  "kind \"Pod\" appears in both resourceFilters",
		},
		{
			name: "invalid - both labelSelector and orLabelSelectors",
			yamlData: `version: v1
namespacedFilterPolicies:
- namespaces: ["test"]
  resourceFilters:
  - kinds: ["Pod"]
    labelSelector:
      app: web
    orLabelSelectors:
    - env: prod`,
			wantErr: true,
			errMsg:  "labelSelector and orLabelSelectors cannot co-exist",
		},
		{
			name: "invalid - bad glob pattern in names",
			yamlData: `version: v1
namespacedFilterPolicies:
- namespaces: ["test"]
  resourceFilters:
  - kinds: ["Pod"]
    names: ["[invalid"]`,
			wantErr: true,
			errMsg:  "invalid glob pattern",
		},
		{
			name: "invalid - bad glob pattern in excludedNames",
			yamlData: `version: v1
namespacedFilterPolicies:
- namespaces: ["test"]
  resourceFilters:
  - kinds: ["Pod"]
    excludedNames: ["[invalid"]`,
			wantErr: true,
			errMsg:  "invalid glob pattern",
		},
		{
			name: "invalid - duplicate namespace pattern",
			yamlData: `version: v1
namespacedFilterPolicies:
- namespaces: ["production"]
  resourceFilters:
  - kinds: ["Pod"]
- namespaces: ["production"]
  resourceFilters:
  - kinds: ["ConfigMap"]`,
			wantErr: true,
			errMsg:  "duplicate namespace pattern",
		},
		{
			name: "invalid - bad namespace pattern",
			yamlData: `version: v1
namespacedFilterPolicies:
- namespaces: ["prod**uction"]
  resourceFilters:
  - kinds: ["Pod"]`,
			wantErr: true,
			errMsg:  "wildcard pattern contains consecutive asterisks",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resPolicies, err := unmarshalResourcePolicies(&tc.yamlData)
			require.NoError(t, err) // Unmarshal should always succeed for our test cases

			policies := &Policies{}
			err = policies.BuildPolicy(resPolicies)
			require.NoError(t, err) // BuildPolicy should always succeed for our test cases

			err = policies.Validate()
			if tc.wantErr {
				require.Error(t, err)
				if tc.errMsg != "" {
					assert.Contains(t, err.Error(), tc.errMsg)
				}
			} else {
				require.NoError(t, err)

				// Verify that we can retrieve the policies
				nfPolicies := policies.GetNamespacedFilterPolicies()
				assert.GreaterOrEqual(t, len(nfPolicies), 1) // Valid test cases have at least 1 policy
			}
		})
	}
}

func TestNamespacedFilterPoliciesAccessor(t *testing.T) {
	yamlData := `version: v1
namespacedFilterPolicies:
- namespaces: ["frontend"]
  resourceFilters:
  - kinds: ["Pod"]
    labelSelector:
      app: web`

	resPolicies, err := unmarshalResourcePolicies(&yamlData)
	require.NoError(t, err)

	policies := &Policies{}
	err = policies.BuildPolicy(resPolicies)
	require.NoError(t, err)

	nfPolicies := policies.GetNamespacedFilterPolicies()
	require.Len(t, nfPolicies, 1)

	policy := nfPolicies[0]
	assert.Equal(t, []string{"frontend"}, policy.Namespaces)
	assert.Len(t, policy.ResourceFilters, 1)

	rf := policy.ResourceFilters[0]
	assert.Equal(t, []string{"Pod"}, rf.Kinds)
	assert.Equal(t, map[string]string{"app": "web"}, rf.LabelSelector)
}

func TestClusterScopedFilterPoliciesAccessor(t *testing.T) {
	yamlData := `version: v1
clusterScopedFilterPolicy:
  resourceFilters:
  - kinds: ["ClusterRole"]
    names: ["my-app-*"]`

	resPolicies, err := unmarshalResourcePolicies(&yamlData)
	require.NoError(t, err)

	policies := &Policies{}
	err = policies.BuildPolicy(resPolicies)
	require.NoError(t, err)

	csfPolicy := policies.GetClusterScopedFilterPolicy()
	require.NotNil(t, csfPolicy)
	assert.Len(t, csfPolicy.ResourceFilters, 1)

	rf := csfPolicy.ResourceFilters[0]
	assert.Equal(t, []string{"ClusterRole"}, rf.Kinds)
	assert.Equal(t, []string{"my-app-*"}, rf.Names)
}

func TestIncludeExcludePolicyAccessor(t *testing.T) {
	yamlData := `version: v1
includeExcludePolicy:
  includedClusterScopedResources:
  - ClusterRole
  excludedClusterScopedResources:
  - ClusterRoleBinding`

	resPolicies, err := unmarshalResourcePolicies(&yamlData)
	require.NoError(t, err)

	policies := &Policies{}
	err = policies.BuildPolicy(resPolicies)
	require.NoError(t, err)

	iePolicy := policies.GetIncludeExcludePolicy()
	require.NotNil(t, iePolicy)
	assert.Equal(t, []string{"ClusterRole"}, iePolicy.IncludedClusterScopedResources)
	assert.Equal(t, []string{"ClusterRoleBinding"}, iePolicy.ExcludedClusterScopedResources)
}

func TestFirstMatchSemantics(t *testing.T) {
	yamlData := `version: v1
namespacedFilterPolicies:
- namespaces: ["team-frontend-*", "specific-ns"]
  resourceFilters:
  - kinds: ["Pod", "ConfigMap", "Secret"]
- namespaces: ["team-*", "another-pattern"]
  resourceFilters:
  - kinds: ["Deployment", "Service"]`

	resPolicies, err := unmarshalResourcePolicies(&yamlData)
	require.NoError(t, err)

	policies := &Policies{}
	err = policies.BuildPolicy(resPolicies)
	require.NoError(t, err)

	err = policies.Validate()
	require.NoError(t, err)

	nfPolicies := policies.GetNamespacedFilterPolicies()
	require.Len(t, nfPolicies, 2)

	// Verify the first policy has the more specific patterns
	policy1 := nfPolicies[0]
	assert.Equal(t, []string{"team-frontend-*", "specific-ns"}, policy1.Namespaces)
	assert.Equal(t, []string{"Pod", "ConfigMap", "Secret"}, policy1.ResourceFilters[0].Kinds)

	// Verify the second policy has the broader patterns
	policy2 := nfPolicies[1]
	assert.Equal(t, []string{"team-*", "another-pattern"}, policy2.Namespaces)
	assert.Equal(t, []string{"Deployment", "Service"}, policy2.ResourceFilters[0].Kinds)
}

func TestClusterScopedFilterPolicies(t *testing.T) {
	testCases := []struct {
		name     string
		yamlData string
		wantErr  bool
		errMsg   string
	}{
		{
			name: "valid - single kind with names",
			yamlData: `version: v1
clusterScopedFilterPolicy:
  resourceFilters:
  - kinds: ["ClusterRole"]
    names: ["my-app-*"]`,
			wantErr: false,
		},
		{
			name: "valid - multi-kind with labelSelector",
			yamlData: `version: v1
clusterScopedFilterPolicy:
  resourceFilters:
  - kinds: ["ClusterRole", "ClusterRoleBinding"]
    labelSelector:
      app: my-app`,
			wantErr: false,
		},
		{
			name: "valid - orLabelSelectors",
			yamlData: `version: v1
clusterScopedFilterPolicy:
  resourceFilters:
  - kinds: ["CustomResourceDefinition"]
    orLabelSelectors:
    - app: my-app
    - app: other-app`,
			wantErr: false,
		},
		{
			name: "valid - excludedNames",
			yamlData: `version: v1
clusterScopedFilterPolicy:
  resourceFilters:
  - kinds: ["ClusterRole"]
    names: ["my-*"]
    excludedNames: ["my-debug-*"]`,
			wantErr: false,
		},
		{
			name: "invalid - empty resourceFilters",
			yamlData: `version: v1
clusterScopedFilterPolicy:
  resourceFilters: []`,
			wantErr: true,
			errMsg:  "resourceFilters cannot be empty; remove the policy block entirely if it is not needed",
		},
		{
			name: "invalid - empty kinds in clusterScopedFilterPolicy",
			yamlData: `version: v1
clusterScopedFilterPolicy:
  resourceFilters:
  - kinds: []
    names: ["my-app-*"]`,
			wantErr: true,
			errMsg:  "kinds must be specified",
		},
		{
			name: "invalid - asterisk kinds (explicit catch-all) in clusterScopedFilterPolicy",
			yamlData: `version: v1
clusterScopedFilterPolicy:
  resourceFilters:
  - kinds: ["*"]
    labelSelector:
      app: my-app`,
			wantErr: true,
			errMsg:  "kinds must be specified",
		},
		{
			name: "invalid - duplicate kinds across entries",
			yamlData: `version: v1
clusterScopedFilterPolicy:
  resourceFilters:
  - kinds: ["ClusterRole"]
    names: ["my-app-*"]
  - kinds: ["ClusterRole"]
    labelSelector:
      app: other`,
			wantErr: true,
			errMsg:  `kind "ClusterRole" appears in both`,
		},
		{
			name: "invalid - labelSelector and orLabelSelectors co-exist",
			yamlData: `version: v1
clusterScopedFilterPolicy:
  resourceFilters:
  - kinds: ["ClusterRole"]
    labelSelector:
      app: my-app
    orLabelSelectors:
    - app: other`,
			wantErr: true,
			errMsg:  "labelSelector and orLabelSelectors cannot co-exist",
		},
		{
			name: "invalid - bad glob in names",
			yamlData: `version: v1
clusterScopedFilterPolicy:
  resourceFilters:
  - kinds: ["ClusterRole"]
    names: ["[invalid"]`,
			wantErr: true,
			errMsg:  "invalid glob pattern",
		},
		{
			name: "invalid - bad glob in excludedNames",
			yamlData: `version: v1
clusterScopedFilterPolicy:
  resourceFilters:
  - kinds: ["ClusterRole"]
    excludedNames: ["[bad"]`,
			wantErr: true,
			errMsg:  "invalid glob pattern",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resPolicies, err := unmarshalResourcePolicies(&tc.yamlData)
			require.NoError(t, err)

			policies := &Policies{}
			err = policies.BuildPolicy(resPolicies)
			require.NoError(t, err)

			err = policies.Validate()
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestPVCVolumeModeMatch(t *testing.T) {
	tests := []struct {
		name          string
		condition     *pvcVolumeModeCondition
		volume        *structuredVolume
		expectedMatch bool
	}{
		{
			name:          "match Block volume mode",
			condition:     &pvcVolumeModeCondition{volumeMode: "Block"},
			volume:        &structuredVolume{pvcVolumeMode: "Block"},
			expectedMatch: true,
		},
		{
			name:          "match Filesystem volume mode",
			condition:     &pvcVolumeModeCondition{volumeMode: "Filesystem"},
			volume:        &structuredVolume{pvcVolumeMode: "Filesystem"},
			expectedMatch: true,
		},
		{
			name:          "no match for different volume mode",
			condition:     &pvcVolumeModeCondition{volumeMode: "Block"},
			volume:        &structuredVolume{pvcVolumeMode: "Filesystem"},
			expectedMatch: false,
		},
		{
			name:          "case-sensitive no match for lowercase volume mode",
			condition:     &pvcVolumeModeCondition{volumeMode: "block"},
			volume:        &structuredVolume{pvcVolumeMode: "Block"},
			expectedMatch: false,
		},
		{
			name:          "no match for unknown condition value against Filesystem",
			condition:     &pvcVolumeModeCondition{volumeMode: "foo"},
			volume:        &structuredVolume{pvcVolumeMode: "Filesystem"},
			expectedMatch: false,
		},
		{
			name:          "match unknown condition value only when volume has same value",
			condition:     &pvcVolumeModeCondition{volumeMode: "foo"},
			volume:        &structuredVolume{pvcVolumeMode: "foo"},
			expectedMatch: true,
		},
		{
			name:          "no match for empty volume mode",
			condition:     &pvcVolumeModeCondition{volumeMode: "Block"},
			volume:        &structuredVolume{pvcVolumeMode: ""},
			expectedMatch: false,
		},
		{
			name:          "match with empty volume mode condition (always match)",
			condition:     &pvcVolumeModeCondition{volumeMode: ""},
			volume:        &structuredVolume{pvcVolumeMode: "Block"},
			expectedMatch: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.condition.match(tc.volume)
			assert.Equal(t, tc.expectedMatch, result)
		})
	}
}

func TestPVCAccessModesMatch(t *testing.T) {
	tests := []struct {
		name          string
		condition     *pvcAccessModesCondition
		volume        *structuredVolume
		expectedMatch bool
	}{
		{
			name:          "match ReadWriteOnce access mode",
			condition:     &pvcAccessModesCondition{accessModes: []string{"ReadWriteOnce"}},
			volume:        &structuredVolume{pvcAccessModes: []string{"ReadWriteOnce"}},
			expectedMatch: true,
		},
		{
			name:          "match exact multiple access modes",
			condition:     &pvcAccessModesCondition{accessModes: []string{"ReadWriteOnce", "ReadOnlyMany"}},
			volume:        &structuredVolume{pvcAccessModes: []string{"ReadWriteOnce", "ReadOnlyMany"}},
			expectedMatch: true,
		},
		{
			name:          "match exact multiple access modes regardless of order",
			condition:     &pvcAccessModesCondition{accessModes: []string{"ReadOnlyMany", "ReadWriteOnce"}},
			volume:        &structuredVolume{pvcAccessModes: []string{"ReadWriteOnce", "ReadOnlyMany"}},
			expectedMatch: true,
		},
		{
			name:          "no match when one of multiple access modes is missing",
			condition:     &pvcAccessModesCondition{accessModes: []string{"ReadWriteOnce", "ReadOnlyMany"}},
			volume:        &structuredVolume{pvcAccessModes: []string{"ReadOnlyMany"}},
			expectedMatch: false,
		},
		{
			name:          "no match when PVC has extra access modes",
			condition:     &pvcAccessModesCondition{accessModes: []string{"ReadWriteMany"}},
			volume:        &structuredVolume{pvcAccessModes: []string{"ReadWriteOnce", "ReadWriteMany"}},
			expectedMatch: false,
		},
		{
			name:          "no match for different access mode",
			condition:     &pvcAccessModesCondition{accessModes: []string{"ReadWriteOnce"}},
			volume:        &structuredVolume{pvcAccessModes: []string{"ReadWriteMany"}},
			expectedMatch: false,
		},
		{
			name:          "case-sensitive no match for lowercase access mode",
			condition:     &pvcAccessModesCondition{accessModes: []string{"readwriteonce"}},
			volume:        &structuredVolume{pvcAccessModes: []string{"ReadWriteOnce"}},
			expectedMatch: false,
		},
		{
			name:          "no match for empty PVC access modes",
			condition:     &pvcAccessModesCondition{accessModes: []string{"ReadWriteOnce"}},
			volume:        &structuredVolume{pvcAccessModes: []string{}},
			expectedMatch: false,
		},
		{
			name:          "match with empty access modes list (always match)",
			condition:     &pvcAccessModesCondition{accessModes: []string{}},
			volume:        &structuredVolume{pvcAccessModes: []string{"ReadWriteOnce"}},
			expectedMatch: true,
		},
		{
			name:          "match with nil access modes list (always match)",
			condition:     &pvcAccessModesCondition{accessModes: nil},
			volume:        &structuredVolume{pvcAccessModes: []string{"ReadWriteOnce"}},
			expectedMatch: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.condition.match(tc.volume)
			assert.Equal(t, tc.expectedMatch, result)
		})
	}
}

// ---- Global backup volume policies ----

func globalPolicyConfigMap(name, data string) *corev1api.ConfigMap {
	return &corev1api.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "velero", Name: name},
		Data:       map[string]string{"policies.yaml": data},
	}
}

func backupWithPolicy(ref string) velerov1api.Backup {
	b := velerov1api.Backup{ObjectMeta: metav1.ObjectMeta{Namespace: "velero", Name: "backup"}}
	if ref != "" {
		b.Spec.ResourcePolicy = &corev1api.TypedLocalObjectReference{Kind: ConfigmapRefType, Name: ref}
	}
	return b
}

// firstActionFor returns the action type the policies select for a PV with the given storage
// class, or "" when nothing matches. It exercises the compiled match logic so the tests verify
// merge ordering rather than internal field layout.
func firstActionFor(p *Policies, storageClass string) VolumeActionType {
	pv := &corev1api.PersistentVolume{Spec: corev1api.PersistentVolumeSpec{StorageClassName: storageClass}}
	vol := &structuredVolume{}
	vol.parsePV(pv)
	if a := p.match(vol); a != nil {
		return a.Type
	}
	return ""
}

func TestGetResourcePoliciesFromBackupWithGlobal(t *testing.T) {
	gp2Skip := `version: v1
volumePolicies:
  - conditions:
      storageClass:
        - gp2
    action:
      type: skip
`
	gp2Snapshot := `version: v1
volumePolicies:
  - conditions:
      storageClass:
        - gp2
    action:
      type: snapshot
`
	otherFsBackup := `version: v1
volumePolicies:
  - conditions:
      storageClass:
        - other
    action:
      type: fs-backup
`

	tests := []struct {
		name                string
		backupCM            *corev1api.ConfigMap
		globalCMName        string
		globalCM            *corev1api.ConfigMap
		backupRef           string
		expectErr           bool
		expectedGp2Action   VolumeActionType
		expectedNumPolicies int
	}{
		{
			name:                "no global, backup only - unchanged behavior",
			backupRef:           "backup01",
			backupCM:            globalPolicyConfigMap("backup01", gp2Snapshot),
			expectedGp2Action:   Snapshot,
			expectedNumPolicies: 1,
		},
		{
			name:                "global only, backup has no policy",
			globalCMName:        "global",
			globalCM:            globalPolicyConfigMap("global", gp2Skip),
			expectedGp2Action:   Skip,
			expectedNumPolicies: 1,
		},
		{
			name:                "no global configured and no backup policy",
			expectedGp2Action:   "",
			expectedNumPolicies: 0,
		},
		{
			name:                "merge - backup policy overrides global for gp2",
			backupRef:           "backup01",
			backupCM:            globalPolicyConfigMap("backup01", gp2Snapshot),
			globalCMName:        "global",
			globalCM:            globalPolicyConfigMap("global", gp2Skip),
			expectedGp2Action:   Snapshot, // backup-level wins (evaluated first)
			expectedNumPolicies: 2,
		},
		{
			name:                "merge - backup inherits non-overlapping global rule",
			backupRef:           "backup01",
			backupCM:            globalPolicyConfigMap("backup01", otherFsBackup),
			globalCMName:        "global",
			globalCM:            globalPolicyConfigMap("global", gp2Skip),
			expectedGp2Action:   Skip, // only global matches gp2
			expectedNumPolicies: 2,
		},
		{
			name:         "global configmap missing - error",
			globalCMName: "global",
			expectErr:    true,
		},
		{
			name:         "global configmap invalid - error",
			globalCMName: "global",
			globalCM:     globalPolicyConfigMap("global", "not: [valid"),
			expectErr:    true,
		},
		{
			// Parses cleanly but fails Policies.Validate() due to the unsupported version.
			name:         "global configmap fails validation - error",
			globalCMName: "global",
			globalCM:     globalPolicyConfigMap("global", "version: v2\nvolumePolicies: []\n"),
			expectErr:    true,
		},
		{
			// Backup references a ResourcePolicy ConfigMap that does not exist, so resolving the
			// backup-level policies fails before the global ones are consulted.
			name:         "backup configmap missing - error",
			backupRef:    "missing-backup-cm",
			globalCMName: "global",
			globalCM:     globalPolicyConfigMap("global", gp2Skip),
			expectErr:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := velerotest.NewFakeControllerRuntimeClient(t)
			if tc.backupCM != nil {
				require.NoError(t, client.Create(t.Context(), tc.backupCM))
			}
			if tc.globalCM != nil {
				require.NoError(t, client.Create(t.Context(), tc.globalCM))
			}

			b := backupWithPolicy(tc.backupRef)

			p, err := GetResourcePoliciesFromBackupWithGlobal(b, client, tc.globalCMName, "velero", logrus.New())
			if tc.expectErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			if tc.expectedNumPolicies == 0 {
				assert.Nil(t, p)
				return
			}
			require.NotNil(t, p)
			assert.Len(t, p.volumePolicies, tc.expectedNumPolicies)
			assert.Equal(t, tc.expectedGp2Action, firstActionFor(p, "gp2"))
		})
	}
}

func TestGetGlobalResourcePoliciesIgnoresNonVolumePolicies(t *testing.T) {
	data := `version: v1
volumePolicies:
  - conditions:
      storageClass:
        - gp2
    action:
      type: skip
namespacedFilterPolicies:
- namespaces: ["frontend"]
  resourceFilters:
  - kinds: ["Pod"]
`
	client := velerotest.NewFakeControllerRuntimeClient(t)
	require.NoError(t, client.Create(t.Context(), globalPolicyConfigMap("global", data)))

	p, err := GetGlobalResourcePolicies(client, "velero", "global", logrus.New())
	require.NoError(t, err)
	require.NotNil(t, p)

	// Only volumePolicies are kept; the namespaced filter policy is dropped.
	assert.Len(t, p.volumePolicies, 1)
	assert.Empty(t, p.GetNamespacedFilterPolicies())
	assert.Nil(t, p.GetIncludeExcludePolicy())
	assert.Nil(t, p.GetClusterScopedFilterPolicy())
}

func TestActionGetDataMover(t *testing.T) {
	testCases := []struct {
		name         string
		action       *Action
		expectedMove string
		expectErr    bool
	}{
		{
			name:      "nil action",
			action:    nil,
			expectErr: true,
		},
		{
			name:         "snapshot action without parameters returns default mover",
			action:       &Action{Type: Snapshot},
			expectedMove: "velero-fs",
		},
		{
			name:         "snapshot action without dataMover parameter returns default mover",
			action:       &Action{Type: Snapshot, Parameters: map[string]any{"other": "value"}},
			expectedMove: "velero-fs",
		},
		{
			name:         "snapshot action with velero dataMover",
			action:       &Action{Type: Snapshot, Parameters: map[string]any{"dataMover": "velero"}},
			expectedMove: "velero",
		},
		{
			name:         "snapshot action with velero-fs dataMover",
			action:       &Action{Type: Snapshot, Parameters: map[string]any{"dataMover": "velero-fs"}},
			expectedMove: "velero-fs",
		},
		{
			name:         "snapshot action with velero-block dataMover",
			action:       &Action{Type: Snapshot, Parameters: map[string]any{"dataMover": "velero-block"}},
			expectedMove: "velero-block",
		},
		{
			name:      "non-snapshot action returns error",
			action:    &Action{Type: FSBackup, Parameters: map[string]any{"dataMover": "velero-fs"}},
			expectErr: true,
		},
		{
			name:      "snapshot action with non-string dataMover returns error",
			action:    &Action{Type: Snapshot, Parameters: map[string]any{"dataMover": 123}},
			expectErr: true,
		},
		{
			name:      "snapshot action with invalid dataMover returns error",
			action:    &Action{Type: Snapshot, Parameters: map[string]any{"dataMover": "unknown"}},
			expectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dataMover, err := tc.action.GetDataMover()
			if tc.expectErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.expectedMove, dataMover)
		})
	}
}
