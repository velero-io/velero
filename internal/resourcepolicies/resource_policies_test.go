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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

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
	// Create a test ConfigMap
	cm := &corev1api.ConfigMap{
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
	}

	// Call the function and check for errors
	resPolicies, err := getResourcePoliciesFromConfig(cm)
	require.NoError(t, err)

	// Check that the returned resourcePolicies object contains the expected data
	assert.Equal(t, "v1", resPolicies.version)

	assert.Len(t, resPolicies.volumePolicies, 3)

	policies := ResourcePolicies{
		Version: "v1",
		VolumePolicies: []VolumePolicy{
			{
				Conditions: map[string]any{
					"capacity": "0,10Gi",
					"csi": map[string]any{
						"driver": "disks.csi.driver",
					},
				},
				Action: Action{
					Type: Skip,
				},
			},
			{
				Conditions: map[string]any{
					"csi": map[string]any{
						"driver":           "files.csi.driver",
						"volumeAttributes": map[string]string{"protocol": "nfs"},
					},
				},
				Action: Action{
					Type: Skip,
				},
			},
			{
				Conditions: map[string]any{
					"pvcLabels": map[string]string{
						"environment": "production",
					},
				},
				Action: Action{
					Type: Skip,
				},
			},
		},
	}

	p := &Policies{}
	err = p.BuildPolicy(&policies)
	if err != nil {
		t.Fatalf("failed to build policy: %v", err)
	}

	assert.Equal(t, p, resPolicies)
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
		name           string
		pvc            *corev1api.PersistentVolumeClaim
		expectedLabels map[string]string
		expectedPhase  string
		expectErr      bool
	}{
		{
			name: "valid PVC with labels and Pending phase",
			pvc: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"env": "prod"},
				},
				Status: corev1api.PersistentVolumeClaimStatus{
					Phase: corev1api.ClaimPending,
				},
			},
			expectedLabels: map[string]string{"env": "prod"},
			expectedPhase:  "Pending",
			expectErr:      false,
		},
		{
			name: "valid PVC with Bound phase",
			pvc: &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{},
				},
				Status: corev1api.PersistentVolumeClaimStatus{
					Phase: corev1api.ClaimBound,
				},
			},
			expectedLabels: nil,
			expectedPhase:  "Bound",
			expectErr:      false,
		},
		{
			name: "valid PVC with Lost phase",
			pvc: &corev1api.PersistentVolumeClaim{
				Status: corev1api.PersistentVolumeClaimStatus{
					Phase: corev1api.ClaimLost,
				},
			},
			expectedLabels: nil,
			expectedPhase:  "Lost",
			expectErr:      false,
		},
		{
			name:           "nil PVC pointer",
			pvc:            (*corev1api.PersistentVolumeClaim)(nil),
			expectedLabels: nil,
			expectedPhase:  "",
			expectErr:      false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &structuredVolume{}
			s.parsePVC(tc.pvc)

			assert.Equal(t, tc.expectedLabels, s.pvcLabels)
			assert.Equal(t, tc.expectedPhase, s.pvcPhase)
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

func TestActionGetDataMover(t *testing.T) {
	testCases := []struct {
		name         string
		action       *Action
		expectedMove string
		expectedOK   bool
	}{
		{
			name:       "nil action",
			action:     nil,
			expectedOK: false,
		},
		{
			name:       "snapshot action without parameters",
			action:     &Action{Type: Snapshot},
			expectedOK: false,
		},
		{
			name:         "snapshot action with velero-fs dataMover",
			action:       &Action{Type: Snapshot, Parameters: map[string]any{"dataMover": "velero-fs"}},
			expectedMove: "velero-fs",
			expectedOK:   true,
		},
		{
			name:         "snapshot action with velero-block dataMover",
			action:       &Action{Type: Snapshot, Parameters: map[string]any{"dataMover": "velero-block"}},
			expectedMove: "velero-block",
			expectedOK:   true,
		},
		{
			name:       "non-snapshot action ignores dataMover",
			action:     &Action{Type: FSBackup, Parameters: map[string]any{"dataMover": "velero-fs"}},
			expectedOK: false,
		},
		{
			name:       "snapshot action with non-string dataMover",
			action:     &Action{Type: Snapshot, Parameters: map[string]any{"dataMover": 123}},
			expectedOK: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dataMover, ok := tc.action.GetDataMover()
			assert.Equal(t, tc.expectedOK, ok)
			assert.Equal(t, tc.expectedMove, dataMover)
		})
	}
}
