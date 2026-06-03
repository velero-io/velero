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
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

func setStructuredVolume(capacity resource.Quantity, sc string, nfs *nFSVolumeSource, csi *csiVolumeSource, pvcLabels map[string]string) *structuredVolume {
	return &structuredVolume{
		capacity:     capacity,
		storageClass: sc,
		nfs:          nfs,
		csi:          csi,
		pvcLabels:    pvcLabels,
	}
}

func TestPVCLabelsMatch(t *testing.T) {
	tests := []struct {
		name          string
		condition     *pvcLabelsCondition
		volume        *structuredVolume
		expectedMatch bool
	}{
		{
			name: "match exact label (single)",
			condition: &pvcLabelsCondition{
				labels: map[string]string{"environment": "production"},
			},
			volume: setStructuredVolume(
				*resource.NewQuantity(0, resource.BinarySI),
				"any",
				nil,
				nil,
				map[string]string{"environment": "production", "app": "database"},
			),
			expectedMatch: true,
		},
		{
			name: "match exact label (multiple)",
			condition: &pvcLabelsCondition{
				labels: map[string]string{"environment": "production", "app": "database"},
			},
			volume: setStructuredVolume(
				*resource.NewQuantity(0, resource.BinarySI),
				"any",
				nil,
				nil,
				map[string]string{"environment": "production", "app": "database"},
			),
			expectedMatch: true,
		},
		{
			name: "mismatch label value",
			condition: &pvcLabelsCondition{
				labels: map[string]string{"environment": "production"},
			},
			volume: setStructuredVolume(
				*resource.NewQuantity(0, resource.BinarySI),
				"any",
				nil,
				nil,
				map[string]string{"environment": "staging", "app": "database"},
			),
			expectedMatch: false,
		},
		{
			name: "missing label key",
			condition: &pvcLabelsCondition{
				labels: map[string]string{"environment": "production", "region": "us-west"},
			},
			volume: setStructuredVolume(
				*resource.NewQuantity(0, resource.BinarySI),
				"any",
				nil,
				nil,
				map[string]string{"environment": "production", "app": "database"},
			),
			expectedMatch: false,
		},
		{
			name: "empty condition always matches",
			condition: &pvcLabelsCondition{
				labels: map[string]string{},
			},
			volume: setStructuredVolume(
				*resource.NewQuantity(0, resource.BinarySI),
				"any",
				nil,
				nil,
				map[string]string{"environment": "staging"},
			),
			expectedMatch: true,
		},
		{
			name: "nil pvcLabels fails non-empty condition",
			condition: &pvcLabelsCondition{
				labels: map[string]string{"environment": "production"},
			},
			volume: setStructuredVolume(
				*resource.NewQuantity(0, resource.BinarySI),
				"any",
				nil,
				nil,
				nil,
			),
			expectedMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match := tt.condition.match(tt.volume)
			assert.Equal(t, tt.expectedMatch, match, "expected match %v, got %v", tt.expectedMatch, match)
		})
	}
}

func TestParseCapacity(t *testing.T) {
	var emptyCapacity capacity
	tests := []struct {
		input       string
		expected    capacity
		expectedErr error
	}{
		{"10Gi,20Gi", capacity{lower: *resource.NewQuantity(10<<30, resource.BinarySI), upper: *resource.NewQuantity(20<<30, resource.BinarySI)}, nil},
		{"10Gi,", capacity{lower: *resource.NewQuantity(10<<30, resource.BinarySI), upper: *resource.NewQuantity(0, resource.DecimalSI)}, nil},
		{"10Gi", emptyCapacity, fmt.Errorf("wrong format of Capacity 10Gi")},
		{"", emptyCapacity, nil},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			actual, actualErr := parseCapacity(test.input)
			if test.expected != emptyCapacity {
				assert.Equal(t, 0, test.expected.lower.Cmp(actual.lower))
				assert.Equal(t, 0, test.expected.upper.Cmp(actual.upper))
			}
			assert.Equal(t, test.expectedErr, actualErr)
		})
	}
}

func TestCapacityIsInRange(t *testing.T) {
	t.Parallel()

	tests := []struct {
		capacity  *capacity
		quantity  resource.Quantity
		isInRange bool
	}{
		{&capacity{*resource.NewQuantity(0, resource.BinarySI), *resource.NewQuantity(10<<30, resource.BinarySI)}, *resource.NewQuantity(5<<30, resource.BinarySI), true},
		{&capacity{*resource.NewQuantity(0, resource.BinarySI), *resource.NewQuantity(10<<30, resource.BinarySI)}, *resource.NewQuantity(15<<30, resource.BinarySI), false},
		{&capacity{*resource.NewQuantity(20<<30, resource.BinarySI), *resource.NewQuantity(0, resource.DecimalSI)}, *resource.NewQuantity(25<<30, resource.BinarySI), true},
		{&capacity{*resource.NewQuantity(20<<30, resource.BinarySI), *resource.NewQuantity(0, resource.DecimalSI)}, *resource.NewQuantity(15<<30, resource.BinarySI), false},
		{&capacity{*resource.NewQuantity(10<<30, resource.BinarySI), *resource.NewQuantity(20<<30, resource.BinarySI)}, *resource.NewQuantity(15<<30, resource.BinarySI), true},
		{&capacity{*resource.NewQuantity(10<<30, resource.BinarySI), *resource.NewQuantity(20<<30, resource.BinarySI)}, *resource.NewQuantity(5<<30, resource.BinarySI), false},
		{&capacity{*resource.NewQuantity(10<<30, resource.BinarySI), *resource.NewQuantity(20<<30, resource.BinarySI)}, *resource.NewQuantity(25<<30, resource.BinarySI), false},
		{&capacity{*resource.NewQuantity(0, resource.BinarySI), *resource.NewQuantity(0, resource.BinarySI)}, *resource.NewQuantity(5<<30, resource.BinarySI), true},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%v with %v", test.capacity, test.quantity), func(t *testing.T) {
			t.Parallel()

			actual := test.capacity.isInRange(test.quantity)

			assert.Equal(t, test.isInRange, actual)
		})
	}
}

func TestStorageClassConditionMatch(t *testing.T) {
	tests := []struct {
		name          string
		condition     *storageClassCondition
		volume        *structuredVolume
		expectedMatch bool
	}{
		{
			name:          "match single storage class",
			condition:     &storageClassCondition{[]string{"gp2"}},
			volume:        setStructuredVolume(*resource.NewQuantity(0, resource.BinarySI), "gp2", nil, nil, nil),
			expectedMatch: true,
		},
		{
			name:          "match multiple storage classes",
			condition:     &storageClassCondition{[]string{"gp2", "ebs-sc"}},
			volume:        setStructuredVolume(*resource.NewQuantity(0, resource.BinarySI), "gp2", nil, nil, nil),
			expectedMatch: true,
		},
		{
			name:          "mismatch storage class",
			condition:     &storageClassCondition{[]string{"gp2"}},
			volume:        setStructuredVolume(*resource.NewQuantity(0, resource.BinarySI), "ebs-sc", nil, nil, nil),
			expectedMatch: false,
		},
		{
			name:          "empty storage class",
			condition:     &storageClassCondition{[]string{}},
			volume:        setStructuredVolume(*resource.NewQuantity(0, resource.BinarySI), "ebs-sc", nil, nil, nil),
			expectedMatch: true,
		},
		{
			name:          "empty volume storage class",
			condition:     &storageClassCondition{[]string{"gp2"}},
			volume:        setStructuredVolume(*resource.NewQuantity(0, resource.BinarySI), "", nil, nil, nil),
			expectedMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match := tt.condition.match(tt.volume)
			if match != tt.expectedMatch {
				t.Errorf("expected %v, but got %v", tt.expectedMatch, match)
			}
		})
	}
}

func TestNFSConditionMatch(t *testing.T) {
	tests := []struct {
		name          string
		condition     *nfsCondition
		volume        *structuredVolume
		expectedMatch bool
	}{
		{
			name:          "match nfs condition",
			condition:     &nfsCondition{&nFSVolumeSource{Server: "192.168.10.20"}},
			volume:        setStructuredVolume(*resource.NewQuantity(0, resource.BinarySI), "", &nFSVolumeSource{Server: "192.168.10.20"}, nil, nil),
			expectedMatch: true,
		},
		{
			name:          "empty nfs condition",
			condition:     &nfsCondition{nil},
			volume:        setStructuredVolume(*resource.NewQuantity(0, resource.BinarySI), "", &nFSVolumeSource{Server: "192.168.10.20"}, nil, nil),
			expectedMatch: true,
		},
		{
			name:          "empty nfs server and path condition",
			condition:     &nfsCondition{&nFSVolumeSource{Server: "", Path: ""}},
			volume:        setStructuredVolume(*resource.NewQuantity(0, resource.BinarySI), "", &nFSVolumeSource{Server: "192.168.10.20"}, nil, nil),
			expectedMatch: true,
		},
		{
			name:          "server mismatch",
			condition:     &nfsCondition{&nFSVolumeSource{Server: "192.168.10.20", Path: ""}},
			volume:        setStructuredVolume(*resource.NewQuantity(0, resource.BinarySI), "", &nFSVolumeSource{Server: ""}, nil, nil),
			expectedMatch: false,
		},
		{
			name:          "empty nfs server condition",
			condition:     &nfsCondition{&nFSVolumeSource{Path: "/mnt/data"}},
			volume:        setStructuredVolume(*resource.NewQuantity(0, resource.BinarySI), "", &nFSVolumeSource{Server: "192.168.10.20", Path: "/mnt/data"}, nil, nil),
			expectedMatch: true,
		},
		{
			name:          "empty nfs volume",
			condition:     &nfsCondition{&nFSVolumeSource{Server: "192.168.10.20"}},
			volume:        setStructuredVolume(*resource.NewQuantity(0, resource.BinarySI), "", nil, nil, nil),
			expectedMatch: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match := tt.condition.match(tt.volume)
			if match != tt.expectedMatch {
				t.Errorf("expected %v, but got %v", tt.expectedMatch, match)
			}
		})
	}
}

func TestCSIConditionMatch(t *testing.T) {
	tests := []struct {
		name          string
		condition     *csiCondition
		volume        *structuredVolume
		expectedMatch bool
	}{
		{
			name:          "match csi driver condition",
			condition:     &csiCondition{&csiVolumeSource{Driver: "test"}},
			volume:        setStructuredVolume(*resource.NewQuantity(0, resource.BinarySI), "", nil, &csiVolumeSource{Driver: "test"}, nil),
			expectedMatch: true,
		},
		{
			name:          "empty csi driver condition",
			condition:     &csiCondition{nil},
			volume:        setStructuredVolume(*resource.NewQuantity(0, resource.BinarySI), "", nil, &csiVolumeSource{Driver: "test"}, nil),
			expectedMatch: true,
		},
		{
			name:          "empty csi driver volume",
			condition:     &csiCondition{&csiVolumeSource{Driver: "test"}},
			volume:        setStructuredVolume(*resource.NewQuantity(0, resource.BinarySI), "", nil, &csiVolumeSource{}, nil),
			expectedMatch: false,
		},
		{
			name:          "match csi volumeAttributes condition",
			condition:     &csiCondition{&csiVolumeSource{Driver: "test", VolumeAttributes: map[string]string{"protocol": "nfs"}}},
			volume:        setStructuredVolume(*resource.NewQuantity(0, resource.BinarySI), "", nil, &csiVolumeSource{Driver: "test", VolumeAttributes: map[string]string{"protocol": "nfs"}}, nil),
			expectedMatch: true,
		},
		{
			name:          "empty csi volumeAttributes condition",
			condition:     &csiCondition{&csiVolumeSource{Driver: "test"}},
			volume:        setStructuredVolume(*resource.NewQuantity(0, resource.BinarySI), "", nil, &csiVolumeSource{Driver: "test", VolumeAttributes: map[string]string{"protocol": "nfs"}}, nil),
			expectedMatch: true,
		},
		{
			name:          "empty csi volumeAttributes volume",
			condition:     &csiCondition{&csiVolumeSource{Driver: "test", VolumeAttributes: map[string]string{"protocol": "nfs"}}},
			volume:        setStructuredVolume(*resource.NewQuantity(0, resource.BinarySI), "", nil, &csiVolumeSource{Driver: "test", VolumeAttributes: map[string]string{"protocol": ""}}, nil),
			expectedMatch: false,
		},
		{
			name:          "empty csi volumeAttributes volume",
			condition:     &csiCondition{&csiVolumeSource{Driver: "test", VolumeAttributes: map[string]string{"protocol": "nfs"}}},
			volume:        setStructuredVolume(*resource.NewQuantity(0, resource.BinarySI), "", nil, &csiVolumeSource{Driver: "test"}, nil),
			expectedMatch: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match := tt.condition.match(tt.volume)
			if match != tt.expectedMatch {
				t.Errorf("expected %v, but got %v", tt.expectedMatch, match)
			}
		})
	}
}

func TestUnmarshalVolumeConditions(t *testing.T) {
	testCases := []struct {
		name          string
		input         map[string]any
		expectedError string
	}{
		{
			name: "Valid input",
			input: map[string]any{
				"capacity": "1Gi,10Gi",
				"storageClass": []string{
					"gp2",
					"ebs-sc",
				},
				"csi": &csiVolumeSource{
					Driver: "aws.efs.csi.driver",
				},
			},
			expectedError: "",
		},
		{
			name: "Invalid input: invalid capacity filed name",
			input: map[string]any{
				"Capacity": "1Gi,10Gi",
			},
			expectedError: "field Capacity not found",
		},
		{
			name: "Invalid input: invalid storage class format",
			input: map[string]any{
				"storageClass": "ebs-sc",
			},
			expectedError: "str `ebs-sc` into []string",
		},
		{
			name: "Invalid input: invalid csi format",
			input: map[string]any{
				"csi": "csi.driver",
			},
			expectedError: "str `csi.driver` into resourcepolicies.csiVolumeSource",
		},
		{
			name: "Invalid input: unknown field",
			input: map[string]any{
				"unknown": "foo",
			},
			expectedError: "field unknown not found in type",
		},
		{
			name: "Valid pvcLabels input as map[string]string",
			input: map[string]any{
				"capacity": "1Gi,10Gi",
				"pvcLabels": map[string]string{
					"environment": "production",
				},
			},
			expectedError: "",
		},
		{
			name: "Valid pvcLabels input as map[string]any",
			input: map[string]any{
				"capacity": "1Gi,10Gi",
				"pvcLabels": map[string]any{
					"environment": "production",
					"app":         "database",
				},
			},
			expectedError: "",
		},
		{
			name: "Invalid pvcLabels input: not a map",
			input: map[string]any{
				"capacity":  "1Gi,10Gi",
				"pvcLabels": "production",
			},
			expectedError: "!!str `production` into map[string]string",
		},
		{
			name: "Valid pvcVolumeMode input",
			input: map[string]any{
				"capacity":      "1Gi,10Gi",
				"pvcVolumeMode": []string{"Filesystem", "Block"},
			},
			expectedError: "",
		},
		{
			name: "Invalid pvcVolumeMode input: not a list",
			input: map[string]any{
				"capacity":      "1Gi,10Gi",
				"pvcVolumeMode": "Block",
			},
			expectedError: "str `Block` into []string",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := unmarshalVolConditions(tc.input)
			if tc.expectedError != "" {
				if err == nil {
					t.Errorf("Expected error '%s', but got nil", tc.expectedError)
				} else if !strings.Contains(err.Error(), tc.expectedError) {
					t.Errorf("Expected error '%s', but got '%v'", tc.expectedError, err)
				}
			}
		})
	}
}

func TestParsePodVolume(t *testing.T) {
	// Mock data
	nfsVolume := corev1api.Volume{}
	nfsVolume.NFS = &corev1api.NFSVolumeSource{
		Server: "nfs.example.com",
		Path:   "/exports/data",
	}
	csiVolume := corev1api.Volume{}
	csiVolume.CSI = &corev1api.CSIVolumeSource{
		Driver:           "csi.example.com",
		VolumeAttributes: map[string]string{"protocol": "nfs"},
	}
	emptyVolume := corev1api.Volume{}

	// Test cases
	testCases := []struct {
		name        string
		inputVolume *corev1api.Volume
		expectedNFS *nFSVolumeSource
		expectedCSI *csiVolumeSource
	}{
		{
			name:        "NFS volume",
			inputVolume: &nfsVolume,
			expectedNFS: &nFSVolumeSource{Server: "nfs.example.com", Path: "/exports/data"},
		},
		{
			name:        "CSI volume",
			inputVolume: &csiVolume,
			expectedCSI: &csiVolumeSource{Driver: "csi.example.com", VolumeAttributes: map[string]string{"protocol": "nfs"}},
		},
		{
			name:        "Empty volume",
			inputVolume: &emptyVolume,
			expectedNFS: nil,
			expectedCSI: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Call the function
			structuredVolume := &structuredVolume{}
			structuredVolume.parsePodVolume(tc.inputVolume)

			// Check the results
			if tc.expectedNFS != nil {
				if structuredVolume.nfs == nil {
					t.Errorf("Expected a non-nil NFS volume source")
				} else if *tc.expectedNFS != *structuredVolume.nfs {
					t.Errorf("NFS volume source does not match expected value")
				}
			}
			if tc.expectedCSI != nil {
				if structuredVolume.csi == nil {
					t.Errorf("Expected a non-nil CSI volume source")
				} else if tc.expectedCSI.Driver != structuredVolume.csi.Driver {
					t.Errorf("CSI volume source does not match expected value")
				}
				// Check volumeAttributes
				if len(tc.expectedCSI.VolumeAttributes) != len(structuredVolume.csi.VolumeAttributes) {
					t.Errorf("CSI volume attributes does not match expected value")
				} else {
					for k, v := range tc.expectedCSI.VolumeAttributes {
						if structuredVolume.csi.VolumeAttributes[k] != v {
							t.Errorf("CSI volume attributes does not match expected value")
						}
					}
				}
			}
		})
	}
}

func TestParsePV(t *testing.T) {
	// Mock data
	nfsVolume := corev1api.PersistentVolume{}
	nfsVolume.Spec.Capacity = corev1api.ResourceList{corev1api.ResourceStorage: resource.MustParse("1Gi")}
	nfsVolume.Spec.NFS = &corev1api.NFSVolumeSource{Server: "nfs.example.com", Path: "/exports/data"}
	csiVolume := corev1api.PersistentVolume{}
	csiVolume.Spec.Capacity = corev1api.ResourceList{corev1api.ResourceStorage: resource.MustParse("2Gi")}
	csiVolume.Spec.CSI = &corev1api.CSIPersistentVolumeSource{Driver: "csi.example.com", VolumeAttributes: map[string]string{"protocol": "nfs"}}
	emptyVolume := corev1api.PersistentVolume{}

	// Test cases
	testCases := []struct {
		name        string
		inputVolume *corev1api.PersistentVolume
		expectedNFS *nFSVolumeSource
		expectedCSI *csiVolumeSource
	}{
		{
			name:        "NFS volume",
			inputVolume: &nfsVolume,
			expectedNFS: &nFSVolumeSource{Server: "nfs.example.com", Path: "/exports/data"},
			expectedCSI: nil,
		},
		{
			name:        "CSI volume",
			inputVolume: &csiVolume,
			expectedNFS: nil,
			expectedCSI: &csiVolumeSource{Driver: "csi.example.com", VolumeAttributes: map[string]string{"protocol": "nfs"}},
		},
		{
			name:        "Empty volume",
			inputVolume: &emptyVolume,
			expectedNFS: nil,
			expectedCSI: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Call the function
			structuredVolume := &structuredVolume{}
			structuredVolume.parsePV(tc.inputVolume)
			// Check the results
			if structuredVolume.capacity != *tc.inputVolume.Spec.Capacity.Storage() {
				t.Errorf("capacity does not match expected value")
			}
			if structuredVolume.storageClass != tc.inputVolume.Spec.StorageClassName {
				t.Errorf("Storage class does not match expected value")
			}
			if tc.expectedNFS != nil {
				if structuredVolume.nfs == nil {
					t.Errorf("Expected a non-nil NFS volume source")
				} else if *tc.expectedNFS != *structuredVolume.nfs {
					t.Errorf("NFS volume source does not match expected value")
				}
			}
			if tc.expectedCSI != nil {
				if structuredVolume.csi == nil {
					t.Errorf("Expected a non-nil CSI volume source")
				} else if tc.expectedCSI.Driver != structuredVolume.csi.Driver {
					t.Errorf("CSI volume source does not match expected value")
				}
				// Check volumeAttributes
				if len(tc.expectedCSI.VolumeAttributes) != len(structuredVolume.csi.VolumeAttributes) {
					t.Errorf("CSI volume attributes does not match expected value")
				} else {
					for k, v := range tc.expectedCSI.VolumeAttributes {
						if structuredVolume.csi.VolumeAttributes[k] != v {
							t.Errorf("CSI volume attributes does not match expected value")
						}
					}
				}
			}
		})
	}
}
