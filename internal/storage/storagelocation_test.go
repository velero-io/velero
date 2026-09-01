/*Copyright 2020 the Velero contributors.

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

package storage

import (
	"testing"
	"time"

	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
	"github.com/vmware-tanzu/velero/pkg/util"
)

func TestIsReadyToValidate(t *testing.T) {
	tests := []struct {
		name                   string
		bslValidationFrequency *metav1.Duration
		lastValidationTime     *metav1.Time
		defaultLocationInfo    DefaultBackupLocationInfo
		ready                  bool
	}{
		{
			name:                   "validate when true when validation frequency is zero and lastValidationTime is nil",
			bslValidationFrequency: &metav1.Duration{Duration: 0},
			defaultLocationInfo: DefaultBackupLocationInfo{
				ServerValidationFrequency: 0,
			},
			ready: true,
		},
		{
			name:                   "don't validate when false when validation is disabled and lastValidationTime is not nil",
			bslValidationFrequency: &metav1.Duration{Duration: 0},
			lastValidationTime:     &metav1.Time{Time: time.Now()},
			defaultLocationInfo: DefaultBackupLocationInfo{
				ServerValidationFrequency: 0,
			},
			ready: false,
		},
		{
			name:                   "validate as per location setting, as that takes precedence, and always if it has never been validated before regardless of the frequency setting",
			bslValidationFrequency: &metav1.Duration{Duration: 1 * time.Hour},
			defaultLocationInfo: DefaultBackupLocationInfo{
				ServerValidationFrequency: 0,
			},
			ready: true,
		},
		{
			name:                   "don't validate as per location setting, as it is set to zero and that takes precedence",
			bslValidationFrequency: &metav1.Duration{Duration: 0},
			defaultLocationInfo: DefaultBackupLocationInfo{
				ServerValidationFrequency: 1,
			},
			lastValidationTime: &metav1.Time{Time: time.Now()},
			ready:              false,
		},
		{
			name: "validate as per default setting when location setting is not set",
			defaultLocationInfo: DefaultBackupLocationInfo{
				ServerValidationFrequency: 1,
			},
			ready: true,
		},
		{
			name: "don't validate when default setting is set to zero and the location setting is not set",
			defaultLocationInfo: DefaultBackupLocationInfo{
				ServerValidationFrequency: 0,
			},
			lastValidationTime: &metav1.Time{Time: time.Now()},
			ready:              false,
		},
		{
			name:                   "don't validate when now is before the NEXT validation time (validation frequency + last validation time)",
			bslValidationFrequency: &metav1.Duration{Duration: 1 * time.Second},
			lastValidationTime:     &metav1.Time{Time: time.Now()},
			defaultLocationInfo: DefaultBackupLocationInfo{
				ServerValidationFrequency: 0,
			},
			ready: false,
		},
		{
			name:                   "validate when now is equal to the NEXT validation time (validation frequency + last validation time)",
			bslValidationFrequency: &metav1.Duration{Duration: 1 * time.Second},
			lastValidationTime:     &metav1.Time{Time: time.Now().Add(-1 * time.Second)},
			defaultLocationInfo: DefaultBackupLocationInfo{
				ServerValidationFrequency: 0,
			},
			ready: true,
		},
		{
			name:                   "validate when now is after the NEXT validation time (validation frequency + last validation time)",
			bslValidationFrequency: &metav1.Duration{Duration: 1 * time.Second},
			lastValidationTime:     &metav1.Time{Time: time.Now().Add(-2 * time.Second)},
			defaultLocationInfo: DefaultBackupLocationInfo{
				ServerValidationFrequency: 0,
			},
			ready: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			log := velerotest.NewLogger()
			actual := IsReadyToValidate(tt.bslValidationFrequency, tt.lastValidationTime, tt.defaultLocationInfo.ServerValidationFrequency, log)
			g.Expect(actual).To(BeIdenticalTo(tt.ready))
		})
	}
}

func TestListBackupStorageLocations(t *testing.T) {
	tests := []struct {
		name            string
		backupLocations *velerov1api.BackupStorageLocationList
		expectError     bool
	}{
		{
			name: "1 existing location does not return an error",
			backupLocations: &velerov1api.BackupStorageLocationList{
				Items: []velerov1api.BackupStorageLocation{
					*builder.ForBackupStorageLocation("ns-1", "location-1").Result(),
				},
			},
			expectError: false,
		},
		{
			name: "multiple existing location does not return an error",
			backupLocations: &velerov1api.BackupStorageLocationList{
				Items: []velerov1api.BackupStorageLocation{
					*builder.ForBackupStorageLocation("ns-1", "location-1").Result(),
					*builder.ForBackupStorageLocation("ns-1", "location-2").Result(),
					*builder.ForBackupStorageLocation("ns-1", "location-3").Result(),
				},
			},
			expectError: false,
		},
		{
			name:            "no existing locations returns an error",
			backupLocations: &velerov1api.BackupStorageLocationList{},
			expectError:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			client := fake.NewClientBuilder().WithScheme(util.VeleroScheme).WithRuntimeObjects(tt.backupLocations).Build()
			if tt.expectError {
				_, err := ListBackupStorageLocations(t.Context(), client, "ns-1")
				g.Expect(err).To(HaveOccurred())
			} else {
				_, err := ListBackupStorageLocations(t.Context(), client, "ns-1")
				g.Expect(err).ToNot(HaveOccurred())
			}
		})
	}
}

func TestGetDefaultBackupStorageLocations(t *testing.T) {
	tests := []struct {
		name             string
		locations        *velerov1api.BackupStorageLocationList
		expectedDefaults []string
		expectedErr      bool
	}{
		{
			name: "no default locations",
			locations: &velerov1api.BackupStorageLocationList{
				Items: []velerov1api.BackupStorageLocation{
					*builder.ForBackupStorageLocation("ns-1", "loc-1").Default(false).Result(),
					*builder.ForBackupStorageLocation("ns-1", "loc-2").Default(false).Result(),
				},
			},
			expectedDefaults: nil,
			expectedErr:      false,
		},
		{
			name: "one default location",
			locations: &velerov1api.BackupStorageLocationList{
				Items: []velerov1api.BackupStorageLocation{
					*builder.ForBackupStorageLocation("ns-1", "loc-1").Default(false).Result(),
					*builder.ForBackupStorageLocation("ns-1", "loc-2").Default(true).Result(),
				},
			},
			expectedDefaults: []string{"loc-2"},
			expectedErr:      false,
		},
		{
			name: "multiple default locations",
			locations: &velerov1api.BackupStorageLocationList{
				Items: []velerov1api.BackupStorageLocation{
					*builder.ForBackupStorageLocation("ns-1", "loc-1").Default(true).Result(),
					*builder.ForBackupStorageLocation("ns-1", "loc-2").Default(true).Result(),
					*builder.ForBackupStorageLocation("ns-1", "loc-3").Default(false).Result(),
				},
			},
			expectedDefaults: []string{"loc-1", "loc-2"},
			expectedErr:      false,
		},
		{
			name:             "empty locations list",
			locations:        &velerov1api.BackupStorageLocationList{},
			expectedDefaults: nil,
			expectedErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			client := fake.NewClientBuilder().WithScheme(util.VeleroScheme).WithRuntimeObjects(tt.locations).Build()

			defaults, err := GetDefaultBackupStorageLocations(t.Context(), client, "ns-1")
			if tt.expectedErr {
				g.Expect(err).To(HaveOccurred())
			} else {
				g.Expect(err).ToNot(HaveOccurred())

				var defaultNames []string
				for _, loc := range defaults.Items {
					defaultNames = append(defaultNames, loc.Name)
				}

				if tt.expectedDefaults == nil {
					g.Expect(defaultNames).To(BeEmpty())
				} else {
					g.Expect(defaultNames).To(ConsistOf(tt.expectedDefaults))
				}
			}
		})
	}
}
