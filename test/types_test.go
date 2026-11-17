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

package test

import "testing"

func TestFeatureEnabled(t *testing.T) {
	tests := []struct {
		name     string
		features string
		feature  string
		want     bool
	}{
		{"empty value", "", FeatureCSI, false},
		{"exact match", "EnableCSI", FeatureCSI, true},
		{"different case", "enablecsi", FeatureCSI, true},
		{"first of a list", "EnableCSI,EnableAPIGroupVersions", FeatureCSI, true},
		{"last of a list", "EnableAPIGroupVersions,EnableCSI", FeatureCSI, true},
		{"middle of a list", "A,EnableCSI,B", FeatureCSI, true},
		{"surrounding spaces", " EnableCSI ", FeatureCSI, true},
		{"spaces after a comma", "EnableAPIGroupVersions, EnableCSI", FeatureCSI, true},
		{"absent", "EnableAPIGroupVersions", FeatureCSI, false},
		{"longer name sharing the prefix", "EnableCSIFoo", FeatureCSI, false},
		{"name as a substring of another", "NotEnableCSI", FeatureCSI, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := FeatureEnabled(tc.features, tc.feature); got != tc.want {
				t.Errorf("FeatureEnabled(%q, %q) = %v, want %v", tc.features, tc.feature, got, tc.want)
			}
		})
	}
}

func TestSnapshotsAreRemote(t *testing.T) {
	tests := []struct {
		name          string
		cloudProvider string
		want          bool
	}{
		// The point of the helper: kind takes snapshots locally, so the fixed
		// waits the cloud providers need are dead time there.
		{"kind", Kind, false},
		{"kind with CSI", KindCSI, false},
		{"aws", AWS, true},
		{"aws with CSI", AwsCSI, true},
		{"azure", Azure, true},
		{"gcp", GCP, true},
		// vSphere is excluded from the pending-snapshot wait at its call site,
		// not here, so this helper must still report it as remote.
		{"vsphere", Vsphere, true},
		// An unrecognized provider keeps the waits rather than silently
		// dropping them.
		{"unknown", "some-new-provider", true},
		{"empty", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := SnapshotsAreRemote(tc.cloudProvider); got != tc.want {
				t.Errorf("SnapshotsAreRemote(%q) = %v, want %v", tc.cloudProvider, got, tc.want)
			}
		})
	}
}
