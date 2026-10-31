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
