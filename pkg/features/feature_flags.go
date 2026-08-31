/*
Copyright 2019 the Velero contributors.

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

package features

import (
	"strings"

	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/vmware-tanzu/velero/pkg/util"
)

type featureFlagSet struct {
	set sets.Set[string]
}

// featureFlags will store all the flags for this process until NewFeatureFlagSet is called.
var featureFlags featureFlagSet

// IsEnabled returns True if a specified flag is enabled.
func IsEnabled(name string) bool {
	return featureFlags.set.Has(name)
}

// Enable adds a given slice of feature names to the current feature list.
func Enable(names ...string) {
	// Initialize the flag set so that users don't have to
	if featureFlags.set == nil {
		NewFeatureFlagSet()
	}

	featureFlags.set.Insert(normalizeFeatureNames(names...)...)
}

// Disable removes all feature flags in a given slice from the current feature list.
func Disable(names ...string) {
	featureFlags.set.Delete(normalizeFeatureNames(names...)...)
}

// All returns enabled features as a slice of strings.
func All() []string {
	return sets.List[string](featureFlags.set)
}

// Serialize returns all features as a comma-separated string.
func Serialize() string {
	return strings.Join(All(), ",")
}

// NewFeatureFlagSet initializes and populates a new FeatureFlagSet.
// This must be called to properly initialize the set for tracking flags.
// It is also useful for selectively controlling flags during tests.
func NewFeatureFlagSet(flags ...string) {
	featureFlags = featureFlagSet{
		set: sets.New[string](normalizeFeatureNames(flags...)...),
	}
}

// normalizeFeatureNames trims whitespace and drops empty entries so values
// like "EnableCSI, EnableAPIGroupVersions" enable the intended features.
func normalizeFeatureNames(names ...string) []string {
	return util.SplitAndTrimCSV(strings.Join(names, ","))
}
