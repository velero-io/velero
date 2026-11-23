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

package restore

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	velerov1api "github.com/velero-io/velero/pkg/apis/velero/v1"
	"github.com/velero-io/velero/pkg/archive"
)

func TestExpandNamespaceWildcards(t *testing.T) {
	tests := []struct {
		name                   string
		includeNamespaces      []string
		excludeNamespaces      []string
		backupResources        map[string]*archive.ResourceItems
		expectedIncludeMatches []string
		expectedExcludeMatches []string
		expectedWildcardResult []string
		expectedError          string
	}{
		{
			name:              "No wildcards - should not expand",
			includeNamespaces: []string{"ns1", "ns2"},
			excludeNamespaces: []string{"ns3"},
			backupResources: map[string]*archive.ResourceItems{
				"namespaces": {ItemsByNamespace: map[string][]string{"ns1": {}, "ns2": {}, "ns3": {}}},
			},
			expectedIncludeMatches: nil,
			expectedExcludeMatches: nil,
			expectedWildcardResult: nil,
		},
		{
			name:              "Simple wildcard include pattern",
			includeNamespaces: []string{"test*"},
			excludeNamespaces: []string{},
			backupResources: map[string]*archive.ResourceItems{
				"namespaces": {ItemsByNamespace: map[string][]string{"test1": {}, "test2": {}, "prod1": {}}},
			},
			expectedIncludeMatches: []string{"test1", "test2"},
			expectedExcludeMatches: []string{},
			expectedWildcardResult: []string{"test1", "test2"},
		},
		{
			name:              "Multiple wildcard patterns",
			includeNamespaces: []string{"test*", "dev*"},
			excludeNamespaces: []string{},
			backupResources: map[string]*archive.ResourceItems{
				"namespaces": {ItemsByNamespace: map[string][]string{"test1": {}, "test2": {}, "dev1": {}, "prod1": {}}},
			},
			expectedIncludeMatches: []string{"dev1", "test1", "test2"},
			expectedExcludeMatches: []string{},
			expectedWildcardResult: []string{"dev1", "test1", "test2"},
		},
		{
			name:              "Wildcard include with wildcard exclude",
			includeNamespaces: []string{"test*"},
			excludeNamespaces: []string{"*-temp"},
			backupResources: map[string]*archive.ResourceItems{
				"namespaces": {ItemsByNamespace: map[string][]string{"test1": {}, "test2-temp": {}, "test3": {}}},
			},
			expectedIncludeMatches: []string{"test1", "test2-temp", "test3"},
			expectedExcludeMatches: []string{"test2-temp"},
			expectedWildcardResult: []string{"test1", "test3"},
		},
		{
			name:              "Wildcard include with literal exclude",
			includeNamespaces: []string{"app-*"},
			excludeNamespaces: []string{"app-test"},
			backupResources: map[string]*archive.ResourceItems{
				"namespaces": {ItemsByNamespace: map[string][]string{"app-prod": {}, "app-test": {}, "app-dev": {}}},
			},
			expectedIncludeMatches: []string{"app-dev", "app-prod", "app-test"},
			expectedExcludeMatches: []string{"app-test"},
			expectedWildcardResult: []string{"app-dev", "app-prod"},
		},
		{
			name:              "Error: wildcard * in excludes",
			includeNamespaces: []string{"test*"},
			excludeNamespaces: []string{"*"},
			backupResources: map[string]*archive.ResourceItems{
				"namespaces": {ItemsByNamespace: map[string][]string{"test1": {}}},
			},
			expectedError: "wildcard '*' is not allowed in restore excludes",
		},
		{
			name:                   "Empty backup - no matches",
			includeNamespaces:      []string{"test*"},
			excludeNamespaces:      []string{},
			backupResources:        map[string]*archive.ResourceItems{},
			expectedIncludeMatches: []string{},
			expectedExcludeMatches: []string{},
			expectedWildcardResult: []string{},
		},
		{
			name:              "Wildcard with no matches",
			includeNamespaces: []string{"nonexistent*"},
			excludeNamespaces: []string{},
			backupResources: map[string]*archive.ResourceItems{
				"namespaces": {ItemsByNamespace: map[string][]string{"test1": {}, "test2": {}}},
			},
			expectedIncludeMatches: []string{},
			expectedExcludeMatches: []string{},
			expectedWildcardResult: []string{},
		},
		{
			name:              "Complex pattern with prefix and suffix",
			includeNamespaces: []string{"app-*-prod"},
			excludeNamespaces: []string{},
			backupResources: map[string]*archive.ResourceItems{
				"namespaces": {ItemsByNamespace: map[string][]string{"app-frontend-prod": {}, "app-backend-prod": {}, "app-frontend-dev": {}}},
			},
			expectedIncludeMatches: []string{"app-backend-prod", "app-frontend-prod"},
			expectedExcludeMatches: []string{},
			expectedWildcardResult: []string{"app-backend-prod", "app-frontend-prod"},
		},
		{
			name:              "Backup with cluster resources",
			includeNamespaces: []string{"test*"},
			excludeNamespaces: []string{},
			backupResources: map[string]*archive.ResourceItems{
				"namespaces":        {ItemsByNamespace: map[string][]string{"test1": {}, "test2": {}}},
				"persistentvolumes": {ItemsByNamespace: map[string][]string{"": {}}}, // cluster-scoped
				"pods.v1":           {ItemsByNamespace: map[string][]string{"test1": {"pod1"}}},
			},
			expectedIncludeMatches: []string{"test1", "test2"},
			expectedExcludeMatches: []string{},
			expectedWildcardResult: []string{"test1", "test2"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			restore := &velerov1api.Restore{
				Spec: velerov1api.RestoreSpec{
					IncludedNamespaces: tc.includeNamespaces,
					ExcludedNamespaces: tc.excludeNamespaces,
				},
			}

			ctx := &restoreContext{
				restore: restore,
				log:     logrus.StandardLogger(),
			}

			err := ctx.expandNamespaceWildcards(tc.backupResources)

			if tc.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedError)
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestExtractNamespacesFromBackup(t *testing.T) {
	tests := []struct {
		name            string
		backupResources map[string]*archive.ResourceItems
		expected        []string
	}{
		{
			name: "Multiple namespaces in backup",
			backupResources: map[string]*archive.ResourceItems{
				"namespaces": {ItemsByNamespace: map[string][]string{"ns1": {}, "ns2": {}, "ns3": {}}},
			},
			expected: []string{"ns1", "ns2", "ns3"},
		},
		{
			name: "Namespaces with resources",
			backupResources: map[string]*archive.ResourceItems{
				"namespaces":  {ItemsByNamespace: map[string][]string{"app1": {}, "app2": {}}},
				"pods.v1":     {ItemsByNamespace: map[string][]string{"app1": {"pod1"}}},
				"services.v1": {ItemsByNamespace: map[string][]string{"app2": {"svc1"}}},
			},
			expected: []string{"app1", "app2"},
		},
		{
			name: "Mixed cluster and namespaced resources",
			backupResources: map[string]*archive.ResourceItems{
				"namespaces":        {ItemsByNamespace: map[string][]string{"test": {}}},
				"persistentvolumes": {ItemsByNamespace: map[string][]string{"": {"pv1"}}},
				"clusterroles":      {ItemsByNamespace: map[string][]string{"": {"cr1"}}},
				"pods.v1":           {ItemsByNamespace: map[string][]string{"test": {"pod1"}}},
			},
			expected: []string{"test"},
		},
		{
			name:            "Empty backup",
			backupResources: map[string]*archive.ResourceItems{},
			expected:        []string{},
		},
		{
			name: "Only cluster resources",
			backupResources: map[string]*archive.ResourceItems{
				"persistentvolumes": {ItemsByNamespace: map[string][]string{"": {"pv1"}}},
				"clusterroles":      {ItemsByNamespace: map[string][]string{"": {"cr1"}}},
				"storageclasses":    {ItemsByNamespace: map[string][]string{"": {"sc1"}}},
			},
			expected: []string{},
		},
		{
			name: "Duplicate namespace entries",
			backupResources: map[string]*archive.ResourceItems{
				"namespaces":    {ItemsByNamespace: map[string][]string{"app": {}}},
				"pods.v1":       {ItemsByNamespace: map[string][]string{"app": {"pod1"}}},
				"configmaps.v1": {ItemsByNamespace: map[string][]string{"app": {"cm1"}}},
			},
			expected: []string{"app"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := extractNamespacesFromBackup(tc.backupResources)
			assert.ElementsMatch(t, tc.expected, result)
		})
	}
}
