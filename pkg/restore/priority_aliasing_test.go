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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/velero-io/velero/pkg/archive"
	"github.com/velero-io/velero/pkg/types"
)

const (
	mutatingWebhooks   = "mutatingwebhookconfigurations.admissionregistration.k8s.io"
	validatingWebhooks = "validatingwebhookconfigurations.admissionregistration.k8s.io"
)

// flagPriorities parses priorities the way the --restore-resource-priorities
// server flag does. With a "-" in the middle, Set slices HighPriorities and
// LowPriorities from one backing array, so HighPriorities has spare capacity.
func flagPriorities(t *testing.T) types.Priorities {
	t.Helper()
	var p types.Priorities
	require.NoError(t, p.Set("namespaces,pods,-,"+mutatingWebhooks+","+validatingWebhooks))
	return p
}

func backupWith(resources ...string) map[string]*archive.ResourceItems {
	m := make(map[string]*archive.ResourceItems, len(resources))
	for _, r := range resources {
		m[r] = &archive.ResourceItems{}
	}
	return m
}

// getOrderedResources must not write into the caller's priority slices,
// whatever the number of unprioritized resources in the backup.
func TestGetOrderedResourcesDoesNotMutateFlagPriorities(t *testing.T) {
	tests := []struct {
		name   string
		backup map[string]*archive.ResourceItems
		want   []string
	}{
		{
			name:   "one unprioritized resource",
			backup: backupWith("configmaps", "pods"),
			want:   []string{"namespaces", "pods", "configmaps", mutatingWebhooks, validatingWebhooks},
		},
		{
			name:   "two unprioritized resources",
			backup: backupWith("configmaps", "deployments.apps", "pods"),
			want:   []string{"namespaces", "pods", "configmaps", "deployments.apps", mutatingWebhooks, validatingWebhooks},
		},
		{
			name:   "three unprioritized resources",
			backup: backupWith("configmaps", "deployments.apps", "secrets"),
			want:   []string{"namespaces", "pods", "configmaps", "deployments.apps", "secrets", mutatingWebhooks, validatingWebhooks},
		},
		{
			name:   "four unprioritized resources",
			backup: backupWith("configmaps", "deployments.apps", "secrets", "services"),
			want:   []string{"namespaces", "pods", "configmaps", "deployments.apps", "secrets", "services", mutatingWebhooks, validatingWebhooks},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := flagPriorities(t)
			wantHigh := append([]string(nil), p.HighPriorities...)
			wantLow := append([]string(nil), p.LowPriorities...)

			assert.Equal(t, tc.want, getOrderedResources(p, tc.backup))
			assert.Equal(t, wantHigh, p.HighPriorities, "HighPriorities changed")
			assert.Equal(t, wantLow, p.LowPriorities, "LowPriorities changed")
		})
	}
}

// The restorer copies the server's priorities into every restore by value
// (restore.go: resourcePriorities: kr.resourcePriorities), so the slices are
// shared across restores. A later restore must still see the configured order.
func TestGetOrderedResourcesRepeatedRestoresKeepServerOrder(t *testing.T) {
	serverPriorities := flagPriorities(t)

	first := getOrderedResources(serverPriorities, backupWith("configmaps", "deployments.apps", "pods"))
	assert.Equal(t, []string{"namespaces", "pods", "configmaps", "deployments.apps", mutatingWebhooks, validatingWebhooks}, first)

	second := getOrderedResources(serverPriorities, backupWith("configmaps", mutatingWebhooks, "secrets"))
	assert.Equal(t, []string{"namespaces", "pods", "configmaps", "secrets", mutatingWebhooks, validatingWebhooks}, second,
		"mutating webhooks must stay low priority (restored after the workloads they guard)")
}

// Every resource type in the backup must appear in the restore order. The
// "restore everything else" pass walks this list once, so a type missing from
// it is silently not restored.
func TestGetOrderedResourcesKeepsEveryBackedUpResource(t *testing.T) {
	p := flagPriorities(t)
	backup := backupWith("configmaps", "deployments.apps", mutatingWebhooks)

	got := getOrderedResources(p, backup)
	for resource := range backup {
		assert.Contains(t, got, resource, "backed-up resource missing from restore order")
	}
}
