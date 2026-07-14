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

package bslworker

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/validation"
)

func TestWorkerNaming(t *testing.T) {
	tests := []struct {
		name    string
		bslName string
	}{
		{name: "short name", bslName: "default"},
		{name: "typical name", bslName: "tenant-a-backups"},
		{name: "very long name", bslName: strings.Repeat("a-very-long-bsl-name", 10)},
		{name: "boundary length name", bslName: strings.Repeat("x", 60)},
		{name: "dotted subdomain name", bslName: "tenant.a.backups"},
		{name: "uppercase name", bslName: "Tenant-A"},
		{name: "mixed invalid chars", bslName: "tenant_a.backups:1"},
		{name: "leading/trailing dots", bslName: ".tenant-a."},
		{name: "long dotted name", bslName: strings.Repeat("a.b.", 30)},
		{name: "all invalid chars", bslName: "____"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, got := range []string{
				WorkerDeploymentName(tc.bslName),
				WorkerServiceName(tc.bslName),
				WorkerTLSSecretName(tc.bslName),
			} {
				assert.LessOrEqual(t, len(got), dns1123LabelMaxLength, "name %q exceeds DNS label limit", got)
				assert.Empty(t, validation.IsDNS1123Label(got), "name %q is not a valid DNS-1123 label", got)
			}
		})
	}
}

func TestWorkerEndpoint(t *testing.T) {
	assert.Equal(t, "velero-bsl-worker-bsl-1.velero.svc:9443", WorkerEndpoint("bsl-1", "velero"))
	assert.Equal(t, "velero-bsl-worker-bsl-1.velero.svc", WorkerServiceDNS("bsl-1", "velero"))
}

func TestWorkerNamingIsDeterministic(t *testing.T) {
	long := strings.Repeat("z", 100)
	assert.Equal(t, WorkerDeploymentName(long), WorkerDeploymentName(long))
	// Distinct BSL names must not collide after truncation.
	assert.NotEqual(t, WorkerDeploymentName(strings.Repeat("z", 100)), WorkerDeploymentName(strings.Repeat("z", 99)+"y"))
	// Names that sanitize to the same label must not collide (different originals).
	assert.NotEqual(t, WorkerDeploymentName("tenant.a"), WorkerDeploymentName("tenant-a"))
	assert.NotEqual(t, WorkerDeploymentName("Tenant-A"), WorkerDeploymentName("tenant-a"))
}
