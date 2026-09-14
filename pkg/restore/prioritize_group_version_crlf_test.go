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

	"github.com/vmware-tanzu/velero/pkg/test"
)

// TestParseUserPrioritiesCRLF verifies that user version priorities parsed
// from an enableapigroupversions ConfigMap written with CRLF line endings
// (common for files edited on Windows) do not retain the trailing "\r".
// A retained "\r" makes versionsContain never match the version, silently
// disabling the user priority (Priority 0 becomes a no-op).
func TestParseUserPrioritiesCRLF(t *testing.T) {
	fakeCtx := &restoreContext{
		log: test.NewLogger(),
	}

	priorities := parseUserPriorities(fakeCtx, "rockbands.music.example.io=v2beta1\r\nother.example.io=v2\r\n")

	assert.Len(t, priorities, 2)

	rb, ok := priorities["rockbands.music.example.io"]
	assert.True(t, ok, "expected key rockbands.music.example.io to exist")
	assert.Len(t, rb.Versions, 1)
	assert.Equal(t, "v2beta1", rb.Versions[0].Version, "trailing \\r must not be retained in the stored version")

	other, ok := priorities["other.example.io"]
	assert.True(t, ok, "expected key other.example.io to exist")
	assert.Len(t, other.Versions, 1)
	assert.Equal(t, "v2", other.Versions[0].Version, "trailing \\r must not be retained in the stored version")

	// A line made only of a carriage return is dropped like blank lines.
	empty := parseUserPriorities(fakeCtx, "\r")
	assert.Empty(t, empty)
}
