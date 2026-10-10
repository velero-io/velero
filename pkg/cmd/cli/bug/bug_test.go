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

package bug

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vmware-tanzu/velero/pkg/buildinfo"
)

func TestNewCommand(t *testing.T) {
	cmd := NewCommand()
	require.NotNil(t, cmd)
	require.Equal(t, "bug", cmd.Use)
	require.Equal(t, "Report a Velero bug", cmd.Short)
}

func TestNewBugInfo(t *testing.T) {
	origVersion := buildinfo.Version
	buildinfo.Version = "v1.18.0"
	defer func() { buildinfo.Version = origVersion }()

	info := newBugInfo("v1.30.0")
	require.NotNil(t, info)
	require.Equal(t, "v1.30.0", info.KubectlVersion)
	require.Equal(t, "v1.18.0", info.VeleroVersion)
	require.NotEmpty(t, info.RuntimeOS)
	require.NotEmpty(t, info.RuntimeArch)
}

func TestRenderToString(t *testing.T) {
	info := newBugInfo("v1.30.0")
	rendered, err := renderToString(info)
	require.NoError(t, err)
	require.NotEmpty(t, rendered)

	// Verify template includes updated repository URLs
	require.Contains(t, rendered, "https://github.com/velero-io/velero/issues")
	require.NotContains(t, rendered, "https://github.com/vmware-tanzu/velero/issues")
	require.Contains(t, rendered, "v1.30.0")
}

func TestIssueURL(t *testing.T) {
	require.True(t, strings.HasPrefix(issueURL, "https://github.com/velero-io/velero/issues/new"))
	require.NotContains(t, issueURL, "vmware-tanzu")
}
