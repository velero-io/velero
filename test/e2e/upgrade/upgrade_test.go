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

package upgrade

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/velero-io/velero/test"
	"github.com/velero-io/velero/test/util/common"
)

func TestGetUpgradeVersionList(t *testing.T) {
	for _, tc := range []struct {
		name      string
		workerOS  string
		snapshots bool
		versions  string
		want      []test.VeleroCLI2Version
		wantError bool
	}{
		{
			name:     "Windows snapshots exclude versions before 1.16 and preserve CLI mappings",
			workerOS: common.WorkerOSWindows, snapshots: true,
			versions: "v1.15.2,v1.16.0,v1.17.2",
			want: []test.VeleroCLI2Version{
				{VeleroVersion: "v1.16.0", VeleroCLI: "cli-2"},
				{VeleroVersion: "v1.17.2"},
			},
		},
		{
			name:     "Windows filesystem backup excludes versions before 1.17",
			workerOS: common.WorkerOSWindows,
			versions: "v1.15.2,v1.16.2,v1.17.0",
			want:     []test.VeleroCLI2Version{{VeleroVersion: "v1.17.0"}},
		},
		{
			name:     "Linux retains older versions",
			workerOS: common.WorkerOSLinux,
			versions: "v1.15.2,v1.16.2,v1.17.2",
			want: []test.VeleroCLI2Version{
				{VeleroVersion: "v1.15.2", VeleroCLI: "cli-1"},
				{VeleroVersion: "v1.16.2", VeleroCLI: "cli-2"},
				{VeleroVersion: "v1.17.2"},
			},
		},
		{
			name:     "Windows retains development versions",
			workerOS: common.WorkerOSWindows,
			versions: "release-1.16-dev,release-1.17-dev,main",
			want: []test.VeleroCLI2Version{
				{VeleroVersion: "release-1.17-dev", VeleroCLI: "cli-2"},
				{VeleroVersion: "main"},
			},
		},
		{
			name:     "Windows excludes all unsupported versions",
			workerOS: common.WorkerOSWindows, snapshots: true,
			versions: "v1.14.1,v1.15.2",
		},
		{
			name:     "Windows preserves missing version for existing skip handling",
			workerOS: common.WorkerOSWindows,
			want:     []test.VeleroCLI2Version{{}},
		},
		{
			name:     "Windows reports invalid versions",
			workerOS: common.WorkerOSWindows,
			versions: "invalid", wantError: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := getUpgradeVersionList(test.VeleroConfig{
				WorkerOS: tc.workerOS, UpgradeFromVeleroVersion: tc.versions,
				UpgradeFromVeleroCLI: "cli-1,cli-2",
			}, tc.snapshots)
			if tc.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}
