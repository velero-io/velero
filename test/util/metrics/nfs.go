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

package metrics

import (
	"context"
	"os/exec"
	"strings"

	"github.com/cockroachdb/errors"
)

func GetNFSPathDiskUsage(ctx context.Context, nfsServerPath string) (string, error) {
	cmd := exec.CommandContext(ctx, "df", "-h", nfsServerPath)
	output, err := cmd.Output()
	if err != nil {
		return "0B", errors.WithStack(err)
	}

	strOutput := string(output)
	// parse command output
	lines := strings.Split(strOutput, "\n")
	if len(lines) < 2 {
		return "0B", errors.Errorf("Failed to get disk usage for nfs server path %s with command output %s", nfsServerPath, strOutput)
	}

	fields := strings.Fields(lines[1])
	if len(fields) < 5 {
		return "0B", errors.Errorf("Failed to parse disk usage for nfs server path %s with command output %s", nfsServerPath, strOutput)
	}

	usedSpaceStr := fields[2]
	return usedSpaceStr, nil
}
