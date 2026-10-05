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

package k8s

import (
	"fmt"
	"os/exec"

	"context"

	"github.com/cockroachdb/errors"

	veleroexec "github.com/vmware-tanzu/velero/pkg/util/exec"
)

func ScaleStatefulSet(ctx context.Context, namespace, name string, replicas int) error {
	cmd := exec.CommandContext(ctx, "kubectl", "scale", "statefulsets", name, fmt.Sprintf("--replicas=%d", replicas), "-n", namespace)
	fmt.Printf("Scale kibishii stateful set in namespace %s with CMD: %s", name, cmd.Args)

	_, stderr, err := veleroexec.RunCommand(cmd)
	if err != nil {
		return errors.Wrap(err, stderr)
	}

	return nil
}
