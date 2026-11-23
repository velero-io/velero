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
	"strings"
	"time"

	"context"

	"k8s.io/apimachinery/pkg/util/wait"

	veleroexec "github.com/velero-io/velero/pkg/util/exec"
)

func KubectlDeleteIAMServiceAcount(ctx context.Context, name, namespace, cluster string) error {
	args := []string{"delete", "iamserviceaccount", name,
		"--namespace", namespace, "--cluster", cluster, "--wait"}
	fmt.Println(args)

	cmd := exec.CommandContext(ctx, "eksctl", args...)
	fmt.Println(cmd)
	stdout, stderr, err := veleroexec.RunCommand(cmd)
	fmt.Printf("Output: %v\n", stdout)
	if strings.Contains(stderr, "NotFound") {
		err = nil
	}
	return err
}

func EksctlCreateIAMServiceAcount(ctx context.Context, name, namespace, policyARN, cluster string) error {
	args := []string{"create", "iamserviceaccount", name,
		"--namespace", namespace, "--cluster", cluster, "--attach-policy-arn", policyARN,
		"--approve", "--override-existing-serviceaccounts"}

	PollInterval := 1 * time.Minute
	PollTimeout := 10 * time.Minute
	return wait.Poll(PollInterval, PollTimeout, func() (bool, error) {
		cmd := exec.CommandContext(ctx, "eksctl", args...)
		fmt.Println(cmd)
		stdout, stderr, err := veleroexec.RunCommand(cmd)
		if err != nil {
			fmt.Printf("eksctl return stdout: %v, stderr: %v, err: %v\n", stdout, stderr, err)
			return false, nil
		}
		return true, nil
	})
}
