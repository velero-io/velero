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

	"github.com/pkg/errors"

	veleroexec "github.com/vmware-tanzu/velero/pkg/util/exec"
)

func InstallCRD(ctx context.Context, yaml string) error {
	fmt.Printf("Install CRD with %s.\n", yaml)
	err := KubectlApplyByFile(ctx, yaml)
	return err
}

func DeleteCRD(ctx context.Context, yaml string) error {
	fmt.Println("Delete CRD", yaml)
	cmd := exec.CommandContext(ctx, "kubectl", "delete", "-f", yaml, "--wait")

	_, stderr, err := veleroexec.RunCommand(cmd)
	if strings.Contains(stderr, "not found") {
		return nil
	}
	if err != nil {
		return errors.Wrap(err, stderr)
	}

	return nil
}

func DeleteCRDByName(ctx context.Context, name string) error {
	fmt.Println("Delete CRD", name)
	cmd := exec.CommandContext(ctx, "kubectl", "delete", "crd", name, "--wait")

	_, stderr, err := veleroexec.RunCommand(cmd)
	if strings.Contains(stderr, "not found") {
		return nil
	}
	if err != nil {
		return errors.Wrap(err, stderr)
	}

	return nil
}

func InstallCR(ctx context.Context, crFile, ns string) error {
	retries := 5
	var stderr string
	var err error

	for i := range retries {
		fmt.Printf("Attempt %d: Install custom resource %s\n", i+1, crFile)
		cmd := exec.CommandContext(ctx, "kubectl", "apply", "-n", ns, "-f", crFile)
		_, stderr, err = veleroexec.RunCommand(cmd)
		if err == nil {
			fmt.Printf("Successfully installed CR on %s.\n", ns)
			return nil
		}

		fmt.Printf("Sleep for %ds before next attempt.\n", 20*i)
		time.Sleep(time.Second * time.Duration(i) * 20)
	}
	return errors.Wrap(err, stderr)
}
