/*
Copyright 2017 the Velero contributors.

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

package plugin

import (
	"context"
	"encoding/json"

	"github.com/cockroachdb/errors"
	jsonpatch "github.com/evanphx/json-patch/v5"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/vmware-tanzu/velero/pkg/client"
	"github.com/vmware-tanzu/velero/pkg/cmd"
)

func NewRemoveCommand(f client.Factory) *cobra.Command {
	c := &cobra.Command{
		Use:   "remove [NAME | IMAGE]",
		Short: "Remove a plugin",
		Args:  cobra.ExactArgs(1),
		Run: func(c *cobra.Command, args []string) {
			kubeClient, err := f.KubeClient()
			if err != nil {
				cmd.CheckError(err)
			}

			veleroDeploy, err := veleroDeployment(context.TODO(), kubeClient, f.Namespace())
			if err != nil {
				cmd.CheckError(err)
			}

			original, err := json.Marshal(veleroDeploy)
			cmd.CheckError(err)

			var (
				initContainers = veleroDeploy.Spec.Template.Spec.InitContainers
				index          = -1
			)

			for x, container := range initContainers {
				if container.Name == args[0] || container.Image == args[0] {
					index = x
					break
				}
			}

			if index == -1 {
				cmd.CheckError(errors.Errorf("init container %s not found in Velero server deployment", args[0]))
			}

			veleroDeploy.Spec.Template.Spec.InitContainers = append(initContainers[0:index], initContainers[index+1:]...)

			updated, err := json.Marshal(veleroDeploy)
			cmd.CheckError(err)

			patchBytes, err := jsonpatch.CreateMergePatch(original, updated)
			cmd.CheckError(err)

			_, err = kubeClient.AppsV1().Deployments(veleroDeploy.Namespace).Patch(context.TODO(), veleroDeploy.Name, types.MergePatchType, patchBytes, metav1.PatchOptions{})
			cmd.CheckError(err)
		},
	}

	return c
}
