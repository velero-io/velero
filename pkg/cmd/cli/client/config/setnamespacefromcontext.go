/*
Copyright The Velero Contributors.

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

package config

import (
	"fmt"

	"github.com/spf13/cobra"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/vmware-tanzu/velero/pkg/client"
	"github.com/vmware-tanzu/velero/pkg/cmd"
)

func NewSetNamespaceFromContextCommand() *cobra.Command {
	var kubeconfig, kubecontext string

	c := &cobra.Command{
		Use:   "set-namespace-from-context",
		Short: "Set the Velero client's configured namespace to the namespace of a kubeconfig context",
		Long: "Reads the namespace associated with the current kubeconfig context (or the context " +
			"specified by --kubecontext) and saves it to the Velero client configuration file, so " +
			"subsequent commands use it as the default namespace without needing --namespace.",
		Run: func(c *cobra.Command, args []string) {
			namespace, err := setNamespaceFromContext(kubeconfig, kubecontext)
			cmd.CheckError(err)

			fmt.Printf("Velero client namespace set to %q\n", namespace)
		},
	}

	c.Flags().StringVar(&kubeconfig, "kubeconfig", "", "Path to the kubeconfig file to use to talk to the Kubernetes apiserver. If unset, try the environment variable KUBECONFIG, as well as in-cluster configuration")
	c.Flags().StringVar(&kubecontext, "kubecontext", "", "The kubeconfig context to read the namespace from. If unset defaults to whatever your current-context is (kubectl config current-context)")

	return c
}

// setNamespaceFromContext reads the namespace from the given kubeconfig/kubecontext (falling
// back to the default kubeconfig loading rules and current-context when empty), saves it to the
// Velero client configuration file, and returns the namespace that was set.
func setNamespaceFromContext(kubeconfig, kubecontext string) (string, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	loadingRules.ExplicitPath = kubeconfig
	overrides := &clientcmd.ConfigOverrides{CurrentContext: kubecontext}
	kubeClientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, overrides)

	namespace, _, err := kubeClientConfig.Namespace()
	if err != nil {
		return "", err
	}

	config, err := client.LoadConfig()
	if err != nil {
		return "", err
	}

	config[client.ConfigKeyNamespace] = namespace
	if err := client.SaveConfig(config); err != nil {
		return "", err
	}

	return namespace, nil
}
