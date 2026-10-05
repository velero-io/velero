/*
Copyright 2017, 2019 the Velero contributors.

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

package client

import (
	"fmt"
	"runtime"

	"github.com/cockroachdb/errors"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/vmware-tanzu/velero/pkg/buildinfo"
)

func buildConfigFromFlags(context, kubeconfigPath string, precedence []string) (*rest.Config, error) {
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfigPath, Precedence: precedence},
		&clientcmd.ConfigOverrides{
			CurrentContext: context,
		}).ClientConfig()
}

// Config returns a *rest.Config, using either the kubeconfig (if specified) or an in-cluster
// configuration.
func Config(kubeconfig, kubecontext, baseName string, qps float32, burst int) (*rest.Config, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	loadingRules.ExplicitPath = kubeconfig
	clientConfig, err := buildConfigFromFlags(kubecontext, kubeconfig, loadingRules.Precedence)
	if err != nil {
		return nil, errors.Wrap(err, "error finding Kubernetes API server config in --kubeconfig, $KUBECONFIG, or in-cluster configuration")
	}

	if qps > 0.0 {
		clientConfig.QPS = qps
	}
	if burst > 0 {
		clientConfig.Burst = burst
	}

	clientConfig.UserAgent = buildUserAgent(
		baseName,
		buildinfo.Version,
		buildinfo.FormattedGitSHA(),
		runtime.GOOS,
		runtime.GOARCH,
	)

	return clientConfig, nil
}

// buildUserAgent builds a User-Agent string from given args.
func buildUserAgent(command, version, formattedSha, os, arch string) string {
	return fmt.Sprintf(
		"%s/%s (%s/%s) %s", command, version, os, arch, formattedSha)
}
