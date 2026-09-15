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

package serverconfig

import (
	"context"
	"errors"

	"github.com/spf13/pflag"
	appsv1api "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"

	"github.com/vmware-tanzu/velero/pkg/cmd/server/config"
	"github.com/vmware-tanzu/velero/pkg/install"
)

var errVeleroDeploymentNotFound = errors.New("velero deployment not found")

// GetDefaultVolumeSnapshotLocations returns the Velero server's
// --default-volume-snapshot-locations map (provider -> location name).
// If the deployment cannot be read or parsed, an empty map is returned.
func GetDefaultVolumeSnapshotLocations(ctx context.Context, kubeClient kubernetes.Interface, namespace string) map[string]string {
	if kubeClient == nil {
		return map[string]string{}
	}

	serverConfig, ok := getServerConfig(ctx, kubeClient, namespace)
	if !ok {
		return map[string]string{}
	}

	locations := serverConfig.DefaultVolumeSnapshotLocations.Data()
	if locations == nil {
		return map[string]string{}
	}

	return locations
}

func getServerConfig(ctx context.Context, kubeClient kubernetes.Interface, namespace string) (*config.Config, bool) {
	deployment, err := veleroDeployment(ctx, kubeClient, namespace)
	if err != nil {
		return nil, false
	}

	for _, container := range deployment.Spec.Template.Spec.Containers {
		if container.Name != "velero" {
			continue
		}

		serverConfig, err := parseServerArgs(container.Args)
		if err != nil {
			return nil, false
		}

		return serverConfig, true
	}

	return nil, false
}

func veleroDeployment(ctx context.Context, kubeClient kubernetes.Interface, namespace string) (*appsv1api.Deployment, error) {
	veleroLabels := labels.FormatLabels(install.Labels())

	deployList, err := kubeClient.
		AppsV1().
		Deployments(namespace).
		List(ctx, metav1.ListOptions{
			LabelSelector: veleroLabels,
		})
	if err != nil {
		return nil, err
	}

	for i := range deployList.Items {
		deploy := &deployList.Items[i]
		for _, container := range deploy.Spec.Template.Spec.Containers {
			if container.Name == "velero" {
				return deploy, nil
			}
		}
	}

	return nil, errVeleroDeploymentNotFound
}

func parseServerArgs(args []string) (*config.Config, error) {
	cfg := config.GetDefaultConfig()
	fs := pflag.NewFlagSet("server", pflag.ContinueOnError)
	fs.ParseErrorsAllowlist.UnknownFlags = true
	cfg.BindFlags(fs)

	serverIndex := -1
	for i, arg := range args {
		if arg == "server" {
			serverIndex = i
			break
		}
	}

	if serverIndex < 0 {
		return cfg, nil
	}

	if err := fs.Parse(args[serverIndex+1:]); err != nil {
		return nil, err
	}

	return cfg, nil
}
