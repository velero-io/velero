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

package common

import (
	"context"
	"fmt"

	"github.com/cockroachdb/errors"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
)

func PluginConfigLabelSelector(kind PluginKind, name string) string {
	return fmt.Sprintf("velero.io/plugin-config,%s=%s", name, kind)
}

func GetPluginConfig(kind PluginKind, name string, client corev1client.ConfigMapInterface) (*corev1api.ConfigMap, error) {
	opts := metav1.ListOptions{
		// velero.io/plugin-config: true
		// velero.io/pod-volume-restore: RestoreItemAction
		LabelSelector: PluginConfigLabelSelector(kind, name),
	}

	list, err := client.List(context.Background(), opts)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if len(list.Items) == 0 {
		return nil, nil
	}

	if len(list.Items) > 1 {
		var items []string
		for _, item := range list.Items {
			items = append(items, item.Name)
		}
		return nil, errors.Errorf("found more than one ConfigMap matching label selector %q: %v", opts.LabelSelector, items)
	}

	return &list.Items[0], nil
}
