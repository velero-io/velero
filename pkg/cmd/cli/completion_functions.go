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

package cli

import (
	"context"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/api/meta"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/client"
)

// completionFunc is the function signature for cobra's ValidArgsFunction.
type completionFunc = func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective)

// completeNames builds a completion function for any Velero list type.
// It extracts resource names via apimachinery's meta helpers.
func completeNames(f client.Factory, list kbclient.ObjectList) completionFunc {
	return func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		kbClient, err := f.KubebuilderClient()
		if err != nil {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		freshList := list.DeepCopyObject().(kbclient.ObjectList)
		if err := kbClient.List(ctx, freshList, &kbclient.ListOptions{Namespace: f.Namespace()}); err != nil {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		items, err := meta.ExtractList(freshList)
		if err != nil {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		var filtered []string
		for _, item := range items {
			accessor, err := meta.Accessor(item)
			if err != nil {
				continue
			}
			if name := accessor.GetName(); strings.HasPrefix(name, toComplete) {
				filtered = append(filtered, name)
			}
		}
		return filtered, cobra.ShellCompDirectiveNoFileComp
	}
}

func CompleteBackupNames(f client.Factory) completionFunc {
	return completeNames(f, &velerov1api.BackupList{})
}

func CompleteRestoreNames(f client.Factory) completionFunc {
	return completeNames(f, &velerov1api.RestoreList{})
}

func CompleteScheduleNames(f client.Factory) completionFunc {
	return completeNames(f, &velerov1api.ScheduleList{})
}

func CompleteBackupStorageLocationNames(f client.Factory) completionFunc {
	return completeNames(f, &velerov1api.BackupStorageLocationList{})
}

func CompleteVolumeSnapshotLocationNames(f client.Factory) completionFunc {
	return completeNames(f, &velerov1api.VolumeSnapshotLocationList{})
}

func CompleteBackupRepositoryNames(f client.Factory) completionFunc {
	return completeNames(f, &velerov1api.BackupRepositoryList{})
}
