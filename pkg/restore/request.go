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

package restore

import (
	"fmt"
	"io"
	"sort"

	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/vmware-tanzu/velero/internal/resourcemodifiers"
	"github.com/vmware-tanzu/velero/internal/resourcepolicies"
	"github.com/vmware-tanzu/velero/internal/volume"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/itemoperation"
	"github.com/vmware-tanzu/velero/pkg/util/kube"
)

const (
	ItemRestoreResultCreated = "created"
	ItemRestoreResultUpdated = "updated"
	ItemRestoreResultFailed  = "failed"
	ItemRestoreResultSkipped = "skipped"
)

type itemKey struct {
	resource  string
	namespace string
	name      string
}

func resourceKey(obj runtime.Object) string {
	gvk := obj.GetObjectKind().GroupVersionKind()
	return fmt.Sprintf("%s/%s", gvk.GroupVersion().String(), gvk.Kind)
}

type Request struct {
	*velerov1api.Restore

	Log                           logrus.FieldLogger
	Backup                        *velerov1api.Backup
	PodVolumeBackups              []*velerov1api.PodVolumeBackup
	VolumeSnapshots               []*volume.Snapshot
	BackupReader                  io.Reader
	RestoredItems                 map[itemKey]restoredItemStatus
	itemOperationsList            *[]*itemoperation.RestoreOperation
	ResourceModifiers             *resourcemodifiers.ResourceModifiers
	ResPolicies                   *resourcepolicies.Policies
	DisableInformerCache          bool
	CSIVolumeSnapshots            []*snapshotv1api.VolumeSnapshot
	BackupVolumeInfoMap           map[string]volume.BackupVolumeInfo
	RestoreVolumeInfoTracker      *volume.RestoreVolumeInfoTracker
	ResourceDeletionStatusTracker kube.ResourceDeletionStatusTracker
}

type restoredItemStatus struct {
	action      string
	itemExists  bool
	createdName string // Actual name assigned by K8s for GenerateName resources
}

// GetItemOperationsList returns ItemOperationsList, initializing it if necessary
func (r *Request) GetItemOperationsList() *[]*itemoperation.RestoreOperation {
	if r.itemOperationsList == nil {
		list := []*itemoperation.RestoreOperation{}
		r.itemOperationsList = &list
	}
	return r.itemOperationsList
}

// RestoredResourceList returns the list of restored resources grouped by the API
// Version and Kind
func (r *Request) RestoredResourceList() map[string][]string {
	resources := map[string][]string{}
	for i, item := range r.RestoredItems {
		// Use createdName if available (GenerateName case), otherwise itemKey.name
		name := i.name
		if item.createdName != "" {
			name = item.createdName
		}

		entry := name
		if i.namespace != "" {
			entry = fmt.Sprintf("%s/%s", i.namespace, name)
		}
		entry = fmt.Sprintf("%s(%s)", entry, item.action)
		resources[i.resource] = append(resources[i.resource], entry)
	}

	// sort namespace/name entries for each GVK
	for _, v := range resources {
		sort.Strings(v)
	}

	return resources
}
