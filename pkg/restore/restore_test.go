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

package restore

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"testing"
	"time"

	"github.com/vmware-tanzu/velero/pkg/util/boolptr"
	"github.com/vmware-tanzu/velero/pkg/util/collections"

	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/dynamic"
	kubetesting "k8s.io/client-go/testing"

	"github.com/vmware-tanzu/velero/internal/volume"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/archive"
	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/client"
	"github.com/vmware-tanzu/velero/pkg/discovery"
	"github.com/vmware-tanzu/velero/pkg/features"
	"github.com/vmware-tanzu/velero/pkg/itemoperation"
	"github.com/vmware-tanzu/velero/pkg/kuberesource"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	riav2 "github.com/vmware-tanzu/velero/pkg/plugin/velero/restoreitemaction/v2"
	vsv1 "github.com/vmware-tanzu/velero/pkg/plugin/velero/volumesnapshotter/v1"
	"github.com/vmware-tanzu/velero/pkg/podvolume"
	uploadermocks "github.com/vmware-tanzu/velero/pkg/podvolume/mocks"
	"github.com/vmware-tanzu/velero/pkg/test"
	"github.com/vmware-tanzu/velero/pkg/types"
	"github.com/vmware-tanzu/velero/pkg/util/kube"
	kubeutil "github.com/vmware-tanzu/velero/pkg/util/kube"
	. "github.com/vmware-tanzu/velero/pkg/util/results"
)

func TestRestorePVWithVolumeInfo(t *testing.T) {
	tests := []struct {
		name          string
		restore       *velerov1api.Restore
		backup        *velerov1api.Backup
		apiResources  []*test.APIResource
		tarball       io.Reader
		want          map[*test.APIResource][]string
		volumeInfoMap map[string]volume.BackupVolumeInfo
	}{
		{
			name:    "Restore PV with native snapshot",
			restore: defaultRestore().Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("persistentvolumes",
					builder.ForPersistentVolume("pv-1").ReclaimPolicy(corev1api.PersistentVolumeReclaimRetain).Result(),
				).Done(),
			apiResources: []*test.APIResource{
				test.PVs(),
			},
			volumeInfoMap: map[string]volume.BackupVolumeInfo{
				"pv-1": {
					BackupMethod: volume.NativeSnapshot,
					PVName:       "pv-1",
					NativeSnapshotInfo: &volume.NativeSnapshotInfo{
						SnapshotHandle: "testSnapshotHandle",
					},
				},
			},
			want: map[*test.APIResource][]string{
				test.PVs(): {"/pv-1"},
			},
		},
		{
			name:    "Restore PV with PVB",
			restore: defaultRestore().Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("persistentvolumes",
					builder.ForPersistentVolume("pv-1").ReclaimPolicy(corev1api.PersistentVolumeReclaimRetain).Result(),
				).Done(),
			apiResources: []*test.APIResource{
				test.PVs(),
			},
			volumeInfoMap: map[string]volume.BackupVolumeInfo{
				"pv-1": {
					BackupMethod: volume.PodVolumeBackup,
					PVName:       "pv-1",
					PVBInfo: &volume.PodVolumeInfo{
						SnapshotHandle: "testSnapshotHandle",
						Size:           100,
						NodeName:       "testNode",
					},
				},
			},
			want: map[*test.APIResource][]string{
				test.PVs(): {},
			},
		},
		{
			name:    "Restore PV with CSI VolumeSnapshot",
			restore: defaultRestore().Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("persistentvolumes",
					builder.ForPersistentVolume("pv-1").ReclaimPolicy(corev1api.PersistentVolumeReclaimRetain).Result(),
				).Done(),
			apiResources: []*test.APIResource{
				test.PVs(),
			},
			volumeInfoMap: map[string]volume.BackupVolumeInfo{
				"pv-1": {
					BackupMethod:      volume.CSISnapshot,
					SnapshotDataMoved: false,
					PVName:            "pv-1",
					CSISnapshotInfo: &volume.CSISnapshotInfo{
						Driver: "pd.csi.storage.gke.io",
					},
				},
			},
			want: map[*test.APIResource][]string{
				test.PVs(): {},
			},
		},
		{
			name:    "Restore PV with DataUpload",
			restore: defaultRestore().Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("persistentvolumes",
					builder.ForPersistentVolume("pv-1").ReclaimPolicy(corev1api.PersistentVolumeReclaimRetain).Result(),
				).Done(),
			apiResources: []*test.APIResource{
				test.PVs(),
			},
			volumeInfoMap: map[string]volume.BackupVolumeInfo{
				"pv-1": {
					BackupMethod:      volume.CSISnapshot,
					SnapshotDataMoved: true,
					PVName:            "pv-1",
					CSISnapshotInfo: &volume.CSISnapshotInfo{
						Driver: "pd.csi.storage.gke.io",
					},
					SnapshotDataMovementInfo: &volume.SnapshotDataMovementInfo{
						DataMover: "velero",
					},
				},
			},
			want: map[*test.APIResource][]string{
				test.PVs(): {},
			},
		},
		{
			name:    "Restore PV with ClaimPolicy as Delete",
			restore: defaultRestore().Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("persistentvolumes",
					builder.ForPersistentVolume("pv-1").ReclaimPolicy(corev1api.PersistentVolumeReclaimDelete).Result(),
				).Done(),
			apiResources: []*test.APIResource{
				test.PVs(),
			},
			volumeInfoMap: map[string]volume.BackupVolumeInfo{
				"pv-1": {
					PVName:  "pv-1",
					Skipped: true,
				},
			},
			want: map[*test.APIResource][]string{
				test.PVs(): {},
			},
		},
		{
			name:    "Restore PV with ClaimPolicy as Retain",
			restore: defaultRestore().Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("persistentvolumes",
					builder.ForPersistentVolume("pv-1").ReclaimPolicy(corev1api.PersistentVolumeReclaimRetain).Result(),
				).Done(),
			apiResources: []*test.APIResource{
				test.PVs(),
			},
			volumeInfoMap: map[string]volume.BackupVolumeInfo{
				"pv-1": {
					PVName:  "pv-1",
					Skipped: true,
				},
			},
			want: map[*test.APIResource][]string{
				test.PVs(): {"/pv-1"},
			},
		},
	}

	features.Enable("EnableCSI")

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)

			for _, r := range tc.apiResources {
				h.DiscoveryClient.WithAPIResource(r)
			}
			require.NoError(t, h.restorer.discoveryHelper.Refresh())

			data := &Request{
				Log:                 h.log,
				Restore:             tc.restore,
				Backup:              tc.backup,
				PodVolumeBackups:    nil,
				VolumeSnapshots:     nil,
				BackupReader:        tc.tarball,
				BackupVolumeInfoMap: tc.volumeInfoMap,
			}
			warnings, errs := h.restorer.Restore(
				data,
				nil, // restoreItemActions
				nil, // volume snapshotter getter
			)

			assertEmptyResults(t, warnings, errs)
			assertAPIContents(t, h, tc.want)
		})
	}
}

// TestRestoreResourceFiltering runs restores with different combinations
// of resource filters (included/excluded resources, included/excluded
// namespaces, label selectors, "include cluster resources" flag), and
// verifies that the set of items created in the API are correct.
// Validation is done by looking at the namespaces/names of the items in
// the API; contents are not checked.
func TestRestoreResourceFiltering(t *testing.T) {
	tests := []struct {
		name         string
		restore      *velerov1api.Restore
		backup       *velerov1api.Backup
		apiResources []*test.APIResource
		tarball      io.Reader
		want         map[*test.APIResource][]string
	}{
		{
			name:    "no filters restores everything",
			restore: defaultRestore().Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("pods",
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-2").Result(),
				).
				AddItems("persistentvolumes",
					builder.ForPersistentVolume("pv-1").Result(),
					builder.ForPersistentVolume("pv-2").Result(),
				).
				Done(),
			apiResources: []*test.APIResource{
				test.Pods(),
				test.PVs(),
			},
			want: map[*test.APIResource][]string{
				test.Pods(): {"ns-1/pod-1", "ns-2/pod-2"},
				test.PVs():  {"/pv-1", "/pv-2"},
			},
		},
		{
			name:    "included resources filter only restores resources of those types",
			restore: defaultRestore().IncludedResources("pods").Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("pods",
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-2").Result(),
				).
				AddItems("persistentvolumes",
					builder.ForPersistentVolume("pv-1").Result(),
					builder.ForPersistentVolume("pv-2").Result(),
				).
				Done(),
			apiResources: []*test.APIResource{
				test.Pods(),
				test.PVs(),
			},
			want: map[*test.APIResource][]string{
				test.Pods(): {"ns-1/pod-1", "ns-2/pod-2"},
			},
		},
		{
			name:    "excluded resources filter only restores resources not of those types",
			restore: defaultRestore().ExcludedResources("pvs").Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("pods",
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-2").Result(),
				).
				AddItems("persistentvolumes",
					builder.ForPersistentVolume("pv-1").Result(),
					builder.ForPersistentVolume("pv-2").Result(),
				).
				Done(),
			apiResources: []*test.APIResource{
				test.Pods(),
				test.PVs(),
			},
			want: map[*test.APIResource][]string{
				test.Pods(): {"ns-1/pod-1", "ns-2/pod-2"},
			},
		},
		{
			name:    "included namespaces filter only restores resources in those namespaces",
			restore: defaultRestore().IncludedNamespaces("ns-1").Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("pods",
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-2").Result(),
				).
				AddItems("deployments.apps",
					builder.ForDeployment("ns-1", "deploy-1").Result(),
					builder.ForDeployment("ns-2", "deploy-2").Result(),
				).
				AddItems("persistentvolumes",
					builder.ForPersistentVolume("pv-1").Result(),
					builder.ForPersistentVolume("pv-2").Result(),
				).
				Done(),
			apiResources: []*test.APIResource{
				test.Pods(),
				test.Deployments(),
				test.PVs(),
			},
			want: map[*test.APIResource][]string{
				test.Pods():        {"ns-1/pod-1"},
				test.Deployments(): {"ns-1/deploy-1"},
			},
		},
		{
			name:    "excluded namespaces filter only restores resources not in those namespaces",
			restore: defaultRestore().ExcludedNamespaces("ns-2").Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("pods",
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-2").Result(),
				).
				AddItems("deployments.apps",
					builder.ForDeployment("ns-1", "deploy-1").Result(),
					builder.ForDeployment("ns-2", "deploy-2").Result(),
				).
				AddItems("persistentvolumes",
					builder.ForPersistentVolume("pv-1").Result(),
					builder.ForPersistentVolume("pv-2").Result(),
				).
				Done(),
			apiResources: []*test.APIResource{
				test.Pods(),
				test.Deployments(),
				test.PVs(),
			},
			want: map[*test.APIResource][]string{
				test.Pods():        {"ns-1/pod-1"},
				test.Deployments(): {"ns-1/deploy-1"},
			},
		},
		{
			name:    "IncludeClusterResources=false only restores namespaced resources",
			restore: defaultRestore().IncludeClusterResources(false).Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("pods",
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-2").Result(),
				).
				AddItems("deployments.apps",
					builder.ForDeployment("ns-1", "deploy-1").Result(),
					builder.ForDeployment("ns-2", "deploy-2").Result(),
				).
				AddItems("persistentvolumes",
					builder.ForPersistentVolume("pv-1").Result(),
					builder.ForPersistentVolume("pv-2").Result(),
				).
				Done(),
			apiResources: []*test.APIResource{
				test.Pods(),
				test.Deployments(),
				test.PVs(),
			},
			want: map[*test.APIResource][]string{
				test.Pods():        {"ns-1/pod-1", "ns-2/pod-2"},
				test.Deployments(): {"ns-1/deploy-1", "ns-2/deploy-2"},
			},
		},
		{
			name:    "label selector only restores matching resources",
			restore: defaultRestore().LabelSelector(&metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}}).Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("pods",
					builder.ForPod("ns-1", "pod-1").ObjectMeta(builder.WithLabels("a", "b")).Result(),
					builder.ForPod("ns-2", "pod-2").Result(),
				).
				AddItems("deployments.apps",
					builder.ForDeployment("ns-1", "deploy-1").Result(),
					builder.ForDeployment("ns-2", "deploy-2").ObjectMeta(builder.WithLabels("a", "b")).Result(),
				).
				AddItems("persistentvolumes",
					builder.ForPersistentVolume("pv-1").ObjectMeta(builder.WithLabels("a", "b")).Result(),
					builder.ForPersistentVolume("pv-2").ObjectMeta(builder.WithLabels("a", "c")).Result(),
				).
				Done(),
			apiResources: []*test.APIResource{
				test.Pods(),
				test.Deployments(),
				test.PVs(),
			},
			want: map[*test.APIResource][]string{
				test.Pods():        {"ns-1/pod-1"},
				test.Deployments(): {"ns-2/deploy-2"},
				test.PVs():         {"/pv-1"},
			},
		},
		{
			name: "OrLabelSelectors only restores matching resources",
			restore: defaultRestore().OrLabelSelector([]*metav1.LabelSelector{{MatchLabels: map[string]string{"a1": "b1"}}, {MatchLabels: map[string]string{"a2": "b2"}},
				{MatchLabels: map[string]string{"a3": "b3"}}, {MatchLabels: map[string]string{"a4": "b4"}}}).Result(),
			backup: defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("pods",
					builder.ForPod("ns-1", "pod-1").ObjectMeta(builder.WithLabels("a1", "b1")).Result(),
					builder.ForPod("ns-2", "pod-2").Result(),
				).
				AddItems("deployments.apps",
					builder.ForDeployment("ns-1", "deploy-1").Result(),
					builder.ForDeployment("ns-2", "deploy-2").ObjectMeta(builder.WithLabels("a3", "b3")).Result(),
				).
				AddItems("persistentvolumes",
					builder.ForPersistentVolume("pv-1").ObjectMeta(builder.WithLabels("a5", "b5")).Result(),
					builder.ForPersistentVolume("pv-2").ObjectMeta(builder.WithLabels("a4", "b4")).Result(),
				).
				Done(),
			apiResources: []*test.APIResource{
				test.Pods(),
				test.Deployments(),
				test.PVs(),
			},
			want: map[*test.APIResource][]string{
				test.Pods():        {"ns-1/pod-1"},
				test.Deployments(): {"ns-2/deploy-2"},
				test.PVs():         {"/pv-2"},
			},
		},
		{
			name:    "should include cluster-scoped resources if restoring subset of namespaces and IncludeClusterResources=true",
			restore: defaultRestore().IncludedNamespaces("ns-1").IncludeClusterResources(true).Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("pods",
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-2").Result(),
				).
				AddItems("deployments.apps",
					builder.ForDeployment("ns-1", "deploy-1").Result(),
					builder.ForDeployment("ns-2", "deploy-2").Result(),
				).
				AddItems("persistentvolumes",
					builder.ForPersistentVolume("pv-1").Result(),
					builder.ForPersistentVolume("pv-2").Result(),
				).
				Done(),
			apiResources: []*test.APIResource{
				test.Pods(),
				test.Deployments(),
				test.PVs(),
			},
			want: map[*test.APIResource][]string{
				test.Pods():        {"ns-1/pod-1"},
				test.Deployments(): {"ns-1/deploy-1"},
				test.PVs():         {"/pv-1", "/pv-2"},
			},
		},
		{
			name:    "should not include cluster-scoped resources if restoring subset of namespaces and IncludeClusterResources=false",
			restore: defaultRestore().IncludedNamespaces("ns-1").IncludeClusterResources(false).Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("pods",
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-2").Result(),
				).
				AddItems("deployments.apps",
					builder.ForDeployment("ns-1", "deploy-1").Result(),
					builder.ForDeployment("ns-2", "deploy-2").Result(),
				).
				AddItems("persistentvolumes",
					builder.ForPersistentVolume("pv-1").Result(),
					builder.ForPersistentVolume("pv-2").Result(),
				).
				Done(),
			apiResources: []*test.APIResource{
				test.Pods(),
				test.Deployments(),
				test.PVs(),
			},
			want: map[*test.APIResource][]string{
				test.Pods():        {"ns-1/pod-1"},
				test.Deployments(): {"ns-1/deploy-1"},
				test.PVs():         {},
			},
		},
		{
			name:    "should not include cluster-scoped resources if restoring subset of namespaces and IncludeClusterResources=nil",
			restore: defaultRestore().IncludedNamespaces("ns-1").Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("pods",
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-2").Result(),
				).
				AddItems("deployments.apps",
					builder.ForDeployment("ns-1", "deploy-1").Result(),
					builder.ForDeployment("ns-2", "deploy-2").Result(),
				).
				AddItems("persistentvolumes",
					builder.ForPersistentVolume("pv-1").Result(),
					builder.ForPersistentVolume("pv-2").Result(),
				).
				Done(),
			apiResources: []*test.APIResource{
				test.Pods(),
				test.Deployments(),
				test.PVs(),
			},
			want: map[*test.APIResource][]string{
				test.Pods():        {"ns-1/pod-1"},
				test.Deployments(): {"ns-1/deploy-1"},
				test.PVs():         {},
			},
		},
		{
			name:    "should include cluster-scoped resources if restoring all namespaces and IncludeClusterResources=true",
			restore: defaultRestore().IncludeClusterResources(true).Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("pods",
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-2").Result(),
				).
				AddItems("deployments.apps",
					builder.ForDeployment("ns-1", "deploy-1").Result(),
					builder.ForDeployment("ns-2", "deploy-2").Result(),
				).
				AddItems("persistentvolumes",
					builder.ForPersistentVolume("pv-1").Result(),
					builder.ForPersistentVolume("pv-2").Result(),
				).
				Done(),
			apiResources: []*test.APIResource{
				test.Pods(),
				test.Deployments(),
				test.PVs(),
			},
			want: map[*test.APIResource][]string{
				test.Pods():        {"ns-1/pod-1", "ns-2/pod-2"},
				test.Deployments(): {"ns-1/deploy-1", "ns-2/deploy-2"},
				test.PVs():         {"/pv-1", "/pv-2"},
			},
		},
		{
			name:    "should not include cluster-scoped resources if restoring all namespaces and IncludeClusterResources=false",
			restore: defaultRestore().IncludeClusterResources(false).Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("pods",
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-2").Result(),
				).
				AddItems("deployments.apps",
					builder.ForDeployment("ns-1", "deploy-1").Result(),
					builder.ForDeployment("ns-2", "deploy-2").Result(),
				).
				AddItems("persistentvolumes",
					builder.ForPersistentVolume("pv-1").Result(),
					builder.ForPersistentVolume("pv-2").Result(),
				).
				Done(),
			apiResources: []*test.APIResource{
				test.Pods(),
				test.Deployments(),
				test.PVs(),
			},
			want: map[*test.APIResource][]string{
				test.Pods():        {"ns-1/pod-1", "ns-2/pod-2"},
				test.Deployments(): {"ns-1/deploy-1", "ns-2/deploy-2"},
			},
		},
		{
			name:    "when a wildcard and a specific resource are included, the wildcard takes precedence",
			restore: defaultRestore().IncludedResources("*", "pods").Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("pods",
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-2").Result(),
				).
				AddItems("deployments.apps",
					builder.ForDeployment("ns-1", "deploy-1").Result(),
					builder.ForDeployment("ns-2", "deploy-2").Result(),
				).
				AddItems("persistentvolumes",
					builder.ForPersistentVolume("pv-1").Result(),
					builder.ForPersistentVolume("pv-2").Result(),
				).
				Done(),
			apiResources: []*test.APIResource{
				test.Pods(),
				test.Deployments(),
				test.PVs(),
			},
			want: map[*test.APIResource][]string{
				test.Pods():        {"ns-1/pod-1", "ns-2/pod-2"},
				test.Deployments(): {"ns-1/deploy-1", "ns-2/deploy-2"},
				test.PVs():         {"/pv-1", "/pv-2"},
			},
		},
		{
			name:    "wildcard excludes are ignored",
			restore: defaultRestore().ExcludedResources("*").Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("pods",
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-2").Result(),
				).
				AddItems("deployments.apps",
					builder.ForDeployment("ns-1", "deploy-1").Result(),
					builder.ForDeployment("ns-2", "deploy-2").Result(),
				).
				AddItems("persistentvolumes",
					builder.ForPersistentVolume("pv-1").Result(),
					builder.ForPersistentVolume("pv-2").Result(),
				).
				Done(),
			apiResources: []*test.APIResource{
				test.Pods(),
				test.Deployments(),
				test.PVs(),
			},
			want: map[*test.APIResource][]string{
				test.Pods():        {"ns-1/pod-1", "ns-2/pod-2"},
				test.Deployments(): {"ns-1/deploy-1", "ns-2/deploy-2"},
				test.PVs():         {"/pv-1", "/pv-2"},
			},
		},
		{
			name:    "unresolvable included resources are ignored",
			restore: defaultRestore().IncludedResources("pods", "unresolvable").Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("pods",
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-2").Result(),
				).
				AddItems("deployments.apps",
					builder.ForDeployment("ns-1", "deploy-1").Result(),
					builder.ForDeployment("ns-2", "deploy-2").Result(),
				).
				AddItems("persistentvolumes",
					builder.ForPersistentVolume("pv-1").Result(),
					builder.ForPersistentVolume("pv-2").Result(),
				).
				Done(),
			apiResources: []*test.APIResource{
				test.Pods(),
				test.Deployments(),
				test.PVs(),
			},
			want: map[*test.APIResource][]string{
				test.Pods(): {"ns-1/pod-1", "ns-2/pod-2"},
			},
		},
		{
			name:    "unresolvable excluded resources are ignored",
			restore: defaultRestore().ExcludedResources("deployments", "unresolvable").Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("pods",
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-2").Result(),
				).
				AddItems("deployments.apps",
					builder.ForDeployment("ns-1", "deploy-1").Result(),
					builder.ForDeployment("ns-2", "deploy-2").Result(),
				).
				AddItems("persistentvolumes",
					builder.ForPersistentVolume("pv-1").Result(),
					builder.ForPersistentVolume("pv-2").Result(),
				).
				Done(),
			apiResources: []*test.APIResource{
				test.Pods(),
				test.Deployments(),
				test.PVs(),
			},
			want: map[*test.APIResource][]string{
				test.Pods(): {"ns-1/pod-1", "ns-2/pod-2"},
				test.PVs():  {"/pv-1", "/pv-2"},
			},
		},
		{
			name:         "mirror pods are not restored",
			restore:      defaultRestore().Result(),
			backup:       defaultBackup().Result(),
			tarball:      test.NewTarWriter(t).AddItems("pods", builder.ForPod("ns-1", "pod-1").ObjectMeta(builder.WithAnnotations(corev1api.MirrorPodAnnotationKey, "foo")).Result()).Done(),
			apiResources: []*test.APIResource{test.Pods()},
			want:         map[*test.APIResource][]string{test.Pods(): {}},
		},
		{
			name:         "service accounts are restored",
			restore:      defaultRestore().Result(),
			backup:       defaultBackup().Result(),
			tarball:      test.NewTarWriter(t).AddItems("serviceaccounts", builder.ForServiceAccount("ns-1", "sa-1").Result()).Done(),
			apiResources: []*test.APIResource{test.ServiceAccounts()},
			want:         map[*test.APIResource][]string{test.ServiceAccounts(): {"ns-1/sa-1"}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)

			for _, r := range tc.apiResources {
				h.DiscoveryClient.WithAPIResource(r)
			}
			require.NoError(t, h.restorer.discoveryHelper.Refresh())

			data := &Request{
				Log:              h.log,
				Restore:          tc.restore,
				Backup:           tc.backup,
				PodVolumeBackups: nil,
				VolumeSnapshots:  nil,
				BackupReader:     tc.tarball,
			}
			warnings, errs := h.restorer.Restore(
				data,
				nil, // restoreItemActions
				nil, // volume snapshotter getter
			)

			assertEmptyResults(t, warnings, errs)
			assertAPIContents(t, h, tc.want)
		})
	}
}

// TestRestoreNamespaceMapping runs restores with namespace mappings specified,
// and verifies that the set of items created in the API are in the correct
// namespaces. Validation is done by looking at the namespaces/names of the items
// in the API; contents are not checked.
func TestRestoreNamespaceMapping(t *testing.T) {
	tests := []struct {
		name         string
		restore      *velerov1api.Restore
		backup       *velerov1api.Backup
		apiResources []*test.APIResource
		tarball      io.Reader
		want         map[*test.APIResource][]string
	}{
		{
			name:    "namespace mappings are applied",
			restore: defaultRestore().NamespaceMappings("ns-1", "mapped-ns-1", "ns-2", "mapped-ns-2").Result(),
			backup:  defaultBackup().Result(),
			apiResources: []*test.APIResource{
				test.Pods(),
			},
			tarball: test.NewTarWriter(t).
				AddItems("pods",
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-2").Result(),
					builder.ForPod("ns-3", "pod-3").Result(),
				).
				Done(),
			want: map[*test.APIResource][]string{
				test.Pods(): {"mapped-ns-1/pod-1", "mapped-ns-2/pod-2", "ns-3/pod-3"},
			},
		},
		{
			name:    "namespace mappings are applied when IncludedNamespaces are specified",
			restore: defaultRestore().IncludedNamespaces("ns-1", "ns-2").NamespaceMappings("ns-1", "mapped-ns-1", "ns-2", "mapped-ns-2").Result(),
			backup:  defaultBackup().Result(),
			apiResources: []*test.APIResource{
				test.Pods(),
			},
			tarball: test.NewTarWriter(t).
				AddItems("pods",
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-2").Result(),
					builder.ForPod("ns-3", "pod-3").Result(),
				).
				Done(),
			want: map[*test.APIResource][]string{
				test.Pods(): {"mapped-ns-1/pod-1", "mapped-ns-2/pod-2"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)

			for _, r := range tc.apiResources {
				h.DiscoveryClient.WithAPIResource(r)
			}
			require.NoError(t, h.restorer.discoveryHelper.Refresh())

			data := &Request{
				Log:              h.log,
				Restore:          tc.restore,
				Backup:           tc.backup,
				PodVolumeBackups: nil,
				VolumeSnapshots:  nil,
				BackupReader:     tc.tarball,
			}
			warnings, errs := h.restorer.Restore(
				data,
				nil, // restoreItemActions
				nil, // volume snapshotter getter
			)

			assertEmptyResults(t, warnings, errs)
			assertAPIContents(t, h, tc.want)
		})
	}
}

// TestRestoreResourcePriorities runs restores with resource priorities specified,
// and verifies that the set of items created in the API are created in the expected
// order. Validation is done by adding a Reactor to the fake dynamic client that records
// resource identifiers as they're created, and comparing that to the expected order.
func TestRestoreResourcePriorities(t *testing.T) {
	tests := []struct {
		name               string
		restore            *velerov1api.Restore
		backup             *velerov1api.Backup
		apiResources       []*test.APIResource
		tarball            io.Reader
		resourcePriorities types.Priorities
	}{
		{
			name:    "resources are restored according to the specified resource priorities",
			restore: defaultRestore().Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("pods",
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-2").Result(),
				).
				AddItems("persistentvolumes",
					builder.ForPersistentVolume("pv-1").Result(),
					builder.ForPersistentVolume("pv-2").Result(),
				).
				AddItems("deployments.apps",
					builder.ForDeployment("ns-1", "deploy-1").Result(),
					builder.ForDeployment("ns-2", "deploy-2").Result(),
				).
				AddItems("serviceaccounts",
					builder.ForServiceAccount("ns-1", "sa-1").Result(),
					builder.ForServiceAccount("ns-2", "sa-2").Result(),
				).
				AddItems("persistentvolumeclaims",
					builder.ForPersistentVolumeClaim("ns-1", "pvc-1").Result(),
					builder.ForPersistentVolumeClaim("ns-2", "pvc-2").Result(),
				).
				Done(),
			apiResources: []*test.APIResource{
				test.Pods(),
				test.PVs(),
				test.Deployments(),
				test.ServiceAccounts(),
			},
			resourcePriorities: types.Priorities{
				HighPriorities: []string{"persistentvolumes", "persistentvolumeclaims", "serviceaccounts"},
				LowPriorities:  []string{"deployments.apps"},
			},
		},
	}

	for _, tc := range tests {
		h := newHarness(t)
		h.restorer.resourcePriorities = tc.resourcePriorities

		recorder := &createRecorder{t: t}
		h.DynamicClient.PrependReactor("create", "*", recorder.reactor())

		for _, r := range tc.apiResources {
			h.DiscoveryClient.WithAPIResource(r)
		}
		require.NoError(t, h.restorer.discoveryHelper.Refresh())

		data := &Request{
			Log:              h.log,
			Restore:          tc.restore,
			Backup:           tc.backup,
			PodVolumeBackups: nil,
			VolumeSnapshots:  nil,
			BackupReader:     tc.tarball,
		}
		warnings, errs := h.restorer.Restore(
			data,
			nil, // restoreItemActions
			nil, // volume snapshotter getter
		)

		assertEmptyResults(t, warnings, errs)
		assertResourceCreationOrder(t, []string{"persistentvolumes", "persistentvolumeclaims", "serviceaccounts", "pods", "deployments.apps"}, recorder.resources)
	}
}

// TestInvalidTarballContents runs restores for tarballs that are invalid in some way, and
// verifies that the set of items created in the API and the errors returned are correct.
// Validation is done by looking at the namespaces/names of the items in the API and the
// Result objects returned from the restorer.
func TestInvalidTarballContents(t *testing.T) {
	tests := []struct {
		name         string
		restore      *velerov1api.Restore
		backup       *velerov1api.Backup
		apiResources []*test.APIResource
		tarball      io.Reader
		actions      []riav2.RestoreItemAction
		want         map[*test.APIResource][]string
		wantErrs     Result
		wantWarnings Result
	}{
		{
			name:    "empty tarball returns a warning",
			restore: defaultRestore().Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				Done(),
			wantWarnings: Result{
				Velero: []string{archive.ErrNotExist.Error()},
			},
		},
		{
			name:    "invalid JSON is reported as an error and restore continues",
			restore: defaultRestore().Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				Add("resources/pods/namespaces/ns-1/pod-1.json", []byte("invalid JSON")).
				AddItems("pods",
					builder.ForPod("ns-1", "pod-2").Result(),
				).
				Done(),
			apiResources: []*test.APIResource{
				test.Pods(),
			},
			want: map[*test.APIResource][]string{
				test.Pods(): {"ns-1/pod-2"},
			},
			wantErrs: Result{
				Namespaces: map[string][]string{
					"ns-1": {"error decoding"},
				},
			},
		},
		{
			name:    "invalid JSON for additional item is reported as an error and restore continues",
			restore: defaultRestore().IncludedNamespaces("ns-1").Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("pods", builder.ForPod("ns-1", "pod-1").Result()).
				Add("resources/persistentvolumes/cluster/pv-1.json", []byte("invalid JSON")).
				Done(),
			apiResources: []*test.APIResource{
				test.Pods(),
				test.PVs(),
			},
			actions: []riav2.RestoreItemAction{
				&pluggableAction{
					executeFunc: func(input *velero.RestoreItemActionExecuteInput) (*velero.RestoreItemActionExecuteOutput, error) {
						return &velero.RestoreItemActionExecuteOutput{
							UpdatedItem: input.Item,
							AdditionalItems: []velero.ResourceIdentifier{
								{GroupResource: kuberesource.PersistentVolumes, Name: "pv-1"},
							},
						}, nil
					},
				},
			},
			want: map[*test.APIResource][]string{
				test.Pods(): {"ns-1/pod-1"},
			},
			wantErrs: Result{
				Namespaces: map[string][]string{
					"ns-1": {"Could not unmarshal additional item: persistentvolumes/pv-1"},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)

			for _, r := range tc.apiResources {
				h.DiscoveryClient.WithAPIResource(r)
			}
			require.NoError(t, h.restorer.discoveryHelper.Refresh())

			data := &Request{
				Log:              h.log,
				Restore:          tc.restore,
				Backup:           tc.backup,
				PodVolumeBackups: nil,
				VolumeSnapshots:  nil,
				BackupReader:     tc.tarball,
			}
			warnings, errs := h.restorer.Restore(
				data,
				tc.actions, // restoreItemActions
				nil,        // volume snapshotter getter
			)
			assertWantErrsOrWarnings(t, tc.wantWarnings, warnings)
			assertWantErrsOrWarnings(t, tc.wantErrs, errs)
			assertAPIContents(t, h, tc.want)
		})
	}
}

func assertWantErrsOrWarnings(t *testing.T, wantRes Result, res Result) {
	t.Helper()
	if wantRes.Velero != nil {
		assert.Len(t, res.Velero, len(wantRes.Velero))
		for i := range res.Velero {
			assert.Contains(t, res.Velero[i], wantRes.Velero[i])
		}
	}
	if wantRes.Namespaces != nil {
		assert.Len(t, res.Namespaces, len(wantRes.Namespaces))
		for ns := range res.Namespaces {
			assert.Len(t, res.Namespaces[ns], len(wantRes.Namespaces[ns]))
			for i := range res.Namespaces[ns] {
				assert.Contains(t, res.Namespaces[ns][i], wantRes.Namespaces[ns][i])
			}
		}
	}
	if wantRes.Cluster != nil {
		assert.Equal(t, wantRes.Cluster, res.Cluster)
	}
}

// TestRestoreItems runs restores of specific items and validates that they are created
// with the expected metadata/spec/status in the API.
func TestRestoreItems(t *testing.T) {
	tests := []struct {
		name                 string
		restore              *velerov1api.Restore
		backup               *velerov1api.Backup
		apiResources         []*test.APIResource
		tarball              io.Reader
		want                 []*test.APIResource
		expectedRestoreItems map[itemKey]restoredItemStatus
		disableInformer      bool
	}{
		{
			name:    "metadata uid/resourceVersion/etc. gets removed",
			restore: defaultRestore().Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("pods",
					builder.ForPod("ns-1", "pod-1").
						ObjectMeta(
							builder.WithLabels("key-1", "val-1"),
							builder.WithAnnotations("key-1", "val-1"),
							builder.WithFinalizers("finalizer-1"),
							builder.WithUID("uid"),
						).
						Result(),
				).
				Done(),
			apiResources: []*test.APIResource{
				test.Pods(),
			},
			want: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").
						ObjectMeta(
							builder.WithLabels("key-1", "val-1", "velero.io/backup-name", "backup-1", "velero.io/restore-name", "restore-1"),
							builder.WithAnnotations("key-1", "val-1"),
							builder.WithFinalizers("finalizer-1"),
						).
						Result(),
				),
			},
			expectedRestoreItems: map[itemKey]restoredItemStatus{
				{resource: "v1/Namespace", namespace: "", name: "ns-1"}: {action: "created", itemExists: true, createdName: "ns-1"},
				{resource: "v1/Pod", namespace: "ns-1", name: "pod-1"}:  {action: "created", itemExists: true, createdName: "pod-1"},
			},
		},
		{
			name:    "status gets removed",
			restore: defaultRestore().Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("pods",
					&corev1api.Pod{
						TypeMeta: metav1.TypeMeta{
							APIVersion: "v1",
							Kind:       "Pod",
						},
						ObjectMeta: metav1.ObjectMeta{
							Namespace: "ns-1",
							Name:      "pod-1",
						},
						Status: corev1api.PodStatus{
							Message: "a non-empty status",
						},
					},
				).
				Done(),
			apiResources: []*test.APIResource{
				test.Pods(),
			},
			want: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").ObjectMeta(builder.WithLabels("velero.io/backup-name", "backup-1", "velero.io/restore-name", "restore-1")).Result(),
				),
			},
		},
		{
			name:    "object gets labeled with full backup and restore names when they're both shorter than 63 characters",
			restore: defaultRestore().Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("pods", builder.ForPod("ns-1", "pod-1").Result()).
				Done(),
			apiResources: []*test.APIResource{
				test.Pods(),
			},
			want: []*test.APIResource{
				test.Pods(builder.ForPod("ns-1", "pod-1").ObjectMeta(builder.WithLabels("velero.io/backup-name", "backup-1", "velero.io/restore-name", "restore-1")).Result()),
			},
		},
		{
			name: "object gets labeled with full backup and restore names when they're both equal to 63 characters",
			restore: builder.ForRestore(velerov1api.DefaultNamespace, "the-really-long-kube-service-name-that-is-exactly-63-characters").
				Backup("the-really-long-kube-service-name-that-is-exactly-63-characters").
				Result(),
			backup: builder.ForBackup(velerov1api.DefaultNamespace, "the-really-long-kube-service-name-that-is-exactly-63-characters").Result(),
			tarball: test.NewTarWriter(t).
				AddItems("pods", builder.ForPod("ns-1", "pod-1").Result()).
				Done(),
			apiResources: []*test.APIResource{
				test.Pods(),
			},
			want: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").
						ObjectMeta(
							builder.WithLabels(
								"velero.io/backup-name", "the-really-long-kube-service-name-that-is-exactly-63-characters",
								"velero.io/restore-name", "the-really-long-kube-service-name-that-is-exactly-63-characters",
							),
						).Result(),
				),
			},
		},
		{
			name: "object gets labeled with shortened backup and restore names when they're both longer than 63 characters",
			restore: builder.ForRestore(velerov1api.DefaultNamespace, "the-really-long-kube-service-name-that-is-much-greater-than-63-characters").
				Backup("the-really-long-kube-service-name-that-is-much-greater-than-63-characters").
				Result(),
			backup: builder.ForBackup(velerov1api.DefaultNamespace, "the-really-long-kube-service-name-that-is-much-greater-than-63-characters").Result(),
			tarball: test.NewTarWriter(t).
				AddItems("pods", builder.ForPod("ns-1", "pod-1").Result()).
				Done(),
			apiResources: []*test.APIResource{
				test.Pods(),
			},
			want: []*test.APIResource{
				test.Pods(builder.ForPod("ns-1", "pod-1").
					ObjectMeta(
						builder.WithLabels(
							"velero.io/backup-name", "the-really-long-kube-service-name-that-is-much-greater-th8a11b3",
							"velero.io/restore-name", "the-really-long-kube-service-name-that-is-much-greater-th8a11b3",
						),
					).
					Result(),
				),
			},
		},
		{
			name:    "no error when service account already exists in cluster and is identical to the backed up one",
			restore: defaultRestore().Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("serviceaccounts", builder.ForServiceAccount("ns-1", "sa-1").Result()).
				Done(),
			apiResources: []*test.APIResource{
				test.ServiceAccounts(builder.ForServiceAccount("ns-1", "sa-1").Result()),
			},
			want: []*test.APIResource{
				test.ServiceAccounts(builder.ForServiceAccount("ns-1", "sa-1").Result()),
			},
			expectedRestoreItems: map[itemKey]restoredItemStatus{
				{resource: "v1/Namespace", namespace: "", name: "ns-1"}:          {action: "created", itemExists: true, createdName: "ns-1"},
				{resource: "v1/ServiceAccount", namespace: "ns-1", name: "sa-1"}: {action: "skipped", itemExists: true},
			},
		},
		{
			name:    "update secret data and labels when secret exists in cluster and is not identical to the backed up one, existing resource policy is update",
			restore: defaultRestore().ExistingResourcePolicy("update").Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("secrets", builder.ForSecret("ns-1", "sa-1").Data(map[string][]byte{"key-1": []byte("value-1")}).Result()).
				Done(),
			apiResources: []*test.APIResource{
				test.Secrets(builder.ForSecret("ns-1", "sa-1").Data(map[string][]byte{"foo": []byte("bar")}).Result()),
			},
			disableInformer: true,
			want: []*test.APIResource{
				test.Secrets(builder.ForSecret("ns-1", "sa-1").ObjectMeta(builder.WithLabels("velero.io/backup-name", "backup-1", "velero.io/restore-name", "restore-1")).Data(map[string][]byte{"key-1": []byte("value-1")}).Result()),
			},
			expectedRestoreItems: map[itemKey]restoredItemStatus{
				{resource: "v1/Namespace", namespace: "", name: "ns-1"}:  {action: "created", itemExists: true, createdName: "ns-1"},
				{resource: "v1/Secret", namespace: "ns-1", name: "sa-1"}: {action: "updated", itemExists: true},
			},
		},
		{
			name:    "update secret data and labels when secret exists in cluster and is not identical to the backed up one, existing resource policy is update, using informer cache",
			restore: defaultRestore().ExistingResourcePolicy("update").Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("secrets", builder.ForSecret("ns-1", "sa-1").Data(map[string][]byte{"key-1": []byte("value-1")}).Result()).
				Done(),
			apiResources: []*test.APIResource{
				test.Secrets(builder.ForSecret("ns-1", "sa-1").Data(map[string][]byte{"foo": []byte("bar")}).Result()),
			},
			disableInformer: false,
			want: []*test.APIResource{
				test.Secrets(builder.ForSecret("ns-1", "sa-1").ObjectMeta(builder.WithLabels("velero.io/backup-name", "backup-1", "velero.io/restore-name", "restore-1")).Data(map[string][]byte{"key-1": []byte("value-1")}).Result()),
			},
			expectedRestoreItems: map[itemKey]restoredItemStatus{
				{resource: "v1/Namespace", namespace: "", name: "ns-1"}:  {action: "created", itemExists: true, createdName: "ns-1"},
				{resource: "v1/Secret", namespace: "ns-1", name: "sa-1"}: {action: "updated", itemExists: true},
			},
		},
		{
			name:    "update service account labels when service account exists in cluster and is identical to the backed up one, existing resource policy is update",
			restore: defaultRestore().ExistingResourcePolicy("update").Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("serviceaccounts", builder.ForServiceAccount("ns-1", "sa-1").Result()).
				Done(),
			apiResources: []*test.APIResource{
				test.ServiceAccounts(builder.ForServiceAccount("ns-1", "sa-1").ObjectMeta(builder.WithLabels("velero.io/backup-name", "foo", "velero.io/restore-name", "bar")).Result()),
			},
			want: []*test.APIResource{
				test.ServiceAccounts(builder.ForServiceAccount("ns-1", "sa-1").ObjectMeta(builder.WithLabels("velero.io/backup-name", "backup-1", "velero.io/restore-name", "restore-1")).Result()),
			},
		},
		{
			name:    "update pod labels when pod exists in cluster and is identical to the backed up one, existing resource policy is update",
			restore: defaultRestore().ExistingResourcePolicy("update").Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("pods", builder.ForPod("ns-1", "sa-1").Result()).
				Done(),
			apiResources: []*test.APIResource{
				test.Pods(builder.ForPod("ns-1", "sa-1").ObjectMeta(builder.WithLabels("velero.io/backup-name", "foo", "velero.io/restore-name", "bar")).Result()),
			},
			want: []*test.APIResource{
				test.Pods(builder.ForPod("ns-1", "sa-1").ObjectMeta(builder.WithLabels("velero.io/backup-name", "backup-1", "velero.io/restore-name", "restore-1")).Result()),
			},
		},
		{
			name:    "do not update pod labels when pod exists in cluster and is identical to the backed up one, existing resource policy is none",
			restore: defaultRestore().ExistingResourcePolicy("none").Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("pods", builder.ForPod("ns-1", "sa-1").Result()).
				Done(),
			apiResources: []*test.APIResource{
				test.Pods(builder.ForPod("ns-1", "sa-1").ObjectMeta(builder.WithLabels("velero.io/backup-name", "foo", "velero.io/restore-name", "bar")).Result()),
			},
			want: []*test.APIResource{
				test.Pods(builder.ForPod("ns-1", "sa-1").ObjectMeta(builder.WithLabels("velero.io/backup-name", "foo", "velero.io/restore-name", "bar")).Result()),
			},
		},
		{
			name:    "do not update pod labels when pod exists in cluster and is identical to the backed up one, existing resource policy is not specified, velero behavior is preserved",
			restore: defaultRestore().Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("pods", builder.ForPod("ns-1", "sa-1").Result()).
				Done(),
			apiResources: []*test.APIResource{
				test.Pods(builder.ForPod("ns-1", "sa-1").ObjectMeta(builder.WithLabels("velero.io/backup-name", "foo", "velero.io/restore-name", "bar")).Result()),
			},
			want: []*test.APIResource{
				test.Pods(builder.ForPod("ns-1", "sa-1").ObjectMeta(builder.WithLabels("velero.io/backup-name", "foo", "velero.io/restore-name", "bar")).Result()),
			},
		},
		{
			name:    "service account secrets and image pull secrets are restored when service account already exists in cluster",
			restore: defaultRestore().Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("serviceaccounts", &corev1api.ServiceAccount{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "v1",
						Kind:       "ServiceAccount",
					},
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ns-1",
						Name:      "sa-1",
					},
					Secrets:          []corev1api.ObjectReference{{Name: "secret-1"}},
					ImagePullSecrets: []corev1api.LocalObjectReference{{Name: "pull-secret-1"}},
				}).
				Done(),
			apiResources: []*test.APIResource{
				test.ServiceAccounts(builder.ForServiceAccount("ns-1", "sa-1").Result()),
			},
			want: []*test.APIResource{
				test.ServiceAccounts(&corev1api.ServiceAccount{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "v1",
						Kind:       "ServiceAccount",
					},
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ns-1",
						Name:      "sa-1",
					},
					Secrets:          []corev1api.ObjectReference{{Name: "secret-1"}},
					ImagePullSecrets: []corev1api.LocalObjectReference{{Name: "pull-secret-1"}},
				}),
			},
		},
		{
			name:    "metadata managedFields gets restored",
			restore: defaultRestore().Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("pods",
					builder.ForPod("ns-1", "pod-1").
						ObjectMeta(
							builder.WithManagedFields([]metav1.ManagedFieldsEntry{
								{
									Manager:    "kubectl",
									Operation:  "Apply",
									APIVersion: "v1",
									FieldsType: "FieldsV1",
									FieldsV1: &metav1.FieldsV1{
										Raw: []byte(`{"f:data": {"f:key":{}}}`),
									},
								},
							}),
						).
						Result(),
				).
				Done(),
			apiResources: []*test.APIResource{
				test.Pods(),
			},
			want: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").
						ObjectMeta(
							builder.WithLabels("velero.io/backup-name", "backup-1", "velero.io/restore-name", "restore-1"),
							builder.WithManagedFields([]metav1.ManagedFieldsEntry{
								{
									Manager:    "kubectl",
									Operation:  "Apply",
									APIVersion: "v1",
									FieldsType: "FieldsV1",
									FieldsV1: &metav1.FieldsV1{
										Raw: []byte(`{"f:data": {"f:key":{}}}`),
									},
								},
							}),
						).
						Result(),
				),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)

			for _, r := range tc.apiResources {
				h.AddItems(t, r)
			}

			data := &Request{
				Log:                  h.log,
				Restore:              tc.restore,
				Backup:               tc.backup,
				PodVolumeBackups:     nil,
				VolumeSnapshots:      nil,
				BackupReader:         tc.tarball,
				RestoredItems:        map[itemKey]restoredItemStatus{},
				DisableInformerCache: tc.disableInformer,
			}
			warnings, errs := h.restorer.Restore(
				data,
				nil, // restoreItemActions
				nil, // volume snapshotter getter
			)

			assertEmptyResults(t, warnings, errs)
			assertRestoredItems(t, h, tc.want)
			if len(tc.expectedRestoreItems) > 0 {
				assert.Equal(t, tc.expectedRestoreItems, data.RestoredItems)
			}
		})
	}
}

// recordResourcesAction is a restore item action that can be configured
// to run for specific resources/namespaces and simply records the items
// that it is executed for.
type recordResourcesAction struct {
	selector                    velero.ResourceSelector
	ids                         []string
	additionalItems             []velero.ResourceIdentifier
	operationID                 string
	waitForAdditionalItems      bool
	additionalItemsReadyTimeout time.Duration
}

func (a *recordResourcesAction) Name() string {
	return ""
}

func (a *recordResourcesAction) AppliesTo() (velero.ResourceSelector, error) {
	return a.selector, nil
}

func (a *recordResourcesAction) Execute(input *velero.RestoreItemActionExecuteInput) (*velero.RestoreItemActionExecuteOutput, error) {
	metadata, err := meta.Accessor(input.Item)
	if err != nil {
		return &velero.RestoreItemActionExecuteOutput{
			UpdatedItem:                 input.Item,
			AdditionalItems:             a.additionalItems,
			OperationID:                 a.operationID,
			WaitForAdditionalItems:      a.waitForAdditionalItems,
			AdditionalItemsReadyTimeout: a.additionalItemsReadyTimeout,
		}, err
	}
	a.ids = append(a.ids, kubeutil.NamespaceAndName(metadata))

	return &velero.RestoreItemActionExecuteOutput{
		UpdatedItem:                 input.Item,
		AdditionalItems:             a.additionalItems,
		OperationID:                 a.operationID,
		WaitForAdditionalItems:      a.waitForAdditionalItems,
		AdditionalItemsReadyTimeout: a.additionalItemsReadyTimeout,
	}, nil
}

func (a *recordResourcesAction) Progress(operationID string, restore *velerov1api.Restore) (velero.OperationProgress, error) {
	return velero.OperationProgress{}, nil
}

func (a *recordResourcesAction) Cancel(operationID string, restore *velerov1api.Restore) error {
	return nil
}

func (a *recordResourcesAction) AreAdditionalItemsReady(additionalItems []velero.ResourceIdentifier, restore *velerov1api.Restore) (bool, error) {
	return true, nil
}

func (a *recordResourcesAction) ForResource(resource string) *recordResourcesAction {
	a.selector.IncludedResources = append(a.selector.IncludedResources, resource)
	return a
}

func (a *recordResourcesAction) ForNamespace(namespace string) *recordResourcesAction {
	a.selector.IncludedNamespaces = append(a.selector.IncludedNamespaces, namespace)
	return a
}

func (a *recordResourcesAction) ForLabelSelector(selector string) *recordResourcesAction {
	a.selector.LabelSelector = selector
	return a
}

func (a *recordResourcesAction) WithAdditionalItems(items []velero.ResourceIdentifier) *recordResourcesAction {
	a.additionalItems = items
	return a
}

// TestRestoreActionsRunForCorrectItems runs restores with restore item actions, and
// verifies that each restore item action is run for the correct set of resources based on its
// AppliesTo() resource selector. Verification is done by using the recordResourcesAction struct,
// which records which resources it's executed for.
func TestRestoreActionsRunForCorrectItems(t *testing.T) {
	tests := []struct {
		name         string
		restore      *velerov1api.Restore
		backup       *velerov1api.Backup
		apiResources []*test.APIResource
		tarball      io.Reader
		actions      map[*recordResourcesAction][]string
	}{
		{
			name:    "single action with no selector runs for all items",
			restore: defaultRestore().Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("pods", builder.ForPod("ns-1", "pod-1").Result(), builder.ForPod("ns-2", "pod-2").Result()).
				AddItems("persistentvolumes", builder.ForPersistentVolume("pv-1").Result(), builder.ForPersistentVolume("pv-2").Result()).
				Done(),
			apiResources: []*test.APIResource{test.Pods(), test.PVs()},
			actions: map[*recordResourcesAction][]string{
				new(recordResourcesAction): {"ns-1/pod-1", "ns-2/pod-2", "pv-1", "pv-2"},
			},
		},
		{
			name:    "single action with a resource selector for namespaced resources runs only for matching resources",
			restore: defaultRestore().Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("pods", builder.ForPod("ns-1", "pod-1").Result(), builder.ForPod("ns-2", "pod-2").Result()).
				AddItems("persistentvolumes", builder.ForPersistentVolume("pv-1").Result(), builder.ForPersistentVolume("pv-2").Result()).
				Done(),
			apiResources: []*test.APIResource{test.Pods(), test.PVs()},
			actions: map[*recordResourcesAction][]string{
				new(recordResourcesAction).ForResource("pods"): {"ns-1/pod-1", "ns-2/pod-2"},
			},
		},
		{
			name:    "single action with a resource selector for cluster-scoped resources runs only for matching resources",
			restore: defaultRestore().Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("pods", builder.ForPod("ns-1", "pod-1").Result(), builder.ForPod("ns-2", "pod-2").Result()).
				AddItems("persistentvolumes", builder.ForPersistentVolume("pv-1").Result(), builder.ForPersistentVolume("pv-2").Result()).
				Done(),
			apiResources: []*test.APIResource{test.Pods(), test.PVs()},
			actions: map[*recordResourcesAction][]string{
				new(recordResourcesAction).ForResource("persistentvolumes"): {"pv-1", "pv-2"},
			},
		},
		{
			name:    "single action with a namespace selector runs only for resources in that namespace",
			restore: defaultRestore().Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("pods", builder.ForPod("ns-1", "pod-1").Result(), builder.ForPod("ns-2", "pod-2").Result()).
				AddItems("persistentvolumeclaims", builder.ForPersistentVolumeClaim("ns-1", "pvc-1").Result(), builder.ForPersistentVolumeClaim("ns-2", "pvc-2").Result()).
				AddItems("persistentvolumes", builder.ForPersistentVolume("pv-1").Result(), builder.ForPersistentVolume("pv-2").Result()).
				Done(),
			apiResources: []*test.APIResource{test.Pods(), test.PVCs(), test.PVs()},
			actions: map[*recordResourcesAction][]string{
				new(recordResourcesAction).ForNamespace("ns-1"): {"ns-1/pod-1", "ns-1/pvc-1"},
			},
		},
		{
			name:    "single action with a resource and namespace selector runs only for matching resources in that namespace",
			restore: defaultRestore().Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("pods", builder.ForPod("ns-1", "pod-1").Result(), builder.ForPod("ns-2", "pod-2").Result()).
				AddItems("persistentvolumeclaims", builder.ForPersistentVolumeClaim("ns-1", "pvc-1").Result(), builder.ForPersistentVolumeClaim("ns-2", "pvc-2").Result()).
				AddItems("persistentvolumes", builder.ForPersistentVolume("pv-1").Result(), builder.ForPersistentVolume("pv-2").Result()).
				Done(),
			apiResources: []*test.APIResource{test.Pods(), test.PVCs(), test.PVs()},
			actions: map[*recordResourcesAction][]string{
				new(recordResourcesAction).ForNamespace("ns-1").ForResource("pods"): {"ns-1/pod-1"},
			},
		},
		{
			name:    "single action with a resource and label selector runs only for resources matching that label",
			restore: defaultRestore().Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("pods",
					builder.ForPod("ns-1", "pod-1").ObjectMeta(builder.WithLabels("restore-resource", "true")).Result(),
					builder.ForPod("ns-1", "pod-2").ObjectMeta(builder.WithLabels("do-not-restore-resource", "true")).Result(),
					builder.ForPod("ns-2", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-2").ObjectMeta(builder.WithLabels("restore-resource")).Result(),
				).Done(),
			apiResources: []*test.APIResource{test.Pods()},
			actions: map[*recordResourcesAction][]string{
				new(recordResourcesAction).ForResource("pods").ForLabelSelector("restore-resource"): {"ns-1/pod-1", "ns-2/pod-2"},
			},
		},
		{
			name:    "multiple actions, each with a different resource selector using short name, run for matching resources",
			restore: defaultRestore().Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("pods", builder.ForPod("ns-1", "pod-1").Result(), builder.ForPod("ns-2", "pod-2").Result()).
				AddItems("persistentvolumeclaims", builder.ForPersistentVolumeClaim("ns-1", "pvc-1").Result(), builder.ForPersistentVolumeClaim("ns-2", "pvc-2").Result()).
				AddItems("persistentvolumes", builder.ForPersistentVolume("pv-1").Result(), builder.ForPersistentVolume("pv-2").Result()).
				Done(),
			apiResources: []*test.APIResource{test.Pods(), test.PVCs(), test.PVs()},
			actions: map[*recordResourcesAction][]string{
				new(recordResourcesAction).ForResource("po"): {"ns-1/pod-1", "ns-2/pod-2"},
				new(recordResourcesAction).ForResource("pv"): {"pv-1", "pv-2"},
			},
		},
		{
			name:    "actions with selectors that don't match anything don't run for any resources",
			restore: defaultRestore().Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("pods", builder.ForPod("ns-1", "pod-1").Result()).
				AddItems("persistentvolumeclaims", builder.ForPersistentVolumeClaim("ns-2", "pvc-2").Result()).
				Done(),
			apiResources: []*test.APIResource{test.Pods(), test.PVCs(), test.PVs()},
			actions: map[*recordResourcesAction][]string{
				new(recordResourcesAction).ForNamespace("ns-1").ForResource("persistentvolumeclaims"): nil,
				new(recordResourcesAction).ForNamespace("ns-2").ForResource("pods"):                   nil,
			},
		},
		{
			name:    "actions run for datauploads resource",
			restore: defaultRestore().Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("datauploads.velero.io", builder.ForDataUpload("velero", "du").Result()).
				Done(),
			apiResources: []*test.APIResource{test.DataUploads()},
			actions: map[*recordResourcesAction][]string{
				new(recordResourcesAction).ForNamespace("velero").ForResource("datauploads.velero.io"): {"velero/du"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)

			for _, r := range tc.apiResources {
				h.AddItems(t, r)
			}

			actions := []riav2.RestoreItemAction{}
			for action := range tc.actions {
				actions = append(actions, action)
			}

			data := &Request{
				Log:              h.log,
				Restore:          tc.restore,
				Backup:           tc.backup,
				PodVolumeBackups: nil,
				VolumeSnapshots:  nil,
				BackupReader:     tc.tarball,
			}
			warnings, errs := h.restorer.Restore(
				data,
				actions,
				nil, // volume snapshotter getter
			)

			assertEmptyResults(t, warnings, errs)

			for action, want := range tc.actions {
				sort.Strings(want)
				sort.Strings(action.ids)
				assert.Equal(t, want, action.ids)
			}
		})
	}
}

// pluggableAction is a restore item action that can be plugged with an Execute
// function body at runtime.
type pluggableAction struct {
	selector     velero.ResourceSelector
	executeFunc  func(*velero.RestoreItemActionExecuteInput) (*velero.RestoreItemActionExecuteOutput, error)
	progressFunc func(string, *velerov1api.Restore) (velero.OperationProgress, error)
}

func (a *pluggableAction) Execute(input *velero.RestoreItemActionExecuteInput) (*velero.RestoreItemActionExecuteOutput, error) {
	if a.executeFunc == nil {
		return &velero.RestoreItemActionExecuteOutput{
			UpdatedItem: input.Item,
		}, nil
	}

	return a.executeFunc(input)
}

func (a *pluggableAction) Name() string {
	return ""
}

func (a *pluggableAction) AppliesTo() (velero.ResourceSelector, error) {
	return a.selector, nil
}

func (a *pluggableAction) Progress(operationID string, restore *velerov1api.Restore) (velero.OperationProgress, error) {
	return velero.OperationProgress{}, nil
}

func (a *pluggableAction) Cancel(operationID string, restore *velerov1api.Restore) error {
	return nil
}

func (a *pluggableAction) addSelector(selector velero.ResourceSelector) *pluggableAction {
	a.selector = selector
	return a
}

func (a *pluggableAction) AreAdditionalItemsReady(additionalItems []velero.ResourceIdentifier, restore *velerov1api.Restore) (bool, error) {
	return true, nil
}

// TestRestoreActionModifications runs restores with restore item actions that modify resources, and
// verifies that the modified item is correctly created in the API. Verification is done by looking
// at the full object in the API.
func TestRestoreActionModifications(t *testing.T) {
	// modifyingActionGetter is a helper function that returns a *pluggableAction, whose Execute(...)
	// method modifies the item being passed in by calling the 'modify' function on it.
	modifyingActionGetter := func(modify func(*unstructured.Unstructured)) *pluggableAction {
		return &pluggableAction{
			executeFunc: func(input *velero.RestoreItemActionExecuteInput) (*velero.RestoreItemActionExecuteOutput, error) {
				obj, ok := input.Item.(*unstructured.Unstructured)
				if !ok {
					return nil, errors.Errorf("unexpected type %T", input.Item)
				}

				res := obj.DeepCopy()
				modify(res)

				return &velero.RestoreItemActionExecuteOutput{
					UpdatedItem: res,
				}, nil
			},
		}
	}

	tests := []struct {
		name         string
		restore      *velerov1api.Restore
		backup       *velerov1api.Backup
		apiResources []*test.APIResource
		tarball      io.Reader
		actions      []riav2.RestoreItemAction
		want         []*test.APIResource
	}{
		{
			name:         "action that adds a label to item gets restored",
			restore:      defaultRestore().Result(),
			backup:       defaultBackup().Result(),
			tarball:      test.NewTarWriter(t).AddItems("pods", builder.ForPod("ns-1", "pod-1").Result()).Done(),
			apiResources: []*test.APIResource{test.Pods()},
			actions: []riav2.RestoreItemAction{
				modifyingActionGetter(func(item *unstructured.Unstructured) {
					item.SetLabels(map[string]string{"updated": "true"})
				}),
			},
			want: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").ObjectMeta(builder.WithLabels("updated", "true")).Result(),
				),
			},
		},
		{
			name:         "action that removes a label to item gets restored",
			restore:      defaultRestore().Result(),
			backup:       defaultBackup().Result(),
			tarball:      test.NewTarWriter(t).AddItems("pods", builder.ForPod("ns-1", "pod-1").ObjectMeta(builder.WithLabels("should-be-removed", "true")).Result()).Done(),
			apiResources: []*test.APIResource{test.Pods()},
			actions: []riav2.RestoreItemAction{
				modifyingActionGetter(func(item *unstructured.Unstructured) {
					item.SetLabels(nil)
				}),
			},
			want: []*test.APIResource{
				test.Pods(builder.ForPod("ns-1", "pod-1").Result()),
			},
		},
		{
			name:         "action with non-matching label selector doesn't prevent restore",
			restore:      defaultRestore().Result(),
			backup:       defaultBackup().Result(),
			tarball:      test.NewTarWriter(t).AddItems("pods", builder.ForPod("ns-1", "pod-1").Result()).Done(),
			apiResources: []*test.APIResource{test.Pods()},
			actions: []riav2.RestoreItemAction{
				modifyingActionGetter(func(item *unstructured.Unstructured) {
					item.SetLabels(map[string]string{"updated": "true"})
				}).addSelector(velero.ResourceSelector{
					IncludedResources: []string{
						"Pod",
					},
					LabelSelector: "nonmatching=label",
				}),
			},
			want: []*test.APIResource{
				test.Pods(builder.ForPod("ns-1", "pod-1").Result()),
			},
		},
		// TODO action that modifies namespace/name - what's the expected behavior?
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)

			for _, r := range tc.apiResources {
				h.AddItems(t, r)
			}

			// every restored item should have the restore and backup name labels, set
			// them here so we don't have to do it in every test case definition above.
			for _, resource := range tc.want {
				for _, item := range resource.Items {
					labels := item.GetLabels()
					if labels == nil {
						labels = make(map[string]string)
					}

					labels["velero.io/restore-name"] = tc.restore.Name
					labels["velero.io/backup-name"] = tc.restore.Spec.BackupName

					item.SetLabels(labels)
				}
			}

			data := &Request{
				Log:              h.log,
				Restore:          tc.restore,
				Backup:           tc.backup,
				PodVolumeBackups: nil,
				VolumeSnapshots:  nil,
				BackupReader:     tc.tarball,
			}
			warnings, errs := h.restorer.Restore(
				data,
				tc.actions,
				nil, // volume snapshotter getter
			)

			assertEmptyResults(t, warnings, errs)
			assertRestoredItems(t, h, tc.want)
		})
	}
}

// TestRestoreWithAsyncOperations runs restores which return operationIDs and
// verifies that the itemoperations are tracked as appropriate. Verification is done by
// looking at the restore request's itemOperationsList field.
func TestRestoreWithAsyncOperations(t *testing.T) {
	// completedOperationAction is a *pluggableAction, whose Execute(...)
	// method returns an operationID which will always be done when calling Progress.
	completedOperationAction := &pluggableAction{
		executeFunc: func(input *velero.RestoreItemActionExecuteInput) (*velero.RestoreItemActionExecuteOutput, error) {
			obj, ok := input.Item.(*unstructured.Unstructured)
			if !ok {
				return nil, errors.Errorf("unexpected type %T", input.Item)
			}
			return &velero.RestoreItemActionExecuteOutput{
				UpdatedItem: obj,
				OperationID: obj.GetName() + "-1",
			}, nil
		},
		progressFunc: func(operationID string, restore *velerov1api.Restore) (velero.OperationProgress, error) {
			return velero.OperationProgress{
				Completed:   true,
				Description: "Done!",
			}, nil
		},
	}

	// incompleteOperationAction is a *pluggableAction, whose Execute(...)
	// method returns an operationID which will never be done when calling Progress.
	incompleteOperationAction := &pluggableAction{
		executeFunc: func(input *velero.RestoreItemActionExecuteInput) (*velero.RestoreItemActionExecuteOutput, error) {
			obj, ok := input.Item.(*unstructured.Unstructured)
			if !ok {
				return nil, errors.Errorf("unexpected type %T", input.Item)
			}
			return &velero.RestoreItemActionExecuteOutput{
				UpdatedItem: obj,
				OperationID: obj.GetName() + "-1",
			}, nil
		},
		progressFunc: func(operationID string, restore *velerov1api.Restore) (velero.OperationProgress, error) {
			return velero.OperationProgress{
				Completed:   false,
				Description: "Working...",
			}, nil
		},
	}

	// noOperationAction is a *pluggableAction, whose Execute(...)
	// method does not return an operationID.
	noOperationAction := &pluggableAction{
		executeFunc: func(input *velero.RestoreItemActionExecuteInput) (*velero.RestoreItemActionExecuteOutput, error) {
			obj, ok := input.Item.(*unstructured.Unstructured)
			if !ok {
				return nil, errors.Errorf("unexpected type %T", input.Item)
			}
			return &velero.RestoreItemActionExecuteOutput{
				UpdatedItem: obj,
			}, nil
		},
	}

	tests := []struct {
		name         string
		restore      *velerov1api.Restore
		backup       *velerov1api.Backup
		apiResources []*test.APIResource
		tarball      io.Reader
		actions      []riav2.RestoreItemAction
		want         []*itemoperation.RestoreOperation
	}{
		{
			name:         "action that starts a short-running process records operation",
			restore:      defaultRestore().Result(),
			backup:       defaultBackup().Result(),
			apiResources: []*test.APIResource{test.Pods()},
			tarball:      test.NewTarWriter(t).AddItems("pods", builder.ForPod("ns-1", "pod-1").Result()).Done(),
			actions: []riav2.RestoreItemAction{
				completedOperationAction,
			},
			want: []*itemoperation.RestoreOperation{
				{
					Spec: itemoperation.RestoreOperationSpec{
						RestoreName: "restore-1",
						ResourceIdentifier: velero.ResourceIdentifier{
							GroupResource: kuberesource.Pods,
							Namespace:     "ns-1",
							Name:          "pod-1"},
						OperationID: "pod-1-1",
					},
					Status: itemoperation.OperationStatus{
						Phase: "New",
					},
				},
			},
		},
		{
			name:         "action that starts a long-running process records operation",
			restore:      defaultRestore().Result(),
			backup:       defaultBackup().Result(),
			apiResources: []*test.APIResource{test.Pods()},
			tarball:      test.NewTarWriter(t).AddItems("pods", builder.ForPod("ns-1", "pod-2").Result()).Done(),
			actions: []riav2.RestoreItemAction{
				incompleteOperationAction,
			},
			want: []*itemoperation.RestoreOperation{
				{
					Spec: itemoperation.RestoreOperationSpec{
						RestoreName: "restore-1",
						ResourceIdentifier: velero.ResourceIdentifier{
							GroupResource: kuberesource.Pods,
							Namespace:     "ns-1",
							Name:          "pod-2"},
						OperationID: "pod-2-1",
					},
					Status: itemoperation.OperationStatus{
						Phase: "New",
					},
				},
			},
		},
		{
			name:         "action that has no operation doesn't record one",
			restore:      defaultRestore().Result(),
			backup:       defaultBackup().Result(),
			apiResources: []*test.APIResource{test.Pods()},
			tarball:      test.NewTarWriter(t).AddItems("pods", builder.ForPod("ns-1", "pod-3").Result()).Done(),
			actions: []riav2.RestoreItemAction{
				noOperationAction,
			},
			want: []*itemoperation.RestoreOperation{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)

			for _, r := range tc.apiResources {
				h.AddItems(t, r)
			}

			data := &Request{
				Log:              h.log,
				Restore:          tc.restore,
				Backup:           tc.backup,
				PodVolumeBackups: nil,
				VolumeSnapshots:  nil,
				BackupReader:     tc.tarball,
			}
			warnings, errs := h.restorer.Restore(
				data,
				tc.actions,
				nil, // volume snapshotter getter
			)

			assertEmptyResults(t, warnings, errs)
			resultOper := *data.GetItemOperationsList()
			// set want Created times so it won't fail the assert.Equal test
			for i, wantOper := range tc.want {
				wantOper.Status.Created = resultOper[i].Status.Created
			}
			assert.Equal(t, tc.want, *data.GetItemOperationsList())
		})
	}
}

// TestRestoreActionAdditionalItems runs restores with restore item actions that return additional items
// to be restored, and verifies that the correct set of items is created in the API. Verification is
// done by looking at the namespaces/names of the items in the API; contents are not checked.
func TestRestoreActionAdditionalItems(t *testing.T) {
	tests := []struct {
		name         string
		restore      *velerov1api.Restore
		backup       *velerov1api.Backup
		tarball      io.Reader
		apiResources []*test.APIResource
		actions      []riav2.RestoreItemAction
		want         map[*test.APIResource][]string
	}{
		{
			name:         "additional items that are already being restored are not restored twice",
			restore:      defaultRestore().Result(),
			backup:       defaultBackup().Result(),
			tarball:      test.NewTarWriter(t).AddItems("pods", builder.ForPod("ns-1", "pod-1").Result(), builder.ForPod("ns-2", "pod-2").Result()).Done(),
			apiResources: []*test.APIResource{test.Pods()},
			actions: []riav2.RestoreItemAction{
				&pluggableAction{
					selector: velero.ResourceSelector{IncludedNamespaces: []string{"ns-1"}},
					executeFunc: func(input *velero.RestoreItemActionExecuteInput) (*velero.RestoreItemActionExecuteOutput, error) {
						return &velero.RestoreItemActionExecuteOutput{
							UpdatedItem: input.Item,
							AdditionalItems: []velero.ResourceIdentifier{
								{GroupResource: kuberesource.Pods, Namespace: "ns-2", Name: "pod-2"},
							},
						}, nil
					},
				},
			},
			want: map[*test.APIResource][]string{
				test.Pods(): {"ns-1/pod-1", "ns-2/pod-2"},
			},
		},
		{
			name:         "when using a restore namespace filter, additional items that are in a non-included namespace are not restored",
			restore:      defaultRestore().IncludedNamespaces("ns-1").Result(),
			backup:       defaultBackup().Result(),
			tarball:      test.NewTarWriter(t).AddItems("pods", builder.ForPod("ns-1", "pod-1").Result(), builder.ForPod("ns-2", "pod-2").Result()).Done(),
			apiResources: []*test.APIResource{test.Pods()},
			actions: []riav2.RestoreItemAction{
				&pluggableAction{
					executeFunc: func(input *velero.RestoreItemActionExecuteInput) (*velero.RestoreItemActionExecuteOutput, error) {
						return &velero.RestoreItemActionExecuteOutput{
							UpdatedItem: input.Item,
							AdditionalItems: []velero.ResourceIdentifier{
								{GroupResource: kuberesource.Pods, Namespace: "ns-2", Name: "pod-2"},
							},
						}, nil
					},
				},
			},
			want: map[*test.APIResource][]string{
				test.Pods(): {"ns-1/pod-1"},
			},
		},
		{
			name:    "when using a restore namespace filter, additional items that are cluster-scoped are restored when IncludeClusterResources=nil",
			restore: defaultRestore().IncludedNamespaces("ns-1").Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("pods", builder.ForPod("ns-1", "pod-1").Result()).
				AddItems("persistentvolumes", builder.ForPersistentVolume("pv-1").Result()).
				Done(),
			apiResources: []*test.APIResource{test.Pods(), test.PVs()},
			actions: []riav2.RestoreItemAction{
				&pluggableAction{
					executeFunc: func(input *velero.RestoreItemActionExecuteInput) (*velero.RestoreItemActionExecuteOutput, error) {
						return &velero.RestoreItemActionExecuteOutput{
							UpdatedItem: input.Item,
							AdditionalItems: []velero.ResourceIdentifier{
								{GroupResource: kuberesource.PersistentVolumes, Name: "pv-1"},
							},
						}, nil
					},
				},
			},
			want: map[*test.APIResource][]string{
				test.Pods(): {"ns-1/pod-1"},
				test.PVs():  {"/pv-1"},
			},
		},
		{
			name:    "additional items that are cluster-scoped are not restored when IncludeClusterResources=false",
			restore: defaultRestore().IncludeClusterResources(false).Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("pods", builder.ForPod("ns-1", "pod-1").Result()).
				AddItems("persistentvolumes", builder.ForPersistentVolume("pv-1").Result()).
				Done(),
			apiResources: []*test.APIResource{test.Pods(), test.PVs()},
			actions: []riav2.RestoreItemAction{
				&pluggableAction{
					executeFunc: func(input *velero.RestoreItemActionExecuteInput) (*velero.RestoreItemActionExecuteOutput, error) {
						return &velero.RestoreItemActionExecuteOutput{
							UpdatedItem: input.Item,
							AdditionalItems: []velero.ResourceIdentifier{
								{GroupResource: kuberesource.PersistentVolumes, Name: "pv-1"},
							},
						}, nil
					},
				},
			},
			want: map[*test.APIResource][]string{
				test.Pods(): {"ns-1/pod-1"},
				test.PVs():  nil,
			},
		},
		{
			name:    "when using a restore resource filter, additional items that are non-included resources are not restored",
			restore: defaultRestore().IncludedResources("pods").Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("pods", builder.ForPod("ns-1", "pod-1").Result()).
				AddItems("persistentvolumes", builder.ForPersistentVolume("pv-1").Result()).
				Done(),
			apiResources: []*test.APIResource{test.Pods(), test.PVs()},
			actions: []riav2.RestoreItemAction{
				&pluggableAction{
					executeFunc: func(input *velero.RestoreItemActionExecuteInput) (*velero.RestoreItemActionExecuteOutput, error) {
						return &velero.RestoreItemActionExecuteOutput{
							UpdatedItem: input.Item,
							AdditionalItems: []velero.ResourceIdentifier{
								{GroupResource: kuberesource.PersistentVolumes, Name: "pv-1"},
							},
						}, nil
					},
				},
			},
			want: map[*test.APIResource][]string{
				test.Pods(): {"ns-1/pod-1"},
				test.PVs():  nil,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)

			for _, r := range tc.apiResources {
				h.AddItems(t, r)
			}

			data := &Request{
				Log:              h.log,
				Restore:          tc.restore,
				Backup:           tc.backup,
				PodVolumeBackups: nil,
				VolumeSnapshots:  nil,
				BackupReader:     tc.tarball,
			}
			warnings, errs := h.restorer.Restore(
				data,
				tc.actions,
				nil, // volume snapshotter getter
			)

			assertEmptyResults(t, warnings, errs)
			assertAPIContents(t, h, tc.want)
		})
	}
}

// TestShouldRestore runs the ShouldRestore function for various permutations of
// existing/nonexisting/being-deleted PVs, PVCs, and namespaces, and verifies the
// result/error matches expectations.
func TestShouldRestore(t *testing.T) {
	tests := []struct {
		name         string
		pvName       string
		apiResources []*test.APIResource
		namespaces   []*corev1api.Namespace
		want         bool
		wantErr      error
	}{
		{
			name:   "when PV is not found, result is true",
			pvName: "pv-1",
			want:   true,
		},
		{
			name:   "when PV is found and has Phase=Released, result is false",
			pvName: "pv-1",
			apiResources: []*test.APIResource{
				test.PVs(&corev1api.PersistentVolume{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "v1",
						Kind:       "PersistentVolume",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name: "pv-1",
					},
					Status: corev1api.PersistentVolumeStatus{
						Phase: corev1api.VolumeReleased,
					},
				}),
			},
			want: false,
		},
		{
			name:   "when PV is found and has associated PVC and namespace that aren't deleting, result is false",
			pvName: "pv-1",
			apiResources: []*test.APIResource{
				test.PVs(
					builder.ForPersistentVolume("pv-1").ClaimRef("ns-1", "pvc-1").Result(),
				),
				test.PVCs(builder.ForPersistentVolumeClaim("ns-1", "pvc-1").Result()),
			},
			namespaces: []*corev1api.Namespace{builder.ForNamespace("ns-1").Result()},
			want:       false,
		},
		{
			name:   "when PV is found and has associated PVC that is deleting, result is false + timeout error",
			pvName: "pv-1",
			apiResources: []*test.APIResource{
				test.PVs(
					builder.ForPersistentVolume("pv-1").ClaimRef("ns-1", "pvc-1").Result(),
				),
				test.PVCs(
					builder.ForPersistentVolumeClaim("ns-1", "pvc-1").ObjectMeta(builder.WithDeletionTimestamp(time.Now())).Result(),
				),
			},
			want:    false,
			wantErr: errors.New("context deadline exceeded"),
		},
		{
			name:   "when PV is found, has associated PVC that's not deleting, has associated NS that is terminating, result is false + timeout error",
			pvName: "pv-1",
			apiResources: []*test.APIResource{
				test.PVs(
					builder.ForPersistentVolume("pv-1").ClaimRef("ns-1", "pvc-1").Result(),
				),
				test.PVCs(builder.ForPersistentVolumeClaim("ns-1", "pvc-1").Result()),
			},
			namespaces: []*corev1api.Namespace{
				builder.ForNamespace("ns-1").Phase(corev1api.NamespaceTerminating).Result(),
			},
			want:    false,
			wantErr: errors.New("context deadline exceeded"),
		},
		{
			name:   "when PV is found, has associated PVC that's not deleting, has associated NS that has deletion timestamp, result is false + timeout error",
			pvName: "pv-1",
			apiResources: []*test.APIResource{
				test.PVs(
					builder.ForPersistentVolume("pv-1").ClaimRef("ns-1", "pvc-1").Result(),
				),
				test.PVCs(builder.ForPersistentVolumeClaim("ns-1", "pvc-1").Result()),
			},
			namespaces: []*corev1api.Namespace{
				builder.ForNamespace("ns-1").ObjectMeta(builder.WithDeletionTimestamp(time.Now())).Result(),
			},
			want:    false,
			wantErr: errors.New("context deadline exceeded"),
		},
		{
			name:   "when PV is found, associated PVC is not found, result is false + timeout error",
			pvName: "pv-1",
			apiResources: []*test.APIResource{
				test.PVs(
					builder.ForPersistentVolume("pv-1").ClaimRef("ns-1", "pvc-1").Result(),
				),
			},
			want:    false,
			wantErr: errors.New("context deadline exceeded"),
		},
		{
			name:   "when PV is found, has associated PVC, associated namespace not found, result is false + timeout error",
			pvName: "pv-1",
			apiResources: []*test.APIResource{
				test.PVs(
					builder.ForPersistentVolume("pv-1").ClaimRef("ns-1", "pvc-1").Result(),
				),
				test.PVCs(builder.ForPersistentVolumeClaim("ns-1", "pvc-1").Result()),
			},
			want:    false,
			wantErr: errors.New("context deadline exceeded"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)

			ctx := &restoreContext{
				log:                           h.log,
				dynamicFactory:                client.NewDynamicFactory(h.DynamicClient),
				namespaceClient:               h.KubeClient.CoreV1().Namespaces(),
				resourceTerminatingTimeout:    time.Millisecond,
				resourceDeletionStatusTracker: kube.NewResourceDeletionStatusTracker(),
			}

			for _, resource := range tc.apiResources {
				h.AddItems(t, resource)
			}

			for _, ns := range tc.namespaces {
				_, err := ctx.namespaceClient.Create(t.Context(), ns, metav1.CreateOptions{})
				require.NoError(t, err)
			}

			pvClient, err := ctx.dynamicFactory.ClientForGroupVersionResource(
				schema.GroupVersion{Group: "", Version: "v1"},
				metav1.APIResource{Name: "persistentvolumes"},
				"",
			)
			require.NoError(t, err)

			res, err := ctx.shouldRestore(tc.pvName, pvClient)
			assert.Equal(t, tc.want, res)
			if tc.wantErr != nil {
				if assert.Error(t, err, "expected a non-nil error") {
					assert.EqualError(t, err, tc.wantErr.Error())
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func assertRestoredItems(t *testing.T, h *harness, want []*test.APIResource) {
	t.Helper()

	for _, resource := range want {
		resourceClient := h.DynamicClient.Resource(resource.GVR())
		for _, item := range resource.Items {
			var client dynamic.ResourceInterface
			if item.GetNamespace() != "" {
				client = resourceClient.Namespace(item.GetNamespace())
			} else {
				client = resourceClient
			}

			res, err := client.Get(t.Context(), item.GetName(), metav1.GetOptions{})
			if !assert.NoError(t, err) { //nolint:testifylint // require is inappropriate
				continue
			}

			itemJSON, err := json.Marshal(item)
			if !assert.NoError(t, err) { //nolint:testifylint // require is inappropriate
				continue
			}

			t.Logf("%v", string(itemJSON))

			u := make(map[string]any)
			if !assert.NoError(t, json.Unmarshal(itemJSON, &u)) { //nolint:testifylint // require is inappropriate
				continue
			}
			want := &unstructured.Unstructured{Object: u}

			// These fields get non-nil zero values in the unstructured objects if they're
			// empty in the structured objects. Remove them to make comparison easier.
			unstructured.RemoveNestedField(want.Object, "metadata", "creationTimestamp")
			unstructured.RemoveNestedField(want.Object, "status")
			unstructured.RemoveNestedField(res.Object, "status")

			assert.Equal(t, want, res)
		}
	}
}

// volumeSnapshotterGetter is a simple implementation of the VolumeSnapshotterGetter
// interface that returns vsv1.VolumeSnapshotters from a map if they exist.
type volumeSnapshotterGetter map[string]vsv1.VolumeSnapshotter

func (vsg volumeSnapshotterGetter) GetVolumeSnapshotter(name string) (vsv1.VolumeSnapshotter, error) {
	snapshotter, ok := vsg[name]
	if !ok {
		return nil, errors.New("volume snapshotter not found")
	}

	return snapshotter, nil
}

// volumeSnapshotter is a test fake for the vsv1.VolumeSnapshotter interface
type volumeSnapshotter struct {
	// a map from snapshotID to volumeID
	snapshotVolumes map[string]string

	// a map from volumeID to new pv name
	pvName map[string]string
}

// Init is a no-op.
func (vs *volumeSnapshotter) Init(config map[string]string) error {
	return nil
}

// CreateVolumeFromSnapshot looks up the specified snapshotID in the snapshotVolumes
// map and returns the corresponding volumeID if it exists, or an error otherwise.
func (vs *volumeSnapshotter) CreateVolumeFromSnapshot(snapshotID, volumeType, volumeAZ string, iops *int64) (volumeID string, err error) {
	volumeID, ok := vs.snapshotVolumes[snapshotID]
	if !ok {
		return "", errors.New("snapshot not found")
	}

	return volumeID, nil
}

// SetVolumeID sets the persistent volume's spec.awsElasticBlockStore.volumeID field
// with the provided volumeID.
func (vs *volumeSnapshotter) SetVolumeID(pv runtime.Unstructured, volumeID string) (runtime.Unstructured, error) {
	unstructured.SetNestedField(pv.UnstructuredContent(), volumeID, "spec", "awsElasticBlockStore", "volumeID")

	newPVName, ok := vs.pvName[volumeID]
	if !ok {
		return pv, nil
	}

	unstructured.SetNestedField(pv.UnstructuredContent(), newPVName, "metadata", "name")
	return pv, nil
}

// GetVolumeID panics because it's not expected to be used for restores.
func (*volumeSnapshotter) GetVolumeID(pv runtime.Unstructured) (string, error) {
	panic("GetVolumeID should not be used for restores")
}

// CreateSnapshot panics because it's not expected to be used for restores.
func (*volumeSnapshotter) CreateSnapshot(volumeID, volumeAZ string, tags map[string]string) (snapshotID string, err error) {
	panic("CreateSnapshot should not be used for restores")
}

// GetVolumeInfo panics because it's not expected to be used for restores.
func (*volumeSnapshotter) GetVolumeInfo(volumeID, volumeAZ string) (string, *int64, error) {
	panic("GetVolumeInfo should not be used for restores")
}

// DeleteSnapshot panics because it's not expected to be used for restores.
func (*volumeSnapshotter) DeleteSnapshot(snapshotID string) error {
	panic("DeleteSnapshot should not be used for backups")
}

// TestRestorePersistentVolumes runs restores for persistent volumes and verifies that
// they are restored as expected, including restoring volumes from snapshots when expected.
// Verification is done by looking at the contents of the API and the metadata/spec/status of
// the items in the API.
func TestRestorePersistentVolumes(t *testing.T) {
	testPVCName := "testPVC"
	tests := []struct {
		name                    string
		restore                 *velerov1api.Restore
		backup                  *velerov1api.Backup
		tarball                 io.Reader
		apiResources            []*test.APIResource
		volumeSnapshots         []*volume.Snapshot
		volumeSnapshotLocations []*velerov1api.VolumeSnapshotLocation
		volumeSnapshotterGetter volumeSnapshotterGetter
		csiVolumeSnapshots      []*snapshotv1api.VolumeSnapshot
		dataUploadResult        *corev1api.ConfigMap
		want                    []*test.APIResource
		wantError               bool
		wantWarning             bool
		csiFeatureVerifierErr   string
	}{
		{
			name:    "when a PV with a reclaim policy of delete has no snapshot and does not exist in-cluster, it does not get restored, and its PVC gets reset for dynamic provisioning",
			restore: defaultRestore().Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("persistentvolumes",
					builder.ForPersistentVolume("pv-1").ReclaimPolicy(corev1api.PersistentVolumeReclaimDelete).ClaimRef("ns-1", "pvc-1").Result(),
				).
				AddItems("persistentvolumeclaims",
					builder.ForPersistentVolumeClaim("ns-1", "pvc-1").
						VolumeName("pv-1").
						ObjectMeta(
							builder.WithAnnotations("pv.kubernetes.io/bind-completed", "true", "pv.kubernetes.io/bound-by-controller", "true", "foo", "bar"),
						).
						Result(),
				).
				Done(),
			apiResources: []*test.APIResource{
				test.PVs(),
				test.PVCs(),
			},
			want: []*test.APIResource{
				test.PVs(),
				test.PVCs(
					builder.ForPersistentVolumeClaim("ns-1", "pvc-1").
						ObjectMeta(
							builder.WithAnnotations("foo", "bar"),
							builder.WithLabels("velero.io/backup-name", "backup-1", "velero.io/restore-name", "restore-1"),
						).
						Result(),
				),
			},
		},
		{
			name:    "when a PV with a reclaim policy of retain has no snapshot and does not exist in-cluster, it gets restored, with its claim ref",
			restore: defaultRestore().Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("persistentvolumes",
					builder.ForPersistentVolume("pv-1").ReclaimPolicy(corev1api.PersistentVolumeReclaimRetain).ClaimRef("ns-1", "pvc-1").Result(),
				).
				Done(),
			apiResources: []*test.APIResource{
				test.PVs(),
				test.PVCs(),
			},
			want: []*test.APIResource{
				test.PVs(
					builder.ForPersistentVolume("pv-1").
						ReclaimPolicy(corev1api.PersistentVolumeReclaimRetain).
						ObjectMeta(
							builder.WithLabels("velero.io/backup-name", "backup-1", "velero.io/restore-name", "restore-1"),
						).
						ClaimRef("ns-1", "pvc-1").
						Result(),
				),
			},
		},
		{
			name:    "when a PV with a reclaim policy of delete has a snapshot and does not exist in-cluster, the snapshot and PV are restored",
			restore: defaultRestore().Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("persistentvolumes",
					builder.ForPersistentVolume("pv-1").ReclaimPolicy(corev1api.PersistentVolumeReclaimDelete).AWSEBSVolumeID("old-volume").Result(),
				).
				Done(),
			apiResources: []*test.APIResource{
				test.PVs(),
				test.PVCs(),
			},
			volumeSnapshots: []*volume.Snapshot{
				{
					Spec: volume.SnapshotSpec{
						BackupName:           "backup-1",
						Location:             "default",
						PersistentVolumeName: "pv-1",
					},
					Status: volume.SnapshotStatus{
						Phase:              volume.SnapshotPhaseCompleted,
						ProviderSnapshotID: "snapshot-1",
					},
				},
			},
			volumeSnapshotLocations: []*velerov1api.VolumeSnapshotLocation{
				builder.ForVolumeSnapshotLocation(velerov1api.DefaultNamespace, "default").Provider("provider-1").Result(),
			},
			volumeSnapshotterGetter: map[string]vsv1.VolumeSnapshotter{
				"provider-1": &volumeSnapshotter{
					snapshotVolumes: map[string]string{"snapshot-1": "new-volume"},
				},
			},
			want: []*test.APIResource{
				test.PVs(
					builder.ForPersistentVolume("pv-1").
						ReclaimPolicy(corev1api.PersistentVolumeReclaimDelete).
						AWSEBSVolumeID("new-volume").
						ObjectMeta(
							builder.WithLabels("velero.io/backup-name", "backup-1", "velero.io/restore-name", "restore-1"),
						).
						Result(),
				),
			},
		},
		{
			name:    "when a PV with a reclaim policy of retain has a snapshot and does not exist in-cluster, the snapshot and PV are restored",
			restore: defaultRestore().Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("persistentvolumes",
					builder.ForPersistentVolume("pv-1").
						ReclaimPolicy(corev1api.PersistentVolumeReclaimRetain).
						AWSEBSVolumeID("old-volume").
						Result(),
				).
				Done(),
			apiResources: []*test.APIResource{
				test.PVs(),
				test.PVCs(),
			},
			volumeSnapshots: []*volume.Snapshot{
				{
					Spec: volume.SnapshotSpec{
						BackupName:           "backup-1",
						Location:             "default",
						PersistentVolumeName: "pv-1",
					},
					Status: volume.SnapshotStatus{
						Phase:              volume.SnapshotPhaseCompleted,
						ProviderSnapshotID: "snapshot-1",
					},
				},
			},
			volumeSnapshotLocations: []*velerov1api.VolumeSnapshotLocation{
				builder.ForVolumeSnapshotLocation(velerov1api.DefaultNamespace, "default").Provider("provider-1").Result(),
			},
			volumeSnapshotterGetter: map[string]vsv1.VolumeSnapshotter{
				"provider-1": &volumeSnapshotter{
					snapshotVolumes: map[string]string{"snapshot-1": "new-volume"},
				},
			},
			want: []*test.APIResource{
				test.PVs(
					builder.ForPersistentVolume("pv-1").
						ReclaimPolicy(corev1api.PersistentVolumeReclaimRetain).
						AWSEBSVolumeID("new-volume").
						ObjectMeta(
							builder.WithLabels("velero.io/backup-name", "backup-1", "velero.io/restore-name", "restore-1"),
						).
						Result(),
				),
			},
		},
		{
			name:    "when a PV with a reclaim policy of delete has a snapshot and exists in-cluster, neither the snapshot nor the PV are restored",
			restore: defaultRestore().Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("persistentvolumes",
					builder.ForPersistentVolume("pv-1").
						ReclaimPolicy(corev1api.PersistentVolumeReclaimDelete).
						AWSEBSVolumeID("old-volume").
						Result(),
				).
				Done(),
			apiResources: []*test.APIResource{
				test.PVs(
					builder.ForPersistentVolume("pv-1").
						ReclaimPolicy(corev1api.PersistentVolumeReclaimDelete).
						AWSEBSVolumeID("old-volume").
						Result(),
				),
				test.PVCs(),
			},
			volumeSnapshots: []*volume.Snapshot{
				{
					Spec: volume.SnapshotSpec{
						BackupName:           "backup-1",
						Location:             "default",
						PersistentVolumeName: "pv-1",
					},
					Status: volume.SnapshotStatus{
						Phase:              volume.SnapshotPhaseCompleted,
						ProviderSnapshotID: "snapshot-1",
					},
				},
			},
			volumeSnapshotLocations: []*velerov1api.VolumeSnapshotLocation{
				builder.ForVolumeSnapshotLocation(velerov1api.DefaultNamespace, "default").Provider("provider-1").Result(),
			},
			volumeSnapshotterGetter: map[string]vsv1.VolumeSnapshotter{
				// the volume snapshotter fake is not configured with any snapshotID -> volumeID
				// mappings as a way to verify that the snapshot is not restored, since if it were
				// restored, we'd get an error of "snapshot not found".
				"provider-1": &volumeSnapshotter{},
			},
			want: []*test.APIResource{
				test.PVs(
					builder.ForPersistentVolume("pv-1").
						ReclaimPolicy(corev1api.PersistentVolumeReclaimDelete).
						AWSEBSVolumeID("old-volume").
						Result(),
				),
			},
		},
		{
			name:    "when a PV with a reclaim policy of retain has a snapshot and exists in-cluster, neither the snapshot nor the PV are restored",
			restore: defaultRestore().Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("persistentvolumes",
					builder.ForPersistentVolume("pv-1").
						ReclaimPolicy(corev1api.PersistentVolumeReclaimRetain).
						AWSEBSVolumeID("old-volume").
						Result(),
				).
				Done(),
			apiResources: []*test.APIResource{
				test.PVs(
					builder.ForPersistentVolume("pv-1").
						ReclaimPolicy(corev1api.PersistentVolumeReclaimRetain).
						AWSEBSVolumeID("old-volume").
						Result(),
				),
				test.PVCs(),
			},
			volumeSnapshots: []*volume.Snapshot{
				{
					Spec: volume.SnapshotSpec{
						BackupName:           "backup-1",
						Location:             "default",
						PersistentVolumeName: "pv-1",
					},
					Status: volume.SnapshotStatus{
						Phase:              volume.SnapshotPhaseCompleted,
						ProviderSnapshotID: "snapshot-1",
					},
				},
			},
			volumeSnapshotLocations: []*velerov1api.VolumeSnapshotLocation{
				builder.ForVolumeSnapshotLocation(velerov1api.DefaultNamespace, "default").Provider("provider-1").Result(),
			},
			volumeSnapshotterGetter: map[string]vsv1.VolumeSnapshotter{
				// the volume snapshotter fake is not configured with any snapshotID -> volumeID
				// mappings as a way to verify that the snapshot is not restored, since if it were
				// restored, we'd get an error of "snapshot not found".
				"provider-1": &volumeSnapshotter{},
			},
			want: []*test.APIResource{
				test.PVs(
					builder.ForPersistentVolume("pv-1").
						ReclaimPolicy(corev1api.PersistentVolumeReclaimRetain).
						AWSEBSVolumeID("old-volume").
						Result(),
				),
			},
		},
		{
			name:    "when a PV with a snapshot is used by a PVC in a namespace that's being remapped, and the original PV exists in-cluster, the PV is renamed",
			restore: defaultRestore().NamespaceMappings("source-ns", "target-ns").Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems(
					"persistentvolumes",
					builder.ForPersistentVolume("source-pv").AWSEBSVolumeID("source-volume").ClaimRef("source-ns", "pvc-1").Result(),
				).
				AddItems(
					"persistentvolumeclaims",
					builder.ForPersistentVolumeClaim("source-ns", "pvc-1").VolumeName("source-pv").Result(),
				).
				Done(),
			apiResources: []*test.APIResource{
				test.PVs(
					builder.ForPersistentVolume("source-pv").AWSEBSVolumeID("source-volume").ClaimRef("source-ns", "pvc-1").Result(),
				),
				test.PVCs(),
			},
			volumeSnapshots: []*volume.Snapshot{
				{
					Spec: volume.SnapshotSpec{
						BackupName:           "backup-1",
						Location:             "default",
						PersistentVolumeName: "source-pv",
					},
					Status: volume.SnapshotStatus{
						Phase:              volume.SnapshotPhaseCompleted,
						ProviderSnapshotID: "snapshot-1",
					},
				},
			},
			volumeSnapshotLocations: []*velerov1api.VolumeSnapshotLocation{
				builder.ForVolumeSnapshotLocation(velerov1api.DefaultNamespace, "default").Provider("provider-1").Result(),
			},
			volumeSnapshotterGetter: map[string]vsv1.VolumeSnapshotter{
				"provider-1": &volumeSnapshotter{
					snapshotVolumes: map[string]string{"snapshot-1": "new-volume"},
				},
			},
			want: []*test.APIResource{
				test.PVs(
					builder.ForPersistentVolume("source-pv").AWSEBSVolumeID("source-volume").ClaimRef("source-ns", "pvc-1").Result(),
					builder.ForPersistentVolume("renamed-source-pv").
						ObjectMeta(
							builder.WithAnnotations("velero.io/original-pv-name", "source-pv"),
							builder.WithLabels("velero.io/backup-name", "backup-1", "velero.io/restore-name", "restore-1"),
							// the namespace for this PV's claimRef should be the one that the PVC was remapped into.
						).ClaimRef("target-ns", "pvc-1").
						AWSEBSVolumeID("new-volume").
						Result(),
				),
				test.PVCs(
					builder.ForPersistentVolumeClaim("target-ns", "pvc-1").
						ObjectMeta(
							builder.WithLabels("velero.io/backup-name", "backup-1", "velero.io/restore-name", "restore-1"),
						).
						VolumeName("renamed-source-pv").
						Result(),
				),
			},
		},
		{
			name:    "when a PV with a snapshot is used by a PVC in a namespace that's being remapped, and the original PV does not exist in-cluster, the PV is not renamed",
			restore: defaultRestore().NamespaceMappings("source-ns", "target-ns").Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems(
					"persistentvolumes",
					builder.ForPersistentVolume("source-pv").AWSEBSVolumeID("source-volume").ClaimRef("source-ns", "pvc-1").Result(),
				).
				AddItems(
					"persistentvolumeclaims",
					builder.ForPersistentVolumeClaim("source-ns", "pvc-1").VolumeName("source-pv").Result(),
				).
				Done(),
			apiResources: []*test.APIResource{
				test.PVs(),
				test.PVCs(),
			},
			volumeSnapshots: []*volume.Snapshot{
				{
					Spec: volume.SnapshotSpec{
						BackupName:           "backup-1",
						Location:             "default",
						PersistentVolumeName: "source-pv",
					},
					Status: volume.SnapshotStatus{
						Phase:              volume.SnapshotPhaseCompleted,
						ProviderSnapshotID: "snapshot-1",
					},
				},
			},
			volumeSnapshotLocations: []*velerov1api.VolumeSnapshotLocation{
				builder.ForVolumeSnapshotLocation(velerov1api.DefaultNamespace, "default").Provider("provider-1").Result(),
			},
			volumeSnapshotterGetter: map[string]vsv1.VolumeSnapshotter{
				"provider-1": &volumeSnapshotter{
					snapshotVolumes: map[string]string{"snapshot-1": "new-volume"},
				},
			},
			want: []*test.APIResource{
				test.PVs(
					builder.ForPersistentVolume("source-pv").
						ObjectMeta(
							builder.WithLabels("velero.io/backup-name", "backup-1", "velero.io/restore-name", "restore-1"),
						).
						ClaimRef("target-ns", "pvc-1").
						AWSEBSVolumeID("new-volume").
						Result(),
				),
				test.PVCs(
					builder.ForPersistentVolumeClaim("target-ns", "pvc-1").
						ObjectMeta(
							builder.WithLabels("velero.io/backup-name", "backup-1", "velero.io/restore-name", "restore-1"),
						).
						VolumeName("source-pv").
						Result(),
				),
			},
		},
		{
			name:    "when a PV without a snapshot is used by a PVC in a namespace that's being remapped, and the original PV exists in-cluster, the PV is not replaced and there is a restore warning",
			restore: defaultRestore().NamespaceMappings("source-ns", "target-ns").Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems(
					"persistentvolumes",
					builder.ForPersistentVolume("source-pv").
						//ReclaimPolicy(corev1api.PersistentVolumeReclaimRetain).
						AWSEBSVolumeID("source-volume").
						ClaimRef("source-ns", "pvc-1").
						Result(),
				).
				AddItems(
					"persistentvolumeclaims",
					builder.ForPersistentVolumeClaim("source-ns", "pvc-1").VolumeName("source-pv").Result(),
				).
				Done(),
			apiResources: []*test.APIResource{
				test.PVs(
					builder.ForPersistentVolume("source-pv").
						//ReclaimPolicy(corev1api.PersistentVolumeReclaimRetain).
						AWSEBSVolumeID("source-volume").
						ClaimRef("source-ns", "pvc-1").
						Result(),
				),
				test.PVCs(),
			},
			want: []*test.APIResource{
				test.PVs(
					builder.ForPersistentVolume("source-pv").
						AWSEBSVolumeID("source-volume").
						ClaimRef("source-ns", "pvc-1").
						Result(),
				),
				test.PVCs(
					builder.ForPersistentVolumeClaim("target-ns", "pvc-1").
						ObjectMeta(
							builder.WithLabels("velero.io/backup-name", "backup-1", "velero.io/restore-name", "restore-1"),
						).
						VolumeName("source-pv").
						Result(),
				),
			},
			wantWarning: true,
		},
		{
			name:    "when a PV without a snapshot is used by a PVC in a namespace that's being remapped, and the original PV does not exist in-cluster, the PV is not renamed",
			restore: defaultRestore().NamespaceMappings("source-ns", "target-ns").Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems(
					"persistentvolumes",
					builder.ForPersistentVolume("source-pv").
						AWSEBSVolumeID("source-volume").
						ClaimRef("source-ns", "pvc-1").
						Result(),
				).
				AddItems(
					"persistentvolumeclaims",
					builder.ForPersistentVolumeClaim("source-ns", "pvc-1").VolumeName("source-pv").Result(),
				).
				Done(),
			apiResources: []*test.APIResource{
				test.PVs(),
				test.PVCs(),
			},
			want: []*test.APIResource{
				test.PVs(
					builder.ForPersistentVolume("source-pv").
						//ReclaimPolicy(corev1api.PersistentVolumeReclaimRetain).
						ObjectMeta(
							builder.WithLabels("velero.io/backup-name", "backup-1", "velero.io/restore-name", "restore-1"),
						).
						// the namespace for this PV's claimRef should be the one that the PVC was remapped into.
						ClaimRef("target-ns", "pvc-1").
						AWSEBSVolumeID("source-volume").
						Result(),
				),
				test.PVCs(
					builder.ForPersistentVolumeClaim("target-ns", "pvc-1").
						ObjectMeta(
							builder.WithLabels("velero.io/backup-name", "backup-1", "velero.io/restore-name", "restore-1"),
						).
						VolumeName("source-pv").
						Result(),
				),
			},
		},
		{
			name:    "when a PV is renamed and the original PV does not exist in-cluster, the PV should be renamed",
			restore: defaultRestore().NamespaceMappings("source-ns", "target-ns").Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems(
					"persistentvolumes",
					builder.ForPersistentVolume("source-pv").AWSEBSVolumeID("source-volume").ClaimRef("source-ns", "pvc-1").Result(),
				).
				AddItems(
					"persistentvolumeclaims",
					builder.ForPersistentVolumeClaim("source-ns", "pvc-1").VolumeName("source-pv").Result(),
				).
				Done(),
			apiResources: []*test.APIResource{
				test.PVs(),
				test.PVCs(),
			},
			volumeSnapshots: []*volume.Snapshot{
				{
					Spec: volume.SnapshotSpec{
						BackupName:           "backup-1",
						Location:             "default",
						PersistentVolumeName: "source-pv",
					},
					Status: volume.SnapshotStatus{
						Phase:              volume.SnapshotPhaseCompleted,
						ProviderSnapshotID: "snapshot-1",
					},
				},
			},
			volumeSnapshotLocations: []*velerov1api.VolumeSnapshotLocation{
				builder.ForVolumeSnapshotLocation(velerov1api.DefaultNamespace, "default").Provider("provider-1").Result(),
			},
			volumeSnapshotterGetter: map[string]vsv1.VolumeSnapshotter{
				"provider-1": &volumeSnapshotter{
					snapshotVolumes: map[string]string{"snapshot-1": "new-pvname"},
					pvName:          map[string]string{"new-pvname": "new-pvname"},
				},
			},
			want: []*test.APIResource{
				test.PVs(
					builder.ForPersistentVolume("new-pvname").
						ObjectMeta(
							builder.WithLabels("velero.io/backup-name", "backup-1", "velero.io/restore-name", "restore-1"),
							builder.WithAnnotations("velero.io/original-pv-name", "source-pv"),
						).
						ClaimRef("target-ns", "pvc-1").
						AWSEBSVolumeID("new-pvname").
						Result(),
				),
				test.PVCs(
					builder.ForPersistentVolumeClaim("target-ns", "pvc-1").
						ObjectMeta(
							builder.WithLabels("velero.io/backup-name", "backup-1", "velero.io/restore-name", "restore-1"),
						).
						VolumeName("new-pvname").
						Result(),
				),
			},
		},
		{
			name:    "when a PV with a reclaim policy of retain has a snapshot and exists in-cluster, neither the snapshot nor the PV are restored",
			restore: defaultRestore().Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("persistentvolumes",
					builder.ForPersistentVolume("pv-1").
						ReclaimPolicy(corev1api.PersistentVolumeReclaimRetain).
						AWSEBSVolumeID("old-volume").
						Result(),
				).
				Done(),
			apiResources: []*test.APIResource{
				test.PVs(
					builder.ForPersistentVolume("pv-1").
						ReclaimPolicy(corev1api.PersistentVolumeReclaimRetain).
						AWSEBSVolumeID("old-volume").
						Result(),
				),
				test.PVCs(),
			},
			volumeSnapshots: []*volume.Snapshot{
				{
					Spec: volume.SnapshotSpec{
						BackupName:           "backup-1",
						Location:             "default",
						PersistentVolumeName: "pv-1",
					},
					Status: volume.SnapshotStatus{
						Phase:              volume.SnapshotPhaseCompleted,
						ProviderSnapshotID: "snapshot-1",
					},
				},
			},
			volumeSnapshotLocations: []*velerov1api.VolumeSnapshotLocation{
				{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: velerov1api.DefaultNamespace,
						Name:      "default",
					},
					Spec: velerov1api.VolumeSnapshotLocationSpec{
						Provider: "provider-1",
					},
				},
			},
			volumeSnapshotterGetter: map[string]vsv1.VolumeSnapshotter{
				// the volume snapshotter fake is not configured with any snapshotID -> volumeID
				// mappings as a way to verify that the snapshot is not restored, since if it were
				// restored, we'd get an error of "snapshot not found".
				"provider-1": &volumeSnapshotter{},
			},

			want: []*test.APIResource{
				test.PVs(
					builder.ForPersistentVolume("pv-1").
						ReclaimPolicy(corev1api.PersistentVolumeReclaimRetain).
						AWSEBSVolumeID("old-volume").
						Result(),
				),
			},
		},
		{
			name:    "when a PV with a snapshot is used by a PVC in a namespace that's being remapped, and the original PV exists in-cluster, the PV is renamed by volumesnapshotter",
			restore: defaultRestore().NamespaceMappings("source-ns", "target-ns").Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems(
					"persistentvolumes",
					builder.ForPersistentVolume("source-pv").AWSEBSVolumeID("source-volume").ClaimRef("source-ns", "pvc-1").Result(),
				).
				AddItems(
					"persistentvolumeclaims",
					builder.ForPersistentVolumeClaim("source-ns", "pvc-1").VolumeName("source-pv").Result(),
				).
				Done(),
			apiResources: []*test.APIResource{
				test.PVs(
					builder.ForPersistentVolume("source-pv").AWSEBSVolumeID("source-volume").ClaimRef("source-ns", "pvc-1").Result(),
				),
				test.PVCs(),
			},
			volumeSnapshots: []*volume.Snapshot{
				{
					Spec: volume.SnapshotSpec{
						BackupName:           "backup-1",
						Location:             "default",
						PersistentVolumeName: "source-pv",
					},
					Status: volume.SnapshotStatus{
						Phase:              volume.SnapshotPhaseCompleted,
						ProviderSnapshotID: "snapshot-1",
					},
				},
			},
			volumeSnapshotLocations: []*velerov1api.VolumeSnapshotLocation{
				builder.ForVolumeSnapshotLocation(velerov1api.DefaultNamespace, "default").Provider("provider-1").Result(),
			},
			volumeSnapshotterGetter: map[string]vsv1.VolumeSnapshotter{
				"provider-1": &volumeSnapshotter{
					snapshotVolumes: map[string]string{"snapshot-1": "new-volume"},
					pvName:          map[string]string{"new-volume": "volumesnapshotter-renamed-source-pv"},
				},
			},
			want: []*test.APIResource{
				test.PVs(
					builder.ForPersistentVolume("source-pv").AWSEBSVolumeID("source-volume").ClaimRef("source-ns", "pvc-1").Result(),
					builder.ForPersistentVolume("volumesnapshotter-renamed-source-pv").
						ObjectMeta(
							builder.WithAnnotations("velero.io/original-pv-name", "source-pv"),
							builder.WithLabels("velero.io/backup-name", "backup-1", "velero.io/restore-name", "restore-1"),
						).
						ClaimRef("target-ns", "pvc-1").
						AWSEBSVolumeID("new-volume").
						Result(),
				),
				test.PVCs(
					builder.ForPersistentVolumeClaim("target-ns", "pvc-1").
						ObjectMeta(
							builder.WithLabels("velero.io/backup-name", "backup-1", "velero.io/restore-name", "restore-1"),
						).
						VolumeName("volumesnapshotter-renamed-source-pv").
						Result(),
				),
			},
		},
		{
			name:    "when a PV with a reclaim policy of retain has a CSI VolumeSnapshot and does not exist in-cluster, the PV is not restored",
			restore: defaultRestore().Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("persistentvolumes",
					builder.ForPersistentVolume("pv-1").
						ReclaimPolicy(corev1api.PersistentVolumeReclaimRetain).
						ClaimRef("velero", testPVCName).
						Result(),
				).
				Done(),
			apiResources: []*test.APIResource{
				test.PVs(),
				test.PVCs(),
			},
			csiVolumeSnapshots: []*snapshotv1api.VolumeSnapshot{
				{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "velero",
						Name:      "test",
					},
					Spec: snapshotv1api.VolumeSnapshotSpec{
						Source: snapshotv1api.VolumeSnapshotSource{
							PersistentVolumeClaimName: &testPVCName,
						},
					},
				},
			},
			volumeSnapshotLocations: []*velerov1api.VolumeSnapshotLocation{
				builder.ForVolumeSnapshotLocation(velerov1api.DefaultNamespace, "default").Provider("provider-1").Result(),
			},
			volumeSnapshotterGetter: map[string]vsv1.VolumeSnapshotter{
				"provider-1": &volumeSnapshotter{
					snapshotVolumes: map[string]string{"snapshot-1": "new-volume"},
				},
			},
			want: []*test.APIResource{},
		},
		{
			name:    "when a PV with a reclaim policy of retain has a DataUpload result CM and does not exist in-cluster, the PV is not restored",
			restore: defaultRestore().ObjectMeta(builder.WithUID("fakeUID")).Result(),
			backup:  defaultBackup().Result(),
			tarball: test.NewTarWriter(t).
				AddItems("persistentvolumes",
					builder.ForPersistentVolume("pv-1").
						ReclaimPolicy(corev1api.PersistentVolumeReclaimRetain).
						ClaimRef("velero", testPVCName).
						Result(),
				).
				Done(),
			apiResources: []*test.APIResource{
				test.PVs(),
				test.PVCs(),
				test.ConfigMaps(),
			},
			volumeSnapshotLocations: []*velerov1api.VolumeSnapshotLocation{
				builder.ForVolumeSnapshotLocation(velerov1api.DefaultNamespace, "default").Provider("provider-1").Result(),
			},
			volumeSnapshotterGetter: map[string]vsv1.VolumeSnapshotter{
				"provider-1": &volumeSnapshotter{
					snapshotVolumes: map[string]string{"snapshot-1": "new-volume"},
				},
			},
			dataUploadResult: builder.ForConfigMap("velero", "test").ObjectMeta(builder.WithLabelsMap(map[string]string{
				velerov1api.RestoreUIDLabel:       "fakeUID",
				velerov1api.PVCNamespaceNameLabel: "velero.testPVC",
				velerov1api.ResourceUsageLabel:    string(velerov1api.VeleroResourceUsageDataUploadResult),
			})).Result(),
			want: []*test.APIResource{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.restorer.resourcePriorities = types.Priorities{HighPriorities: []string{"persistentvolumes", "persistentvolumeclaims"}}
			h.restorer.pvRenamer = func(oldName string) (string, error) {
				renamed := "renamed-" + oldName
				return renamed, nil
			}

			// set up the VolumeSnapshotLocation client and add test data to it
			for _, vsl := range tc.volumeSnapshotLocations {
				require.NoError(t, h.restorer.kbClient.Create(t.Context(), vsl))
			}

			if tc.dataUploadResult != nil {
				require.NoError(t, h.restorer.kbClient.Create(t.Context(), tc.dataUploadResult))
			}

			for _, r := range tc.apiResources {
				h.AddItems(t, r)
			}

			// Collect the IDs of all of the wanted resources so we can ensure the
			// exact set exists in the API after restore.
			wantIDs := make(map[*test.APIResource][]string)
			for i, resource := range tc.want {
				wantIDs[tc.want[i]] = []string{}

				for _, item := range resource.Items {
					wantIDs[tc.want[i]] = append(wantIDs[tc.want[i]], fmt.Sprintf("%s/%s", item.GetNamespace(), item.GetName()))
				}
			}

			data := &Request{
				Log:                      h.log,
				Restore:                  tc.restore,
				Backup:                   tc.backup,
				VolumeSnapshots:          tc.volumeSnapshots,
				BackupReader:             tc.tarball,
				CSIVolumeSnapshots:       tc.csiVolumeSnapshots,
				RestoreVolumeInfoTracker: volume.NewRestoreVolInfoTracker(tc.restore, h.log, test.NewFakeControllerRuntimeClient(t)),
			}
			warnings, errs := h.restorer.Restore(
				data,
				nil, // restoreItemActions
				tc.volumeSnapshotterGetter,
			)

			if tc.wantWarning {
				assertNonEmptyResults(t, "warning", warnings)
			} else {
				assertEmptyResults(t, warnings)
			}
			if tc.wantError {
				assertNonEmptyResults(t, "error", errs)
			} else {
				assertEmptyResults(t, errs)
			}
			assertAPIContents(t, h, wantIDs)
			assertRestoredItems(t, h, tc.want)
		})
	}
}

type fakePodVolumeRestorerFactory struct {
	restorer *uploadermocks.Restorer
}

func (f *fakePodVolumeRestorerFactory) NewRestorer(context.Context, *velerov1api.Restore) (podvolume.Restorer, error) {
	return f.restorer, nil
}

// TestRestoreWithPodVolume verifies that a call to RestorePodVolumes was made as and when
// expected for the given pods by using a mock for the pod volume restorer.
func TestRestoreWithPodVolume(t *testing.T) {
	tests := []struct {
		name                        string
		restore                     *velerov1api.Restore
		backup                      *velerov1api.Backup
		apiResources                []*test.APIResource
		podVolumeBackups            []*velerov1api.PodVolumeBackup
		podWithPVBs, podWithoutPVBs []*corev1api.Pod
		want                        map[*test.APIResource][]string
	}{
		{
			name:         "a pod that exists in given backup and contains associated PVBs should have RestorePodVolumes called",
			restore:      defaultRestore().Result(),
			backup:       defaultBackup().Result(),
			apiResources: []*test.APIResource{test.Pods()},
			podVolumeBackups: []*velerov1api.PodVolumeBackup{
				builder.ForPodVolumeBackup("velero", "pvb-1").PodName("pod-1").SnapshotID("foo").Result(),
				builder.ForPodVolumeBackup("velero", "pvb-2").PodName("pod-2").PodNamespace("ns-1").SnapshotID("foo").Result(),
				builder.ForPodVolumeBackup("velero", "pvb-3").PodName("pod-4").PodNamespace("ns-2").SnapshotID("foo").Result(),
			},
			podWithPVBs: []*corev1api.Pod{
				builder.ForPod("ns-1", "pod-2").
					Result(),
				builder.ForPod("ns-2", "pod-4").
					Result(),
			},
			podWithoutPVBs: []*corev1api.Pod{
				builder.ForPod("ns-2", "pod-3").
					Result(),
			},
			want: map[*test.APIResource][]string{
				test.Pods(): {"ns-1/pod-2", "ns-2/pod-3", "ns-2/pod-4"},
			},
		},
		{
			name:         "a pod that exists in given backup but does not contain associated PVBs should not have should have RestorePodVolumes called",
			restore:      defaultRestore().Result(),
			backup:       defaultBackup().Result(),
			apiResources: []*test.APIResource{test.Pods()},
			podVolumeBackups: []*velerov1api.PodVolumeBackup{
				builder.ForPodVolumeBackup("velero", "pvb-1").PodName("pod-1").Result(),
				builder.ForPodVolumeBackup("velero", "pvb-2").PodName("pod-2").Result(),
			},
			podWithPVBs: []*corev1api.Pod{},
			podWithoutPVBs: []*corev1api.Pod{
				builder.ForPod("ns-1", "pod-3").
					Result(),
				builder.ForPod("ns-2", "pod-4").
					Result(),
			},
			want: map[*test.APIResource][]string{
				test.Pods(): {"ns-1/pod-3", "ns-2/pod-4"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			restorer := new(uploadermocks.Restorer)
			defer restorer.AssertExpectations(t)
			h.restorer.podVolumeRestorerFactory = &fakePodVolumeRestorerFactory{
				restorer: restorer,
			}

			// needed only to indicate resource types that can be restored, in this case, pods
			for _, resource := range tc.apiResources {
				h.AddItems(t, resource)
			}

			tarball := test.NewTarWriter(t)

			// these backed up pods don't have any PVBs associated with them, so a call to RestorePodVolumes is not expected to be made for them
			for _, pod := range tc.podWithoutPVBs {
				tarball.AddItems("pods", pod)
			}

			// these backed up pods have PVBs associated with them, so a call to RestorePodVolumes will be made for each of them
			for _, pod := range tc.podWithPVBs {
				tarball.AddItems("pods", pod)

				// the restore process adds these labels before restoring, so we must add them here too otherwise they won't match
				pod.Labels = map[string]string{"velero.io/backup-name": tc.backup.Name, "velero.io/restore-name": tc.restore.Name}
				expectedArgs := podvolume.RestoreData{
					Restore:          tc.restore,
					Pod:              pod,
					PodVolumeBackups: tc.podVolumeBackups,
					SourceNamespace:  pod.Namespace,
					BackupLocation:   "",
				}
				restorer.
					On("RestorePodVolumes", expectedArgs, mock.Anything).
					Return(nil)
			}

			data := &Request{
				Log:              h.log,
				Restore:          tc.restore,
				Backup:           tc.backup,
				PodVolumeBackups: tc.podVolumeBackups,
				BackupReader:     tarball.Done(),
			}

			warnings, errs := h.restorer.Restore(
				data,
				nil, // restoreItemActions
				nil, // volume snapshotter getter
			)

			assertEmptyResults(t, warnings, errs)
			assertAPIContents(t, h, tc.want)
		})
	}
}

func TestResetMetadata(t *testing.T) {
	tests := []struct {
		name        string
		obj         *unstructured.Unstructured
		expectedErr bool
		expectedRes *unstructured.Unstructured
	}{
		{
			name:        "no metadata causes error",
			obj:         &unstructured.Unstructured{},
			expectedErr: true,
		},
		{
			name:        "keep name, namespace, labels, annotations, managedFields, finalizers",
			obj:         newTestUnstructured().WithMetadata("name", "namespace", "labels", "annotations", "managedFields", "finalizers").Unstructured,
			expectedErr: false,
			expectedRes: newTestUnstructured().WithMetadata("name", "namespace", "labels", "annotations", "managedFields", "finalizers").Unstructured,
		},
		{
			name:        "remove uid, ownerReferences",
			obj:         newTestUnstructured().WithMetadata("name", "namespace", "uid", "ownerReferences").Unstructured,
			expectedErr: false,
			expectedRes: newTestUnstructured().WithMetadata("name", "namespace").Unstructured,
		},
		{
			name:        "keep status",
			obj:         newTestUnstructured().WithMetadata().WithStatus().Unstructured,
			expectedErr: false,
			expectedRes: newTestUnstructured().WithMetadata().WithStatus().Unstructured,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, err := resetMetadata(test.obj)

			if assert.Equal(t, test.expectedErr, err != nil) {
				assert.Equal(t, test.expectedRes, res)
			}
		})
	}
}

func TestResetStatus(t *testing.T) {
	tests := []struct {
		name        string
		obj         *unstructured.Unstructured
		expectedRes *unstructured.Unstructured
	}{
		{
			name:        "no status don't cause error",
			obj:         &unstructured.Unstructured{},
			expectedRes: &unstructured.Unstructured{},
		},
		{
			name:        "remove status",
			obj:         newTestUnstructured().WithMetadata().WithStatus().Unstructured,
			expectedRes: newTestUnstructured().WithMetadata().Unstructured,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resetStatus(test.obj)
			assert.Equal(t, test.expectedRes, test.obj)
		})
	}
}

func TestIsCompleted(t *testing.T) {
	tests := []struct {
		name          string
		expected      bool
		content       string
		groupResource schema.GroupResource
		expectedErr   bool
	}{
		{
			name:          "Failed pods are complete",
			expected:      true,
			content:       `{"apiVersion":"v1","kind":"Pod","metadata":{"namespace":"ns","name":"pod1"}, "status": {"phase": "Failed"}}`,
			groupResource: schema.GroupResource{Group: "", Resource: "pods"},
		},
		{
			name:          "Succeeded pods are complete",
			expected:      true,
			content:       `{"apiVersion":"v1","kind":"Pod","metadata":{"namespace":"ns","name":"pod1"}, "status": {"phase": "Succeeded"}}`,
			groupResource: schema.GroupResource{Group: "", Resource: "pods"},
		},
		{
			name:          "Pending pods aren't complete",
			expected:      false,
			content:       `{"apiVersion":"v1","kind":"Pod","metadata":{"namespace":"ns","name":"pod1"}, "status": {"phase": "Pending"}}`,
			groupResource: schema.GroupResource{Group: "", Resource: "pods"},
		},
		{
			name:          "Running pods aren't complete",
			expected:      false,
			content:       `{"apiVersion":"v1","kind":"Pod","metadata":{"namespace":"ns","name":"pod1"}, "status": {"phase": "Running"}}`,
			groupResource: schema.GroupResource{Group: "", Resource: "pods"},
		},
		{
			name:          "Jobs without a completion time aren't complete",
			expected:      false,
			content:       `{"apiVersion":"v1","kind":"Pod","metadata":{"namespace":"ns","name":"pod1"}}`,
			groupResource: schema.GroupResource{Group: "batch", Resource: "jobs"},
		},
		{
			name:          "Jobs with a completion time are completed",
			expected:      true,
			content:       `{"apiVersion":"v1","kind":"Pod","metadata":{"namespace":"ns","name":"pod1"}, "status": {"completionTime": "bar"}}`,
			groupResource: schema.GroupResource{Group: "batch", Resource: "jobs"},
		},
		{
			name:          "Jobs with an empty completion time are not completed",
			expected:      false,
			content:       `{"apiVersion":"v1","kind":"Pod","metadata":{"namespace":"ns","name":"pod1"}, "status": {"completionTime": ""}}`,
			groupResource: schema.GroupResource{Group: "batch", Resource: "jobs"},
		},
		{
			name:          "Something not a pod or a job may actually be complete, but we're not concerned with that",
			expected:      false,
			content:       `{"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "ns"}, "status": {"completionTime": "bar", "phase":"Completed"}}`,
			groupResource: schema.GroupResource{Group: "", Resource: "namespaces"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := test.UnstructuredOrDie(tt.content)
			backup, err := isCompleted(u, tt.groupResource)

			if assert.Equal(t, tt.expectedErr, err != nil) {
				assert.Equal(t, tt.expected, backup)
			}
		})
	}
}

func Test_getOrderedResources(t *testing.T) {
	tests := []struct {
		name               string
		resourcePriorities types.Priorities
		backupResources    map[string]*archive.ResourceItems
		want               []string
	}{
		{
			name:               "when only priorities are specified, they're returned in order",
			resourcePriorities: types.Priorities{HighPriorities: []string{"prio-3", "prio-2", "prio-1"}},
			backupResources:    nil,
			want:               []string{"prio-3", "prio-2", "prio-1"},
		},
		{
			name:               "when only backup resources are specified, they're returned in alphabetical order",
			resourcePriorities: types.Priorities{},
			backupResources: map[string]*archive.ResourceItems{
				"backup-resource-3": nil,
				"backup-resource-2": nil,
				"backup-resource-1": nil,
			},
			want: []string{"backup-resource-1", "backup-resource-2", "backup-resource-3"},
		},
		{
			name:               "when priorities and backup resources are specified, they're returned in the correct order",
			resourcePriorities: types.Priorities{HighPriorities: []string{"prio-3", "prio-2", "prio-1"}},
			backupResources: map[string]*archive.ResourceItems{
				"prio-3":            nil,
				"backup-resource-3": nil,
				"backup-resource-2": nil,
				"backup-resource-1": nil,
			},
			want: []string{"prio-3", "prio-2", "prio-1", "backup-resource-1", "backup-resource-2", "backup-resource-3"},
		},
		{
			name:               "when priorities and backup resources are specified, they're returned in the correct order",
			resourcePriorities: types.Priorities{HighPriorities: []string{"prio-3", "prio-2", "prio-1"}, LowPriorities: []string{"prio-0"}},
			backupResources: map[string]*archive.ResourceItems{
				"prio-3":            nil,
				"prio-0":            nil,
				"backup-resource-3": nil,
				"backup-resource-2": nil,
				"backup-resource-1": nil,
			},
			want: []string{"prio-3", "prio-2", "prio-1", "backup-resource-1", "backup-resource-2", "backup-resource-3", "prio-0"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, getOrderedResources(tc.resourcePriorities, tc.backupResources))
		})
	}
}

// assertResourceCreationOrder ensures that resources were created in the expected
// order. Any resources *not* in resourcePriorities are required to come *after* all
// resources in any order.
func assertResourceCreationOrder(t *testing.T, resourcePriorities []string, createdResources []resourceID) {
	t.Helper()
	// lastSeen tracks the index in 'resourcePriorities' of the last resource type
	// we saw created. Once we've seen a resource in 'resourcePriorities', we should
	// never see another instance of a prior resource.
	lastSeen := 0

	// Find the index in 'resourcePriorities' of the resource type for
	// the current item, if it exists. This index ('current') *must*
	// be greater than or equal to 'lastSeen', which was the last resource
	// we saw, since otherwise the current resource would be out of order. By
	// initializing current to len(ordered), we're saying that if the resource
	// is not explicitly in orderedResources, then it must come *after*
	// all orderedResources.
	for _, r := range createdResources {
		current := len(resourcePriorities)
		for i, item := range resourcePriorities {
			if item == r.groupResource {
				current = i
				break
			}
		}

		// the index of the current resource must be the same as or greater than the index of
		// the last resource we saw for the restored order to be correct.
		assert.GreaterOrEqual(t, current, lastSeen, "%s was restored out of order", r.groupResource)
		lastSeen = current
	}
}

type resourceID struct {
	groupResource string
	nsAndName     string
}

// createRecorder provides a Reactor that can be used to capture
// resources created in a fake client.
type createRecorder struct {
	t         *testing.T
	resources []resourceID
}

func (cr *createRecorder) reactor() func(kubetesting.Action) (bool, runtime.Object, error) {
	return func(action kubetesting.Action) (bool, runtime.Object, error) {
		createAction, ok := action.(kubetesting.CreateAction)
		if !ok {
			return false, nil, nil
		}

		accessor, err := meta.Accessor(createAction.GetObject())
		require.NoError(cr.t, err)

		cr.resources = append(cr.resources, resourceID{
			groupResource: action.GetResource().GroupResource().String(),
			nsAndName:     fmt.Sprintf("%s/%s", action.GetNamespace(), accessor.GetName()),
		})

		return false, nil, nil
	}
}

func defaultRestore() *builder.RestoreBuilder {
	return builder.ForRestore(velerov1api.DefaultNamespace, "restore-1").Backup("backup-1")
}

// assertAPIContents asserts that the dynamic client on the provided harness contains
// all of the items specified in 'want' (a map from an APIResource definition to a slice
// of resource identifiers, formatted as <namespace>/<name>).
func assertAPIContents(t *testing.T, h *harness, want map[*test.APIResource][]string) {
	t.Helper()

	for r, want := range want {
		res, err := h.DynamicClient.Resource(r.GVR()).List(t.Context(), metav1.ListOptions{})
		require.NoError(t, err)
		if err != nil {
			continue
		}

		got := sets.NewString()
		for _, item := range res.Items {
			got.Insert(fmt.Sprintf("%s/%s", item.GetNamespace(), item.GetName()))
		}

		assert.Equal(t, sets.NewString(want...), got)
	}
}

func assertEmptyResults(t *testing.T, res ...Result) {
	t.Helper()

	for _, r := range res {
		assert.Empty(t, r.Cluster)
		assert.Empty(t, r.Namespaces)
		assert.Empty(t, r.Velero)
	}
}

func assertNonEmptyResults(t *testing.T, typeMsg string, res ...Result) {
	t.Helper()
	total := 0
	for _, r := range res {
		total += len(r.Cluster)
		total += len(r.Namespaces)
		total += len(r.Velero)
	}
	assert.Positive(t, total, "Expected at least one "+typeMsg)
}

type harness struct {
	*test.APIServer

	restorer *kubernetesRestorer
	log      logrus.FieldLogger
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	apiServer := test.NewAPIServer(t)
	log := logrus.StandardLogger()
	kbClient := test.NewFakeControllerRuntimeClient(t)

	discoveryHelper, err := discovery.NewHelper(apiServer.DiscoveryClient, log)
	require.NoError(t, err)

	return &harness{
		APIServer: apiServer,
		restorer: &kubernetesRestorer{
			discoveryHelper:            discoveryHelper,
			dynamicFactory:             client.NewDynamicFactory(apiServer.DynamicClient),
			namespaceClient:            apiServer.KubeClient.CoreV1().Namespaces(),
			resourceTerminatingTimeout: time.Minute,
			logger:                     log,
			fileSystem:                 test.NewFakeFileSystem(),

			// unsupported
			podVolumeRestorerFactory:      nil,
			podVolumeTimeout:              0,
			kbClient:                      kbClient,
			resourceDeletionStatusTracker: kube.NewResourceDeletionStatusTracker(),
		},
		log: log,
	}
}

func (h *harness) AddItems(t *testing.T, resource *test.APIResource) {
	t.Helper()

	h.DiscoveryClient.WithAPIResource(resource)
	require.NoError(t, h.restorer.discoveryHelper.Refresh())

	for _, item := range resource.Items {
		obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(item)
		require.NoError(t, err)

		unstructuredObj := &unstructured.Unstructured{Object: obj}

		// These fields have non-nil zero values in the unstructured objects. We remove
		// them to make comparison easier in our tests.
		unstructured.RemoveNestedField(unstructuredObj.Object, "metadata", "creationTimestamp")
		unstructured.RemoveNestedField(unstructuredObj.Object, "status")

		if resource.Namespaced {
			_, err = h.DynamicClient.Resource(resource.GVR()).Namespace(item.GetNamespace()).Create(t.Context(), unstructuredObj, metav1.CreateOptions{})
		} else {
			_, err = h.DynamicClient.Resource(resource.GVR()).Create(t.Context(), unstructuredObj, metav1.CreateOptions{})
		}
		require.NoError(t, err)
	}
}

func Test_resetVolumeBindingInfo(t *testing.T) {
	tests := []struct {
		name     string
		obj      *unstructured.Unstructured
		expected *unstructured.Unstructured
	}{
		{
			name: "PVs that are bound have their binding and dynamic provisioning annotations removed",
			obj: newTestUnstructured().WithMetadataField("kind", "persistentVolume").
				WithName("pv-1").WithAnnotations(
				kubeutil.KubeAnnBindCompleted,
				kubeutil.KubeAnnBoundByController,
				kubeutil.KubeAnnDynamicallyProvisioned,
			).WithSpecField("claimRef", map[string]any{
				"namespace":       "ns-1",
				"name":            "pvc-1",
				"uid":             "abc",
				"resourceVersion": "1"}).Unstructured,
			expected: newTestUnstructured().WithMetadataField("kind", "persistentVolume").
				WithName("pv-1").
				WithAnnotations(kubeutil.KubeAnnDynamicallyProvisioned).
				WithSpecField("claimRef", map[string]any{
					"namespace": "ns-1", "name": "pvc-1"}).Unstructured,
		},
		{
			name: "PVCs that are bound have their binding annotations removed, but the volume name stays",
			obj: newTestUnstructured().WithMetadataField("kind", "persistentVolumeClaim").
				WithName("pvc-1").WithAnnotations(
				kubeutil.KubeAnnBindCompleted,
				kubeutil.KubeAnnBoundByController,
			).WithSpecField("volumeName", "pv-1").Unstructured,
			expected: newTestUnstructured().WithMetadataField("kind", "persistentVolumeClaim").
				WithName("pvc-1").WithAnnotations().
				WithSpecField("volumeName", "pv-1").Unstructured,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actual := resetVolumeBindingInfo(tc.obj)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestIsAlreadyExistsError(t *testing.T) {
	tests := []struct {
		name        string
		apiResource *test.APIResource
		obj         *unstructured.Unstructured
		err         error
		expected    bool
	}{
		{
			name:     "The input error is IsAlreadyExists error",
			err:      apierrors.NewAlreadyExists(schema.GroupResource{}, ""),
			expected: true,
		},
		{
			name: "The input obj isn't service",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"kind": "Pod",
				},
			},
			expected: false,
		},
		{
			name: "The StatusError contains no causes",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"kind": "Service",
				},
			},
			err: &apierrors.StatusError{
				ErrStatus: metav1.Status{
					Reason: metav1.StatusReasonInvalid,
				},
			},
			expected: false,
		},
		{
			name: "The causes contains not only port already allocated error",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"kind": "Service",
				},
			},
			err: &apierrors.StatusError{
				ErrStatus: metav1.Status{
					Reason: metav1.StatusReasonInvalid,
					Details: &metav1.StatusDetails{
						Causes: []metav1.StatusCause{
							{Message: "provided port is already allocated"},
							{Message: "other error"},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Get already allocated error but the service doesn't exist",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"kind": "Service",
					"metadata": map[string]any{
						"namespace": "default",
						"name":      "test",
					},
				},
			},
			err: &apierrors.StatusError{
				ErrStatus: metav1.Status{
					Reason: metav1.StatusReasonInvalid,
					Details: &metav1.StatusDetails{
						Causes: []metav1.StatusCause{
							{Message: "provided port is already allocated"},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Get already allocated error and the service exists",
			apiResource: test.Services(
				builder.ForService("default", "test").Result(),
			),
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"kind": "Service",
					"metadata": map[string]any{
						"namespace": "default",
						"name":      "test",
					},
				},
			},
			err: &apierrors.StatusError{
				ErrStatus: metav1.Status{
					Reason: metav1.StatusReasonInvalid,
					Details: &metav1.StatusDetails{
						Causes: []metav1.StatusCause{
							{Message: "provided port is already allocated"},
						},
					},
				},
			},
			expected: true,
		},
	}
	for _, test := range tests {
		h := newHarness(t)

		ctx := &restoreContext{
			log:                           h.log,
			dynamicFactory:                client.NewDynamicFactory(h.DynamicClient),
			namespaceClient:               h.KubeClient.CoreV1().Namespaces(),
			resourceDeletionStatusTracker: kube.NewResourceDeletionStatusTracker(),
		}

		if test.apiResource != nil {
			h.AddItems(t, test.apiResource)
		}

		client, err := ctx.dynamicFactory.ClientForGroupVersionResource(
			schema.GroupVersion{Group: "", Version: "v1"},
			metav1.APIResource{Name: "services"},
			"default",
		)
		require.NoError(t, err)

		t.Run(test.name, func(t *testing.T) {
			result, err := isAlreadyExistsError(ctx, test.obj, test.err, client)
			require.NoError(t, err)

			assert.Equal(t, test.expected, result)
		})
	}
}

func TestHasCSIVolumeSnapshot(t *testing.T) {
	tests := []struct {
		name           string
		vs             *snapshotv1api.VolumeSnapshot
		obj            *unstructured.Unstructured
		expectedResult bool
	}{
		{
			name: "Invalid PV, expect false.",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"kind": 1,
				},
			},
			expectedResult: false,
		},
		{
			name: "Cannot find VS, expect false",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"kind":       "PersistentVolume",
					"apiVersion": "v1",
					"metadata": map[string]any{
						"namespace": "default",
						"name":      "test",
					},
				},
			},
			expectedResult: false,
		},
		{
			name: "VS's source PVC is nil, expect false",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"kind":       "PersistentVolume",
					"apiVersion": "v1",
					"metadata": map[string]any{
						"namespace": "default",
						"name":      "test",
					},
					"spec": map[string]any{
						"claimRef": map[string]any{
							"namespace": "velero",
							"name":      "test",
						},
					},
				},
			},
			vs:             builder.ForVolumeSnapshot("velero", "test").Result(),
			expectedResult: false,
		},
		{
			name: "PVs claimref is nil, expect false.",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"kind":       "PersistentVolume",
					"apiVersion": "v1",
					"metadata": map[string]any{
						"namespace": "velero",
						"name":      "test",
					},
				},
			},
			vs:             builder.ForVolumeSnapshot("velero", "test").SourcePVC("test").Result(),
			expectedResult: false,
		},

		{
			name: "Find VS, expect true.",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"kind":       "PersistentVolume",
					"apiVersion": "v1",
					"metadata": map[string]any{
						"namespace": "velero",
						"name":      "test",
					},
					"spec": map[string]any{
						"claimRef": map[string]any{
							"namespace": "velero",
							"name":      "test",
						},
					},
				},
			},
			vs:             builder.ForVolumeSnapshot("velero", "test").SourcePVC("test").Result(),
			expectedResult: true,
		},
	}

	for _, tc := range tests {
		h := newHarness(t)

		ctx := &restoreContext{
			log:                           h.log,
			resourceDeletionStatusTracker: kube.NewResourceDeletionStatusTracker(),
		}

		if tc.vs != nil {
			ctx.csiVolumeSnapshots = []*snapshotv1api.VolumeSnapshot{tc.vs}
		}

		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expectedResult, hasCSIVolumeSnapshot(ctx, tc.obj))
		})
	}
}

func TestHasSnapshotDataUpload(t *testing.T) {
	tests := []struct {
		name           string
		duResult       *corev1api.ConfigMap
		obj            *unstructured.Unstructured
		expectedResult bool
		restore        *velerov1api.Restore
	}{
		{
			name: "Invalid PV, expect false.",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"kind": 1,
				},
			},
			expectedResult: false,
		},
		{
			name: "PV without ClaimRef, expect false",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"kind":       "PersistentVolume",
					"apiVersion": "v1",
					"metadata": map[string]any{
						"namespace": "default",
						"name":      "test",
					},
				},
			},
			duResult:       builder.ForConfigMap("velero", "test").Result(),
			restore:        builder.ForRestore("velero", "test").ObjectMeta(builder.WithUID("fakeUID")).Result(),
			expectedResult: false,
		},
		{
			name: "Cannot find DataUploadResult CM, expect false",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"kind":       "PersistentVolume",
					"apiVersion": "v1",
					"metadata": map[string]any{
						"namespace": "default",
						"name":      "test",
					},
					"spec": map[string]any{
						"claimRef": map[string]any{
							"namespace": "velero",
							"name":      "testPVC",
						},
					},
				},
			},
			duResult:       builder.ForConfigMap("velero", "test").Result(),
			restore:        builder.ForRestore("velero", "test").ObjectMeta(builder.WithUID("fakeUID")).Result(),
			expectedResult: false,
		},
		{
			name: "Find DataUploadResult CM, expect true",
			obj: &unstructured.Unstructured{
				Object: map[string]any{
					"kind":       "PersistentVolume",
					"apiVersion": "v1",
					"metadata": map[string]any{
						"namespace": "default",
						"name":      "test",
					},
					"spec": map[string]any{
						"claimRef": map[string]any{
							"namespace": "velero",
							"name":      "testPVC",
						},
					},
				},
			},
			duResult: builder.ForConfigMap("velero", "test").ObjectMeta(builder.WithLabelsMap(map[string]string{
				velerov1api.RestoreUIDLabel:       "fakeUID",
				velerov1api.PVCNamespaceNameLabel: "velero/testPVC",
				velerov1api.ResourceUsageLabel:    string(velerov1api.VeleroResourceUsageDataUploadResult),
			})).Result(),
			restore:        builder.ForRestore("velero", "test").ObjectMeta(builder.WithUID("fakeUID")).Result(),
			expectedResult: false,
		},
	}

	for _, tc := range tests {
		h := newHarness(t)

		ctx := &restoreContext{
			log:                           h.log,
			kbClient:                      h.restorer.kbClient,
			restore:                       tc.restore,
			resourceDeletionStatusTracker: kube.NewResourceDeletionStatusTracker(),
		}

		if tc.duResult != nil {
			require.NoError(t, ctx.kbClient.Create(t.Context(), tc.duResult))
		}

		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expectedResult, hasSnapshotDataUpload(ctx, tc.obj))
		})
	}
}

func TestDetermineRestoreStatus(t *testing.T) {
	tests := []struct {
		name                string
		annotations         map[string]string
		restoreSpecIncludes *bool
		expectedDecision    bool
	}{
		{
			name:                "No annotation, fallback to restore spec",
			annotations:         nil,
			restoreSpecIncludes: boolptr.True(),
			expectedDecision:    true,
		},
		{
			name:                "No annotation, restore spec excludes",
			annotations:         nil,
			restoreSpecIncludes: boolptr.False(),
			expectedDecision:    false,
		},
		{
			name:                "Annotation explicitly set to true, restore spec is false",
			annotations:         map[string]string{ObjectStatusRestoreAnnotationKey: "true"},
			restoreSpecIncludes: boolptr.False(),
			expectedDecision:    true,
		},
		{
			name:                "Annotation explicitly set to false, restore spec is true",
			annotations:         map[string]string{ObjectStatusRestoreAnnotationKey: "false"},
			restoreSpecIncludes: boolptr.True(),
			expectedDecision:    false,
		},
		{
			name:                "Invalid annotation value, fallback to restore spec",
			annotations:         map[string]string{ObjectStatusRestoreAnnotationKey: "foo"},
			restoreSpecIncludes: boolptr.True(),
			expectedDecision:    true,
		},
		{
			name:                "Empty annotation value, fallback to restore spec",
			annotations:         map[string]string{ObjectStatusRestoreAnnotationKey: ""},
			restoreSpecIncludes: boolptr.False(),
			expectedDecision:    false,
		},
		{
			name:                "Mixed-case annotation value 'True' should be treated as true",
			annotations:         map[string]string{ObjectStatusRestoreAnnotationKey: "True"},
			restoreSpecIncludes: boolptr.True(),
			expectedDecision:    true,
		},
		{
			name:                "Mixed-case annotation value 'FALSE' should be treated as false",
			annotations:         map[string]string{ObjectStatusRestoreAnnotationKey: "FALSE"},
			restoreSpecIncludes: boolptr.True(),
			expectedDecision:    false,
		},
		{
			name:                "Nil IncludesExcludes, but annotation is 'true'",
			annotations:         map[string]string{ObjectStatusRestoreAnnotationKey: "true"},
			restoreSpecIncludes: nil,
			expectedDecision:    true,
		},
		{
			name:                "Nil IncludesExcludes, but annotation is 'false'",
			annotations:         map[string]string{ObjectStatusRestoreAnnotationKey: "false"},
			restoreSpecIncludes: nil,
			expectedDecision:    false,
		},
		{
			name:                "Nil IncludesExcludes, no annotation (default to false)",
			annotations:         nil,
			restoreSpecIncludes: nil,
			expectedDecision:    false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			obj := &unstructured.Unstructured{}
			obj.SetAnnotations(test.annotations)

			var includesExcludes *collections.IncludesExcludes
			if test.restoreSpecIncludes != nil {
				includesExcludes = collections.NewIncludesExcludes()
				if *test.restoreSpecIncludes {
					includesExcludes.Includes("*")
				} else {
					includesExcludes.Excludes("*")
				}
			}

			log := logrus.New()
			result := determineRestoreStatus(obj, includesExcludes, "testGroupResource", log)

			assert.Equal(t, test.expectedDecision, result)
		})
	}
}
