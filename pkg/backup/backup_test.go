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

package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

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

	"github.com/vmware-tanzu/velero/internal/resourcepolicies"
	"github.com/vmware-tanzu/velero/internal/volume"
	"github.com/vmware-tanzu/velero/pkg/apis/velero/shared"
	velerov1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	velerov2alpha1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v2alpha1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/client"
	"github.com/vmware-tanzu/velero/pkg/discovery"
	"github.com/vmware-tanzu/velero/pkg/features"
	"github.com/vmware-tanzu/velero/pkg/itemoperation"
	"github.com/vmware-tanzu/velero/pkg/kuberesource"
	"github.com/vmware-tanzu/velero/pkg/persistence"
	persistencemocks "github.com/vmware-tanzu/velero/pkg/persistence/mocks"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	biav2 "github.com/vmware-tanzu/velero/pkg/plugin/velero/backupitemaction/v2"
	ibav1 "github.com/vmware-tanzu/velero/pkg/plugin/velero/itemblockaction/v1"
	vsv1 "github.com/vmware-tanzu/velero/pkg/plugin/velero/volumesnapshotter/v1"
	"github.com/vmware-tanzu/velero/pkg/podvolume"
	"github.com/vmware-tanzu/velero/pkg/test"
	kubeutil "github.com/vmware-tanzu/velero/pkg/util/kube"
)

func TestBackedUpItemsMatchesTarballContents(t *testing.T) {
	// TODO: figure out if this can be replaced with the restmapper
	// (https://github.com/kubernetes/apimachinery/blob/035e418f1ad9b6da47c4e01906a0cfe32f4ee2e7/pkg/api/meta/restmapper.go)
	gvkToResource := map[string]string{
		"v1/Pod":              "pods",
		"apps/v1/Deployment":  "deployments.apps",
		"v1/PersistentVolume": "persistentvolumes",
	}

	h := newHarness(t, nil)
	defer h.itemBlockPool.Stop()

	req := &Request{
		Backup:           defaultBackup().Result(),
		SkippedPVTracker: NewSkipPVTracker(),
		BackedUpItems:    NewBackedUpItemsMap(),
		WorkerPool:       &h.itemBlockPool,
	}

	backupFile := bytes.NewBuffer([]byte{})

	apiResources := []*test.APIResource{
		test.Pods(
			builder.ForPod("foo", "bar").Result(),
			builder.ForPod("zoo", "raz").Result(),
		),
		test.Deployments(
			builder.ForDeployment("foo", "bar").Result(),
			builder.ForDeployment("zoo", "raz").Result(),
		),
		test.PVs(
			builder.ForPersistentVolume("bar").ClaimRef("foo", "pvc1").Result(),
			builder.ForPersistentVolume("baz").ClaimRef("bar", "pvc2").Result(),
		),
	}
	for _, resource := range apiResources {
		h.addItems(t, resource)
	}

	h.backupper.Backup(h.log, req, backupFile, nil, nil, nil)

	// go through BackedUpItems after the backup to assemble the list of files we
	// expect to see in the tarball and compare to see if they match
	var expectedFiles []string
	for item := range req.BackedUpItems.CopyItemMap() {
		file := "resources/" + gvkToResource[item.resource]
		if item.namespace != "" {
			file = file + "/namespaces/" + item.namespace
		} else {
			file = file + "/cluster"
		}
		file = file + "/" + item.name + ".json"
		expectedFiles = append(expectedFiles, file)

		fileWithVersion := "resources/" + gvkToResource[item.resource]
		if item.namespace != "" {
			fileWithVersion = fileWithVersion + "/v1-preferredversion/" + "namespaces/" + item.namespace
		} else {
			fileWithVersion = fileWithVersion + "/v1-preferredversion" + "/cluster"
		}
		fileWithVersion = fileWithVersion + "/" + item.name + ".json"
		expectedFiles = append(expectedFiles, fileWithVersion)
	}

	assertTarballContents(t, backupFile, append(expectedFiles, "metadata/version")...)
}

// TestBackupProgressIsUpdated verifies that after a backup has run, its
// status.progress fields are updated to reflect the total number of items
// backed up. It validates this by comparing their values to the length of
// the request's BackedUpItems field.
func TestBackupProgressIsUpdated(t *testing.T) {
	h := newHarness(t, nil)
	defer h.itemBlockPool.Stop()
	req := &Request{
		Backup:           defaultBackup().Result(),
		SkippedPVTracker: NewSkipPVTracker(),
		BackedUpItems:    NewBackedUpItemsMap(),
		WorkerPool:       &h.itemBlockPool,
	}
	backupFile := bytes.NewBuffer([]byte{})

	apiResources := []*test.APIResource{
		test.Pods(
			builder.ForPod("foo", "bar").Result(),
			builder.ForPod("zoo", "raz").Result(),
		),
		test.Deployments(
			builder.ForDeployment("foo", "bar").Result(),
			builder.ForDeployment("zoo", "raz").Result(),
		),
		test.PVs(
			builder.ForPersistentVolume("bar").Result(),
			builder.ForPersistentVolume("baz").Result(),
		),
	}
	for _, resource := range apiResources {
		h.addItems(t, resource)
	}

	h.backupper.Backup(h.log, req, backupFile, nil, nil, nil)

	require.NotNil(t, req.Status.Progress)
	assert.Equal(t, req.BackedUpItems.Len(), req.Status.Progress.TotalItems)
	assert.Equal(t, req.BackedUpItems.Len(), req.Status.Progress.ItemsBackedUp)
}

// TestBackupOldResourceFiltering runs backups with different combinations
// of resource filters (included/excluded resources, included/excluded
// namespaces, label selectors, "include cluster resources" flag), and
// verifies that the set of items written to the backup tarball are
// correct. Validation is done by looking at the names of the files in
// the backup tarball; the contents of the files are not checked.
func TestBackupOldResourceFiltering(t *testing.T) {
	tests := []struct {
		name         string
		backup       *velerov1.Backup
		apiResources []*test.APIResource
		want         []string
		actions      []biav2.BackupItemAction
	}{
		{
			name:   "no filters backs up everything",
			backup: defaultBackup().Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("foo", "bar").Result(),
					builder.ForPod("zoo", "raz").Result(),
				),
				test.Deployments(
					builder.ForDeployment("foo", "bar").Result(),
					builder.ForDeployment("zoo", "raz").Result(),
				),
			},
			want: []string{
				"resources/pods/namespaces/foo/bar.json",
				"resources/pods/namespaces/zoo/raz.json",
				"resources/deployments.apps/namespaces/foo/bar.json",
				"resources/deployments.apps/namespaces/zoo/raz.json",
				"resources/pods/v1-preferredversion/namespaces/foo/bar.json",
				"resources/pods/v1-preferredversion/namespaces/zoo/raz.json",
				"resources/deployments.apps/v1-preferredversion/namespaces/foo/bar.json",
				"resources/deployments.apps/v1-preferredversion/namespaces/zoo/raz.json",
			},
		},
		{
			name: "included resources filter only backs up resources of those types",
			backup: defaultBackup().
				IncludedResources("pods").
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("foo", "bar").Result(),
					builder.ForPod("zoo", "raz").Result(),
				),
				test.Deployments(
					builder.ForDeployment("foo", "bar").Result(),
					builder.ForDeployment("zoo", "raz").Result(),
				),
			},
			want: []string{
				"resources/pods/namespaces/foo/bar.json",
				"resources/pods/namespaces/zoo/raz.json",
				"resources/pods/v1-preferredversion/namespaces/foo/bar.json",
				"resources/pods/v1-preferredversion/namespaces/zoo/raz.json",
			},
		},
		{
			name: "excluded resources filter only backs up resources not of those types",
			backup: defaultBackup().
				ExcludedResources("deployments").
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("foo", "bar").Result(),
					builder.ForPod("zoo", "raz").Result(),
				),
				test.Deployments(
					builder.ForDeployment("foo", "bar").Result(),
					builder.ForDeployment("zoo", "raz").Result(),
				),
			},
			want: []string{
				"resources/pods/namespaces/foo/bar.json",
				"resources/pods/namespaces/zoo/raz.json",
				"resources/pods/v1-preferredversion/namespaces/foo/bar.json",
				"resources/pods/v1-preferredversion/namespaces/zoo/raz.json",
			},
		},
		{
			name: "included namespaces filter only backs up resources in those namespaces",
			backup: defaultBackup().
				IncludedNamespaces("foo").
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("foo", "bar").Result(),
					builder.ForPod("zoo", "raz").Result(),
				),
				test.Deployments(
					builder.ForDeployment("foo", "bar").Result(),
					builder.ForDeployment("zoo", "raz").Result(),
				),
			},
			want: []string{
				"resources/pods/namespaces/foo/bar.json",
				"resources/deployments.apps/namespaces/foo/bar.json",
				"resources/pods/v1-preferredversion/namespaces/foo/bar.json",
				"resources/deployments.apps/v1-preferredversion/namespaces/foo/bar.json",
			},
		},
		{
			name: "excluded namespaces filter only backs up resources not in those namespaces",
			backup: defaultBackup().
				ExcludedNamespaces("zoo").
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("foo", "bar").Phase(corev1api.PodRunning).Result(),
					builder.ForPod("zoo", "raz").Phase(corev1api.PodRunning).Result(),
				),
				test.Deployments(
					builder.ForDeployment("foo", "bar").Result(),
					builder.ForDeployment("zoo", "raz").Result(),
				),
			},
			want: []string{
				"resources/pods/namespaces/foo/bar.json",
				"resources/deployments.apps/namespaces/foo/bar.json",
				"resources/pods/v1-preferredversion/namespaces/foo/bar.json",
				"resources/deployments.apps/v1-preferredversion/namespaces/foo/bar.json",
			},
		},
		{
			name: "IncludeClusterResources=false only backs up namespaced resources",
			backup: defaultBackup().
				IncludeClusterResources(false).
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("foo", "bar").Result(),
					builder.ForPod("zoo", "raz").Result(),
				),
				test.Deployments(
					builder.ForDeployment("foo", "bar").Result(),
					builder.ForDeployment("zoo", "raz").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("bar").Result(),
					builder.ForPersistentVolume("baz").Result(),
				),
			},
			want: []string{
				"resources/pods/namespaces/foo/bar.json",
				"resources/pods/namespaces/zoo/raz.json",
				"resources/deployments.apps/namespaces/foo/bar.json",
				"resources/deployments.apps/namespaces/zoo/raz.json",
				"resources/pods/v1-preferredversion/namespaces/foo/bar.json",
				"resources/pods/v1-preferredversion/namespaces/zoo/raz.json",
				"resources/deployments.apps/v1-preferredversion/namespaces/foo/bar.json",
				"resources/deployments.apps/v1-preferredversion/namespaces/zoo/raz.json",
			},
		},
		{
			name: "label selector only backs up matching resources",
			backup: defaultBackup().
				LabelSelector(&metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}}).
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("foo", "bar").ObjectMeta(builder.WithLabels("a", "b")).Result(),
					builder.ForPod("zoo", "raz").Result(),
				),
				test.Deployments(
					builder.ForDeployment("foo", "bar").Result(),
					builder.ForDeployment("zoo", "raz").ObjectMeta(builder.WithLabels("a", "b")).Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("bar").ObjectMeta(builder.WithLabels("a", "b")).Result(),
					builder.ForPersistentVolume("baz").ObjectMeta(builder.WithLabels("a", "c")).Result(),
				),
			},
			want: []string{
				"resources/pods/namespaces/foo/bar.json",
				"resources/deployments.apps/namespaces/zoo/raz.json",
				"resources/persistentvolumes/cluster/bar.json",
				"resources/pods/v1-preferredversion/namespaces/foo/bar.json",
				"resources/deployments.apps/v1-preferredversion/namespaces/zoo/raz.json",
				"resources/persistentvolumes/v1-preferredversion/cluster/bar.json",
			},
		},
		{
			name: "OrLabelSelector only backs up matching resources",
			backup: defaultBackup().
				OrLabelSelector([]*metav1.LabelSelector{{MatchLabels: map[string]string{"a1": "b1"}}, {MatchLabels: map[string]string{"a2": "b2"}},
					{MatchLabels: map[string]string{"a3": "b3"}}, {MatchLabels: map[string]string{"a4": "b4"}}}).
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("foo", "bar").ObjectMeta(builder.WithLabels("a1", "b1")).Result(),
					builder.ForPod("zoo", "raz").Result(),
				),
				test.Deployments(
					builder.ForDeployment("foo", "bar").Result(),
					builder.ForDeployment("zoo", "raz").ObjectMeta(builder.WithLabels("a2", "b2")).Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("bar").ObjectMeta(builder.WithLabels("a4", "b4")).Result(),
					builder.ForPersistentVolume("baz").ObjectMeta(builder.WithLabels("a5", "b5")).Result(),
				),
			},
			want: []string{
				"resources/pods/namespaces/foo/bar.json",
				"resources/deployments.apps/namespaces/zoo/raz.json",
				"resources/persistentvolumes/cluster/bar.json",
				"resources/pods/v1-preferredversion/namespaces/foo/bar.json",
				"resources/deployments.apps/v1-preferredversion/namespaces/zoo/raz.json",
				"resources/persistentvolumes/v1-preferredversion/cluster/bar.json",
			},
		},
		{
			name: "resources with velero.io/exclude-from-backup=true label are not included",
			backup: defaultBackup().
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("foo", "bar").ObjectMeta(builder.WithLabels(velerov1.ExcludeFromBackupLabel, "true")).Result(),
					builder.ForPod("zoo", "raz").Result(),
				),
				test.Deployments(
					builder.ForDeployment("foo", "bar").Result(),
					builder.ForDeployment("zoo", "raz").ObjectMeta(builder.WithLabels(velerov1.ExcludeFromBackupLabel, "true")).Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("bar").ObjectMeta(builder.WithLabels("a", "b")).Result(),
					builder.ForPersistentVolume("baz").ObjectMeta(builder.WithLabels(velerov1.ExcludeFromBackupLabel, "true")).Result(),
				),
			},
			want: []string{
				"resources/pods/namespaces/zoo/raz.json",
				"resources/deployments.apps/namespaces/foo/bar.json",
				"resources/persistentvolumes/cluster/bar.json",
				"resources/pods/v1-preferredversion/namespaces/zoo/raz.json",
				"resources/deployments.apps/v1-preferredversion/namespaces/foo/bar.json",
				"resources/persistentvolumes/v1-preferredversion/cluster/bar.json",
			},
		},
		{
			name: "resources with velero.io/exclude-from-backup=true label are not included even if matching label selector",
			backup: defaultBackup().
				LabelSelector(&metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}}).
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("foo", "bar").ObjectMeta(builder.WithLabels(velerov1.ExcludeFromBackupLabel, "true", "a", "b")).Result(),
					builder.ForPod("zoo", "raz").ObjectMeta(builder.WithLabels("a", "b")).Result(),
				),
				test.Deployments(
					builder.ForDeployment("foo", "bar").Result(),
					builder.ForDeployment("zoo", "raz").ObjectMeta(builder.WithLabels(velerov1.ExcludeFromBackupLabel, "true", "a", "b")).Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("bar").ObjectMeta(builder.WithLabels("a", "b")).Result(),
					builder.ForPersistentVolume("baz").ObjectMeta(builder.WithLabels("a", "b", velerov1.ExcludeFromBackupLabel, "true")).Result(),
				),
			},
			want: []string{
				"resources/pods/namespaces/zoo/raz.json",
				"resources/persistentvolumes/cluster/bar.json",
				"resources/pods/v1-preferredversion/namespaces/zoo/raz.json",
				"resources/persistentvolumes/v1-preferredversion/cluster/bar.json",
			},
		},
		{
			name: "resources with velero.io/exclude-from-backup label specified but not 'true' are included",
			backup: defaultBackup().
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("foo", "bar").ObjectMeta(builder.WithLabels(velerov1.ExcludeFromBackupLabel, "false")).Result(),
					builder.ForPod("zoo", "raz").Result(),
				),
				test.Deployments(
					builder.ForDeployment("foo", "bar").Result(),
					builder.ForDeployment("zoo", "raz").ObjectMeta(builder.WithLabels(velerov1.ExcludeFromBackupLabel, "1")).Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("bar").ObjectMeta(builder.WithLabels("a", "b")).Result(),
					builder.ForPersistentVolume("baz").ObjectMeta(builder.WithLabels(velerov1.ExcludeFromBackupLabel, "")).Result(),
				),
			},
			want: []string{
				"resources/pods/namespaces/foo/bar.json",
				"resources/pods/namespaces/zoo/raz.json",
				"resources/deployments.apps/namespaces/foo/bar.json",
				"resources/deployments.apps/namespaces/zoo/raz.json",
				"resources/persistentvolumes/cluster/bar.json",
				"resources/persistentvolumes/cluster/baz.json",
				"resources/pods/v1-preferredversion/namespaces/foo/bar.json",
				"resources/pods/v1-preferredversion/namespaces/zoo/raz.json",
				"resources/deployments.apps/v1-preferredversion/namespaces/foo/bar.json",
				"resources/deployments.apps/v1-preferredversion/namespaces/zoo/raz.json",
				"resources/persistentvolumes/v1-preferredversion/cluster/bar.json",
				"resources/persistentvolumes/v1-preferredversion/cluster/baz.json",
			},
		},
		{
			name: "should include cluster-scoped resources if backing up subset of namespaces and IncludeClusterResources=true",
			backup: defaultBackup().
				IncludedNamespaces("ns-1", "ns-2").
				IncludeClusterResources(true).
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-1").Result(),
					builder.ForPod("ns-3", "pod-1").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("pv-1").Result(),
					builder.ForPersistentVolume("pv-2").Result(),
				),
			},
			want: []string{
				"resources/pods/namespaces/ns-1/pod-1.json",
				"resources/pods/namespaces/ns-2/pod-1.json",
				"resources/persistentvolumes/cluster/pv-1.json",
				"resources/persistentvolumes/cluster/pv-2.json",
				"resources/pods/v1-preferredversion/namespaces/ns-1/pod-1.json",
				"resources/pods/v1-preferredversion/namespaces/ns-2/pod-1.json",
				"resources/persistentvolumes/v1-preferredversion/cluster/pv-1.json",
				"resources/persistentvolumes/v1-preferredversion/cluster/pv-2.json",
			},
		},
		{
			name: "should not include cluster-scoped resource if backing up subset of namespaces and IncludeClusterResources=false",
			backup: defaultBackup().
				IncludedNamespaces("ns-1", "ns-2").
				IncludeClusterResources(false).
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-1").Result(),
					builder.ForPod("ns-3", "pod-1").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("pv-1").Result(),
					builder.ForPersistentVolume("pv-2").Result(),
				),
			},
			want: []string{
				"resources/pods/namespaces/ns-1/pod-1.json",
				"resources/pods/namespaces/ns-2/pod-1.json",
				"resources/pods/v1-preferredversion/namespaces/ns-1/pod-1.json",
				"resources/pods/v1-preferredversion/namespaces/ns-2/pod-1.json",
			},
		},
		{
			name: "should not include cluster-scoped resource if backing up subset of namespaces and IncludeClusterResources=nil",
			backup: defaultBackup().
				IncludedNamespaces("ns-1", "ns-2").
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-1").Result(),
					builder.ForPod("ns-3", "pod-1").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("pv-1").Result(),
					builder.ForPersistentVolume("pv-2").Result(),
				),
			},
			want: []string{
				"resources/pods/namespaces/ns-1/pod-1.json",
				"resources/pods/namespaces/ns-2/pod-1.json",
				"resources/pods/v1-preferredversion/namespaces/ns-1/pod-1.json",
				"resources/pods/v1-preferredversion/namespaces/ns-2/pod-1.json",
			},
		},
		{
			name: "should include cluster-scoped resources if backing up all namespaces and IncludeClusterResources=true",
			backup: defaultBackup().
				IncludeClusterResources(true).
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-1").Result(),
					builder.ForPod("ns-3", "pod-1").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("pv-1").Result(),
					builder.ForPersistentVolume("pv-2").Result(),
				),
			},
			want: []string{
				"resources/pods/namespaces/ns-1/pod-1.json",
				"resources/pods/namespaces/ns-2/pod-1.json",
				"resources/pods/namespaces/ns-3/pod-1.json",
				"resources/persistentvolumes/cluster/pv-1.json",
				"resources/persistentvolumes/cluster/pv-2.json",
				"resources/pods/v1-preferredversion/namespaces/ns-1/pod-1.json",
				"resources/pods/v1-preferredversion/namespaces/ns-2/pod-1.json",
				"resources/pods/v1-preferredversion/namespaces/ns-3/pod-1.json",
				"resources/persistentvolumes/v1-preferredversion/cluster/pv-1.json",
				"resources/persistentvolumes/v1-preferredversion/cluster/pv-2.json",
			},
		},
		{
			name: "should not include cluster-scoped resources if backing up all namespaces and IncludeClusterResources=false",
			backup: defaultBackup().
				IncludeClusterResources(false).
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-1").Result(),
					builder.ForPod("ns-3", "pod-1").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("pv-1").Result(),
					builder.ForPersistentVolume("pv-2").Result(),
				),
			},
			want: []string{
				"resources/pods/namespaces/ns-1/pod-1.json",
				"resources/pods/namespaces/ns-2/pod-1.json",
				"resources/pods/namespaces/ns-3/pod-1.json",
				"resources/pods/v1-preferredversion/namespaces/ns-1/pod-1.json",
				"resources/pods/v1-preferredversion/namespaces/ns-2/pod-1.json",
				"resources/pods/v1-preferredversion/namespaces/ns-3/pod-1.json",
			},
		},
		{
			name: "should include cluster-scoped resources if backing up all namespaces and IncludeClusterResources=nil",
			backup: defaultBackup().
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-1").Result(),
					builder.ForPod("ns-3", "pod-1").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("pv-1").Result(),
					builder.ForPersistentVolume("pv-2").Result(),
				),
			},
			want: []string{
				"resources/pods/namespaces/ns-1/pod-1.json",
				"resources/pods/namespaces/ns-2/pod-1.json",
				"resources/pods/namespaces/ns-3/pod-1.json",
				"resources/persistentvolumes/cluster/pv-1.json",
				"resources/persistentvolumes/cluster/pv-2.json",
				"resources/pods/v1-preferredversion/namespaces/ns-1/pod-1.json",
				"resources/pods/v1-preferredversion/namespaces/ns-2/pod-1.json",
				"resources/pods/v1-preferredversion/namespaces/ns-3/pod-1.json",
				"resources/persistentvolumes/v1-preferredversion/cluster/pv-1.json",
				"resources/persistentvolumes/v1-preferredversion/cluster/pv-2.json",
			},
		},
		{
			name: "when a wildcard and a specific resource are included, the wildcard takes precedence",
			backup: defaultBackup().
				IncludedResources("*", "pods").
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("foo", "bar").Result(),
					builder.ForPod("zoo", "raz").Result(),
				),
				test.Deployments(
					builder.ForDeployment("foo", "bar").Result(),
					builder.ForDeployment("zoo", "raz").Result(),
				),
			},
			want: []string{
				"resources/pods/namespaces/foo/bar.json",
				"resources/pods/namespaces/zoo/raz.json",
				"resources/deployments.apps/namespaces/foo/bar.json",
				"resources/deployments.apps/namespaces/zoo/raz.json",
				"resources/pods/v1-preferredversion/namespaces/foo/bar.json",
				"resources/pods/v1-preferredversion/namespaces/zoo/raz.json",
				"resources/deployments.apps/v1-preferredversion/namespaces/foo/bar.json",
				"resources/deployments.apps/v1-preferredversion/namespaces/zoo/raz.json",
			},
		},
		{
			name: "wildcard excludes are ignored",
			backup: defaultBackup().
				ExcludedResources("*").
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("foo", "bar").Result(),
					builder.ForPod("zoo", "raz").Result(),
				),
				test.Deployments(
					builder.ForDeployment("foo", "bar").Result(),
					builder.ForDeployment("zoo", "raz").Result(),
				),
			},
			want: []string{
				"resources/pods/namespaces/foo/bar.json",
				"resources/pods/namespaces/zoo/raz.json",
				"resources/deployments.apps/namespaces/foo/bar.json",
				"resources/deployments.apps/namespaces/zoo/raz.json",
				"resources/pods/v1-preferredversion/namespaces/foo/bar.json",
				"resources/pods/v1-preferredversion/namespaces/zoo/raz.json",
				"resources/deployments.apps/v1-preferredversion/namespaces/foo/bar.json",
				"resources/deployments.apps/v1-preferredversion/namespaces/zoo/raz.json",
			},
		},
		{
			name: "unresolvable included resources are ignored",
			backup: defaultBackup().
				IncludedResources("pods", "unresolvable").
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("foo", "bar").Result(),
					builder.ForPod("zoo", "raz").Result(),
				),
				test.Deployments(
					builder.ForDeployment("foo", "bar").Result(),
					builder.ForDeployment("zoo", "raz").Result(),
				),
			},
			want: []string{
				"resources/pods/namespaces/foo/bar.json",
				"resources/pods/namespaces/zoo/raz.json",
				"resources/pods/v1-preferredversion/namespaces/foo/bar.json",
				"resources/pods/v1-preferredversion/namespaces/zoo/raz.json",
			},
		},
		{
			name: "when all included resources are unresolvable, nothing is included",
			backup: defaultBackup().
				IncludedResources("unresolvable-1", "unresolvable-2").
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("foo", "bar").Result(),
					builder.ForPod("zoo", "raz").Result(),
				),
				test.Deployments(
					builder.ForDeployment("foo", "bar").Result(),
					builder.ForDeployment("zoo", "raz").Result(),
				),
			},
			want: []string{},
		},
		{
			name: "unresolvable excluded resources are ignored",
			backup: defaultBackup().
				ExcludedResources("deployments", "unresolvable").
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("foo", "bar").Result(),
					builder.ForPod("zoo", "raz").Result(),
				),
				test.Deployments(
					builder.ForDeployment("foo", "bar").Result(),
					builder.ForDeployment("zoo", "raz").Result(),
				),
			},
			want: []string{
				"resources/pods/namespaces/foo/bar.json",
				"resources/pods/namespaces/zoo/raz.json",
				"resources/pods/v1-preferredversion/namespaces/foo/bar.json",
				"resources/pods/v1-preferredversion/namespaces/zoo/raz.json",
			},
		},
		{
			name: "when all excluded resources are unresolvable, nothing is excluded",
			backup: defaultBackup().
				IncludedResources("*").
				ExcludedResources("unresolvable-1", "unresolvable-2").
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("foo", "bar").Result(),
					builder.ForPod("zoo", "raz").Result(),
				),
				test.Deployments(
					builder.ForDeployment("foo", "bar").Result(),
					builder.ForDeployment("zoo", "raz").Result(),
				),
			},
			want: []string{
				"resources/pods/namespaces/foo/bar.json",
				"resources/pods/namespaces/zoo/raz.json",
				"resources/pods/v1-preferredversion/namespaces/foo/bar.json",
				"resources/pods/v1-preferredversion/namespaces/zoo/raz.json",
				"resources/deployments.apps/namespaces/foo/bar.json",
				"resources/deployments.apps/namespaces/zoo/raz.json",
				"resources/deployments.apps/v1-preferredversion/namespaces/foo/bar.json",
				"resources/deployments.apps/v1-preferredversion/namespaces/zoo/raz.json",
			},
		},
		{
			name:   "terminating resources are not backed up",
			backup: defaultBackup().Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-2").ObjectMeta(builder.WithDeletionTimestamp(time.Now())).Result(),
				),
			},
			want: []string{
				"resources/pods/namespaces/ns-1/pod-1.json",
				"resources/pods/v1-preferredversion/namespaces/ns-1/pod-1.json",
			},
		},
		{
			name:   "new filters' default value should not impact the old filters' function",
			backup: defaultBackup().IncludedNamespaces("foo").IncludeClusterResources(true).Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("foo", "bar").Volumes(builder.ForVolume("foo").PersistentVolumeClaimSource("test-1").Result()).Result(),
					builder.ForPod("zoo", "raz").Result(),
				),
				test.Deployments(
					builder.ForDeployment("foo", "bar").Result(),
					builder.ForDeployment("zoo", "raz").Result(),
				),
				test.PVCs(
					builder.ForPersistentVolumeClaim("foo", "test-1").VolumeName("test1").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("test1").Result(),
					builder.ForPersistentVolume("test2").Result(),
				),
			},
			want: []string{
				"resources/deployments.apps/namespaces/foo/bar.json",
				"resources/deployments.apps/v1-preferredversion/namespaces/foo/bar.json",
				"resources/persistentvolumeclaims/namespaces/foo/test-1.json",
				"resources/persistentvolumeclaims/v1-preferredversion/namespaces/foo/test-1.json",
				"resources/persistentvolumes/cluster/test1.json",
				"resources/persistentvolumes/cluster/test2.json",
				"resources/persistentvolumes/v1-preferredversion/cluster/test1.json",
				"resources/persistentvolumes/v1-preferredversion/cluster/test2.json",
				"resources/pods/namespaces/foo/bar.json",
				"resources/pods/v1-preferredversion/namespaces/foo/bar.json",
			},
			actions: []biav2.BackupItemAction{
				&pluggableAction{
					selector: velero.ResourceSelector{IncludedResources: []string{"persistentvolumeclaims"}},
					executeFunc: func(item runtime.Unstructured, backup *velerov1.Backup) (runtime.Unstructured, []velero.ResourceIdentifier, string, []velero.ResourceIdentifier, error) {
						additionalItems := []velero.ResourceIdentifier{
							{GroupResource: kuberesource.PersistentVolumes, Name: "test1"},
						}

						return item, additionalItems, "", nil, nil
					},
				},
			},
		},
		{
			name:   "Resource's CRD should be included",
			backup: defaultBackup().IncludedNamespaces("foo").Result(),
			apiResources: []*test.APIResource{
				test.CRDs(
					builder.ForCustomResourceDefinitionV1Beta1("backups.velero.io").Result(),
					builder.ForCustomResourceDefinitionV1Beta1("volumesnapshotlocations.velero.io").Result(),
					builder.ForCustomResourceDefinitionV1Beta1("test.velero.io").Result(),
				),
				test.VSLs(
					builder.ForVolumeSnapshotLocation("foo", "bar").Result(),
				),
				test.Backups(
					builder.ForBackup("zoo", "raz").Result(),
				),
			},
			want: []string{
				"resources/customresourcedefinitions.apiextensions.k8s.io/cluster/volumesnapshotlocations.velero.io.json",
				"resources/customresourcedefinitions.apiextensions.k8s.io/v1beta1-preferredversion/cluster/volumesnapshotlocations.velero.io.json",
				"resources/volumesnapshotlocations.velero.io/namespaces/foo/bar.json",
				"resources/volumesnapshotlocations.velero.io/v1-preferredversion/namespaces/foo/bar.json",
			},
		},
		{
			name:   "Resource's CRD is not included, when CRD is excluded.",
			backup: defaultBackup().IncludedNamespaces("foo").ExcludedResources("customresourcedefinitions.apiextensions.k8s.io").Result(),
			apiResources: []*test.APIResource{
				test.CRDs(
					builder.ForCustomResourceDefinitionV1Beta1("backups.velero.io").Result(),
					builder.ForCustomResourceDefinitionV1Beta1("volumesnapshotlocations.velero.io").Result(),
					builder.ForCustomResourceDefinitionV1Beta1("test.velero.io").Result(),
				),
				test.VSLs(
					builder.ForVolumeSnapshotLocation("foo", "bar").Result(),
				),
				test.Backups(
					builder.ForBackup("zoo", "raz").Result(),
				),
			},
			want: []string{
				"resources/volumesnapshotlocations.velero.io/namespaces/foo/bar.json",
				"resources/volumesnapshotlocations.velero.io/v1-preferredversion/namespaces/foo/bar.json",
			},
		},
	}

	itemBlockPool := StartItemBlockWorkerPool(t.Context(), 1, logrus.StandardLogger())
	defer itemBlockPool.Stop()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var (
				h   = newHarness(t, itemBlockPool)
				req = &Request{
					Backup:           tc.backup,
					SkippedPVTracker: NewSkipPVTracker(),
					BackedUpItems:    NewBackedUpItemsMap(),
					WorkerPool:       itemBlockPool,
				}
				backupFile = bytes.NewBuffer([]byte{})
			)

			for _, resource := range tc.apiResources {
				h.addItems(t, resource)
			}

			h.backupper.Backup(h.log, req, backupFile, tc.actions, nil, nil)

			assertTarballContents(t, backupFile, append(tc.want, "metadata/version")...)
		})
	}
}

// TestCRDInclusion tests whether related CRDs are included, based on
// backed-up resources and "include cluster resources" flag, and
// verifies that the set of items written to the backup tarball are
// correct. Validation is done by looking at the names of the files in
// the backup tarball; the contents of the files are not checked.
func TestCRDInclusion(t *testing.T) {
	tests := []struct {
		name         string
		backup       *velerov1.Backup
		apiResources []*test.APIResource
		want         []string
	}{
		{
			name: "include cluster resources=auto includes all CRDs when running a full-cluster backup",
			backup: defaultBackup().
				Result(),
			apiResources: []*test.APIResource{
				test.CRDs(
					builder.ForCustomResourceDefinitionV1Beta1("backups.velero.io").Result(),
					builder.ForCustomResourceDefinitionV1Beta1("volumesnapshotlocations.velero.io").Result(),
					builder.ForCustomResourceDefinitionV1Beta1("test.velero.io").Result(),
				),
				test.VSLs(
					builder.ForVolumeSnapshotLocation("foo", "vsl-1").Result(),
				),
			},
			want: []string{
				"resources/customresourcedefinitions.apiextensions.k8s.io/cluster/backups.velero.io.json",
				"resources/customresourcedefinitions.apiextensions.k8s.io/cluster/volumesnapshotlocations.velero.io.json",
				"resources/customresourcedefinitions.apiextensions.k8s.io/cluster/test.velero.io.json",
				"resources/volumesnapshotlocations.velero.io/namespaces/foo/vsl-1.json",
				"resources/customresourcedefinitions.apiextensions.k8s.io/v1beta1-preferredversion/cluster/backups.velero.io.json",
				"resources/customresourcedefinitions.apiextensions.k8s.io/v1beta1-preferredversion/cluster/volumesnapshotlocations.velero.io.json",
				"resources/customresourcedefinitions.apiextensions.k8s.io/v1beta1-preferredversion/cluster/test.velero.io.json",
				"resources/volumesnapshotlocations.velero.io/v1-preferredversion/namespaces/foo/vsl-1.json",
			},
		},
		{
			name: "include cluster resources=false excludes all CRDs when backing up all namespaces",
			backup: defaultBackup().
				IncludeClusterResources(false).
				Result(),
			apiResources: []*test.APIResource{
				test.CRDs(
					builder.ForCustomResourceDefinitionV1Beta1("backups.velero.io").Result(),
					builder.ForCustomResourceDefinitionV1Beta1("volumesnapshotlocations.velero.io").Result(),
					builder.ForCustomResourceDefinitionV1Beta1("test.velero.io").Result(),
				),
				test.VSLs(
					builder.ForVolumeSnapshotLocation("foo", "vsl-1").Result(),
				),
			},
			want: []string{
				"resources/volumesnapshotlocations.velero.io/namespaces/foo/vsl-1.json",
				"resources/volumesnapshotlocations.velero.io/v1-preferredversion/namespaces/foo/vsl-1.json",
			},
		},
		{
			name: "include cluster resources=true includes all CRDs when running a full-cluster backup",
			backup: defaultBackup().
				IncludeClusterResources(true).
				Result(),
			apiResources: []*test.APIResource{
				test.CRDs(
					builder.ForCustomResourceDefinitionV1Beta1("backups.velero.io").Result(),
					builder.ForCustomResourceDefinitionV1Beta1("volumesnapshotlocations.velero.io").Result(),
					builder.ForCustomResourceDefinitionV1Beta1("test.velero.io").Result(),
				),
				test.VSLs(
					builder.ForVolumeSnapshotLocation("foo", "vsl-1").Result(),
				),
			},
			want: []string{
				"resources/customresourcedefinitions.apiextensions.k8s.io/cluster/backups.velero.io.json",
				"resources/customresourcedefinitions.apiextensions.k8s.io/cluster/volumesnapshotlocations.velero.io.json",
				"resources/customresourcedefinitions.apiextensions.k8s.io/cluster/test.velero.io.json",
				"resources/volumesnapshotlocations.velero.io/namespaces/foo/vsl-1.json",
				"resources/customresourcedefinitions.apiextensions.k8s.io/v1beta1-preferredversion/cluster/backups.velero.io.json",
				"resources/customresourcedefinitions.apiextensions.k8s.io/v1beta1-preferredversion/cluster/volumesnapshotlocations.velero.io.json",
				"resources/customresourcedefinitions.apiextensions.k8s.io/v1beta1-preferredversion/cluster/test.velero.io.json",
				"resources/volumesnapshotlocations.velero.io/v1-preferredversion/namespaces/foo/vsl-1.json",
			},
		},
		{
			name: "include-cluster-resources=false excludes all CRDs when backing up selected namespaces",
			backup: defaultBackup().
				IncludeClusterResources(false).
				IncludedNamespaces("foo").
				Result(),
			apiResources: []*test.APIResource{
				test.CRDs(
					builder.ForCustomResourceDefinitionV1Beta1("backups.velero.io").Result(),
					builder.ForCustomResourceDefinitionV1Beta1("volumesnapshotlocations.velero.io").Result(),
					builder.ForCustomResourceDefinitionV1Beta1("test.velero.io").Result(),
				),
				test.VSLs(
					builder.ForVolumeSnapshotLocation("foo", "bar").Result(),
				),
			},
			want: []string{
				"resources/volumesnapshotlocations.velero.io/namespaces/foo/bar.json",
				"resources/volumesnapshotlocations.velero.io/v1-preferredversion/namespaces/foo/bar.json",
			},
		},
		{
			name: "include cluster resources=true includes all CRDs when backing up selected namespaces",
			backup: defaultBackup().
				IncludeClusterResources(true).
				IncludedNamespaces("foo").
				Result(),
			apiResources: []*test.APIResource{
				test.CRDs(
					builder.ForCustomResourceDefinitionV1Beta1("backups.velero.io").Result(),
					builder.ForCustomResourceDefinitionV1Beta1("volumesnapshotlocations.velero.io").Result(),
					builder.ForCustomResourceDefinitionV1Beta1("test.velero.io").Result(),
				),
				test.VSLs(
					builder.ForVolumeSnapshotLocation("foo", "vsl-1").Result(),
				),
			},
			want: []string{
				"resources/customresourcedefinitions.apiextensions.k8s.io/cluster/backups.velero.io.json",
				"resources/customresourcedefinitions.apiextensions.k8s.io/cluster/volumesnapshotlocations.velero.io.json",
				"resources/customresourcedefinitions.apiextensions.k8s.io/cluster/test.velero.io.json",
				"resources/volumesnapshotlocations.velero.io/namespaces/foo/vsl-1.json",
				"resources/customresourcedefinitions.apiextensions.k8s.io/v1beta1-preferredversion/cluster/backups.velero.io.json",
				"resources/customresourcedefinitions.apiextensions.k8s.io/v1beta1-preferredversion/cluster/volumesnapshotlocations.velero.io.json",
				"resources/customresourcedefinitions.apiextensions.k8s.io/v1beta1-preferredversion/cluster/test.velero.io.json",
				"resources/volumesnapshotlocations.velero.io/v1-preferredversion/namespaces/foo/vsl-1.json",
			},
		},
	}

	itemBlockPool := StartItemBlockWorkerPool(t.Context(), 1, logrus.StandardLogger())
	defer itemBlockPool.Stop()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var (
				h   = newHarness(t, itemBlockPool)
				req = &Request{
					Backup:           tc.backup,
					SkippedPVTracker: NewSkipPVTracker(),
					BackedUpItems:    NewBackedUpItemsMap(),
					WorkerPool:       itemBlockPool,
				}
				backupFile = bytes.NewBuffer([]byte{})
			)

			for _, resource := range tc.apiResources {
				h.addItems(t, resource)
			}

			h.backupper.Backup(h.log, req, backupFile, nil, nil, nil)

			assertTarballContents(t, backupFile, append(tc.want, "metadata/version")...)
		})
	}
}

// TestBackupResourceCohabitation runs backups for resources that "cohabitate",
// meaning they exist in multiple API groups (e.g. deployments.extensions and
// deployments.apps), and verifies that only one copy of each resource is backed
// up, with preference for the non-"extensions" API group.
func TestBackupResourceCohabitation(t *testing.T) {
	tests := []struct {
		name         string
		backup       *velerov1.Backup
		apiResources []*test.APIResource
		want         []string
	}{
		{
			name:   "when deployments exist only in extensions, they're backed up",
			backup: defaultBackup().Result(),
			apiResources: []*test.APIResource{
				test.ExtensionsDeployments(
					builder.ForDeployment("foo", "bar").Result(),
					builder.ForDeployment("zoo", "raz").Result(),
				),
			},
			want: []string{
				"resources/deployments.extensions/namespaces/foo/bar.json",
				"resources/deployments.extensions/namespaces/zoo/raz.json",
				"resources/deployments.extensions/v1-preferredversion/namespaces/foo/bar.json",
				"resources/deployments.extensions/v1-preferredversion/namespaces/zoo/raz.json",
			},
		},
		{
			name:   "when deployments exist in both apps and extensions, only apps/deployments are backed up",
			backup: defaultBackup().Result(),
			apiResources: []*test.APIResource{
				test.ExtensionsDeployments(
					builder.ForDeployment("foo", "bar").Result(),
					builder.ForDeployment("zoo", "raz").Result(),
				),
				test.Deployments(
					builder.ForDeployment("foo", "bar").Result(),
					builder.ForDeployment("zoo", "raz").Result(),
				),
			},
			want: []string{
				"resources/deployments.apps/namespaces/foo/bar.json",
				"resources/deployments.apps/namespaces/zoo/raz.json",
				"resources/deployments.apps/v1-preferredversion/namespaces/foo/bar.json",
				"resources/deployments.apps/v1-preferredversion/namespaces/zoo/raz.json",
			},
		},
		{
			name:   "when deployments exist that are not in the cohabiting groups those are backed up along with apps/deployments",
			backup: defaultBackup().Result(),
			apiResources: []*test.APIResource{
				test.VeleroDeployments(
					builder.ForTestCR("Deployment", "foo", "bar").Result(),
					builder.ForTestCR("Deployment", "zoo", "raz").Result(),
				),
				test.Deployments(
					builder.ForDeployment("foo", "bar").Result(),
					builder.ForDeployment("zoo", "raz").Result(),
				),
			},
			want: []string{
				"resources/deployments.apps/namespaces/foo/bar.json",
				"resources/deployments.apps/namespaces/zoo/raz.json",
				"resources/deployments.apps/v1-preferredversion/namespaces/foo/bar.json",
				"resources/deployments.apps/v1-preferredversion/namespaces/zoo/raz.json",
				"resources/deployments.velero.io/namespaces/foo/bar.json",
				"resources/deployments.velero.io/namespaces/zoo/raz.json",
				"resources/deployments.velero.io/v1-preferredversion/namespaces/foo/bar.json",
				"resources/deployments.velero.io/v1-preferredversion/namespaces/zoo/raz.json",
			},
		},
	}

	itemBlockPool := StartItemBlockWorkerPool(t.Context(), 1, logrus.StandardLogger())
	defer itemBlockPool.Stop()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var (
				h   = newHarness(t, itemBlockPool)
				req = &Request{
					Backup:           tc.backup,
					SkippedPVTracker: NewSkipPVTracker(),
					BackedUpItems:    NewBackedUpItemsMap(),
					WorkerPool:       itemBlockPool,
				}
				backupFile = bytes.NewBuffer([]byte{})
			)

			for _, resource := range tc.apiResources {
				h.addItems(t, resource)
			}

			h.backupper.Backup(h.log, req, backupFile, nil, nil, nil)

			assertTarballContents(t, backupFile, append(tc.want, "metadata/version")...)
		})
	}
}

// TestBackupUsesNewCohabitatingResourcesForEachBackup ensures that when two backups are
// run that each include cohabiting resources, one copy of the relevant resources is
// backed up in each backup. Verification is done by looking at the contents of the backup
// tarball. This covers a specific issue that was fixed by https://github.com/vmware-tanzu/velero/pull/485.
func TestBackupUsesNewCohabitatingResourcesForEachBackup(t *testing.T) {
	h := newHarness(t, nil)
	defer h.itemBlockPool.Stop()

	// run and verify backup 1
	backup1 := &Request{
		Backup:           defaultBackup().Result(),
		SkippedPVTracker: NewSkipPVTracker(),
		BackedUpItems:    NewBackedUpItemsMap(),
		WorkerPool:       &h.itemBlockPool,
	}
	backup1File := bytes.NewBuffer([]byte{})

	h.addItems(t, test.Deployments(builder.ForDeployment("ns-1", "deploy-1").Result()))
	h.addItems(t, test.ExtensionsDeployments(builder.ForDeployment("ns-1", "deploy-1").Result()))

	h.backupper.Backup(h.log, backup1, backup1File, nil, nil, nil)

	assertTarballContents(t, backup1File, "metadata/version", "resources/deployments.apps/namespaces/ns-1/deploy-1.json", "resources/deployments.apps/v1-preferredversion/namespaces/ns-1/deploy-1.json")

	// run and verify backup 2
	backup2 := &Request{
		Backup:           defaultBackup().Result(),
		SkippedPVTracker: NewSkipPVTracker(),
		BackedUpItems:    NewBackedUpItemsMap(),
		WorkerPool:       &h.itemBlockPool,
	}
	backup2File := bytes.NewBuffer([]byte{})

	h.backupper.Backup(h.log, backup2, backup2File, nil, nil, nil)

	assertTarballContents(t, backup2File, "metadata/version", "resources/deployments.apps/namespaces/ns-1/deploy-1.json", "resources/deployments.apps/v1-preferredversion/namespaces/ns-1/deploy-1.json")
}

// TestBackupResourceOrdering runs backups of the core API group and ensures that items are backed
// up in the expected order (pods, PVCs, PVs, everything else). Verification is done by looking
// at the order of files written to the backup tarball.
func TestBackupResourceOrdering(t *testing.T) {
	tests := []struct {
		name         string
		backup       *velerov1.Backup
		apiResources []*test.APIResource
	}{
		{
			name: "core API group: pods come before pvcs, pvcs come before pvs, pvs come before anything else",
			backup: defaultBackup().
				SnapshotVolumes(false).
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("foo", "bar").Result(),
					builder.ForPod("zoo", "raz").Result(),
				),
				test.PVCs(
					builder.ForPersistentVolumeClaim("foo", "bar").Result(),
					builder.ForPersistentVolumeClaim("zoo", "raz").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("bar").Result(),
					builder.ForPersistentVolume("baz").Result(),
				),
				test.Secrets(
					builder.ForSecret("foo", "bar").Result(),
					builder.ForSecret("zoo", "raz").Result(),
				),
			},
		},
	}

	itemBlockPool := StartItemBlockWorkerPool(t.Context(), 1, logrus.StandardLogger())
	defer itemBlockPool.Stop()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var (
				h   = newHarness(t, itemBlockPool)
				req = &Request{
					Backup:           tc.backup,
					SkippedPVTracker: NewSkipPVTracker(),
					BackedUpItems:    NewBackedUpItemsMap(),
					WorkerPool:       itemBlockPool,
				}
				backupFile = bytes.NewBuffer([]byte{})
			)

			for _, resource := range tc.apiResources {
				h.addItems(t, resource)
			}

			h.backupper.Backup(h.log, req, backupFile, nil, nil, nil)

			assertTarballOrdering(t, backupFile, "pods", "persistentvolumeclaims", "persistentvolumes")
		})
	}
}

// recordResourcesAction is a backup item action that can be configured
// to run for specific resources/namespaces and simply records the items
// that it is executed for.
type recordResourcesAction struct {
	name               string
	selector           velero.ResourceSelector
	ids                []string
	backups            []velerov1.Backup
	executionErr       error
	additionalItems    []velero.ResourceIdentifier
	operationID        string
	postOperationItems []velero.ResourceIdentifier
	skippedCSISnapshot bool
}

func (a *recordResourcesAction) Execute(item runtime.Unstructured, backup *velerov1.Backup) (runtime.Unstructured, []velero.ResourceIdentifier, string, []velero.ResourceIdentifier, error) {
	metadata, err := meta.Accessor(item)
	if err != nil {
		return item, a.additionalItems, a.operationID, a.postOperationItems, err
	}
	a.ids = append(a.ids, kubeutil.NamespaceAndName(metadata))
	a.backups = append(a.backups, *backup)
	if a.skippedCSISnapshot {
		u := &unstructured.Unstructured{Object: item.UnstructuredContent()}
		u.SetAnnotations(map[string]string{velerov1.SkippedNoCSIPVAnnotation: "true"})
		item = u
		a.additionalItems = nil
	}
	return item, a.additionalItems, a.operationID, a.postOperationItems, a.executionErr
}

func (a *recordResourcesAction) AppliesTo() (velero.ResourceSelector, error) {
	return a.selector, nil
}

func (a *recordResourcesAction) Progress(operationID string, backup *velerov1.Backup) (velero.OperationProgress, error) {
	return velero.OperationProgress{}, nil
}

func (a *recordResourcesAction) Cancel(operationID string, backup *velerov1.Backup) error {
	return nil
}

func (a *recordResourcesAction) Name() string {
	return a.name
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

func (a *recordResourcesAction) WithName(name string) *recordResourcesAction {
	a.name = name
	return a
}

func (a *recordResourcesAction) WithExecutionErr(executionErr error) *recordResourcesAction {
	a.executionErr = executionErr
	return a
}

func (a *recordResourcesAction) WithSkippedCSISnapshotFlag(flag bool) *recordResourcesAction {
	a.skippedCSISnapshot = flag
	return a
}

// TestBackupItemActionsForSkippedPV runs backups with backup item actions, and
// verifies that the data in SkippedPVTracker is updated as expected.
func TestBackupItemActionsForSkippedPV(t *testing.T) {
	itemBlockPool := StartItemBlockWorkerPool(t.Context(), 1, logrus.StandardLogger())
	defer itemBlockPool.Stop()

	tests := []struct {
		name             string
		backupReq        *Request
		apiResources     []*test.APIResource
		runtimeResources []runtime.Object
		actions          []*recordResourcesAction
		resPolicies      *resourcepolicies.ResourcePolicies
		// {pvName:{approach: reason}}
		expectSkippedPVs    map[string]map[string]string
		expectNotSkippedPVs []string
	}{
		{
			name: "backup item action returns the 'not a CSI volume' error and the PV should be tracked as skippedPV",
			backupReq: &Request{
				Backup:           defaultBackup().SnapshotVolumes(false).Result(),
				SkippedPVTracker: NewSkipPVTracker(),
				BackedUpItems:    NewBackedUpItemsMap(),
				WorkerPool:       itemBlockPool,
			},
			resPolicies: &resourcepolicies.ResourcePolicies{
				Version: "v1",
				VolumePolicies: []resourcepolicies.VolumePolicy{
					{
						Action: resourcepolicies.Action{Type: "snapshot"},
						Conditions: map[string]any{
							"storageClass": []string{"gp2"},
						},
					},
				},
			},
			apiResources: []*test.APIResource{
				test.PVs(
					builder.ForPersistentVolume("pv-1").StorageClass("gp2").Result(),
				),
				test.PVCs(
					builder.ForPersistentVolumeClaim("ns-1", "pvc-1").VolumeName("pv-1").StorageClass("gp2").Phase(corev1api.ClaimBound).Result(),
				),
			},
			runtimeResources: []runtime.Object{
				builder.ForPersistentVolume("pv-1").StorageClass("gp2").Result(),
				builder.ForPersistentVolumeClaim("ns-1", "pvc-1").VolumeName("pv-1").StorageClass("gp2").Phase(corev1api.ClaimBound).Result(),
			},
			actions: []*recordResourcesAction{
				new(recordResourcesAction).WithName(csiBIAPluginName).ForNamespace("ns-1").ForResource("persistentvolumeclaims").WithSkippedCSISnapshotFlag(true),
			},
			expectSkippedPVs: map[string]map[string]string{
				"pv-1": {
					csiSnapshotApproach: "skipped b/c it's not a CSI volume",
				},
			},
		},
		{
			name: "backup item action named as CSI plugin executed successfully and the PV will be removed from the skipped PV tracker",
			backupReq: &Request{
				Backup: defaultBackup().Result(),
				SkippedPVTracker: &skipPVTracker{
					RWMutex: &sync.RWMutex{},
					pvs: map[string]map[string]string{
						"pv-1": {
							"any": "whatever reason",
						},
					},
					includedPVs: map[string]struct{}{},
				},
				BackedUpItems: NewBackedUpItemsMap(),
				WorkerPool:    itemBlockPool,
			},
			apiResources: []*test.APIResource{
				test.PVCs(
					builder.ForPersistentVolumeClaim("ns-1", "pvc-1").VolumeName("pv-1").Phase(corev1api.ClaimBound).Result(),
				),
			},
			runtimeResources: []runtime.Object{
				builder.ForPersistentVolumeClaim("ns-1", "pvc-1").VolumeName("pv-1").Phase(corev1api.ClaimBound).Result(),
				builder.ForPersistentVolume("pv-1").StorageClass("gp2").Result(),
			},
			actions: []*recordResourcesAction{
				new(recordResourcesAction).ForNamespace("ns-1").ForResource("persistentvolumeclaims").WithName(csiBIAPluginName),
			},
			expectNotSkippedPVs: []string{"pv-1"},
		},
	}
	// Enable CSI feature before running the test, because Velero will check whether
	// CSI feature is enabled before executing CSI plugin actions.
	features.NewFeatureFlagSet("EnableCSI")
	defer func() {
		features.NewFeatureFlagSet("")
	}()
	for _, tc := range tests {
		t.Run(tc.name, func(tt *testing.T) {
			var (
				h          = newHarness(t, itemBlockPool)
				backupFile = bytes.NewBuffer([]byte{})
				fakeClient = test.NewFakeControllerRuntimeClient(t, tc.runtimeResources...)
			)
			h.backupper.kbClient = fakeClient

			for _, resource := range tc.apiResources {
				h.addItems(t, resource)
			}

			actions := []biav2.BackupItemAction{}
			for _, action := range tc.actions {
				actions = append(actions, action)
			}

			if tc.resPolicies != nil {
				tc.backupReq.ResPolicies = new(resourcepolicies.Policies)
				require.NoError(t, tc.backupReq.ResPolicies.BuildPolicy(tc.resPolicies))
			}

			err := h.backupper.Backup(h.log, tc.backupReq, backupFile, actions, nil, nil)
			require.NoError(t, err)

			if tc.expectSkippedPVs != nil {
				for pvName, reasons := range tc.expectSkippedPVs {
					v, ok := tc.backupReq.SkippedPVTracker.pvs[pvName]
					assert.True(tt, ok)
					for approach, reason := range reasons {
						assert.Equal(tt, reason, v[approach])
					}
				}
			}
			for _, pvName := range tc.expectNotSkippedPVs {
				_, ok := tc.backupReq.SkippedPVTracker.pvs[pvName]
				assert.False(tt, ok)
			}
		})
	}
}

// TestBackupActionsRunForCorrectItems runs backups with backup item actions, and
// verifies that each backup item action is run for the correct set of resources based on its
// AppliesTo() resource selector. Verification is done by using the recordResourcesAction struct,
// which records which resources it's executed for.
func TestBackupActionsRunForCorrectItems(t *testing.T) {
	tests := []struct {
		name         string
		backup       *velerov1.Backup
		apiResources []*test.APIResource

		// actions is a map from a recordResourcesAction (which will record the items it was called for)
		// to a slice of expected items, formatted as {namespace}/{name}.
		actions map[*recordResourcesAction][]string
	}{
		{
			name: "single action with no selector runs for all items",
			backup: defaultBackup().
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-2").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("pv-1").Result(),
					builder.ForPersistentVolume("pv-2").Result(),
				),
			},
			actions: map[*recordResourcesAction][]string{
				new(recordResourcesAction): {"ns-1/pod-1", "ns-2/pod-2", "pv-1", "pv-2"},
			},
		},
		{
			name: "single action with a resource selector for namespaced resources runs only for matching resources",
			backup: defaultBackup().
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-2").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("pv-1").Result(),
					builder.ForPersistentVolume("pv-2").Result(),
				),
			},
			actions: map[*recordResourcesAction][]string{
				new(recordResourcesAction).ForResource("pods"): {"ns-1/pod-1", "ns-2/pod-2"},
			},
		},
		{
			name: "single action with a resource selector for cluster-scoped resources runs only for matching resources",
			backup: defaultBackup().
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-2").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("pv-1").Result(),
					builder.ForPersistentVolume("pv-2").Result(),
				),
			},
			actions: map[*recordResourcesAction][]string{
				new(recordResourcesAction).ForResource("persistentvolumes"): {"pv-1", "pv-2"},
			},
		},
		{
			name: "single action with a namespace selector runs only for resources in that namespace",
			backup: defaultBackup().
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-2").Result(),
				),
				test.PVCs(
					builder.ForPersistentVolumeClaim("ns-1", "pvc-1").Result(),
					builder.ForPersistentVolumeClaim("ns-2", "pvc-2").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("pv-1").Result(),
					builder.ForPersistentVolume("pv-2").Result(),
				),
				test.Namespaces(
					builder.ForNamespace("ns-1").Result(),
					builder.ForNamespace("ns-2").Result(),
				),
			},
			actions: map[*recordResourcesAction][]string{
				new(recordResourcesAction).ForNamespace("ns-1"): {"ns-1/pod-1", "ns-1/pvc-1"},
			},
		},
		{
			name: "single action with a resource and namespace selector runs only for matching resources",
			backup: defaultBackup().
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-2").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("pv-1").Result(),
					builder.ForPersistentVolume("pv-2").Result(),
				),
			},
			actions: map[*recordResourcesAction][]string{
				new(recordResourcesAction).ForResource("pods").ForNamespace("ns-1"): {"ns-1/pod-1"},
			},
		},
		{
			name: "multiple actions, each with a different resource selector using short name, run for matching resources",
			backup: defaultBackup().
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-2").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("pv-1").Result(),
					builder.ForPersistentVolume("pv-2").Result(),
				),
			},
			actions: map[*recordResourcesAction][]string{
				new(recordResourcesAction).ForResource("po"): {"ns-1/pod-1", "ns-2/pod-2"},
				new(recordResourcesAction).ForResource("pv"): {"pv-1", "pv-2"},
			},
		},
		{
			name: "actions with selectors that don't match anything don't run for any resources",
			backup: defaultBackup().
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").Result(),
				),
				test.PVCs(
					builder.ForPersistentVolumeClaim("ns-2", "pvc-2").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("pv-1").Result(),
					builder.ForPersistentVolume("pv-2").Result(),
				),
			},
			actions: map[*recordResourcesAction][]string{
				new(recordResourcesAction).ForNamespace("ns-1").ForResource("persistentvolumeclaims"): nil,
				new(recordResourcesAction).ForNamespace("ns-2").ForResource("pods"):                   nil,
			},
		},
		{
			name: "action with a selector that has unresolvable resources doesn't run for any resources",
			backup: defaultBackup().
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").Result(),
				),
				test.PVCs(
					builder.ForPersistentVolumeClaim("ns-2", "pvc-2").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("pv-1").Result(),
					builder.ForPersistentVolume("pv-2").Result(),
				),
			},
			actions: map[*recordResourcesAction][]string{
				new(recordResourcesAction).ForResource("unresolvable"): nil,
			},
		},
	}

	itemBlockPool := StartItemBlockWorkerPool(t.Context(), 1, logrus.StandardLogger())
	defer itemBlockPool.Stop()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var (
				h   = newHarness(t, itemBlockPool)
				req = &Request{
					Backup:           tc.backup,
					SkippedPVTracker: NewSkipPVTracker(),
					BackedUpItems:    NewBackedUpItemsMap(),
					WorkerPool:       itemBlockPool,
				}
				backupFile = bytes.NewBuffer([]byte{})
			)

			for _, resource := range tc.apiResources {
				h.addItems(t, resource)
			}

			actions := []biav2.BackupItemAction{}
			for action := range tc.actions {
				actions = append(actions, action)
			}

			err := h.backupper.Backup(h.log, req, backupFile, actions, nil, nil)
			require.NoError(t, err)

			for action, want := range tc.actions {
				assert.Equal(t, want, action.ids)
			}
		})
	}
}

// TestBackupWithInvalidActions runs backups with backup item actions that are invalid
// in some way (e.g. an invalid label selector returned from AppliesTo(), an error returned
// from AppliesTo()) and verifies that this causes the backupper.Backup(...) method to
// return an error.
func TestBackupWithInvalidActions(t *testing.T) {
	// all test cases in this function are expected to cause the method under test
	// to return an error, so no expected results need to be set up.
	tests := []struct {
		name         string
		backup       *velerov1.Backup
		apiResources []*test.APIResource
		actions      []biav2.BackupItemAction
	}{
		{
			name: "action with invalid label selector results in an error",
			backup: defaultBackup().
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("foo", "bar").Result(),
					builder.ForPod("zoo", "raz").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("bar").Result(),
					builder.ForPersistentVolume("baz").Result(),
				),
			},
			actions: []biav2.BackupItemAction{
				new(recordResourcesAction).ForLabelSelector("=invalid-selector"),
			},
		},
		{
			name: "action returning an error from AppliesTo results in an error",
			backup: defaultBackup().
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("foo", "bar").Result(),
					builder.ForPod("zoo", "raz").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("bar").Result(),
					builder.ForPersistentVolume("baz").Result(),
				),
			},
			actions: []biav2.BackupItemAction{
				&appliesToErrorAction{},
			},
		},
	}

	itemBlockPool := StartItemBlockWorkerPool(t.Context(), 1, logrus.StandardLogger())
	defer itemBlockPool.Stop()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var (
				h   = newHarness(t, itemBlockPool)
				req = &Request{
					Backup:           tc.backup,
					SkippedPVTracker: NewSkipPVTracker(),
					BackedUpItems:    NewBackedUpItemsMap(),
					WorkerPool:       itemBlockPool,
				}
				backupFile = bytes.NewBuffer([]byte{})
			)

			for _, resource := range tc.apiResources {
				h.addItems(t, resource)
			}

			assert.Error(t, h.backupper.Backup(h.log, req, backupFile, tc.actions, nil, nil))
		})
	}
}

// appliesToErrorAction is a backup item action that always returns
// an error when AppliesTo() is called.
type appliesToErrorAction struct{}

func (a *appliesToErrorAction) AppliesTo() (velero.ResourceSelector, error) {
	return velero.ResourceSelector{}, errors.New("error calling AppliesTo")
}

func (a *appliesToErrorAction) Execute(item runtime.Unstructured, backup *velerov1.Backup) (runtime.Unstructured, []velero.ResourceIdentifier, string, []velero.ResourceIdentifier, error) {
	panic("not implemented")
}

func (a *appliesToErrorAction) GetRelatedItems(item runtime.Unstructured, backup *velerov1.Backup) ([]velero.ResourceIdentifier, error) {
	panic("not implemented")
}

func (a *appliesToErrorAction) Progress(operationID string, backup *velerov1.Backup) (velero.OperationProgress, error) {
	panic("not implemented")
}

func (a *appliesToErrorAction) Cancel(operationID string, backup *velerov1.Backup) error {
	panic("not implemented")
}

func (a *appliesToErrorAction) Name() string {
	return ""
}

// TestBackupActionModifications runs backups with backup item actions that make modifications
// to items in their Execute(...) methods and verifies that these modifications are
// persisted to the backup tarball. Verification is done by inspecting the file contents
// of the tarball.
func TestBackupActionModifications(t *testing.T) {
	// modifyingActionGetter is a helper function that returns a *pluggableAction, whose Execute(...)
	// method modifies the item being passed in by calling the 'modify' function on it.
	modifyingActionGetter := func(modify func(*unstructured.Unstructured)) *pluggableAction {
		return &pluggableAction{
			executeFunc: func(item runtime.Unstructured, backup *velerov1.Backup) (runtime.Unstructured, []velero.ResourceIdentifier, string, []velero.ResourceIdentifier, error) {
				obj, ok := item.(*unstructured.Unstructured)
				if !ok {
					return nil, nil, "", nil, errors.Errorf("unexpected type %T", item)
				}

				res := obj.DeepCopy()
				modify(res)

				return res, nil, "", nil, nil
			},
		}
	}

	tests := []struct {
		name         string
		backup       *velerov1.Backup
		apiResources []*test.APIResource
		actions      []biav2.BackupItemAction
		want         map[string]unstructuredObject
	}{
		{
			name:   "action that adds a label to item gets persisted",
			backup: defaultBackup().Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").Result(),
				),
			},
			actions: []biav2.BackupItemAction{
				modifyingActionGetter(func(item *unstructured.Unstructured) {
					item.SetLabels(map[string]string{"updated": "true"})
				}),
			},
			want: map[string]unstructuredObject{
				"resources/pods/namespaces/ns-1/pod-1.json": toUnstructuredOrFail(t, builder.ForPod("ns-1", "pod-1").ObjectMeta(builder.WithLabels("updated", "true")).Result()),
			},
		},
		{
			name:   "action that removes labels from item gets persisted",
			backup: defaultBackup().Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").ObjectMeta(builder.WithLabels("should-be-removed", "true")).Result(),
				),
			},
			actions: []biav2.BackupItemAction{
				modifyingActionGetter(func(item *unstructured.Unstructured) {
					item.SetLabels(nil)
				}),
			},
			want: map[string]unstructuredObject{
				"resources/pods/namespaces/ns-1/pod-1.json": toUnstructuredOrFail(t, builder.ForPod("ns-1", "pod-1").Result()),
			},
		},
		{
			name:   "action that sets a spec field on item gets persisted",
			backup: defaultBackup().Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").Result(),
				),
			},
			actions: []biav2.BackupItemAction{
				modifyingActionGetter(func(item *unstructured.Unstructured) {
					item.Object["spec"].(map[string]any)["nodeName"] = "foo"
				}),
			},
			want: map[string]unstructuredObject{
				"resources/pods/namespaces/ns-1/pod-1.json": toUnstructuredOrFail(t, builder.ForPod("ns-1", "pod-1").NodeName("foo").Result()),
			},
		},
		{
			name: "modifications to name and namespace in an action are persisted in JSON and in filename",
			backup: defaultBackup().
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").Result(),
				),
			},
			actions: []biav2.BackupItemAction{
				modifyingActionGetter(func(item *unstructured.Unstructured) {
					item.SetName(item.GetName() + "-updated")
					item.SetNamespace(item.GetNamespace() + "-updated")
				}),
			},
			want: map[string]unstructuredObject{
				"resources/pods/namespaces/ns-1-updated/pod-1-updated.json": toUnstructuredOrFail(t, builder.ForPod("ns-1-updated", "pod-1-updated").Result()),
			},
		},
	}

	itemBlockPool := StartItemBlockWorkerPool(t.Context(), 1, logrus.StandardLogger())
	defer itemBlockPool.Stop()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var (
				h   = newHarness(t, itemBlockPool)
				req = &Request{
					Backup:           tc.backup,
					SkippedPVTracker: NewSkipPVTracker(),
					BackedUpItems:    NewBackedUpItemsMap(),
					WorkerPool:       itemBlockPool,
				}
				backupFile = bytes.NewBuffer([]byte{})
			)

			for _, resource := range tc.apiResources {
				h.addItems(t, resource)
			}

			err := h.backupper.Backup(h.log, req, backupFile, tc.actions, nil, nil)
			require.NoError(t, err)

			assertTarballFileContents(t, backupFile, tc.want)
		})
	}
}

// TestBackupActionAdditionalItems runs backups with backup item actions that return
// additional items to be backed up, and verifies that those items are included in the
// backup tarball as appropriate. Verification is done by looking at the files that exist
// in the backup tarball.
func TestBackupActionAdditionalItems(t *testing.T) {
	tests := []struct {
		name         string
		backup       *velerov1.Backup
		apiResources []*test.APIResource
		actions      []biav2.BackupItemAction
		ibActions    []ibav1.ItemBlockAction
		want         []string
	}{
		{
			name:   "additional items that are already being backed up are not backed up twice",
			backup: defaultBackup().Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-2").Result(),
					builder.ForPod("ns-3", "pod-3").Result(),
				),
			},
			actions: []biav2.BackupItemAction{
				&pluggableAction{
					selector: velero.ResourceSelector{IncludedNamespaces: []string{"ns-1"}},
					executeFunc: func(item runtime.Unstructured, backup *velerov1.Backup) (runtime.Unstructured, []velero.ResourceIdentifier, string, []velero.ResourceIdentifier, error) {
						additionalItems := []velero.ResourceIdentifier{
							{GroupResource: kuberesource.Pods, Namespace: "ns-2", Name: "pod-2"},
							{GroupResource: kuberesource.Pods, Namespace: "ns-3", Name: "pod-3"},
						}

						return item, additionalItems, "", nil, nil
					},
				},
			},
			want: []string{
				"resources/pods/namespaces/ns-1/pod-1.json",
				"resources/pods/namespaces/ns-2/pod-2.json",
				"resources/pods/namespaces/ns-3/pod-3.json",
				"resources/pods/v1-preferredversion/namespaces/ns-1/pod-1.json",
				"resources/pods/v1-preferredversion/namespaces/ns-2/pod-2.json",
				"resources/pods/v1-preferredversion/namespaces/ns-3/pod-3.json",
			},
		},
		{
			name:   "when using a backup namespace filter, additional items that are in a non-included namespace are not backed up",
			backup: defaultBackup().IncludedNamespaces("ns-1").Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-2").Result(),
					builder.ForPod("ns-3", "pod-3").Result(),
				),
			},
			actions: []biav2.BackupItemAction{
				&pluggableAction{
					executeFunc: func(item runtime.Unstructured, backup *velerov1.Backup) (runtime.Unstructured, []velero.ResourceIdentifier, string, []velero.ResourceIdentifier, error) {
						additionalItems := []velero.ResourceIdentifier{
							{GroupResource: kuberesource.Pods, Namespace: "ns-2", Name: "pod-2"},
							{GroupResource: kuberesource.Pods, Namespace: "ns-3", Name: "pod-3"},
						}

						return item, additionalItems, "", nil, nil
					},
				},
			},
			want: []string{
				"resources/pods/namespaces/ns-1/pod-1.json",
				"resources/pods/v1-preferredversion/namespaces/ns-1/pod-1.json",
			},
		},
		{
			name:   "when using a backup namespace filter, additional items that are cluster-scoped are backed up",
			backup: defaultBackup().IncludedNamespaces("ns-1").Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-2").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("pv-1").Result(),
					builder.ForPersistentVolume("pv-2").Result(),
				),
			},
			actions: []biav2.BackupItemAction{
				&pluggableAction{
					executeFunc: func(item runtime.Unstructured, backup *velerov1.Backup) (runtime.Unstructured, []velero.ResourceIdentifier, string, []velero.ResourceIdentifier, error) {
						additionalItems := []velero.ResourceIdentifier{
							{GroupResource: kuberesource.PersistentVolumes, Name: "pv-1"},
							{GroupResource: kuberesource.PersistentVolumes, Name: "pv-2"},
						}

						return item, additionalItems, "", nil, nil
					},
				},
			},
			want: []string{
				"resources/pods/namespaces/ns-1/pod-1.json",
				"resources/persistentvolumes/cluster/pv-1.json",
				"resources/persistentvolumes/cluster/pv-2.json",
				"resources/pods/v1-preferredversion/namespaces/ns-1/pod-1.json",
				"resources/persistentvolumes/v1-preferredversion/cluster/pv-1.json",
				"resources/persistentvolumes/v1-preferredversion/cluster/pv-2.json",
			},
		},
		{
			name:   "when using a backup resource filter, additional items that are non-included resources are not backed up",
			backup: defaultBackup().IncludedResources("pods").Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("pv-1").Result(),
					builder.ForPersistentVolume("pv-2").Result(),
				),
			},
			actions: []biav2.BackupItemAction{
				&pluggableAction{
					executeFunc: func(item runtime.Unstructured, backup *velerov1.Backup) (runtime.Unstructured, []velero.ResourceIdentifier, string, []velero.ResourceIdentifier, error) {
						additionalItems := []velero.ResourceIdentifier{
							{GroupResource: kuberesource.PersistentVolumes, Name: "pv-1"},
							{GroupResource: kuberesource.PersistentVolumes, Name: "pv-2"},
						}

						return item, additionalItems, "", nil, nil
					},
				},
			},
			want: []string{
				"resources/pods/namespaces/ns-1/pod-1.json",
				"resources/pods/v1-preferredversion/namespaces/ns-1/pod-1.json",
			},
		},
		{
			name:   "when IncludeClusterResources=false, additional items that are cluster-scoped are not backed up",
			backup: defaultBackup().IncludeClusterResources(false).Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-2").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("pv-1").Result(),
					builder.ForPersistentVolume("pv-2").Result(),
				),
			},
			actions: []biav2.BackupItemAction{
				&pluggableAction{
					executeFunc: func(item runtime.Unstructured, backup *velerov1.Backup) (runtime.Unstructured, []velero.ResourceIdentifier, string, []velero.ResourceIdentifier, error) {
						additionalItems := []velero.ResourceIdentifier{
							{GroupResource: kuberesource.PersistentVolumes, Name: "pv-1"},
							{GroupResource: kuberesource.PersistentVolumes, Name: "pv-2"},
						}

						return item, additionalItems, "", nil, nil
					},
				},
			},
			want: []string{
				"resources/pods/namespaces/ns-1/pod-1.json",
				"resources/pods/namespaces/ns-2/pod-2.json",
				"resources/pods/v1-preferredversion/namespaces/ns-1/pod-1.json",
				"resources/pods/v1-preferredversion/namespaces/ns-2/pod-2.json",
			},
		},
		{
			name:   "additional items with the velero.io/exclude-from-backup label are not backed up",
			backup: defaultBackup().IncludedNamespaces("ns-1").Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("pv-1").ObjectMeta(builder.WithLabels(velerov1.ExcludeFromBackupLabel, "true")).Result(),
					builder.ForPersistentVolume("pv-2").Result(),
				),
			},
			actions: []biav2.BackupItemAction{
				&pluggableAction{
					executeFunc: func(item runtime.Unstructured, backup *velerov1.Backup) (runtime.Unstructured, []velero.ResourceIdentifier, string, []velero.ResourceIdentifier, error) {
						additionalItems := []velero.ResourceIdentifier{
							{GroupResource: kuberesource.PersistentVolumes, Name: "pv-1"},
							{GroupResource: kuberesource.PersistentVolumes, Name: "pv-2"},
						}

						return item, additionalItems, "", nil, nil
					},
				},
			},
			want: []string{
				"resources/pods/namespaces/ns-1/pod-1.json",
				"resources/persistentvolumes/cluster/pv-2.json",
				"resources/pods/v1-preferredversion/namespaces/ns-1/pod-1.json",
				"resources/persistentvolumes/v1-preferredversion/cluster/pv-2.json",
			},
		},

		{
			name:   "if additional items aren't found in the API, they're skipped and the original item is still backed up",
			backup: defaultBackup().Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-2").Result(),
					builder.ForPod("ns-3", "pod-3").Result(),
				),
			},
			actions: []biav2.BackupItemAction{
				&pluggableAction{
					selector: velero.ResourceSelector{IncludedNamespaces: []string{"ns-1"}},
					executeFunc: func(item runtime.Unstructured, backup *velerov1.Backup) (runtime.Unstructured, []velero.ResourceIdentifier, string, []velero.ResourceIdentifier, error) {
						additionalItems := []velero.ResourceIdentifier{
							{GroupResource: kuberesource.Pods, Namespace: "ns-4", Name: "pod-4"},
							{GroupResource: kuberesource.Pods, Namespace: "ns-5", Name: "pod-5"},
						}

						return item, additionalItems, "", nil, nil
					},
				},
			},
			want: []string{
				"resources/pods/namespaces/ns-1/pod-1.json",
				"resources/pods/namespaces/ns-2/pod-2.json",
				"resources/pods/namespaces/ns-3/pod-3.json",
				"resources/pods/v1-preferredversion/namespaces/ns-1/pod-1.json",
				"resources/pods/v1-preferredversion/namespaces/ns-2/pod-2.json",
				"resources/pods/v1-preferredversion/namespaces/ns-3/pod-3.json",
			},
		},
	}

	itemBlockPool := StartItemBlockWorkerPool(t.Context(), 1, logrus.StandardLogger())
	defer itemBlockPool.Stop()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var (
				h   = newHarness(t, itemBlockPool)
				req = &Request{
					Backup:           tc.backup,
					SkippedPVTracker: NewSkipPVTracker(),
					BackedUpItems:    NewBackedUpItemsMap(),
					WorkerPool:       itemBlockPool,
				}
				backupFile = bytes.NewBuffer([]byte{})
			)

			for _, resource := range tc.apiResources {
				h.addItems(t, resource)
			}

			err := h.backupper.Backup(h.log, req, backupFile, tc.actions, nil, nil)
			require.NoError(t, err)

			assertTarballContents(t, backupFile, append(tc.want, "metadata/version")...)
		})
	}
}

// recordResourcesIBA is an ItemBlock item action that can be configured
// to run for specific resources/namespaces and simply records the items
// that it is executed for.
type recordResourcesIBA struct {
	name         string
	selector     velero.ResourceSelector
	ids          []string
	backups      []velerov1.Backup
	executionErr error
	relatedItems []velero.ResourceIdentifier
}

func (a *recordResourcesIBA) GetRelatedItems(item runtime.Unstructured, backup *velerov1.Backup) ([]velero.ResourceIdentifier, error) {
	metadata, err := meta.Accessor(item)
	if err != nil {
		return a.relatedItems, err
	}
	a.ids = append(a.ids, kubeutil.NamespaceAndName(metadata))
	a.backups = append(a.backups, *backup)
	return a.relatedItems, a.executionErr
}

func (a *recordResourcesIBA) AppliesTo() (velero.ResourceSelector, error) {
	return a.selector, nil
}

func (a *recordResourcesIBA) Name() string {
	return a.name
}

func (a *recordResourcesIBA) ForResource(resource string) *recordResourcesIBA {
	a.selector.IncludedResources = append(a.selector.IncludedResources, resource)
	return a
}

func (a *recordResourcesIBA) ForNamespace(namespace string) *recordResourcesIBA {
	a.selector.IncludedNamespaces = append(a.selector.IncludedNamespaces, namespace)
	return a
}

func (a *recordResourcesIBA) ForLabelSelector(selector string) *recordResourcesIBA {
	a.selector.LabelSelector = selector
	return a
}

func (a *recordResourcesIBA) WithRelatedItems(items []velero.ResourceIdentifier) *recordResourcesIBA {
	a.relatedItems = items
	return a
}

func (a *recordResourcesIBA) WithName(name string) *recordResourcesIBA {
	a.name = name
	return a
}

func (a *recordResourcesIBA) WithExecutionErr(executionErr error) *recordResourcesIBA {
	a.executionErr = executionErr
	return a
}

// TestItemBlockActionsRunForCorrectItems runs backups with ItemBlock actions, and
// verifies that each action is run for the correct set of resources based on its
// AppliesTo() resource selector. Verification is done by using the recordResourcesIBA struct,
// which records which resources it's executed for.
func TestItemBlockActionsRunForCorrectItems(t *testing.T) {
	tests := []struct {
		name         string
		backup       *velerov1.Backup
		apiResources []*test.APIResource

		// actions is a map from a recordResourcesIBA (which will record the items it was called for)
		// to a slice of expected items, formatted as {namespace}/{name}.
		actions map[*recordResourcesIBA][]string
	}{
		{
			name: "single action with no selector runs for all items",
			backup: defaultBackup().
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-2").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("pv-1").Result(),
					builder.ForPersistentVolume("pv-2").Result(),
				),
			},
			actions: map[*recordResourcesIBA][]string{
				new(recordResourcesIBA): {"ns-1/pod-1", "ns-2/pod-2", "pv-1", "pv-2"},
			},
		},
		{
			name: "single action with a resource selector for namespaced resources runs only for matching resources",
			backup: defaultBackup().
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-2").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("pv-1").Result(),
					builder.ForPersistentVolume("pv-2").Result(),
				),
			},
			actions: map[*recordResourcesIBA][]string{
				new(recordResourcesIBA).ForResource("pods"): {"ns-1/pod-1", "ns-2/pod-2"},
			},
		},
		{
			name: "single action with a resource selector for cluster-scoped resources runs only for matching resources",
			backup: defaultBackup().
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-2").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("pv-1").Result(),
					builder.ForPersistentVolume("pv-2").Result(),
				),
			},
			actions: map[*recordResourcesIBA][]string{
				new(recordResourcesIBA).ForResource("persistentvolumes"): {"pv-1", "pv-2"},
			},
		},
		{
			name: "single action with a namespace selector runs only for resources in that namespace",
			backup: defaultBackup().
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-2").Result(),
				),
				test.PVCs(
					builder.ForPersistentVolumeClaim("ns-1", "pvc-1").Result(),
					builder.ForPersistentVolumeClaim("ns-2", "pvc-2").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("pv-1").Result(),
					builder.ForPersistentVolume("pv-2").Result(),
				),
				test.Namespaces(
					builder.ForNamespace("ns-1").Result(),
					builder.ForNamespace("ns-2").Result(),
				),
			},
			actions: map[*recordResourcesIBA][]string{
				new(recordResourcesIBA).ForNamespace("ns-1"): {"ns-1/pod-1", "ns-1/pvc-1"},
			},
		},
		{
			name: "single action with a resource and namespace selector runs only for matching resources",
			backup: defaultBackup().
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-2").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("pv-1").Result(),
					builder.ForPersistentVolume("pv-2").Result(),
				),
			},
			actions: map[*recordResourcesIBA][]string{
				new(recordResourcesIBA).ForResource("pods").ForNamespace("ns-1"): {"ns-1/pod-1"},
			},
		},
		{
			name: "multiple actions, each with a different resource selector using short name, run for matching resources",
			backup: defaultBackup().
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-2").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("pv-1").Result(),
					builder.ForPersistentVolume("pv-2").Result(),
				),
			},
			actions: map[*recordResourcesIBA][]string{
				new(recordResourcesIBA).ForResource("po"): {"ns-1/pod-1", "ns-2/pod-2"},
				new(recordResourcesIBA).ForResource("pv"): {"pv-1", "pv-2"},
			},
		},
		{
			name: "actions with selectors that don't match anything don't run for any resources",
			backup: defaultBackup().
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").Result(),
				),
				test.PVCs(
					builder.ForPersistentVolumeClaim("ns-2", "pvc-2").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("pv-1").Result(),
					builder.ForPersistentVolume("pv-2").Result(),
				),
			},
			actions: map[*recordResourcesIBA][]string{
				new(recordResourcesIBA).ForNamespace("ns-1").ForResource("persistentvolumeclaims"): nil,
				new(recordResourcesIBA).ForNamespace("ns-2").ForResource("pods"):                   nil,
			},
		},
		{
			name: "action with a selector that has unresolvable resources doesn't run for any resources",
			backup: defaultBackup().
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").Result(),
				),
				test.PVCs(
					builder.ForPersistentVolumeClaim("ns-2", "pvc-2").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("pv-1").Result(),
					builder.ForPersistentVolume("pv-2").Result(),
				),
			},
			actions: map[*recordResourcesIBA][]string{
				new(recordResourcesIBA).ForResource("unresolvable"): nil,
			},
		},
	}

	itemBlockPool := StartItemBlockWorkerPool(t.Context(), 1, logrus.StandardLogger())
	defer itemBlockPool.Stop()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var (
				h   = newHarness(t, itemBlockPool)
				req = &Request{
					Backup:           tc.backup,
					SkippedPVTracker: NewSkipPVTracker(),
					BackedUpItems:    NewBackedUpItemsMap(),
					WorkerPool:       itemBlockPool,
				}
				backupFile = bytes.NewBuffer([]byte{})
			)

			for _, resource := range tc.apiResources {
				h.addItems(t, resource)
			}

			actions := []ibav1.ItemBlockAction{}
			for action := range tc.actions {
				actions = append(actions, action)
			}

			err := h.backupper.Backup(h.log, req, backupFile, nil, actions, nil)
			require.NoError(t, err)

			for action, want := range tc.actions {
				assert.Equal(t, want, action.ids)
			}
		})
	}
}

// TestBackupWithInvalidItemBlockActions runs backups with ItemBlock actions that are invalid
// in some way (e.g. an invalid label selector returned from AppliesTo(), an error returned
// from AppliesTo()) and verifies that this causes the backupper.Backup(...) method to
// return an error.
func TestBackupWithInvalidItemBlockActions(t *testing.T) {
	// all test cases in this function are expected to cause the method under test
	// to return an error, so no expected results need to be set up.
	tests := []struct {
		name         string
		backup       *velerov1.Backup
		apiResources []*test.APIResource
		actions      []ibav1.ItemBlockAction
	}{
		{
			name: "action with invalid label selector results in an error",
			backup: defaultBackup().
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("foo", "bar").Result(),
					builder.ForPod("zoo", "raz").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("bar").Result(),
					builder.ForPersistentVolume("baz").Result(),
				),
			},
			actions: []ibav1.ItemBlockAction{
				new(recordResourcesIBA).ForLabelSelector("=invalid-selector"),
			},
		},
		{
			name: "action returning an error from AppliesTo results in an error",
			backup: defaultBackup().
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("foo", "bar").Result(),
					builder.ForPod("zoo", "raz").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("bar").Result(),
					builder.ForPersistentVolume("baz").Result(),
				),
			},
			actions: []ibav1.ItemBlockAction{
				&appliesToErrorAction{},
			},
		},
	}

	itemBlockPool := StartItemBlockWorkerPool(t.Context(), 1, logrus.StandardLogger())
	defer itemBlockPool.Stop()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var (
				h   = newHarness(t, itemBlockPool)
				req = &Request{
					Backup:           tc.backup,
					SkippedPVTracker: NewSkipPVTracker(),
					BackedUpItems:    NewBackedUpItemsMap(),
					WorkerPool:       itemBlockPool,
				}
				backupFile = bytes.NewBuffer([]byte{})
			)

			for _, resource := range tc.apiResources {
				h.addItems(t, resource)
			}

			assert.Error(t, h.backupper.Backup(h.log, req, backupFile, nil, tc.actions, nil))
		})
	}
}

// TestItemBlockActionRelatedItems runs backups with ItemBlock actions that return
// related items, and verifies that those items are included in the
// backup tarball as appropriate. Verification is done by looking at the files that exist
// in the backup tarball.
func TestItemBlockActionRelatedItems(t *testing.T) {
	tests := []struct {
		name         string
		backup       *velerov1.Backup
		apiResources []*test.APIResource
		actions      []ibav1.ItemBlockAction
		want         []string
	}{
		{
			name:   "related items that are already being backed up are not backed up twice",
			backup: defaultBackup().Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-2").Result(),
					builder.ForPod("ns-3", "pod-3").Result(),
				),
			},
			actions: []ibav1.ItemBlockAction{
				&pluggableIBA{
					selector: velero.ResourceSelector{IncludedNamespaces: []string{"ns-1"}},
					getRelatedItemsFunc: func(item runtime.Unstructured, backup *velerov1.Backup) ([]velero.ResourceIdentifier, error) {
						relatedItems := []velero.ResourceIdentifier{
							{GroupResource: kuberesource.Pods, Namespace: "ns-2", Name: "pod-2"},
							{GroupResource: kuberesource.Pods, Namespace: "ns-3", Name: "pod-3"},
						}

						return relatedItems, nil
					},
				},
			},
			want: []string{
				"resources/pods/namespaces/ns-1/pod-1.json",
				"resources/pods/namespaces/ns-2/pod-2.json",
				"resources/pods/namespaces/ns-3/pod-3.json",
				"resources/pods/v1-preferredversion/namespaces/ns-1/pod-1.json",
				"resources/pods/v1-preferredversion/namespaces/ns-2/pod-2.json",
				"resources/pods/v1-preferredversion/namespaces/ns-3/pod-3.json",
			},
		},
		{
			name:   "when using a backup namespace filter, related items that are in a non-included namespace are not backed up",
			backup: defaultBackup().IncludedNamespaces("ns-1").Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-2").Result(),
					builder.ForPod("ns-3", "pod-3").Result(),
				),
			},
			actions: []ibav1.ItemBlockAction{
				&pluggableIBA{
					getRelatedItemsFunc: func(item runtime.Unstructured, backup *velerov1.Backup) ([]velero.ResourceIdentifier, error) {
						relatedItems := []velero.ResourceIdentifier{
							{GroupResource: kuberesource.Pods, Namespace: "ns-2", Name: "pod-2"},
							{GroupResource: kuberesource.Pods, Namespace: "ns-3", Name: "pod-3"},
						}

						return relatedItems, nil
					},
				},
			},
			want: []string{
				"resources/pods/namespaces/ns-1/pod-1.json",
				"resources/pods/v1-preferredversion/namespaces/ns-1/pod-1.json",
			},
		},
		{
			name:   "when using a backup namespace filter, related items that are cluster-scoped are backed up",
			backup: defaultBackup().IncludedNamespaces("ns-1").Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-2").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("pv-1").Result(),
					builder.ForPersistentVolume("pv-2").Result(),
				),
			},
			actions: []ibav1.ItemBlockAction{
				&pluggableIBA{
					getRelatedItemsFunc: func(item runtime.Unstructured, backup *velerov1.Backup) ([]velero.ResourceIdentifier, error) {
						relatedItems := []velero.ResourceIdentifier{
							{GroupResource: kuberesource.PersistentVolumes, Name: "pv-1"},
							{GroupResource: kuberesource.PersistentVolumes, Name: "pv-2"},
						}

						return relatedItems, nil
					},
				},
			},
			want: []string{
				"resources/pods/namespaces/ns-1/pod-1.json",
				"resources/persistentvolumes/cluster/pv-1.json",
				"resources/persistentvolumes/cluster/pv-2.json",
				"resources/pods/v1-preferredversion/namespaces/ns-1/pod-1.json",
				"resources/persistentvolumes/v1-preferredversion/cluster/pv-1.json",
				"resources/persistentvolumes/v1-preferredversion/cluster/pv-2.json",
			},
		},
		{
			name:   "when using a backup resource filter, related items that are non-included resources are not backed up",
			backup: defaultBackup().IncludedResources("pods").Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("pv-1").Result(),
					builder.ForPersistentVolume("pv-2").Result(),
				),
			},
			actions: []ibav1.ItemBlockAction{
				&pluggableIBA{
					getRelatedItemsFunc: func(item runtime.Unstructured, backup *velerov1.Backup) ([]velero.ResourceIdentifier, error) {
						relatedItems := []velero.ResourceIdentifier{
							{GroupResource: kuberesource.PersistentVolumes, Name: "pv-1"},
							{GroupResource: kuberesource.PersistentVolumes, Name: "pv-2"},
						}

						return relatedItems, nil
					},
				},
			},
			want: []string{
				"resources/pods/namespaces/ns-1/pod-1.json",
				"resources/pods/v1-preferredversion/namespaces/ns-1/pod-1.json",
			},
		},
		{
			name:   "when IncludeClusterResources=false, related items that are cluster-scoped are not backed up",
			backup: defaultBackup().IncludeClusterResources(false).Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-2").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("pv-1").Result(),
					builder.ForPersistentVolume("pv-2").Result(),
				),
			},
			actions: []ibav1.ItemBlockAction{
				&pluggableIBA{
					getRelatedItemsFunc: func(item runtime.Unstructured, backup *velerov1.Backup) ([]velero.ResourceIdentifier, error) {
						relatedItems := []velero.ResourceIdentifier{
							{GroupResource: kuberesource.PersistentVolumes, Name: "pv-1"},
							{GroupResource: kuberesource.PersistentVolumes, Name: "pv-2"},
						}

						return relatedItems, nil
					},
				},
			},
			want: []string{
				"resources/pods/namespaces/ns-1/pod-1.json",
				"resources/pods/namespaces/ns-2/pod-2.json",
				"resources/pods/v1-preferredversion/namespaces/ns-1/pod-1.json",
				"resources/pods/v1-preferredversion/namespaces/ns-2/pod-2.json",
			},
		},
		{
			name:   "related items with the velero.io/exclude-from-backup label are not backed up",
			backup: defaultBackup().IncludedNamespaces("ns-1").Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("pv-1").ObjectMeta(builder.WithLabels(velerov1.ExcludeFromBackupLabel, "true")).Result(),
					builder.ForPersistentVolume("pv-2").Result(),
				),
			},
			actions: []ibav1.ItemBlockAction{
				&pluggableIBA{
					getRelatedItemsFunc: func(item runtime.Unstructured, backup *velerov1.Backup) ([]velero.ResourceIdentifier, error) {
						relatedItems := []velero.ResourceIdentifier{
							{GroupResource: kuberesource.PersistentVolumes, Name: "pv-1"},
							{GroupResource: kuberesource.PersistentVolumes, Name: "pv-2"},
						}

						return relatedItems, nil
					},
				},
			},
			want: []string{
				"resources/pods/namespaces/ns-1/pod-1.json",
				"resources/persistentvolumes/cluster/pv-2.json",
				"resources/pods/v1-preferredversion/namespaces/ns-1/pod-1.json",
				"resources/persistentvolumes/v1-preferredversion/cluster/pv-2.json",
			},
		},

		{
			name:   "if related items aren't found in the API, they're skipped and the original item is still backed up",
			backup: defaultBackup().Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-2").Result(),
					builder.ForPod("ns-3", "pod-3").Result(),
				),
			},
			actions: []ibav1.ItemBlockAction{
				&pluggableIBA{
					selector: velero.ResourceSelector{IncludedNamespaces: []string{"ns-1"}},
					getRelatedItemsFunc: func(item runtime.Unstructured, backup *velerov1.Backup) ([]velero.ResourceIdentifier, error) {
						relatedItems := []velero.ResourceIdentifier{
							{GroupResource: kuberesource.Pods, Namespace: "ns-4", Name: "pod-4"},
							{GroupResource: kuberesource.Pods, Namespace: "ns-5", Name: "pod-5"},
						}

						return relatedItems, nil
					},
				},
			},
			want: []string{
				"resources/pods/namespaces/ns-1/pod-1.json",
				"resources/pods/namespaces/ns-2/pod-2.json",
				"resources/pods/namespaces/ns-3/pod-3.json",
				"resources/pods/v1-preferredversion/namespaces/ns-1/pod-1.json",
				"resources/pods/v1-preferredversion/namespaces/ns-2/pod-2.json",
				"resources/pods/v1-preferredversion/namespaces/ns-3/pod-3.json",
			},
		},
	}

	itemBlockPool := StartItemBlockWorkerPool(t.Context(), 1, logrus.StandardLogger())
	defer itemBlockPool.Stop()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var (
				h   = newHarness(t, itemBlockPool)
				req = &Request{
					Backup:           tc.backup,
					SkippedPVTracker: NewSkipPVTracker(),
					BackedUpItems:    NewBackedUpItemsMap(),
					WorkerPool:       itemBlockPool,
				}
				backupFile = bytes.NewBuffer([]byte{})
			)

			for _, resource := range tc.apiResources {
				h.addItems(t, resource)
			}

			err := h.backupper.Backup(h.log, req, backupFile, nil, tc.actions, nil)
			require.NoError(t, err)

			assertTarballContents(t, backupFile, append(tc.want, "metadata/version")...)
		})
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

func int64Ptr(val int) *int64 {
	i := int64(val)
	return &i
}

type volumeIdentifier struct {
	volumeID string
	volumeAZ string
}

type volumeInfo struct {
	volumeType  string
	iops        *int64
	snapshotErr bool
}

// fakeVolumeSnapshotter is a test fake for the vsv1.VolumeSnapshotter interface.
type fakeVolumeSnapshotter struct {
	// PVVolumeNames is a map from PV name to volume ID, used as the basis
	// for the GetVolumeID method.
	PVVolumeNames map[string]string

	// Volumes is a map from volume identifier (volume ID + AZ) to a struct
	// of volume info, used for the GetVolumeInfo and CreateSnapshot methods.
	Volumes map[volumeIdentifier]*volumeInfo
}

// WithVolume is a test helper for registering persistent volumes that the
// fakeVolumeSnapshotter should handle.
func (vs *fakeVolumeSnapshotter) WithVolume(pvName, id, az, volumeType string, iops int, snapshotErr bool) *fakeVolumeSnapshotter {
	if vs.PVVolumeNames == nil {
		vs.PVVolumeNames = make(map[string]string)
	}
	vs.PVVolumeNames[pvName] = id

	if vs.Volumes == nil {
		vs.Volumes = make(map[volumeIdentifier]*volumeInfo)
	}

	identifier := volumeIdentifier{
		volumeID: id,
		volumeAZ: az,
	}

	vs.Volumes[identifier] = &volumeInfo{
		volumeType:  volumeType,
		iops:        int64Ptr(iops),
		snapshotErr: snapshotErr,
	}

	return vs
}

// Init is a no-op.
func (*fakeVolumeSnapshotter) Init(config map[string]string) error {
	return nil
}

// GetVolumeID looks up the PV name in the PVVolumeNames map and returns the result
// if found, or an error otherwise.
func (vs *fakeVolumeSnapshotter) GetVolumeID(pv runtime.Unstructured) (string, error) {
	obj := pv.(*unstructured.Unstructured)

	volumeID, ok := vs.PVVolumeNames[obj.GetName()]
	if !ok {
		return "", errors.New("unsupported volume type")
	}

	return volumeID, nil
}

// CreateSnapshot looks up the volume in the Volume map. If it's not found, an error is
// returned; if snapshotErr is true on the result, an error is returned; otherwise,
// a snapshotID of "<volumeID>-snapshot" is returned.
func (vs *fakeVolumeSnapshotter) CreateSnapshot(volumeID, volumeAZ string, tags map[string]string) (snapshotID string, err error) {
	vi, ok := vs.Volumes[volumeIdentifier{volumeID: volumeID, volumeAZ: volumeAZ}]
	if !ok {
		return "", errors.New("volume not found")
	}

	if vi.snapshotErr {
		return "", errors.New("error calling CreateSnapshot")
	}

	return volumeID + "-snapshot", nil
}

// GetVolumeInfo returns volume info if it exists in the Volumes map
// for the specified volume ID and AZ, or an error otherwise.
func (vs *fakeVolumeSnapshotter) GetVolumeInfo(volumeID, volumeAZ string) (string, *int64, error) {
	vi, ok := vs.Volumes[volumeIdentifier{volumeID: volumeID, volumeAZ: volumeAZ}]
	if !ok {
		return "", nil, errors.New("volume not found")
	}

	return vi.volumeType, vi.iops, nil
}

// CreateVolumeFromSnapshot panics because it's not expected to be used for backups.
func (*fakeVolumeSnapshotter) CreateVolumeFromSnapshot(snapshotID, volumeType, volumeAZ string, iops *int64) (volumeID string, err error) {
	panic("CreateVolumeFromSnapshot should not be used for backups")
}

// SetVolumeID panics because it's not expected to be used for backups.
func (*fakeVolumeSnapshotter) SetVolumeID(pv runtime.Unstructured, volumeID string) (runtime.Unstructured, error) {
	panic("SetVolumeID should not be used for backups")
}

// DeleteSnapshot panics because it's not expected to be used for backups.
func (*fakeVolumeSnapshotter) DeleteSnapshot(snapshotID string) error {
	panic("DeleteSnapshot should not be used for backups")
}

// TestBackupWithSnapshots runs backups with volume snapshot locations and volume snapshotters
// configured and verifies that snapshots are created as appropriate. Verification is done by
// looking at the backup request's VolumeSnapshots field. This test uses the fakeVolumeSnapshotter
// struct in place of real volume snapshotters.
func TestBackupWithSnapshots(t *testing.T) {
	// TODO: add more verification for skippedPVTracker
	itemBlockPool := StartItemBlockWorkerPool(t.Context(), 1, logrus.StandardLogger())
	defer itemBlockPool.Stop()
	tests := []struct {
		name              string
		req               *Request
		vsls              []*velerov1.VolumeSnapshotLocation
		apiResources      []*test.APIResource
		snapshotterGetter volumeSnapshotterGetter
		want              []*volume.Snapshot
	}{
		{
			name: "persistent volume with no zone annotation creates a snapshot",
			req: &Request{
				Backup: defaultBackup().Result(),
				SnapshotLocations: []*velerov1.VolumeSnapshotLocation{
					newSnapshotLocation("velero", "default", "default"),
				},
				SkippedPVTracker: NewSkipPVTracker(),
				BackedUpItems:    NewBackedUpItemsMap(),
				WorkerPool:       itemBlockPool,
			},
			apiResources: []*test.APIResource{
				test.PVs(
					builder.ForPersistentVolume("pv-1").Result(),
				),
			},
			snapshotterGetter: map[string]vsv1.VolumeSnapshotter{
				"default": new(fakeVolumeSnapshotter).WithVolume("pv-1", "vol-1", "", "type-1", 100, false),
			},
			want: []*volume.Snapshot{
				{
					Spec: volume.SnapshotSpec{
						BackupName:           "backup-1",
						Location:             "default",
						PersistentVolumeName: "pv-1",
						ProviderVolumeID:     "vol-1",
						VolumeType:           "type-1",
						VolumeIOPS:           int64Ptr(100),
					},
					Status: volume.SnapshotStatus{
						Phase:              volume.SnapshotPhaseCompleted,
						ProviderSnapshotID: "vol-1-snapshot",
					},
				},
			},
		},
		{
			name: "persistent volume with deprecated zone annotation creates a snapshot",
			req: &Request{
				Backup: defaultBackup().Result(),
				SnapshotLocations: []*velerov1.VolumeSnapshotLocation{
					newSnapshotLocation("velero", "default", "default"),
				},
				SkippedPVTracker: NewSkipPVTracker(),
				BackedUpItems:    NewBackedUpItemsMap(),
				WorkerPool:       itemBlockPool,
			},
			apiResources: []*test.APIResource{
				test.PVs(
					builder.ForPersistentVolume("pv-1").ObjectMeta(builder.WithLabels("failure-domain.beta.kubernetes.io/zone", "zone-1")).Result(),
				),
			},
			snapshotterGetter: map[string]vsv1.VolumeSnapshotter{
				"default": new(fakeVolumeSnapshotter).WithVolume("pv-1", "vol-1", "zone-1", "type-1", 100, false),
			},
			want: []*volume.Snapshot{
				{
					Spec: volume.SnapshotSpec{
						BackupName:           "backup-1",
						Location:             "default",
						PersistentVolumeName: "pv-1",
						ProviderVolumeID:     "vol-1",
						VolumeAZ:             "zone-1",
						VolumeType:           "type-1",
						VolumeIOPS:           int64Ptr(100),
					},
					Status: volume.SnapshotStatus{
						Phase:              volume.SnapshotPhaseCompleted,
						ProviderSnapshotID: "vol-1-snapshot",
					},
				},
			},
		},
		{
			name: "persistent volume with GA zone annotation creates a snapshot",
			req: &Request{
				Backup: defaultBackup().Result(),
				SnapshotLocations: []*velerov1.VolumeSnapshotLocation{
					newSnapshotLocation("velero", "default", "default"),
				},
				SkippedPVTracker: NewSkipPVTracker(),
				BackedUpItems:    NewBackedUpItemsMap(),
				WorkerPool:       itemBlockPool,
			},
			apiResources: []*test.APIResource{
				test.PVs(
					builder.ForPersistentVolume("pv-1").ObjectMeta(builder.WithLabels("topology.kubernetes.io/zone", "zone-1")).Result(),
				),
			},
			snapshotterGetter: map[string]vsv1.VolumeSnapshotter{
				"default": new(fakeVolumeSnapshotter).WithVolume("pv-1", "vol-1", "zone-1", "type-1", 100, false),
			},
			want: []*volume.Snapshot{
				{
					Spec: volume.SnapshotSpec{
						BackupName:           "backup-1",
						Location:             "default",
						PersistentVolumeName: "pv-1",
						ProviderVolumeID:     "vol-1",
						VolumeAZ:             "zone-1",
						VolumeType:           "type-1",
						VolumeIOPS:           int64Ptr(100),
					},
					Status: volume.SnapshotStatus{
						Phase:              volume.SnapshotPhaseCompleted,
						ProviderSnapshotID: "vol-1-snapshot",
					},
				},
			},
		},
		{
			name: "persistent volume with both GA and deprecated zone annotation creates a snapshot and should use the GA",
			req: &Request{
				Backup: defaultBackup().Result(),
				SnapshotLocations: []*velerov1.VolumeSnapshotLocation{
					newSnapshotLocation("velero", "default", "default"),
				},
				SkippedPVTracker: NewSkipPVTracker(),
				BackedUpItems:    NewBackedUpItemsMap(),
				WorkerPool:       itemBlockPool,
			},
			apiResources: []*test.APIResource{
				test.PVs(
					builder.ForPersistentVolume("pv-1").ObjectMeta(builder.WithLabelsMap(map[string]string{"failure-domain.beta.kubernetes.io/zone": "zone-1-deprecated", "topology.kubernetes.io/zone": "zone-1-ga"})).Result(),
				),
			},
			snapshotterGetter: map[string]vsv1.VolumeSnapshotter{
				"default": new(fakeVolumeSnapshotter).WithVolume("pv-1", "vol-1", "zone-1-ga", "type-1", 100, false),
			},
			want: []*volume.Snapshot{
				{
					Spec: volume.SnapshotSpec{
						BackupName:           "backup-1",
						Location:             "default",
						PersistentVolumeName: "pv-1",
						ProviderVolumeID:     "vol-1",
						VolumeAZ:             "zone-1-ga",
						VolumeType:           "type-1",
						VolumeIOPS:           int64Ptr(100),
					},
					Status: volume.SnapshotStatus{
						Phase:              volume.SnapshotPhaseCompleted,
						ProviderSnapshotID: "vol-1-snapshot",
					},
				},
			},
		},
		{
			name: "error returned from CreateSnapshot results in a failed snapshot",
			req: &Request{
				Backup: defaultBackup().Result(),
				SnapshotLocations: []*velerov1.VolumeSnapshotLocation{
					newSnapshotLocation("velero", "default", "default"),
				},
				SkippedPVTracker: NewSkipPVTracker(),
				BackedUpItems:    NewBackedUpItemsMap(),
				WorkerPool:       itemBlockPool,
			},
			apiResources: []*test.APIResource{
				test.PVs(
					builder.ForPersistentVolume("pv-1").Result(),
				),
			},
			snapshotterGetter: map[string]vsv1.VolumeSnapshotter{
				"default": new(fakeVolumeSnapshotter).WithVolume("pv-1", "vol-1", "", "type-1", 100, true),
			},
			want: []*volume.Snapshot{
				{
					Spec: volume.SnapshotSpec{
						BackupName:           "backup-1",
						Location:             "default",
						PersistentVolumeName: "pv-1",
						ProviderVolumeID:     "vol-1",
						VolumeType:           "type-1",
						VolumeIOPS:           int64Ptr(100),
					},
					Status: volume.SnapshotStatus{
						Phase: volume.SnapshotPhaseFailed,
					},
				},
			},
		},
		{
			name: "backup with SnapshotVolumes=false does not create any snapshots",
			req: &Request{
				Backup: defaultBackup().SnapshotVolumes(false).Result(),
				SnapshotLocations: []*velerov1.VolumeSnapshotLocation{
					newSnapshotLocation("velero", "default", "default"),
				},
				SkippedPVTracker: NewSkipPVTracker(),
				BackedUpItems:    NewBackedUpItemsMap(),
				WorkerPool:       itemBlockPool,
			},
			apiResources: []*test.APIResource{
				test.PVs(
					builder.ForPersistentVolume("pv-1").Result(),
				),
			},
			snapshotterGetter: map[string]vsv1.VolumeSnapshotter{
				"default": new(fakeVolumeSnapshotter).WithVolume("pv-1", "vol-1", "", "type-1", 100, false),
			},
			want: nil,
		},
		{
			name: "backup with no volume snapshot locations does not create any snapshots",
			req: &Request{
				Backup:           defaultBackup().Result(),
				SkippedPVTracker: NewSkipPVTracker(),
				BackedUpItems:    NewBackedUpItemsMap(),
				WorkerPool:       itemBlockPool,
			},
			apiResources: []*test.APIResource{
				test.PVs(
					builder.ForPersistentVolume("pv-1").Result(),
				),
			},
			snapshotterGetter: map[string]vsv1.VolumeSnapshotter{
				"default": new(fakeVolumeSnapshotter).WithVolume("pv-1", "vol-1", "", "type-1", 100, false),
			},
			want: nil,
		},
		{
			name: "backup with no volume snapshotters does not create any snapshots",
			req: &Request{
				Backup: defaultBackup().Result(),
				SnapshotLocations: []*velerov1.VolumeSnapshotLocation{
					newSnapshotLocation("velero", "default", "default"),
				},
				SkippedPVTracker: NewSkipPVTracker(),
				BackedUpItems:    NewBackedUpItemsMap(),
				WorkerPool:       itemBlockPool,
			},
			apiResources: []*test.APIResource{
				test.PVs(
					builder.ForPersistentVolume("pv-1").Result(),
				),
			},
			snapshotterGetter: map[string]vsv1.VolumeSnapshotter{},
			want:              nil,
		},
		{
			name: "unsupported persistent volume type does not create any snapshots",
			req: &Request{
				Backup: defaultBackup().Result(),
				SnapshotLocations: []*velerov1.VolumeSnapshotLocation{
					newSnapshotLocation("velero", "default", "default"),
				},
				SkippedPVTracker: NewSkipPVTracker(),
				BackedUpItems:    NewBackedUpItemsMap(),
				WorkerPool:       itemBlockPool,
			},
			apiResources: []*test.APIResource{
				test.PVs(
					builder.ForPersistentVolume("pv-1").Result(),
				),
			},
			snapshotterGetter: map[string]vsv1.VolumeSnapshotter{
				"default": new(fakeVolumeSnapshotter),
			},
			want: nil,
		},
		{
			name: "when there are multiple volumes, snapshot locations, and snapshotters, volumes are matched to the right snapshotters",
			req: &Request{
				Backup: defaultBackup().Result(),
				SnapshotLocations: []*velerov1.VolumeSnapshotLocation{
					newSnapshotLocation("velero", "default", "default"),
					newSnapshotLocation("velero", "another", "another"),
				},
				SkippedPVTracker: NewSkipPVTracker(),
				BackedUpItems:    NewBackedUpItemsMap(),
				WorkerPool:       itemBlockPool,
			},
			apiResources: []*test.APIResource{
				test.PVs(
					builder.ForPersistentVolume("pv-1").Result(),
					builder.ForPersistentVolume("pv-2").Result(),
				),
			},
			snapshotterGetter: map[string]vsv1.VolumeSnapshotter{
				"default": new(fakeVolumeSnapshotter).WithVolume("pv-1", "vol-1", "", "type-1", 100, false),
				"another": new(fakeVolumeSnapshotter).WithVolume("pv-2", "vol-2", "", "type-2", 100, false),
			},
			want: []*volume.Snapshot{
				{
					Spec: volume.SnapshotSpec{
						BackupName:           "backup-1",
						Location:             "default",
						PersistentVolumeName: "pv-1",
						ProviderVolumeID:     "vol-1",
						VolumeType:           "type-1",
						VolumeIOPS:           int64Ptr(100),
					},
					Status: volume.SnapshotStatus{
						Phase:              volume.SnapshotPhaseCompleted,
						ProviderSnapshotID: "vol-1-snapshot",
					},
				},
				{
					Spec: volume.SnapshotSpec{
						BackupName:           "backup-1",
						Location:             "another",
						PersistentVolumeName: "pv-2",
						ProviderVolumeID:     "vol-2",
						VolumeType:           "type-2",
						VolumeIOPS:           int64Ptr(100),
					},
					Status: volume.SnapshotStatus{
						Phase:              volume.SnapshotPhaseCompleted,
						ProviderSnapshotID: "vol-2-snapshot",
					},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var (
				h          = newHarness(t, itemBlockPool)
				backupFile = bytes.NewBuffer([]byte{})
			)

			for _, resource := range tc.apiResources {
				h.addItems(t, resource)
			}

			err := h.backupper.Backup(h.log, tc.req, backupFile, nil, nil, tc.snapshotterGetter)
			require.NoError(t, err)

			assert.Equal(t, tc.want, tc.req.VolumeSnapshots.Get())
		})
	}
}

// TestBackupWithAsyncOperations runs backups which return operationIDs and
// verifies that the itemoperations are tracked as appropriate. Verification is done by
// looking at the backup request's itemOperationsList field.
func TestBackupWithAsyncOperations(t *testing.T) {
	// completedOperationAction is a *pluggableAction, whose Execute(...)
	// method returns an operationID which will always be done when calling Progress.
	completedOperationAction := &pluggableAction{
		executeFunc: func(item runtime.Unstructured, backup *velerov1.Backup) (runtime.Unstructured, []velero.ResourceIdentifier, string, []velero.ResourceIdentifier, error) {
			obj, ok := item.(*unstructured.Unstructured)
			if !ok {
				return nil, nil, "", nil, errors.Errorf("unexpected type %T", item)
			}

			return obj, nil, obj.GetName() + "-1", nil, nil
		},
		progressFunc: func(operationID string, backup *velerov1.Backup) (velero.OperationProgress, error) {
			return velero.OperationProgress{
				Completed:   true,
				Description: "Done!",
			}, nil
		},
	}

	// incompleteOperationAction is a *pluggableAction, whose Execute(...)
	// method returns an operationID which will never be done when calling Progress.
	incompleteOperationAction := &pluggableAction{
		executeFunc: func(item runtime.Unstructured, backup *velerov1.Backup) (runtime.Unstructured, []velero.ResourceIdentifier, string, []velero.ResourceIdentifier, error) {
			obj, ok := item.(*unstructured.Unstructured)
			if !ok {
				return nil, nil, "", nil, errors.Errorf("unexpected type %T", item)
			}

			return obj, nil, obj.GetName() + "-1", nil, nil
		},
		progressFunc: func(operationID string, backup *velerov1.Backup) (velero.OperationProgress, error) {
			return velero.OperationProgress{
				Completed:   false,
				Description: "Working...",
			}, nil
		},
	}

	// noOperationAction is a *pluggableAction, whose Execute(...)
	// method does not return an operationID.
	noOperationAction := &pluggableAction{
		executeFunc: func(item runtime.Unstructured, backup *velerov1.Backup) (runtime.Unstructured, []velero.ResourceIdentifier, string, []velero.ResourceIdentifier, error) {
			obj, ok := item.(*unstructured.Unstructured)
			if !ok {
				return nil, nil, "", nil, errors.Errorf("unexpected type %T", item)
			}

			return obj, nil, "", nil, nil
		},
	}

	itemBlockPool := StartItemBlockWorkerPool(t.Context(), 1, logrus.StandardLogger())
	defer itemBlockPool.Stop()
	tests := []struct {
		name         string
		req          *Request
		apiResources []*test.APIResource
		actions      []biav2.BackupItemAction
		want         []*itemoperation.BackupOperation
	}{
		{
			name: "action that starts a short-running process records operation",
			req: &Request{
				Backup:           defaultBackup().Result(),
				SkippedPVTracker: NewSkipPVTracker(),
				BackedUpItems:    NewBackedUpItemsMap(),
				WorkerPool:       itemBlockPool,
			},
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").Result(),
				),
			},
			actions: []biav2.BackupItemAction{
				completedOperationAction,
			},
			want: []*itemoperation.BackupOperation{
				{
					Spec: itemoperation.BackupOperationSpec{
						BackupName: "backup-1",
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
			name: "action that starts a long-running process records operation",
			req: &Request{
				Backup:           defaultBackup().Result(),
				SkippedPVTracker: NewSkipPVTracker(),
				BackedUpItems:    NewBackedUpItemsMap(),
				WorkerPool:       itemBlockPool,
			},
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-2").Result(),
				),
			},
			actions: []biav2.BackupItemAction{
				incompleteOperationAction,
			},
			want: []*itemoperation.BackupOperation{
				{
					Spec: itemoperation.BackupOperationSpec{
						BackupName: "backup-1",
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
			name: "action that has no operation doesn't record one",
			req: &Request{
				Backup:           defaultBackup().Result(),
				SkippedPVTracker: NewSkipPVTracker(),
				BackedUpItems:    NewBackedUpItemsMap(),
				WorkerPool:       itemBlockPool,
			},
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-3").Result(),
				),
			},
			actions: []biav2.BackupItemAction{
				noOperationAction,
			},
			want: []*itemoperation.BackupOperation{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var (
				h          = newHarness(t, itemBlockPool)
				backupFile = bytes.NewBuffer([]byte{})
			)

			for _, resource := range tc.apiResources {
				h.addItems(t, resource)
			}

			err := h.backupper.Backup(h.log, tc.req, backupFile, tc.actions, nil, nil)
			require.NoError(t, err)

			resultOper := *tc.req.GetItemOperationsList()
			// set want Created times so it won't fail the assert.Equal test
			for i, wantOper := range tc.want {
				wantOper.Status.Created = resultOper[i].Status.Created
			}
			assert.Equal(t, tc.want, *tc.req.GetItemOperationsList())
		})
	}
}

// TestBackupWithInvalidHooks runs backups with invalid hook specifications and verifies
// that an error is returned.
func TestBackupWithInvalidHooks(t *testing.T) {
	tests := []struct {
		name         string
		backup       *velerov1.Backup
		apiResources []*test.APIResource
		want         error
	}{
		{
			name: "hook with invalid label selector causes backup to fail",
			backup: defaultBackup().
				Hooks(velerov1.BackupHooks{
					Resources: []velerov1.BackupResourceHookSpec{
						{
							Name: "hook-with-invalid-label-selector",
							LabelSelector: &metav1.LabelSelector{
								MatchExpressions: []metav1.LabelSelectorRequirement{
									{
										Key:      "foo",
										Operator: metav1.LabelSelectorOperator("nonexistent-operator"),
										Values:   []string{"bar"},
									},
								},
							},
						},
					},
				}).
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("foo", "bar").Result(),
				),
			},
			want: errors.New("\"nonexistent-operator\" is not a valid label selector operator"),
		},
	}

	itemBlockPool := StartItemBlockWorkerPool(t.Context(), 1, logrus.StandardLogger())
	defer itemBlockPool.Stop()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var (
				h   = newHarness(t, itemBlockPool)
				req = &Request{
					Backup:           tc.backup,
					SkippedPVTracker: NewSkipPVTracker(),
					BackedUpItems:    NewBackedUpItemsMap(),
					WorkerPool:       itemBlockPool,
				}
				backupFile = bytes.NewBuffer([]byte{})
			)

			for _, resource := range tc.apiResources {
				h.addItems(t, resource)
			}

			assert.EqualError(t, h.backupper.Backup(h.log, req, backupFile, nil, nil, nil), tc.want.Error())
		})
	}
}

// TestBackupWithHooks runs backups with valid hook specifications and verifies that the
// hooks are run. It uses a MockPodCommandExecutor since hooks can't actually be executed
// in running pods during the unit test. Verification is done by asserting expected method
// calls on the mock object.
func TestBackupWithHooks(t *testing.T) {
	type expectedCall struct {
		podNamespace string
		podName      string
		hookName     string
		hook         *velerov1.ExecHook
		err          error
	}

	tests := []struct {
		name                       string
		backup                     *velerov1.Backup
		apiResources               []*test.APIResource
		actions                    []ibav1.ItemBlockAction
		wantExecutePodCommandCalls []*expectedCall
		wantBackedUp               []string
		wantHookExecutionLog       []test.HookExecutionEntry
	}{
		{
			name: "pre hook with no resource filters runs for all pods",
			backup: defaultBackup().
				Hooks(velerov1.BackupHooks{
					Resources: []velerov1.BackupResourceHookSpec{
						{
							Name: "hook-1",
							PreHooks: []velerov1.BackupResourceHook{
								{
									Exec: &velerov1.ExecHook{
										Command: []string{"ls", "/tmp"},
									},
								},
							},
						},
					},
				}).
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-2").Result(),
				),
			},
			wantExecutePodCommandCalls: []*expectedCall{
				{
					podNamespace: "ns-1",
					podName:      "pod-1",
					hookName:     "hook-1",
					hook: &velerov1.ExecHook{
						Command: []string{"ls", "/tmp"},
					},
					err: nil,
				},
				{
					podNamespace: "ns-2",
					podName:      "pod-2",
					hookName:     "hook-1",
					hook: &velerov1.ExecHook{
						Command: []string{"ls", "/tmp"},
					},
					err: nil,
				},
			},
			wantBackedUp: []string{
				"resources/pods/namespaces/ns-1/pod-1.json",
				"resources/pods/namespaces/ns-2/pod-2.json",
				"resources/pods/v1-preferredversion/namespaces/ns-1/pod-1.json",
				"resources/pods/v1-preferredversion/namespaces/ns-2/pod-2.json",
			},
		},
		{
			name: "post hook with no resource filters runs for all pods",
			backup: defaultBackup().
				Hooks(velerov1.BackupHooks{
					Resources: []velerov1.BackupResourceHookSpec{
						{
							Name: "hook-1",
							PostHooks: []velerov1.BackupResourceHook{
								{
									Exec: &velerov1.ExecHook{
										Command: []string{"ls", "/tmp"},
									},
								},
							},
						},
					},
				}).
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-2").Result(),
				),
			},
			wantExecutePodCommandCalls: []*expectedCall{
				{
					podNamespace: "ns-1",
					podName:      "pod-1",
					hookName:     "hook-1",
					hook: &velerov1.ExecHook{
						Command: []string{"ls", "/tmp"},
					},
					err: nil,
				},
				{
					podNamespace: "ns-2",
					podName:      "pod-2",
					hookName:     "hook-1",
					hook: &velerov1.ExecHook{
						Command: []string{"ls", "/tmp"},
					},
					err: nil,
				},
			},
			wantBackedUp: []string{
				"resources/pods/namespaces/ns-1/pod-1.json",
				"resources/pods/namespaces/ns-2/pod-2.json",
				"resources/pods/v1-preferredversion/namespaces/ns-1/pod-1.json",
				"resources/pods/v1-preferredversion/namespaces/ns-2/pod-2.json",
			},
		},
		{
			name: "pre and post hooks run for a pod",
			backup: defaultBackup().
				Hooks(velerov1.BackupHooks{
					Resources: []velerov1.BackupResourceHookSpec{
						{
							Name: "hook-1",
							PreHooks: []velerov1.BackupResourceHook{
								{
									Exec: &velerov1.ExecHook{
										Command: []string{"pre"},
									},
								},
							},
							PostHooks: []velerov1.BackupResourceHook{
								{
									Exec: &velerov1.ExecHook{
										Command: []string{"post"},
									},
								},
							},
						},
					},
				}).
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").Result(),
				),
			},
			wantExecutePodCommandCalls: []*expectedCall{
				{
					podNamespace: "ns-1",
					podName:      "pod-1",
					hookName:     "hook-1",
					hook: &velerov1.ExecHook{
						Command: []string{"pre"},
					},
					err: nil,
				},
				{
					podNamespace: "ns-1",
					podName:      "pod-1",
					hookName:     "hook-1",
					hook: &velerov1.ExecHook{
						Command: []string{"post"},
					},
					err: nil,
				},
			},
			wantBackedUp: []string{
				"resources/pods/namespaces/ns-1/pod-1.json",
				"resources/pods/v1-preferredversion/namespaces/ns-1/pod-1.json",
			},
		},
		{
			name: "pre and post hooks run for two pods sequentially by pods in different ItemBlocks",
			backup: defaultBackup().
				Hooks(velerov1.BackupHooks{
					Resources: []velerov1.BackupResourceHookSpec{
						{
							Name: "hook-1",
							PreHooks: []velerov1.BackupResourceHook{
								{
									Exec: &velerov1.ExecHook{
										Command: []string{"pre"},
									},
								},
							},
							PostHooks: []velerov1.BackupResourceHook{
								{
									Exec: &velerov1.ExecHook{
										Command: []string{"post"},
									},
								},
							},
						},
					},
				}).
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-1", "pod-2").Result(),
				),
			},
			wantExecutePodCommandCalls: []*expectedCall{
				{
					podNamespace: "ns-1",
					podName:      "pod-1",
					hookName:     "hook-1",
					hook: &velerov1.ExecHook{
						Command: []string{"pre"},
					},
					err: nil,
				},
				{
					podNamespace: "ns-1",
					podName:      "pod-1",
					hookName:     "hook-1",
					hook: &velerov1.ExecHook{
						Command: []string{"post"},
					},
					err: nil,
				},
				{
					podNamespace: "ns-1",
					podName:      "pod-2",
					hookName:     "hook-1",
					hook: &velerov1.ExecHook{
						Command: []string{"pre"},
					},
					err: nil,
				},
				{
					podNamespace: "ns-1",
					podName:      "pod-2",
					hookName:     "hook-1",
					hook: &velerov1.ExecHook{
						Command: []string{"post"},
					},
					err: nil,
				},
			},
			wantHookExecutionLog: []test.HookExecutionEntry{
				{
					Namespace:   "ns-1",
					Name:        "pod-1",
					HookName:    "hook-1",
					HookCommand: []string{"pre"},
				},
				{
					Namespace:   "ns-1",
					Name:        "pod-1",
					HookName:    "hook-1",
					HookCommand: []string{"post"},
				},
				{
					Namespace:   "ns-1",
					Name:        "pod-2",
					HookName:    "hook-1",
					HookCommand: []string{"pre"},
				},
				{
					Namespace:   "ns-1",
					Name:        "pod-2",
					HookName:    "hook-1",
					HookCommand: []string{"post"},
				},
			},
			wantBackedUp: []string{
				"resources/pods/namespaces/ns-1/pod-1.json",
				"resources/pods/namespaces/ns-1/pod-2.json",
				"resources/pods/v1-preferredversion/namespaces/ns-1/pod-1.json",
				"resources/pods/v1-preferredversion/namespaces/ns-1/pod-2.json",
			},
		},
		{
			name: "both pre hooks run before both post hooks for pods in the same ItemBlock",
			backup: defaultBackup().
				Hooks(velerov1.BackupHooks{
					Resources: []velerov1.BackupResourceHookSpec{
						{
							Name: "hook-1",
							PreHooks: []velerov1.BackupResourceHook{
								{
									Exec: &velerov1.ExecHook{
										Command: []string{"pre"},
									},
								},
							},
							PostHooks: []velerov1.BackupResourceHook{
								{
									Exec: &velerov1.ExecHook{
										Command: []string{"post"},
									},
								},
							},
						},
					},
				}).
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-1", "pod-2").Result(),
				),
			},
			actions: []ibav1.ItemBlockAction{
				&pluggableIBA{
					selector: velero.ResourceSelector{IncludedNamespaces: []string{"ns-1"}},
					getRelatedItemsFunc: func(item runtime.Unstructured, backup *velerov1.Backup) ([]velero.ResourceIdentifier, error) {
						relatedItems := []velero.ResourceIdentifier{
							{GroupResource: kuberesource.Pods, Namespace: "ns-1", Name: "pod-1"},
							{GroupResource: kuberesource.Pods, Namespace: "ns-1", Name: "pod-2"},
						}

						return relatedItems, nil
					},
				},
			},
			wantExecutePodCommandCalls: []*expectedCall{
				{
					podNamespace: "ns-1",
					podName:      "pod-1",
					hookName:     "hook-1",
					hook: &velerov1.ExecHook{
						Command: []string{"pre"},
					},
					err: nil,
				},
				{
					podNamespace: "ns-1",
					podName:      "pod-1",
					hookName:     "hook-1",
					hook: &velerov1.ExecHook{
						Command: []string{"post"},
					},
					err: nil,
				},
				{
					podNamespace: "ns-1",
					podName:      "pod-2",
					hookName:     "hook-1",
					hook: &velerov1.ExecHook{
						Command: []string{"pre"},
					},
					err: nil,
				},
				{
					podNamespace: "ns-1",
					podName:      "pod-2",
					hookName:     "hook-1",
					hook: &velerov1.ExecHook{
						Command: []string{"post"},
					},
					err: nil,
				},
			},
			wantHookExecutionLog: []test.HookExecutionEntry{
				{
					Namespace:   "ns-1",
					Name:        "pod-1",
					HookName:    "hook-1",
					HookCommand: []string{"pre"},
				},
				{
					Namespace:   "ns-1",
					Name:        "pod-2",
					HookName:    "hook-1",
					HookCommand: []string{"pre"},
				},
				{
					Namespace:   "ns-1",
					Name:        "pod-1",
					HookName:    "hook-1",
					HookCommand: []string{"post"},
				},
				{
					Namespace:   "ns-1",
					Name:        "pod-2",
					HookName:    "hook-1",
					HookCommand: []string{"post"},
				},
			},
			wantBackedUp: []string{
				"resources/pods/namespaces/ns-1/pod-1.json",
				"resources/pods/namespaces/ns-1/pod-2.json",
				"resources/pods/v1-preferredversion/namespaces/ns-1/pod-1.json",
				"resources/pods/v1-preferredversion/namespaces/ns-1/pod-2.json",
			},
		},
		{
			name: "item is not backed up if hook returns an error when OnError=Fail",
			backup: defaultBackup().
				Hooks(velerov1.BackupHooks{
					Resources: []velerov1.BackupResourceHookSpec{
						{
							Name: "hook-1",
							PreHooks: []velerov1.BackupResourceHook{
								{
									Exec: &velerov1.ExecHook{
										Command: []string{"ls", "/tmp"},
										OnError: velerov1.HookErrorModeFail,
									},
								},
							},
						},
					},
				}).
				Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-2").Result(),
				),
			},
			wantExecutePodCommandCalls: []*expectedCall{
				{
					podNamespace: "ns-1",
					podName:      "pod-1",
					hookName:     "hook-1",
					hook: &velerov1.ExecHook{
						Command: []string{"ls", "/tmp"},
						OnError: velerov1.HookErrorModeFail,
					},
					err: errors.New("exec hook error"),
				},
				{
					podNamespace: "ns-2",
					podName:      "pod-2",
					hookName:     "hook-1",
					hook: &velerov1.ExecHook{
						Command: []string{"ls", "/tmp"},
						OnError: velerov1.HookErrorModeFail,
					},
					err: nil,
				},
			},
			wantBackedUp: []string{
				"resources/pods/namespaces/ns-2/pod-2.json",
				"resources/pods/v1-preferredversion/namespaces/ns-2/pod-2.json",
			},
		},
	}

	itemBlockPool := StartItemBlockWorkerPool(t.Context(), 1, logrus.StandardLogger())
	defer itemBlockPool.Stop()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var (
				h   = newHarness(t, itemBlockPool)
				req = &Request{
					Backup:           tc.backup,
					SkippedPVTracker: NewSkipPVTracker(),
					BackedUpItems:    NewBackedUpItemsMap(),
					WorkerPool:       itemBlockPool,
				}
				backupFile         = bytes.NewBuffer([]byte{})
				podCommandExecutor = new(test.MockPodCommandExecutor)
			)

			h.backupper.podCommandExecutor = podCommandExecutor
			defer podCommandExecutor.AssertExpectations(t)

			for _, expect := range tc.wantExecutePodCommandCalls {
				podCommandExecutor.On("ExecutePodCommand",
					mock.Anything,
					mock.Anything,
					expect.podNamespace,
					expect.podName,
					expect.hookName,
					expect.hook,
				).Return(expect.err)
			}

			for _, resource := range tc.apiResources {
				h.addItems(t, resource)
			}

			require.NoError(t, h.backupper.Backup(h.log, req, backupFile, nil, tc.actions, nil))

			if tc.wantHookExecutionLog != nil {
				assert.Equal(t, tc.wantHookExecutionLog, podCommandExecutor.HookExecutionLog)
			}
			assertTarballContents(t, backupFile, append(tc.wantBackedUp, "metadata/version")...)
		})
	}
}

type fakePodVolumeBackupperFactory struct{}

func (f *fakePodVolumeBackupperFactory) NewBackupper(context.Context, logrus.FieldLogger, *velerov1.Backup, string) (podvolume.Backupper, error) {
	return &fakePodVolumeBackupper{}, nil
}

type fakePodVolumeBackupper struct {
	pvbs []*velerov1.PodVolumeBackup
}

// BackupPodVolumes returns one pod volume backup per entry in volumes, with namespace "velero"
// and name "pvb-<pod-namespace>-<pod-name>-<volume-name>".
func (b *fakePodVolumeBackupper) BackupPodVolumes(backup *velerov1.Backup, pod *corev1api.Pod, volumes []string, _ *resourcepolicies.Policies, _ logrus.FieldLogger) ([]*velerov1.PodVolumeBackup, *podvolume.PVCBackupSummary, []error) {
	var res []*velerov1.PodVolumeBackup
	pvcSummary := podvolume.NewPVCBackupSummary()

	anno := pod.GetAnnotations()
	if anno != nil && anno["backup.velero.io/bakupper-skip"] != "" {
		return res, pvcSummary, nil
	}

	for _, vol := range volumes {
		pvb := builder.ForPodVolumeBackup("velero", fmt.Sprintf("pvb-%s-%s-%s", pod.Namespace, pod.Name, vol)).Volume(vol).Result()
		res = append(res, pvb)
	}

	b.pvbs = res

	return res, pvcSummary, nil
}

func (b *fakePodVolumeBackupper) WaitAllPodVolumesProcessed(log logrus.FieldLogger) []*velerov1.PodVolumeBackup {
	return b.pvbs
}

func (b *fakePodVolumeBackupper) GetPodVolumeBackupByPodAndVolume(podNamespace, podName, volume string) (*velerov1.PodVolumeBackup, error) {
	for _, pvb := range b.pvbs {
		if pvb.Spec.Pod.Namespace == podNamespace && pvb.Spec.Pod.Name == podName && pvb.Spec.Volume == volume {
			return pvb, nil
		}
	}
	return nil, nil
}
func (b *fakePodVolumeBackupper) ListPodVolumeBackupsByPod(podNamespace, podName string) ([]*velerov1.PodVolumeBackup, error) {
	var pvbs []*velerov1.PodVolumeBackup
	for _, pvb := range b.pvbs {
		if pvb.Spec.Pod.Namespace == podNamespace && pvb.Spec.Pod.Name == podName {
			pvbs = append(pvbs, pvb)
		}
	}
	return pvbs, nil
}

// TestBackupWithPodVolume runs backups of pods that are annotated for PodVolume backup,
// and ensures that the pod volume backupper is called, that the returned PodVolumeBackups
// are added to the Request object, and that when PVCs are backed up with PodVolume, the
// claimed PVs are not also snapshotted using a VolumeSnapshotter.
func TestBackupWithPodVolume(t *testing.T) {
	tests := []struct {
		name              string
		backup            *velerov1.Backup
		apiResources      []*test.APIResource
		pod               *corev1api.Pod
		vsl               *velerov1.VolumeSnapshotLocation
		snapshotterGetter volumeSnapshotterGetter
		want              []*velerov1.PodVolumeBackup
	}{
		{
			name:   "a pod annotated for pod volume backup should result in pod volume backups being returned",
			backup: defaultBackup().Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").
						ObjectMeta(builder.WithAnnotations("backup.velero.io/backup-volumes", "foo")).
						Volumes(&corev1api.Volume{
							Name: "foo",
							VolumeSource: corev1api.VolumeSource{
								PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
									ClaimName: "foo",
								},
							},
						}).
						Result(),
				),
				test.PVCs(),
			},
			want: []*velerov1.PodVolumeBackup{
				builder.ForPodVolumeBackup("velero", "pvb-ns-1-pod-1-foo").Volume("foo").Result(),
			},
		},
		{
			name:   "when a PVC is used by two pods and annotated for pod volume backup on both, only one should be backed up",
			backup: defaultBackup().Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").
						ObjectMeta(builder.WithAnnotations("backup.velero.io/backup-volumes", "foo")).
						Volumes(builder.ForVolume("foo").PersistentVolumeClaimSource("pvc-1").Result()).
						Result(),
				),
				test.Pods(
					builder.ForPod("ns-1", "pod-2").
						ObjectMeta(builder.WithAnnotations("backup.velero.io/backup-volumes", "bar")).
						Volumes(builder.ForVolume("bar").PersistentVolumeClaimSource("pvc-1").Result()).
						Result(),
				),
				test.PVCs(),
			},
			want: []*velerov1.PodVolumeBackup{
				builder.ForPodVolumeBackup("velero", "pvb-ns-1-pod-1-foo").Volume("foo").Result(),
			},
		},
		{
			name:   "when a PVC is used by two pods and annotated for pod volume backup on both, the backup for pod1 gives up the PVC, the backup for pod2 should include it",
			backup: defaultBackup().Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").
						ObjectMeta(builder.WithAnnotations("backup.velero.io/backup-volumes", "foo", "backup.velero.io/bakupper-skip", "foo")).
						Volumes(builder.ForVolume("foo").PersistentVolumeClaimSource("pvc-1").Result()).
						Result(),
				),
				test.Pods(
					builder.ForPod("ns-1", "pod-2").
						ObjectMeta(builder.WithAnnotations("backup.velero.io/backup-volumes", "bar")).
						Volumes(builder.ForVolume("bar").PersistentVolumeClaimSource("pvc-1").Result()).
						Result(),
				),
				test.PVCs(),
			},
			want: []*velerov1.PodVolumeBackup{
				builder.ForPodVolumeBackup("velero", "pvb-ns-1-pod-2-bar").Volume("bar").Result(),
			},
		},
		{
			name:   "when PVC pod volumes are backed up using pod volume backup, their claimed PVs are not also snapshotted",
			backup: defaultBackup().Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("ns-1", "pod-1").
						Volumes(
							builder.ForVolume("vol-1").PersistentVolumeClaimSource("pvc-1").Result(),
							builder.ForVolume("vol-2").PersistentVolumeClaimSource("pvc-2").Result(),
						).
						ObjectMeta(
							builder.WithAnnotations("backup.velero.io/backup-volumes", "vol-1,vol-2"),
						).
						Result(),
				),
				test.PVCs(
					builder.ForPersistentVolumeClaim("ns-1", "pvc-1").VolumeName("pv-1").Result(),
					builder.ForPersistentVolumeClaim("ns-1", "pvc-2").VolumeName("pv-2").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("pv-1").ClaimRef("ns-1", "pvc-1").Result(),
					builder.ForPersistentVolume("pv-2").ClaimRef("ns-1", "pvc-2").Result(),
				),
			},
			pod: builder.ForPod("ns-1", "pod-1").
				Volumes(
					builder.ForVolume("vol-1").PersistentVolumeClaimSource("pvc-1").Result(),
					builder.ForVolume("vol-2").PersistentVolumeClaimSource("pvc-2").Result(),
				).
				ObjectMeta(
					builder.WithAnnotations("backup.velero.io/backup-volumes", "vol-1,vol-2"),
				).
				Result(),
			vsl: newSnapshotLocation("velero", "default", "default"),
			snapshotterGetter: map[string]vsv1.VolumeSnapshotter{
				"default": new(fakeVolumeSnapshotter).
					WithVolume("pv-1", "vol-1", "", "type-1", 100, false).
					WithVolume("pv-2", "vol-2", "", "type-1", 100, false),
			},
			want: []*velerov1.PodVolumeBackup{
				builder.ForPodVolumeBackup("velero", "pvb-ns-1-pod-1-vol-1").Volume("vol-1").Result(),
				builder.ForPodVolumeBackup("velero", "pvb-ns-1-pod-1-vol-2").Volume("vol-2").Result(),
			},
		},
	}

	itemBlockPool := StartItemBlockWorkerPool(t.Context(), 1, logrus.StandardLogger())
	defer itemBlockPool.Stop()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var (
				h   = newHarness(t, itemBlockPool)
				req = &Request{
					Backup:            tc.backup,
					SnapshotLocations: []*velerov1.VolumeSnapshotLocation{tc.vsl},
					SkippedPVTracker:  NewSkipPVTracker(),
					BackedUpItems:     NewBackedUpItemsMap(),
					WorkerPool:        itemBlockPool,
				}
				backupFile = bytes.NewBuffer([]byte{})
			)

			if tc.pod != nil {
				require.NoError(t, h.backupper.kbClient.Create(t.Context(), tc.pod))
			}

			h.backupper.podVolumeBackupperFactory = new(fakePodVolumeBackupperFactory)

			for _, resource := range tc.apiResources {
				h.addItems(t, resource)
			}

			require.NoError(t, h.backupper.Backup(h.log, req, backupFile, nil, nil, tc.snapshotterGetter))

			assert.Equal(t, tc.want, req.PodVolumeBackups)

			// this assumes that we don't have any test cases where some PVs should be snapshotted using a VolumeSnapshotter
			assert.Nil(t, req.VolumeSnapshots.Get())
		})
	}
}

// pluggableAction is a backup item action that can be plugged with Execute
// and Progress function bodies at runtime.
type pluggableAction struct {
	selector     velero.ResourceSelector
	executeFunc  func(runtime.Unstructured, *velerov1.Backup) (runtime.Unstructured, []velero.ResourceIdentifier, string, []velero.ResourceIdentifier, error)
	progressFunc func(string, *velerov1.Backup) (velero.OperationProgress, error)
}

func (a *pluggableAction) Execute(item runtime.Unstructured, backup *velerov1.Backup) (runtime.Unstructured, []velero.ResourceIdentifier, string, []velero.ResourceIdentifier, error) {
	if a.executeFunc == nil {
		return item, nil, "", nil, nil
	}

	return a.executeFunc(item, backup)
}

func (a *pluggableAction) AppliesTo() (velero.ResourceSelector, error) {
	return a.selector, nil
}

func (a *pluggableAction) Progress(operationID string, backup *velerov1.Backup) (velero.OperationProgress, error) {
	if a.progressFunc == nil {
		return velero.OperationProgress{}, nil
	}

	return a.progressFunc(operationID, backup)
}

func (a *pluggableAction) Cancel(operationID string, backup *velerov1.Backup) error {
	return nil
}

func (a *pluggableAction) Name() string {
	return ""
}

// pluggableIBA is an ItemBlock action that can be plugged with GetRelatedItems function bodies at runtime.
type pluggableIBA struct {
	selector            velero.ResourceSelector
	getRelatedItemsFunc func(runtime.Unstructured, *velerov1.Backup) ([]velero.ResourceIdentifier, error)
}

func (a *pluggableIBA) GetRelatedItems(item runtime.Unstructured, backup *velerov1.Backup) ([]velero.ResourceIdentifier, error) {
	if a.getRelatedItemsFunc == nil {
		return nil, nil
	}

	return a.getRelatedItemsFunc(item, backup)
}

func (a *pluggableIBA) AppliesTo() (velero.ResourceSelector, error) {
	return a.selector, nil
}

func (a *pluggableIBA) Name() string {
	return ""
}

type harness struct {
	*test.APIServer
	backupper     *kubernetesBackupper
	log           logrus.FieldLogger
	itemBlockPool ItemBlockWorkerPool
}

func (h *harness) addItems(t *testing.T, resource *test.APIResource) {
	t.Helper()

	h.DiscoveryClient.WithAPIResource(resource)
	require.NoError(t, h.backupper.discoveryHelper.Refresh())

	for _, item := range resource.Items {
		obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(item)
		require.NoError(t, err)

		unstructuredObj := &unstructured.Unstructured{Object: obj}

		if resource.Namespaced {
			namespace := &corev1api.Namespace{ObjectMeta: metav1.ObjectMeta{Name: item.GetNamespace()}}
			err = h.backupper.kbClient.Create(t.Context(), namespace)
			if err != nil && !apierrors.IsAlreadyExists(err) {
				require.NoError(t, err)
			}

			_, err = h.DynamicClient.Resource(resource.GVR()).Namespace(item.GetNamespace()).Create(t.Context(), unstructuredObj, metav1.CreateOptions{})
		} else {
			_, err = h.DynamicClient.Resource(resource.GVR()).Create(t.Context(), unstructuredObj, metav1.CreateOptions{})
		}
		require.NoError(t, err)
	}
}

func newHarness(t *testing.T, itemBlockPool *ItemBlockWorkerPool) *harness {
	t.Helper()

	apiServer := test.NewAPIServer(t)
	log := logrus.StandardLogger()

	discoveryHelper, err := discovery.NewHelper(apiServer.DiscoveryClient, log)
	require.NoError(t, err)

	if itemBlockPool == nil {
		itemBlockPool = StartItemBlockWorkerPool(t.Context(), 1, log)
	}
	return &harness{
		APIServer: apiServer,
		backupper: &kubernetesBackupper{
			kbClient:        test.NewFakeControllerRuntimeClient(t),
			dynamicFactory:  client.NewDynamicFactory(apiServer.DynamicClient),
			discoveryHelper: discoveryHelper,

			// unsupported
			podCommandExecutor:        nil,
			podVolumeBackupperFactory: new(fakePodVolumeBackupperFactory),
			podVolumeTimeout:          60 * time.Second,
		},
		log:           log,
		itemBlockPool: *itemBlockPool,
	}
}

func newSnapshotLocation(ns, name, provider string) *velerov1.VolumeSnapshotLocation {
	return &velerov1.VolumeSnapshotLocation{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      name,
		},
		Spec: velerov1.VolumeSnapshotLocationSpec{
			Provider: provider,
		},
	}
}

func defaultBackup() *builder.BackupBuilder {
	return builder.ForBackup(velerov1.DefaultNamespace, "backup-1").DefaultVolumesToFsBackup(false).IncludedNamespaces("*")
}

func toUnstructuredOrFail(t *testing.T, obj any) map[string]any {
	t.Helper()

	res, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	require.NoError(t, err)

	return res
}

// assertTarballContents verifies that the gzipped tarball stored in the provided
// backupFile contains exactly the file names specified.
func assertTarballContents(t *testing.T, backupFile io.Reader, items ...string) {
	t.Helper()

	gzr, err := gzip.NewReader(backupFile)
	require.NoError(t, err)

	r := tar.NewReader(gzr)

	var files []string
	for {
		hdr, err := r.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)

		files = append(files, hdr.Name)
	}

	sort.Strings(files)
	sort.Strings(items)
	assert.Equal(t, items, files)
}

// unstructuredObject is a type alias to improve readability.
type unstructuredObject map[string]any

// assertTarballFileContents verifies that the gzipped tarball stored in the provided
// backupFile contains the files specified as keys in 'want', and for each of those
// files verifies that the content of the file is JSON and is equivalent to the JSON
// content stored as values in 'want'.
func assertTarballFileContents(t *testing.T, backupFile io.Reader, want map[string]unstructuredObject) {
	t.Helper()

	gzr, err := gzip.NewReader(backupFile)
	require.NoError(t, err)

	r := tar.NewReader(gzr)
	items := make(map[string][]byte)

	for {
		hdr, err := r.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)

		bytes, err := io.ReadAll(r)
		require.NoError(t, err)

		items[hdr.Name] = bytes
	}

	for name, wantItem := range want {
		gotData, ok := items[name]
		assert.True(t, ok, "did not find item %s in tarball", name)
		if !ok {
			continue
		}

		// json-unmarshal the data from the tarball
		var got unstructuredObject
		err := json.Unmarshal(gotData, &got)
		require.NoError(t, err)
		if err != nil {
			continue
		}

		assert.Equal(t, wantItem, got)
	}
}

// assertTarballOrdering ensures that resources were written to the tarball in the expected
// order. Any resources *not* in orderedResources are required to come *after* all resources
// in orderedResources, in any order.
func assertTarballOrdering(t *testing.T, backupFile io.Reader, orderedResources ...string) {
	t.Helper()

	gzr, err := gzip.NewReader(backupFile)
	require.NoError(t, err)

	r := tar.NewReader(gzr)

	// lastSeen tracks the index in 'orderedResources' of the last resource type
	// we saw in the tarball. Once we've seen a resource in 'orderedResources',
	// we should never see another instance of a prior resource.
	lastSeen := 0

	for {
		hdr, err := r.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)

		// ignore files like metadata/version
		if !strings.HasPrefix(hdr.Name, "resources/") {
			continue
		}

		// get the resource name
		parts := strings.Split(hdr.Name, "/")
		require.GreaterOrEqual(t, len(parts), 2)
		resourceName := parts[1]

		// Find the index in 'orderedResources' of the resource type for
		// the current tar item, if it exists. This index ('current') *must*
		// be greater than or equal to 'lastSeen', which was the last resource
		// we saw, since otherwise the current resource would be out of order. By
		// initializing current to len(ordered), we're saying that if the resource
		// is not explicitly in orederedResources, then it must come *after*
		// all orderedResources.
		current := len(orderedResources)
		for i, item := range orderedResources {
			if item == resourceName {
				current = i
				break
			}
		}

		// the index of the current resource must be the same as or greater than the index of
		// the last resource we saw for the backed-up order to be correct.
		assert.GreaterOrEqual(t, current, lastSeen, "%s was backed up out of order", resourceName)
		lastSeen = current
	}
}

func TestBackupNewResourceFiltering(t *testing.T) {
	tests := []struct {
		name         string
		backup       *velerov1.Backup
		apiResources []*test.APIResource
		want         []string
		actions      []biav2.BackupItemAction
	}{
		{
			name:   "no namespace-scoped resources + some cluster-scoped resources",
			backup: defaultBackup().IncludedClusterScopedResources("persistentvolumes").ExcludedNamespaceScopedResources("*").Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("foo", "bar").Result(),
					builder.ForPod("zoo", "raz").Result(),
				),
				test.Deployments(
					builder.ForDeployment("foo", "bar").Result(),
					builder.ForDeployment("zoo", "raz").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("testing").Result(),
				),
			},
			want: []string{
				"resources/persistentvolumes/cluster/testing.json",
				"resources/persistentvolumes/v1-preferredversion/cluster/testing.json",
			},
		},
		{
			name:   "no namespace-scoped resources + all cluster-scoped resources",
			backup: defaultBackup().IncludedClusterScopedResources("*").ExcludedNamespaceScopedResources("*").Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("foo", "bar").Result(),
					builder.ForPod("zoo", "raz").Result(),
				),
				test.Deployments(
					builder.ForDeployment("foo", "bar").Result(),
					builder.ForDeployment("zoo", "raz").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("test1").Result(),
					builder.ForPersistentVolume("test2").Result(),
				),
				test.CRDs(
					builder.ForCustomResourceDefinitionV1Beta1("backups.velero.io").Result(),
				),
			},
			want: []string{
				"resources/customresourcedefinitions.apiextensions.k8s.io/cluster/backups.velero.io.json",
				"resources/persistentvolumes/cluster/test1.json",
				"resources/persistentvolumes/cluster/test2.json",
				"resources/customresourcedefinitions.apiextensions.k8s.io/v1beta1-preferredversion/cluster/backups.velero.io.json",
				"resources/persistentvolumes/v1-preferredversion/cluster/test1.json",
				"resources/persistentvolumes/v1-preferredversion/cluster/test2.json",
			},
		},
		{
			name:   "some namespace-scoped resources + no cluster-scoped resources 1",
			backup: defaultBackup().ExcludedClusterScopedResources("*").IncludedNamespaces("foo", "zoo").Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("foo", "bar").Result(),
					builder.ForPod("zoo", "raz").Result(),
				),
				test.Deployments(
					builder.ForDeployment("foo", "bar").Result(),
					builder.ForDeployment("zoo", "raz").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("test1").Result(),
					builder.ForPersistentVolume("test2").Result(),
				),
				test.CRDs(
					builder.ForCustomResourceDefinitionV1Beta1("backups.velero.io").Result(),
				),
			},
			want: []string{
				"resources/deployments.apps/namespaces/foo/bar.json",
				"resources/deployments.apps/namespaces/zoo/raz.json",
				"resources/deployments.apps/v1-preferredversion/namespaces/foo/bar.json",
				"resources/deployments.apps/v1-preferredversion/namespaces/zoo/raz.json",
				"resources/pods/namespaces/foo/bar.json",
				"resources/pods/namespaces/zoo/raz.json",
				"resources/pods/v1-preferredversion/namespaces/foo/bar.json",
				"resources/pods/v1-preferredversion/namespaces/zoo/raz.json",
			},
		},
		{
			name:   "some namespace-scoped resources + no cluster-scoped resources 2",
			backup: defaultBackup().ExcludedClusterScopedResources("*").IncludedNamespaceScopedResources("pods", "deployments").Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("foo", "bar").Result(),
					builder.ForPod("zoo", "raz").Result(),
				),
				test.Deployments(
					builder.ForDeployment("foo", "bar").Result(),
					builder.ForDeployment("zoo", "raz").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("test1").Result(),
					builder.ForPersistentVolume("test2").Result(),
				),
				test.CRDs(
					builder.ForCustomResourceDefinitionV1Beta1("backups.velero.io").Result(),
				),
			},
			want: []string{
				"resources/deployments.apps/namespaces/foo/bar.json",
				"resources/deployments.apps/namespaces/zoo/raz.json",
				"resources/deployments.apps/v1-preferredversion/namespaces/foo/bar.json",
				"resources/deployments.apps/v1-preferredversion/namespaces/zoo/raz.json",
				"resources/pods/namespaces/foo/bar.json",
				"resources/pods/namespaces/zoo/raz.json",
				"resources/pods/v1-preferredversion/namespaces/foo/bar.json",
				"resources/pods/v1-preferredversion/namespaces/zoo/raz.json",
			},
		},
		{
			name:   "some namespace-scoped resources + no cluster-scoped resources 3",
			backup: defaultBackup().ExcludedClusterScopedResources("*").IncludedNamespaces("foo").IncludedNamespaceScopedResources("pods", "deployments").Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("foo", "bar").Result(),
					builder.ForPod("zoo", "raz").Result(),
				),
				test.Deployments(
					builder.ForDeployment("foo", "bar").Result(),
					builder.ForDeployment("zoo", "raz").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("test1").Result(),
					builder.ForPersistentVolume("test2").Result(),
				),
				test.CRDs(
					builder.ForCustomResourceDefinitionV1Beta1("backups.velero.io").Result(),
				),
			},
			want: []string{
				"resources/deployments.apps/namespaces/foo/bar.json",
				"resources/deployments.apps/v1-preferredversion/namespaces/foo/bar.json",
				"resources/pods/namespaces/foo/bar.json",
				"resources/pods/v1-preferredversion/namespaces/foo/bar.json",
			},
		},
		{
			name:   "some namespace-scoped resources + no cluster-scoped resources 4",
			backup: defaultBackup().ExcludedClusterScopedResources("*").ExcludedNamespaceScopedResources("pods").Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("foo", "bar").Result(),
					builder.ForPod("zoo", "raz").Result(),
				),
				test.Deployments(
					builder.ForDeployment("foo", "bar").Result(),
					builder.ForDeployment("zoo", "raz").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("test1").Result(),
					builder.ForPersistentVolume("test2").Result(),
				),
				test.CRDs(
					builder.ForCustomResourceDefinitionV1Beta1("backups.velero.io").Result(),
				),
			},
			want: []string{
				"resources/deployments.apps/namespaces/foo/bar.json",
				"resources/deployments.apps/namespaces/zoo/raz.json",
				"resources/deployments.apps/v1-preferredversion/namespaces/foo/bar.json",
				"resources/deployments.apps/v1-preferredversion/namespaces/zoo/raz.json",
			},
		},
		{
			name:   "some namespace-scoped resources + only related cluster-scoped resources 2",
			backup: defaultBackup().IncludedNamespaces("foo").IncludedNamespaceScopedResources("pods", "persistentvolumeclaims").Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("foo", "bar").Volumes(builder.ForVolume("foo").PersistentVolumeClaimSource("test-1").Result()).Result(),
					builder.ForPod("zoo", "raz").Result(),
				),
				test.Deployments(
					builder.ForDeployment("foo", "bar").Result(),
					builder.ForDeployment("zoo", "raz").Result(),
				),
				test.PVCs(
					builder.ForPersistentVolumeClaim("foo", "test-1").VolumeName("test1").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("test1").Result(),
					builder.ForPersistentVolume("test2").Result(),
				),
			},
			want: []string{
				"resources/persistentvolumeclaims/namespaces/foo/test-1.json",
				"resources/persistentvolumeclaims/v1-preferredversion/namespaces/foo/test-1.json",
				"resources/persistentvolumes/cluster/test1.json",
				"resources/persistentvolumes/v1-preferredversion/cluster/test1.json",
				"resources/pods/namespaces/foo/bar.json",
				"resources/pods/v1-preferredversion/namespaces/foo/bar.json",
			},
			actions: []biav2.BackupItemAction{
				&pluggableAction{
					selector: velero.ResourceSelector{IncludedResources: []string{"persistentvolumeclaims"}},
					executeFunc: func(item runtime.Unstructured, backup *velerov1.Backup) (runtime.Unstructured, []velero.ResourceIdentifier, string, []velero.ResourceIdentifier, error) {
						additionalItems := []velero.ResourceIdentifier{
							{GroupResource: kuberesource.PersistentVolumes, Name: "test1"},
						}

						return item, additionalItems, "", nil, nil
					},
				},
			},
		},
		{
			name:   "some namespace-scoped resources + only related cluster-scoped resources 3",
			backup: defaultBackup().IncludedNamespaces("foo").ExcludedNamespaceScopedResources("deployments").Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("foo", "bar").Volumes(builder.ForVolume("foo").PersistentVolumeClaimSource("test-1").Result()).Result(),
				),
				test.Deployments(
					builder.ForDeployment("foo", "bar").Result(),
					builder.ForDeployment("zoo", "raz").Result(),
				),
				test.PVCs(
					builder.ForPersistentVolumeClaim("foo", "test-1").VolumeName("test1").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("test1").Result(),
					builder.ForPersistentVolume("test2").Result(),
				),
			},
			want: []string{
				"resources/persistentvolumeclaims/namespaces/foo/test-1.json",
				"resources/persistentvolumeclaims/v1-preferredversion/namespaces/foo/test-1.json",
				"resources/persistentvolumes/cluster/test1.json",
				"resources/persistentvolumes/v1-preferredversion/cluster/test1.json",
				"resources/pods/namespaces/foo/bar.json",
				"resources/pods/v1-preferredversion/namespaces/foo/bar.json",
			},
			actions: []biav2.BackupItemAction{
				&pluggableAction{
					selector: velero.ResourceSelector{IncludedResources: []string{"persistentvolumeclaims"}},
					executeFunc: func(item runtime.Unstructured, backup *velerov1.Backup) (runtime.Unstructured, []velero.ResourceIdentifier, string, []velero.ResourceIdentifier, error) {
						additionalItems := []velero.ResourceIdentifier{
							{GroupResource: kuberesource.PersistentVolumes, Name: "test1"},
						}

						return item, additionalItems, "", nil, nil
					},
				},
			},
		},
		{
			name:   "some namespace-scoped resources + some additional cluster-scoped resources 1",
			backup: defaultBackup().IncludedNamespaces("foo").IncludedClusterScopedResources("customresourcedefinitions").Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("foo", "bar").Result(),
					builder.ForPod("zoo", "raz").Result(),
				),
				test.Deployments(
					builder.ForDeployment("foo", "bar").Result(),
					builder.ForDeployment("zoo", "raz").Result(),
				),
				test.PVCs(
					builder.ForPersistentVolumeClaim("foo", "test-1").VolumeName("test1").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("test1").Result(),
					builder.ForPersistentVolume("test2").Result(),
				),
				test.CRDs(
					builder.ForCustomResourceDefinitionV1Beta1("backups.velero.io").Result(),
				),
			},
			want: []string{
				"resources/customresourcedefinitions.apiextensions.k8s.io/cluster/backups.velero.io.json",
				"resources/customresourcedefinitions.apiextensions.k8s.io/v1beta1-preferredversion/cluster/backups.velero.io.json",
				"resources/deployments.apps/namespaces/foo/bar.json",
				"resources/deployments.apps/v1-preferredversion/namespaces/foo/bar.json",
				"resources/persistentvolumeclaims/namespaces/foo/test-1.json",
				"resources/persistentvolumeclaims/v1-preferredversion/namespaces/foo/test-1.json",
				"resources/persistentvolumes/cluster/test1.json",
				"resources/persistentvolumes/v1-preferredversion/cluster/test1.json",
				"resources/pods/namespaces/foo/bar.json",
				"resources/pods/v1-preferredversion/namespaces/foo/bar.json",
			},
			actions: []biav2.BackupItemAction{
				&pluggableAction{
					selector: velero.ResourceSelector{IncludedResources: []string{"persistentvolumeclaims"}},
					executeFunc: func(item runtime.Unstructured, backup *velerov1.Backup) (runtime.Unstructured, []velero.ResourceIdentifier, string, []velero.ResourceIdentifier, error) {
						additionalItems := []velero.ResourceIdentifier{
							{GroupResource: kuberesource.PersistentVolumes, Name: "test1"},
						}

						return item, additionalItems, "", nil, nil
					},
				},
			},
		},
		{
			name:   "some namespace-scoped resources + some additional cluster-scoped resources 2",
			backup: defaultBackup().IncludedNamespaceScopedResources("persistentvolumeclaims").IncludedClusterScopedResources("customresourcedefinitions").Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("foo", "bar").Result(),
					builder.ForPod("zoo", "raz").Result(),
				),
				test.Deployments(
					builder.ForDeployment("foo", "bar").Result(),
					builder.ForDeployment("zoo", "raz").Result(),
				),
				test.PVCs(
					builder.ForPersistentVolumeClaim("foo", "test-1").VolumeName("test1").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("test1").Result(),
					builder.ForPersistentVolume("test2").Result(),
				),
				test.CRDs(
					builder.ForCustomResourceDefinitionV1Beta1("backups.velero.io").Result(),
				),
			},
			want: []string{
				"resources/customresourcedefinitions.apiextensions.k8s.io/cluster/backups.velero.io.json",
				"resources/customresourcedefinitions.apiextensions.k8s.io/v1beta1-preferredversion/cluster/backups.velero.io.json",
				"resources/persistentvolumeclaims/namespaces/foo/test-1.json",
				"resources/persistentvolumeclaims/v1-preferredversion/namespaces/foo/test-1.json",
				"resources/persistentvolumes/cluster/test1.json",
				"resources/persistentvolumes/v1-preferredversion/cluster/test1.json",
			},
			actions: []biav2.BackupItemAction{
				&pluggableAction{
					selector: velero.ResourceSelector{IncludedResources: []string{"persistentvolumeclaims"}},
					executeFunc: func(item runtime.Unstructured, backup *velerov1.Backup) (runtime.Unstructured, []velero.ResourceIdentifier, string, []velero.ResourceIdentifier, error) {
						additionalItems := []velero.ResourceIdentifier{
							{GroupResource: kuberesource.PersistentVolumes, Name: "test1"},
						}

						return item, additionalItems, "", nil, nil
					},
				},
			},
		},
		{
			name:   "some namespace-scoped resources + some additional cluster-scoped resources 3",
			backup: defaultBackup().IncludedNamespaces("foo").IncludedNamespaceScopedResources("pods", "persistentvolumeclaims").IncludedClusterScopedResources("customresourcedefinitions").Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("foo", "bar").Result(),
					builder.ForPod("zoo", "raz").Result(),
				),
				test.Deployments(
					builder.ForDeployment("foo", "bar").Result(),
					builder.ForDeployment("zoo", "raz").Result(),
				),
				test.PVCs(
					builder.ForPersistentVolumeClaim("foo", "test-1").VolumeName("test1").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("test1").Result(),
					builder.ForPersistentVolume("test2").Result(),
				),
				test.CRDs(
					builder.ForCustomResourceDefinitionV1Beta1("backups.velero.io").Result(),
				),
			},
			want: []string{
				"resources/customresourcedefinitions.apiextensions.k8s.io/cluster/backups.velero.io.json",
				"resources/customresourcedefinitions.apiextensions.k8s.io/v1beta1-preferredversion/cluster/backups.velero.io.json",
				"resources/persistentvolumeclaims/namespaces/foo/test-1.json",
				"resources/persistentvolumeclaims/v1-preferredversion/namespaces/foo/test-1.json",
				"resources/persistentvolumes/cluster/test1.json",
				"resources/persistentvolumes/v1-preferredversion/cluster/test1.json",
				"resources/pods/namespaces/foo/bar.json",
				"resources/pods/v1-preferredversion/namespaces/foo/bar.json",
			},
			actions: []biav2.BackupItemAction{
				&pluggableAction{
					selector: velero.ResourceSelector{IncludedResources: []string{"persistentvolumeclaims"}},
					executeFunc: func(item runtime.Unstructured, backup *velerov1.Backup) (runtime.Unstructured, []velero.ResourceIdentifier, string, []velero.ResourceIdentifier, error) {
						additionalItems := []velero.ResourceIdentifier{
							{GroupResource: kuberesource.PersistentVolumes, Name: "test1"},
						}

						return item, additionalItems, "", nil, nil
					},
				},
			},
		},
		{
			name:   "some namespace-scoped resources + some additional cluster-scoped resources 4",
			backup: defaultBackup().IncludedNamespaces("foo").IncludedNamespaceScopedResources("pods", "persistentvolumeclaims").IncludedClusterScopedResources("*").ExcludedClusterScopedResources("customresourcedefinitions.apiextensions.k8s.io").Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("foo", "bar").Result(),
					builder.ForPod("zoo", "raz").Result(),
				),
				test.Deployments(
					builder.ForDeployment("foo", "bar").Result(),
					builder.ForDeployment("zoo", "raz").Result(),
				),
				test.PVCs(
					builder.ForPersistentVolumeClaim("foo", "test-1").VolumeName("test1").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("test1").Result(),
					builder.ForPersistentVolume("test2").Result(),
				),
				test.CRDs(
					builder.ForCustomResourceDefinitionV1Beta1("backups.velero.io").Result(),
				),
			},
			want: []string{
				"resources/persistentvolumeclaims/namespaces/foo/test-1.json",
				"resources/persistentvolumeclaims/v1-preferredversion/namespaces/foo/test-1.json",
				"resources/persistentvolumes/cluster/test1.json",
				"resources/persistentvolumes/cluster/test2.json",
				"resources/persistentvolumes/v1-preferredversion/cluster/test1.json",
				"resources/persistentvolumes/v1-preferredversion/cluster/test2.json",
				"resources/pods/namespaces/foo/bar.json",
				"resources/pods/v1-preferredversion/namespaces/foo/bar.json",
			},
			actions: []biav2.BackupItemAction{
				&pluggableAction{
					selector: velero.ResourceSelector{IncludedResources: []string{"persistentvolumeclaims"}},
					executeFunc: func(item runtime.Unstructured, backup *velerov1.Backup) (runtime.Unstructured, []velero.ResourceIdentifier, string, []velero.ResourceIdentifier, error) {
						additionalItems := []velero.ResourceIdentifier{
							{GroupResource: kuberesource.PersistentVolumes, Name: "test1"},
						}

						return item, additionalItems, "", nil, nil
					},
				},
			},
		},
		{
			name:   "some namespace-scoped resources + all cluster-scoped resources 1",
			backup: defaultBackup().IncludedNamespaces("foo").IncludedClusterScopedResources("*").Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("foo", "bar").Result(),
					builder.ForPod("zoo", "raz").Result(),
				),
				test.Deployments(
					builder.ForDeployment("foo", "bar").Result(),
					builder.ForDeployment("zoo", "raz").Result(),
				),
				test.PVCs(
					builder.ForPersistentVolumeClaim("foo", "test-1").VolumeName("test1").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("test1").Result(),
					builder.ForPersistentVolume("test2").Result(),
				),
			},
			want: []string{
				"resources/deployments.apps/namespaces/foo/bar.json",
				"resources/deployments.apps/v1-preferredversion/namespaces/foo/bar.json",
				"resources/persistentvolumeclaims/namespaces/foo/test-1.json",
				"resources/persistentvolumeclaims/v1-preferredversion/namespaces/foo/test-1.json",
				"resources/persistentvolumes/cluster/test1.json",
				"resources/persistentvolumes/v1-preferredversion/cluster/test1.json",
				"resources/persistentvolumes/cluster/test2.json",
				"resources/persistentvolumes/v1-preferredversion/cluster/test2.json",
				"resources/pods/namespaces/foo/bar.json",
				"resources/pods/v1-preferredversion/namespaces/foo/bar.json",
			},
		},
		{
			name:   "some namespace-scoped resources + all cluster-scoped resources 2",
			backup: defaultBackup().IncludedNamespaceScopedResources("pods").IncludedClusterScopedResources("*").Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("foo", "bar").Result(),
					builder.ForPod("zoo", "raz").Result(),
				),
				test.Deployments(
					builder.ForDeployment("foo", "bar").Result(),
					builder.ForDeployment("zoo", "raz").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("test1").Result(),
					builder.ForPersistentVolume("test2").Result(),
				),
				test.CRDs(
					builder.ForCustomResourceDefinitionV1Beta1("backups.velero.io").Result(),
				),
			},
			want: []string{
				"resources/customresourcedefinitions.apiextensions.k8s.io/cluster/backups.velero.io.json",
				"resources/customresourcedefinitions.apiextensions.k8s.io/v1beta1-preferredversion/cluster/backups.velero.io.json",
				"resources/persistentvolumes/cluster/test1.json",
				"resources/persistentvolumes/cluster/test2.json",
				"resources/persistentvolumes/v1-preferredversion/cluster/test1.json",
				"resources/persistentvolumes/v1-preferredversion/cluster/test2.json",
				"resources/pods/namespaces/foo/bar.json",
				"resources/pods/namespaces/zoo/raz.json",
				"resources/pods/v1-preferredversion/namespaces/foo/bar.json",
				"resources/pods/v1-preferredversion/namespaces/zoo/raz.json",
			},
		},
		{
			name:   "some namespace-scoped resources + all cluster-scoped resources 3",
			backup: defaultBackup().IncludedNamespaces("foo").IncludedNamespaceScopedResources("pods").IncludedClusterScopedResources("*").Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("foo", "bar").Result(),
					builder.ForPod("zoo", "raz").Result(),
				),
				test.Deployments(
					builder.ForDeployment("foo", "bar").Result(),
					builder.ForDeployment("zoo", "raz").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("test1").Result(),
					builder.ForPersistentVolume("test2").Result(),
				),
				test.CRDs(
					builder.ForCustomResourceDefinitionV1Beta1("backups.velero.io").Result(),
				),
			},
			want: []string{
				"resources/customresourcedefinitions.apiextensions.k8s.io/cluster/backups.velero.io.json",
				"resources/customresourcedefinitions.apiextensions.k8s.io/v1beta1-preferredversion/cluster/backups.velero.io.json",
				"resources/persistentvolumes/cluster/test1.json",
				"resources/persistentvolumes/cluster/test2.json",
				"resources/persistentvolumes/v1-preferredversion/cluster/test1.json",
				"resources/persistentvolumes/v1-preferredversion/cluster/test2.json",
				"resources/pods/namespaces/foo/bar.json",
				"resources/pods/v1-preferredversion/namespaces/foo/bar.json",
			},
		},
		{
			name:   "all namespace-scoped resources + no cluster-scoped resources",
			backup: defaultBackup().ExcludedClusterScopedResources("*").Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("foo", "bar").Result(),
					builder.ForPod("zoo", "raz").Result(),
				),
				test.Deployments(
					builder.ForDeployment("foo", "bar").Result(),
					builder.ForDeployment("zoo", "raz").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("test1").Result(),
					builder.ForPersistentVolume("test2").Result(),
				),
				test.CRDs(
					builder.ForCustomResourceDefinitionV1Beta1("backups.velero.io").Result(),
				),
			},
			want: []string{
				"resources/deployments.apps/namespaces/foo/bar.json",
				"resources/deployments.apps/namespaces/zoo/raz.json",
				"resources/deployments.apps/v1-preferredversion/namespaces/foo/bar.json",
				"resources/deployments.apps/v1-preferredversion/namespaces/zoo/raz.json",
				"resources/pods/namespaces/foo/bar.json",
				"resources/pods/namespaces/zoo/raz.json",
				"resources/pods/v1-preferredversion/namespaces/foo/bar.json",
				"resources/pods/v1-preferredversion/namespaces/zoo/raz.json",
			},
		},
		{
			name:   "all namespace-scoped resources + all cluster-scoped resources",
			backup: defaultBackup().IncludedClusterScopedResources("*").Result(),
			apiResources: []*test.APIResource{
				test.Pods(
					builder.ForPod("foo", "bar").Result(),
					builder.ForPod("zoo", "raz").Result(),
				),
				test.Deployments(
					builder.ForDeployment("foo", "bar").Result(),
					builder.ForDeployment("zoo", "raz").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("test1").Result(),
					builder.ForPersistentVolume("test2").Result(),
				),
				test.CRDs(
					builder.ForCustomResourceDefinitionV1Beta1("backups.velero.io").Result(),
				),
			},
			want: []string{
				"resources/customresourcedefinitions.apiextensions.k8s.io/cluster/backups.velero.io.json",
				"resources/customresourcedefinitions.apiextensions.k8s.io/v1beta1-preferredversion/cluster/backups.velero.io.json",
				"resources/deployments.apps/namespaces/foo/bar.json",
				"resources/deployments.apps/namespaces/zoo/raz.json",
				"resources/deployments.apps/v1-preferredversion/namespaces/foo/bar.json",
				"resources/deployments.apps/v1-preferredversion/namespaces/zoo/raz.json",
				"resources/persistentvolumes/cluster/test1.json",
				"resources/persistentvolumes/cluster/test2.json",
				"resources/persistentvolumes/v1-preferredversion/cluster/test1.json",
				"resources/persistentvolumes/v1-preferredversion/cluster/test2.json",
				"resources/pods/namespaces/foo/bar.json",
				"resources/pods/namespaces/zoo/raz.json",
				"resources/pods/v1-preferredversion/namespaces/foo/bar.json",
				"resources/pods/v1-preferredversion/namespaces/zoo/raz.json",
			},
		},
		{
			name:   "namespace resource should be included even it's not specified in the include list, when IncludedNamespaces has specified value 1",
			backup: defaultBackup().IncludedNamespaces("foo").IncludedNamespaceScopedResources("Secrets").Result(),
			apiResources: []*test.APIResource{
				test.Secrets(
					builder.ForSecret("foo", "bar").Result(),
					builder.ForSecret("zoo", "raz").Result(),
				),
				test.Deployments(
					builder.ForDeployment("foo", "bar").Result(),
					builder.ForDeployment("zoo", "raz").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("foo").Result(),
				),
				test.Namespaces(
					builder.ForNamespace("foo").Result(),
				),
			},
			want: []string{
				"resources/namespaces/cluster/foo.json",
				"resources/namespaces/v1-preferredversion/cluster/foo.json",
				"resources/secrets/namespaces/foo/bar.json",
				"resources/secrets/v1-preferredversion/namespaces/foo/bar.json",
			},
		},
		{
			name:   "namespace resource should be included even it's not specified in the include list, when IncludedNamespaces has specified value 2",
			backup: defaultBackup().IncludedNamespaces("foo").IncludedClusterScopedResources("persistentvolumes").Result(),
			apiResources: []*test.APIResource{
				test.Secrets(
					builder.ForSecret("foo", "bar").Result(),
					builder.ForSecret("zoo", "raz").Result(),
				),
				test.Deployments(
					builder.ForDeployment("foo", "bar").Result(),
					builder.ForDeployment("zoo", "raz").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("foo").Result(),
				),
				test.Namespaces(
					builder.ForNamespace("foo").Result(),
				),
			},
			want: []string{
				"resources/namespaces/cluster/foo.json",
				"resources/namespaces/v1-preferredversion/cluster/foo.json",
				"resources/secrets/namespaces/foo/bar.json",
				"resources/secrets/v1-preferredversion/namespaces/foo/bar.json",
				"resources/deployments.apps/namespaces/foo/bar.json",
				"resources/deployments.apps/v1-preferredversion/namespaces/foo/bar.json",
				"resources/persistentvolumes/cluster/foo.json",
				"resources/persistentvolumes/v1-preferredversion/cluster/foo.json",
			},
		},
		{
			name:   "namespace resource should be included even it's not specified in the include list, when IncludedNamespaces is asterisk.",
			backup: defaultBackup().IncludedNamespaces("*").IncludedClusterScopedResources("persistentvolumes").Result(),
			apiResources: []*test.APIResource{
				test.Secrets(
					builder.ForSecret("foo", "bar").Result(),
					builder.ForSecret("zoo", "raz").Result(),
				),
				test.Deployments(
					builder.ForDeployment("foo", "bar").Result(),
					builder.ForDeployment("zoo", "raz").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("foo").Result(),
				),
				test.Namespaces(
					builder.ForNamespace("foo").Result(),
					builder.ForNamespace("zoo").Result(),
				),
			},
			want: []string{
				"resources/namespaces/cluster/foo.json",
				"resources/namespaces/v1-preferredversion/cluster/foo.json",
				"resources/namespaces/cluster/zoo.json",
				"resources/namespaces/v1-preferredversion/cluster/zoo.json",
				"resources/secrets/namespaces/foo/bar.json",
				"resources/secrets/namespaces/zoo/raz.json",
				"resources/secrets/v1-preferredversion/namespaces/foo/bar.json",
				"resources/secrets/v1-preferredversion/namespaces/zoo/raz.json",
				"resources/deployments.apps/namespaces/foo/bar.json",
				"resources/deployments.apps/namespaces/zoo/raz.json",
				"resources/deployments.apps/v1-preferredversion/namespaces/foo/bar.json",
				"resources/deployments.apps/v1-preferredversion/namespaces/zoo/raz.json",
				"resources/persistentvolumes/cluster/foo.json",
				"resources/persistentvolumes/v1-preferredversion/cluster/foo.json",
			},
		},
		{
			name:   "when all namespace-scoped resources are involved, cluster-scoped resources should be included too",
			backup: defaultBackup().IncludedNamespaces("*").IncludedNamespaceScopedResources("*").Result(),
			apiResources: []*test.APIResource{
				test.Secrets(
					builder.ForSecret("foo", "bar").Result(),
					builder.ForSecret("zoo", "raz").Result(),
				),
				test.Deployments(
					builder.ForDeployment("foo", "bar").Result(),
					builder.ForDeployment("zoo", "raz").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("foo").Result(),
					builder.ForPersistentVolume("bar").Result(),
				),
				test.Namespaces(
					builder.ForNamespace("foo").Result(),
					builder.ForNamespace("zoo").Result(),
				),
			},
			want: []string{
				"resources/namespaces/cluster/foo.json",
				"resources/namespaces/v1-preferredversion/cluster/foo.json",
				"resources/namespaces/cluster/zoo.json",
				"resources/namespaces/v1-preferredversion/cluster/zoo.json",
				"resources/secrets/namespaces/foo/bar.json",
				"resources/secrets/namespaces/zoo/raz.json",
				"resources/secrets/v1-preferredversion/namespaces/foo/bar.json",
				"resources/secrets/v1-preferredversion/namespaces/zoo/raz.json",
				"resources/deployments.apps/namespaces/foo/bar.json",
				"resources/deployments.apps/namespaces/zoo/raz.json",
				"resources/deployments.apps/v1-preferredversion/namespaces/foo/bar.json",
				"resources/deployments.apps/v1-preferredversion/namespaces/zoo/raz.json",
				"resources/persistentvolumes/cluster/foo.json",
				"resources/persistentvolumes/v1-preferredversion/cluster/foo.json",
				"resources/persistentvolumes/cluster/bar.json",
				"resources/persistentvolumes/v1-preferredversion/cluster/bar.json",
			},
		},
		{
			name:   "IncludedNamespaces is asterisk, but not all namespace-scoped resource types are include, additional cluster-scoped resources should not be included.",
			backup: defaultBackup().IncludedNamespaces("*").IncludedNamespaceScopedResources("secrets").Result(),
			apiResources: []*test.APIResource{
				test.Secrets(
					builder.ForSecret("foo", "bar").Result(),
					builder.ForSecret("zoo", "raz").Result(),
				),
				test.Deployments(
					builder.ForDeployment("foo", "bar").Result(),
					builder.ForDeployment("zoo", "raz").Result(),
				),
				test.PVs(
					builder.ForPersistentVolume("foo").Result(),
					builder.ForPersistentVolume("bar").Result(),
				),
				test.Namespaces(
					builder.ForNamespace("foo").Result(),
					builder.ForNamespace("zoo").Result(),
				),
			},
			want: []string{
				"resources/namespaces/cluster/foo.json",
				"resources/namespaces/v1-preferredversion/cluster/foo.json",
				"resources/namespaces/cluster/zoo.json",
				"resources/namespaces/v1-preferredversion/cluster/zoo.json",
				"resources/secrets/namespaces/foo/bar.json",
				"resources/secrets/namespaces/zoo/raz.json",
				"resources/secrets/v1-preferredversion/namespaces/foo/bar.json",
				"resources/secrets/v1-preferredversion/namespaces/zoo/raz.json",
			},
		},
		{
			name:   "Resource's CRD should be included",
			backup: defaultBackup().IncludedNamespaces("foo").IncludedNamespaceScopedResources("volumesnapshotlocations.velero.io", "backups.velero.io").Result(),
			apiResources: []*test.APIResource{
				test.CRDs(
					builder.ForCustomResourceDefinitionV1Beta1("backups.velero.io").Result(),
					builder.ForCustomResourceDefinitionV1Beta1("volumesnapshotlocations.velero.io").Result(),
					builder.ForCustomResourceDefinitionV1Beta1("test.velero.io").Result(),
				),
				test.VSLs(
					builder.ForVolumeSnapshotLocation("foo", "bar").Result(),
				),
				test.Backups(
					builder.ForBackup("zoo", "raz").Result(),
				),
			},
			want: []string{
				"resources/customresourcedefinitions.apiextensions.k8s.io/cluster/volumesnapshotlocations.velero.io.json",
				"resources/customresourcedefinitions.apiextensions.k8s.io/v1beta1-preferredversion/cluster/volumesnapshotlocations.velero.io.json",
				"resources/volumesnapshotlocations.velero.io/namespaces/foo/bar.json",
				"resources/volumesnapshotlocations.velero.io/v1-preferredversion/namespaces/foo/bar.json",
			},
		},
		{
			name:   "Resource's CRD is not included, when CRD is excluded.",
			backup: defaultBackup().IncludedNamespaces("foo").IncludedNamespaceScopedResources("volumesnapshotlocations.velero.io", "backups.velero.io").ExcludedClusterScopedResources("customresourcedefinitions.apiextensions.k8s.io").Result(),
			apiResources: []*test.APIResource{
				test.CRDs(
					builder.ForCustomResourceDefinitionV1Beta1("backups.velero.io").Result(),
					builder.ForCustomResourceDefinitionV1Beta1("volumesnapshotlocations.velero.io").Result(),
					builder.ForCustomResourceDefinitionV1Beta1("test.velero.io").Result(),
				),
				test.VSLs(
					builder.ForVolumeSnapshotLocation("foo", "bar").Result(),
				),
				test.Backups(
					builder.ForBackup("zoo", "raz").Result(),
				),
			},
			want: []string{
				"resources/volumesnapshotlocations.velero.io/namespaces/foo/bar.json",
				"resources/volumesnapshotlocations.velero.io/v1-preferredversion/namespaces/foo/bar.json",
			},
		},
	}

	itemBlockPool := StartItemBlockWorkerPool(t.Context(), 1, logrus.StandardLogger())
	defer itemBlockPool.Stop()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var (
				h   = newHarness(t, itemBlockPool)
				req = &Request{
					Backup:           tc.backup,
					SkippedPVTracker: NewSkipPVTracker(),
					BackedUpItems:    NewBackedUpItemsMap(),
					WorkerPool:       itemBlockPool,
				}
				backupFile = bytes.NewBuffer([]byte{})
			)

			for _, resource := range tc.apiResources {
				h.addItems(t, resource)
			}

			h.backupper.Backup(h.log, req, backupFile, tc.actions, nil, nil)

			assertTarballContents(t, backupFile, append(tc.want, "metadata/version")...)
		})
	}
}

func TestBackupNamespaces(t *testing.T) {
	tests := []struct {
		name         string
		backup       *velerov1.Backup
		apiResources []*test.APIResource
		want         []string
	}{
		{
			name: "LabelSelector test",
			backup: defaultBackup().LabelSelector(&metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}}).
				Result(),
			apiResources: []*test.APIResource{
				test.Namespaces(
					builder.ForNamespace("ns-1").Phase(corev1api.NamespaceActive).Result(),
					builder.ForNamespace("ns-2").Phase(corev1api.NamespaceActive).Result(),
					builder.ForNamespace("ns-3").Phase(corev1api.NamespaceActive).Result(),
				),
				test.Deployments(
					builder.ForDeployment("ns-1", "deploy-1").ObjectMeta(builder.WithLabels("a", "b")).Result(),
				),
			},
			want: []string{
				"resources/namespaces/cluster/ns-1.json",
				"resources/namespaces/v1-preferredversion/cluster/ns-1.json",
				"resources/deployments.apps/namespaces/ns-1/deploy-1.json",
				"resources/deployments.apps/v1-preferredversion/namespaces/ns-1/deploy-1.json",
			},
		},
		{
			name: "OrLabelSelector test",
			backup: defaultBackup().OrLabelSelector([]*metav1.LabelSelector{
				{MatchLabels: map[string]string{"a": "b"}},
				{MatchLabels: map[string]string{"c": "d"}},
			}).Result(),
			apiResources: []*test.APIResource{
				test.Namespaces(
					builder.ForNamespace("ns-1").Phase(corev1api.NamespaceActive).Result(),
					builder.ForNamespace("ns-2").Phase(corev1api.NamespaceActive).Result(),
					builder.ForNamespace("ns-3").Phase(corev1api.NamespaceActive).Result(),
				),
				test.Deployments(
					builder.ForDeployment("ns-1", "deploy-1").ObjectMeta(builder.WithLabels("a", "b")).Result(),
					builder.ForDeployment("ns-2", "deploy-2").ObjectMeta(builder.WithLabels("c", "d")).Result(),
				),
			},
			want: []string{
				"resources/namespaces/cluster/ns-1.json",
				"resources/namespaces/v1-preferredversion/cluster/ns-1.json",
				"resources/namespaces/cluster/ns-2.json",
				"resources/namespaces/v1-preferredversion/cluster/ns-2.json",
				"resources/deployments.apps/namespaces/ns-1/deploy-1.json",
				"resources/deployments.apps/v1-preferredversion/namespaces/ns-1/deploy-1.json",
				"resources/deployments.apps/namespaces/ns-2/deploy-2.json",
				"resources/deployments.apps/v1-preferredversion/namespaces/ns-2/deploy-2.json",
			},
		},
		{
			name: "LabelSelector and Namespace filtering test",
			backup: defaultBackup().IncludedNamespaces("ns-1").LabelSelector(&metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}}).
				Result(),
			apiResources: []*test.APIResource{
				test.Namespaces(
					builder.ForNamespace("ns-1").Phase(corev1api.NamespaceActive).Result(),
					builder.ForNamespace("ns-2").Phase(corev1api.NamespaceActive).Result(),
					builder.ForNamespace("ns-3").Phase(corev1api.NamespaceActive).Result(),
				),
				test.Deployments(
					builder.ForDeployment("ns-1", "deploy-1").ObjectMeta(builder.WithLabels("a", "b")).Result(),
				),
			},
			want: []string{
				"resources/namespaces/cluster/ns-1.json",
				"resources/namespaces/v1-preferredversion/cluster/ns-1.json",
				"resources/deployments.apps/namespaces/ns-1/deploy-1.json",
				"resources/deployments.apps/v1-preferredversion/namespaces/ns-1/deploy-1.json",
			},
		},
		{
			name: "LabelSelector and Namespace exclude filtering test",
			backup: defaultBackup().ExcludedNamespaces("ns-1", "ns-2").LabelSelector(&metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}}).
				Result(),
			apiResources: []*test.APIResource{
				test.Namespaces(
					builder.ForNamespace("ns-1").ObjectMeta(builder.WithLabels("a", "b")).Phase(corev1api.NamespaceActive).Result(),
					builder.ForNamespace("ns-2").Phase(corev1api.NamespaceActive).Result(),
					builder.ForNamespace("ns-3").Phase(corev1api.NamespaceActive).Result(),
				),
				test.Deployments(
					builder.ForDeployment("ns-1", "deploy-1").ObjectMeta(builder.WithLabels("a", "b")).Result(),
				),
			},
			want: []string{
				"resources/namespaces/cluster/ns-1.json",
				"resources/namespaces/v1-preferredversion/cluster/ns-1.json",
				"resources/namespaces/cluster/ns-3.json",
				"resources/namespaces/v1-preferredversion/cluster/ns-3.json",
			},
		},
		{
			name:   "Empty namespace test",
			backup: defaultBackup().IncludedNamespaces("invalid*").Result(),
			apiResources: []*test.APIResource{
				test.Namespaces(
					builder.ForNamespace("ns-1").Phase(corev1api.NamespaceActive).Result(),
					builder.ForNamespace("ns-2").Phase(corev1api.NamespaceActive).Result(),
					builder.ForNamespace("ns-3").Phase(corev1api.NamespaceActive).Result(),
				),
				test.Deployments(
					builder.ForDeployment("ns-1", "deploy-1").ObjectMeta(builder.WithLabels("a", "b")).Result(),
				),
			},
			want: []string{},
		},
		{
			name:   "Default namespace filter test",
			backup: defaultBackup().Result(),
			apiResources: []*test.APIResource{
				test.Namespaces(
					builder.ForNamespace("ns-1").Phase(corev1api.NamespaceActive).Result(),
					builder.ForNamespace("ns-2").Phase(corev1api.NamespaceActive).Result(),
					builder.ForNamespace("ns-3").Phase(corev1api.NamespaceActive).Result(),
				),
				test.Deployments(
					builder.ForDeployment("ns-1", "deploy-1").ObjectMeta(builder.WithLabels("a", "b")).Result(),
				),
			},
			want: []string{
				"resources/namespaces/cluster/ns-1.json",
				"resources/namespaces/v1-preferredversion/cluster/ns-1.json",
				"resources/namespaces/cluster/ns-2.json",
				"resources/namespaces/v1-preferredversion/cluster/ns-2.json",
				"resources/namespaces/cluster/ns-3.json",
				"resources/namespaces/v1-preferredversion/cluster/ns-3.json",
				"resources/deployments.apps/namespaces/ns-1/deploy-1.json",
				"resources/deployments.apps/v1-preferredversion/namespaces/ns-1/deploy-1.json",
			},
		},
	}

	itemBlockPool := StartItemBlockWorkerPool(t.Context(), 1, logrus.StandardLogger())
	defer itemBlockPool.Stop()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var (
				h   = newHarness(t, itemBlockPool)
				req = &Request{
					Backup:           tc.backup,
					SkippedPVTracker: NewSkipPVTracker(),
					BackedUpItems:    NewBackedUpItemsMap(),
					WorkerPool:       itemBlockPool,
				}
				backupFile = bytes.NewBuffer([]byte{})
			)

			for _, resource := range tc.apiResources {
				h.addItems(t, resource)
			}

			h.backupper.Backup(h.log, req, backupFile, nil, nil, nil)

			assertTarballContents(t, backupFile, append(tc.want, "metadata/version")...)
		})
	}
}

func TestUpdateVolumeInfos(t *testing.T) {
	timeExample := time.Date(2014, 6, 5, 11, 56, 45, 0, time.Local)
	now := metav1.NewTime(timeExample)
	logger := logrus.StandardLogger()

	tests := []struct {
		name                string
		operations          []*itemoperation.BackupOperation
		dataUpload          *velerov2alpha1.DataUpload
		volumeInfos         []*volume.BackupVolumeInfo
		expectedVolumeInfos []*volume.BackupVolumeInfo
	}{
		{
			name: "CSISnapshot VolumeInfo update with Operation fails",
			operations: []*itemoperation.BackupOperation{
				{
					Spec: itemoperation.BackupOperationSpec{
						OperationID: "test-operation",
					},
					Status: itemoperation.OperationStatus{
						Error:   "failed",
						Updated: &now,
					},
				},
			},
			volumeInfos: []*volume.BackupVolumeInfo{
				{
					BackupMethod:        volume.CSISnapshot,
					CompletionTimestamp: &metav1.Time{},
					CSISnapshotInfo: &volume.CSISnapshotInfo{
						OperationID: "test-operation",
					},
				},
			},
			expectedVolumeInfos: []*volume.BackupVolumeInfo{
				{
					BackupMethod:        volume.CSISnapshot,
					CompletionTimestamp: &now,
					Result:              volume.VolumeResultFailed,
					CSISnapshotInfo: &volume.CSISnapshotInfo{
						OperationID: "test-operation",
					},
				},
			},
		},
		{
			name: "CSISnapshot VolumeInfo update",
			operations: []*itemoperation.BackupOperation{
				{
					Spec: itemoperation.BackupOperationSpec{
						OperationID: "test-operation",
					},
					Status: itemoperation.OperationStatus{
						Updated: &now,
					},
				},
			},
			volumeInfos: []*volume.BackupVolumeInfo{
				{
					BackupMethod:        volume.CSISnapshot,
					CompletionTimestamp: &metav1.Time{},
					CSISnapshotInfo: &volume.CSISnapshotInfo{
						OperationID: "test-operation",
					},
				},
			},
			expectedVolumeInfos: []*volume.BackupVolumeInfo{
				{
					BackupMethod:        volume.CSISnapshot,
					CompletionTimestamp: &now,
					Result:              volume.VolumeResultSucceeded,
					CSISnapshotInfo: &volume.CSISnapshotInfo{
						OperationID: "test-operation",
					},
				},
			},
		},
		{
			name:       "DataUpload VolumeInfo update with fail phase",
			operations: []*itemoperation.BackupOperation{},
			dataUpload: builder.ForDataUpload("velero", "du-1").
				CompletionTimestamp(&now).
				CSISnapshot(&velerov2alpha1.CSISnapshotSpec{VolumeSnapshot: "vs-1"}).
				SnapshotID("snapshot-id").
				Progress(shared.DataMoveOperationProgress{TotalBytes: 1000}).
				IncrementalBytes(500).
				Phase(velerov2alpha1.DataUploadPhaseFailed).
				SourceNamespace("ns-1").
				SourcePVC("pvc-1").
				Result(),
			volumeInfos: []*volume.BackupVolumeInfo{
				{
					PVCName:             "pvc-1",
					PVCNamespace:        "ns-1",
					CompletionTimestamp: &metav1.Time{},
					SnapshotDataMovementInfo: &volume.SnapshotDataMovementInfo{
						DataMover: "velero",
					},
				},
			},
			expectedVolumeInfos: []*volume.BackupVolumeInfo{
				{
					PVCName:             "pvc-1",
					PVCNamespace:        "ns-1",
					CompletionTimestamp: &now,
					Result:              volume.VolumeResultFailed,
					SnapshotDataMovementInfo: &volume.SnapshotDataMovementInfo{
						DataMover:        "velero",
						RetainedSnapshot: "vs-1",
						SnapshotHandle:   "snapshot-id",
						Size:             1000,
						IncrementalSize:  500,
						Phase:            velerov2alpha1.DataUploadPhaseFailed,
					},
				},
			},
		},
		{
			name:       "DataUpload VolumeInfo update",
			operations: []*itemoperation.BackupOperation{},
			dataUpload: builder.ForDataUpload("velero", "du-1").
				CompletionTimestamp(&now).
				CSISnapshot(&velerov2alpha1.CSISnapshotSpec{VolumeSnapshot: "vs-1"}).
				SnapshotID("snapshot-id").
				Progress(shared.DataMoveOperationProgress{TotalBytes: 1000}).
				IncrementalBytes(500).
				Phase(velerov2alpha1.DataUploadPhaseCompleted).
				SourceNamespace("ns-1").
				SourcePVC("pvc-1").
				Result(),
			volumeInfos: []*volume.BackupVolumeInfo{
				{
					PVCName:             "pvc-1",
					PVCNamespace:        "ns-1",
					CompletionTimestamp: &metav1.Time{},
					SnapshotDataMovementInfo: &volume.SnapshotDataMovementInfo{
						DataMover: "velero",
					},
				},
			},
			expectedVolumeInfos: []*volume.BackupVolumeInfo{
				{
					PVCName:             "pvc-1",
					PVCNamespace:        "ns-1",
					CompletionTimestamp: &now,
					Result:              volume.VolumeResultSucceeded,
					SnapshotDataMovementInfo: &volume.SnapshotDataMovementInfo{
						DataMover:        "velero",
						RetainedSnapshot: "vs-1",
						SnapshotHandle:   "snapshot-id",
						Size:             1000,
						IncrementalSize:  500,
						Phase:            velerov2alpha1.DataUploadPhaseCompleted,
					},
				},
			},
		},
		{
			// This is an error case. No crash happen here is good enough.
			name:       "VolumeInfo doesn't have SnapshotDataMovementInfo when there is a matching DataUpload",
			operations: []*itemoperation.BackupOperation{},
			dataUpload: builder.ForDataUpload("velero", "du-1").
				CompletionTimestamp(&now).
				CSISnapshot(&velerov2alpha1.CSISnapshotSpec{VolumeSnapshot: "vs-1"}).
				SnapshotID("snapshot-id").
				Progress(shared.DataMoveOperationProgress{TotalBytes: 1000}).
				IncrementalBytes(500).
				Phase(velerov2alpha1.DataUploadPhaseCompleted).
				SourceNamespace("ns-1").
				SourcePVC("pvc-1").
				Result(),
			volumeInfos: []*volume.BackupVolumeInfo{
				{
					PVCName:                  "pvc-1",
					PVCNamespace:             "ns-1",
					CompletionTimestamp:      &metav1.Time{},
					SnapshotDataMovementInfo: nil,
				},
			},
			expectedVolumeInfos: []*volume.BackupVolumeInfo{
				{
					PVCName:                  "pvc-1",
					PVCNamespace:             "ns-1",
					CompletionTimestamp:      &metav1.Time{},
					SnapshotDataMovementInfo: nil,
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			unstructures := []unstructured.Unstructured{}
			if tc.dataUpload != nil {
				duMap, error := runtime.DefaultUnstructuredConverter.ToUnstructured(tc.dataUpload)
				require.NoError(t, error)
				unstructures = append(unstructures,
					unstructured.Unstructured{
						Object: duMap,
					},
				)
			}

			require.NoError(t, updateVolumeInfos(tc.volumeInfos, unstructures, tc.operations, logger))
			if len(tc.expectedVolumeInfos) > 0 {
				require.Equal(t, tc.expectedVolumeInfos[0].CompletionTimestamp, tc.volumeInfos[0].CompletionTimestamp)
				require.Equal(t, tc.expectedVolumeInfos[0].SnapshotDataMovementInfo, tc.volumeInfos[0].SnapshotDataMovementInfo)
			}
		})
	}
}

func TestPutVolumeInfos(t *testing.T) {
	backupName := "backup-01"

	backupStore := new(persistencemocks.BackupStore)

	backupStore.On("PutBackupVolumeInfos", mock.Anything, mock.Anything).Return(nil)

	require.NoError(t, putVolumeInfos(backupName, []*volume.BackupVolumeInfo{}, backupStore))
}

type fakeSingleObjectBackupStoreGetter struct {
	store persistence.BackupStore
}

func (f *fakeSingleObjectBackupStoreGetter) Get(*velerov1.BackupStorageLocation, persistence.ObjectStoreGetter, logrus.FieldLogger) (persistence.BackupStore, error) {
	return f.store, nil
}

// NewFakeSingleObjectBackupStoreGetter returns an ObjectBackupStoreGetter
// that will return only the given BackupStore.
func NewFakeSingleObjectBackupStoreGetter(store persistence.BackupStore) persistence.ObjectBackupStoreGetter {
	return &fakeSingleObjectBackupStoreGetter{store: store}
}
