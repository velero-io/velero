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
	"fmt"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	factorymocks "github.com/vmware-tanzu/velero/pkg/client/mocks"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
)

// TestCompleteNames exercises the core completeNames helper with various list
// types, prefix filters, and edge cases (empty cluster, no match).
func TestCompleteNames(t *testing.T) {
	tests := []struct {
		name       string
		objects    []runtime.Object
		list       kbclient.ObjectList
		toComplete string
		want       []string
	}{
		{
			name:       "no resources returns nil",
			objects:    nil,
			list:       &velerov1api.BackupList{},
			toComplete: "",
			want:       nil,
		},
		{
			name: "returns all matching names",
			objects: []runtime.Object{
				&velerov1api.Backup{ObjectMeta: metav1.ObjectMeta{Name: "daily", Namespace: "velero"}},
				&velerov1api.Backup{ObjectMeta: metav1.ObjectMeta{Name: "weekly", Namespace: "velero"}},
			},
			list:       &velerov1api.BackupList{},
			toComplete: "",
			want:       []string{"daily", "weekly"},
		},
		{
			name: "filters by prefix",
			objects: []runtime.Object{
				&velerov1api.Backup{ObjectMeta: metav1.ObjectMeta{Name: "daily", Namespace: "velero"}},
				&velerov1api.Backup{ObjectMeta: metav1.ObjectMeta{Name: "weekly", Namespace: "velero"}},
				&velerov1api.Backup{ObjectMeta: metav1.ObjectMeta{Name: "daily-full", Namespace: "velero"}},
			},
			list:       &velerov1api.BackupList{},
			toComplete: "dai",
			want:       []string{"daily", "daily-full"},
		},
		{
			name: "no prefix match returns nil",
			objects: []runtime.Object{
				&velerov1api.Backup{ObjectMeta: metav1.ObjectMeta{Name: "daily", Namespace: "velero"}},
			},
			list:       &velerov1api.BackupList{},
			toComplete: "xyz",
			want:       nil,
		},
		{
			name: "works with RestoreList",
			objects: []runtime.Object{
				&velerov1api.Restore{ObjectMeta: metav1.ObjectMeta{Name: "restore-1", Namespace: "velero"}},
				&velerov1api.Restore{ObjectMeta: metav1.ObjectMeta{Name: "restore-2", Namespace: "velero"}},
			},
			list:       &velerov1api.RestoreList{},
			toComplete: "restore-",
			want:       []string{"restore-1", "restore-2"},
		},
		{
			name: "works with ScheduleList",
			objects: []runtime.Object{
				&velerov1api.Schedule{ObjectMeta: metav1.ObjectMeta{Name: "nightly", Namespace: "velero"}},
			},
			list:       &velerov1api.ScheduleList{},
			toComplete: "",
			want:       []string{"nightly"},
		},
		{
			name: "works with BackupStorageLocationList",
			objects: []runtime.Object{
				&velerov1api.BackupStorageLocation{ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "velero"}},
				&velerov1api.BackupStorageLocation{ObjectMeta: metav1.ObjectMeta{Name: "secondary", Namespace: "velero"}},
			},
			list:       &velerov1api.BackupStorageLocationList{},
			toComplete: "s",
			want:       []string{"secondary"},
		},
		{
			name: "works with VolumeSnapshotLocationList",
			objects: []runtime.Object{
				&velerov1api.VolumeSnapshotLocation{ObjectMeta: metav1.ObjectMeta{Name: "aws-snap", Namespace: "velero"}},
			},
			list:       &velerov1api.VolumeSnapshotLocationList{},
			toComplete: "",
			want:       []string{"aws-snap"},
		},
		{
			name: "works with BackupRepositoryList",
			objects: []runtime.Object{
				&velerov1api.BackupRepository{ObjectMeta: metav1.ObjectMeta{Name: "repo-1", Namespace: "velero"}},
			},
			list:       &velerov1api.BackupRepositoryList{},
			toComplete: "",
			want:       []string{"repo-1"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			kbClient := velerotest.NewFakeControllerRuntimeClient(t, tc.objects...)

			f := new(factorymocks.Factory)
			f.On("KubebuilderClient").Return(kbClient, nil)
			f.On("Namespace").Return("velero")

			completionFn := completeNames(f, tc.list)
			got, directive := completionFn(&cobra.Command{}, nil, tc.toComplete)

			assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestCompleteNames_KubebuilderClientError verifies that a factory error
// (e.g. no kubeconfig) returns nil completions instead of panicking.
func TestCompleteNames_KubebuilderClientError(t *testing.T) {
	f := new(factorymocks.Factory)
	f.On("KubebuilderClient").Return(nil, fmt.Errorf("connection refused"))

	completionFn := completeNames(f, &velerov1api.BackupList{})
	got, directive := completionFn(&cobra.Command{}, nil, "")

	assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive)
	assert.Nil(t, got)
}

// TestCompleteWrappers verifies each exported Complete*Names wrapper returns
// only its own resource type. A single fake client holds one object of every
// type, so each wrapper must filter correctly and not leak other kinds.
func TestCompleteWrappers(t *testing.T) {
	objects := []runtime.Object{
		&velerov1api.Backup{ObjectMeta: metav1.ObjectMeta{Name: "b1", Namespace: "velero"}},
		&velerov1api.Restore{ObjectMeta: metav1.ObjectMeta{Name: "r1", Namespace: "velero"}},
		&velerov1api.Schedule{ObjectMeta: metav1.ObjectMeta{Name: "s1", Namespace: "velero"}},
		&velerov1api.BackupStorageLocation{ObjectMeta: metav1.ObjectMeta{Name: "bsl1", Namespace: "velero"}},
		&velerov1api.VolumeSnapshotLocation{ObjectMeta: metav1.ObjectMeta{Name: "vsl1", Namespace: "velero"}},
		&velerov1api.BackupRepository{ObjectMeta: metav1.ObjectMeta{Name: "br1", Namespace: "velero"}},
	}
	kbClient := velerotest.NewFakeControllerRuntimeClient(t, objects...)

	f := new(factorymocks.Factory)
	f.On("KubebuilderClient").Return(kbClient, nil)
	f.On("Namespace").Return("velero")

	tests := []struct {
		name     string
		fn       completionFunc
		expected []string
	}{
		{"CompleteBackupNames", CompleteBackupNames(f), []string{"b1"}},
		{"CompleteRestoreNames", CompleteRestoreNames(f), []string{"r1"}},
		{"CompleteScheduleNames", CompleteScheduleNames(f), []string{"s1"}},
		{"CompleteBackupStorageLocationNames", CompleteBackupStorageLocationNames(f), []string{"bsl1"}},
		{"CompleteVolumeSnapshotLocationNames", CompleteVolumeSnapshotLocationNames(f), []string{"vsl1"}},
		{"CompleteBackupRepositoryNames", CompleteBackupRepositoryNames(f), []string{"br1"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, directive := tc.fn(&cobra.Command{}, nil, "")
			require.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive)
			assert.Equal(t, tc.expected, got)
		})
	}
}
