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

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"
)

// Resource gets a Velero GroupResource for a specified resource
func Resource(resource string) schema.GroupResource {
	return SchemeGroupVersion.WithResource(resource).GroupResource()
}

type typeInfo struct {
	PluralName   string
	ItemType     runtime.Object
	ItemListType runtime.Object
}

func newTypeInfo(pluralName string, itemType, itemListType runtime.Object) typeInfo {
	return typeInfo{
		PluralName:   pluralName,
		ItemType:     itemType,
		ItemListType: itemListType,
	}
}

// CustomResources returns a map of all custom resources within the Velero
// API group, keyed on Kind.
func CustomResources() map[string]typeInfo {
	return map[string]typeInfo{
		"Backup":                    newTypeInfo("backups", &Backup{}, &BackupList{}),
		"Restore":                   newTypeInfo("restores", &Restore{}, &RestoreList{}),
		"Schedule":                  newTypeInfo("schedules", &Schedule{}, &ScheduleList{}),
		"DownloadRequest":           newTypeInfo("downloadrequests", &DownloadRequest{}, &DownloadRequestList{}),
		"DeleteBackupRequest":       newTypeInfo("deletebackuprequests", &DeleteBackupRequest{}, &DeleteBackupRequestList{}),
		"BackupCancellationRequest": newTypeInfo("backupcancellationrequests", &BackupCancellationRequest{}, &BackupCancellationRequestList{}),
		"PodVolumeBackup":           newTypeInfo("podvolumebackups", &PodVolumeBackup{}, &PodVolumeBackupList{}),
		"PodVolumeRestore":          newTypeInfo("podvolumerestores", &PodVolumeRestore{}, &PodVolumeRestoreList{}),
		"BackupRepository":          newTypeInfo("backuprepositories", &BackupRepository{}, &BackupRepositoryList{}),
		"BackupStorageLocation":     newTypeInfo("backupstoragelocations", &BackupStorageLocation{}, &BackupStorageLocationList{}),
		"VolumeSnapshotLocation":    newTypeInfo("volumesnapshotlocations", &VolumeSnapshotLocation{}, &VolumeSnapshotLocationList{}),
		"ServerStatusRequest":       newTypeInfo("serverstatusrequests", &ServerStatusRequest{}, &ServerStatusRequestList{}),
	}
}

// CustomResourceKinds returns a list of all custom resources kinds within the Velero
func CustomResourceKinds() sets.Set[string] {
	kinds := sets.New[string]()

	resources := CustomResources()
	for kind := range resources {
		kinds.Insert(kind)
	}

	return kinds
}

func addKnownTypes(scheme *runtime.Scheme) error {
	for _, typeInfo := range CustomResources() {
		scheme.AddKnownTypes(SchemeGroupVersion, typeInfo.ItemType, typeInfo.ItemListType)
	}

	metav1.AddToGroupVersion(scheme, SchemeGroupVersion)
	return nil
}
