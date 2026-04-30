/*
Copyright 2019 the Velero contributors.

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
	"fmt"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/vmware-tanzu/velero/internal/credentials"
	"github.com/vmware-tanzu/velero/internal/volume"
	api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/util/boolptr"
)

// errPVNeedsReprovisioning is returned when a PV has no snapshot and a Delete
// reclaim policy, indicating the underlying storage may no longer exist and the
// PV should be dynamically re-provisioned instead of restored as-is.
var errPVNeedsReprovisioning = fmt.Errorf("persistent volume has no snapshot and Delete reclaim policy; it should be dynamically re-provisioned")

type PVRestorer interface {
	executePVAction(obj *unstructured.Unstructured) (*unstructured.Unstructured, error)
}

type pvRestorer struct {
	logger                  logrus.FieldLogger
	backup                  *api.Backup
	restorePVs              *bool
	volumeSnapshots         []*volume.Snapshot
	volumeSnapshotterGetter VolumeSnapshotterGetter
	kbclient                client.Client
	credentialFileStore     credentials.FileStore
	volInfoTracker          *volume.RestoreVolumeInfoTracker
}

func (r *pvRestorer) executePVAction(obj *unstructured.Unstructured) (*unstructured.Unstructured, error) {
	pvName := obj.GetName()
	if pvName == "" {
		return nil, errors.New("PersistentVolume is missing its name")
	}

	if boolptr.IsSetToFalse(r.restorePVs) {
		// The restore has pv restores disabled, so we can return early
		return obj, nil
	}

	log := r.logger.WithFields(logrus.Fields{"persistentVolume": pvName})

	snapshotInfo, err := getSnapshotInfo(pvName, r.backup, r.volumeSnapshots, r.kbclient, r.credentialFileStore)
	if err != nil {
		return nil, err
	}
	if snapshotInfo == nil {
		log.Infof("No snapshot found for persistent volume")
		if hasDeleteReclaimPolicy(obj.Object) {
			log.Warnf("Persistent volume has Delete reclaim policy but no snapshot; underlying storage may no longer exist, triggering dynamic re-provisioning")
			return nil, errPVNeedsReprovisioning
		}
		return obj, nil
	}

	volumeSnapshotter, err := r.volumeSnapshotterGetter.GetVolumeSnapshotter(snapshotInfo.location.Spec.Provider)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if err := volumeSnapshotter.Init(snapshotInfo.location.Spec.Config); err != nil {
		return nil, errors.WithStack(err)
	}

	volumeID, err := volumeSnapshotter.CreateVolumeFromSnapshot(snapshotInfo.providerSnapshotID, snapshotInfo.volumeType, snapshotInfo.volumeAZ, snapshotInfo.volumeIOPS)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	log.WithField("providerSnapshotID", snapshotInfo.providerSnapshotID).Info("successfully restored persistent volume from snapshot")

	updated1, err := volumeSnapshotter.SetVolumeID(obj, volumeID)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	updated2, ok := updated1.(*unstructured.Unstructured)
	if !ok {
		return nil, errors.Errorf("unexpected type %T", updated1)
	}
	var iops int64
	if snapshotInfo.volumeIOPS != nil {
		iops = *snapshotInfo.volumeIOPS
	}
	r.volInfoTracker.TrackNativeSnapshot(updated2.GetName(), snapshotInfo.providerSnapshotID, snapshotInfo.volumeType, snapshotInfo.volumeAZ, iops)
	return updated2, nil
}

type snapshotInfo struct {
	providerSnapshotID string
	volumeType         string
	volumeAZ           string
	volumeIOPS         *int64
	location           *api.VolumeSnapshotLocation
}

func getSnapshotInfo(pvName string, backup *api.Backup, volumeSnapshots []*volume.Snapshot, client client.Client, credentialStore credentials.FileStore) (*snapshotInfo, error) {
	var pvSnapshot *volume.Snapshot
	for _, snapshot := range volumeSnapshots {
		if snapshot.Spec.PersistentVolumeName == pvName {
			pvSnapshot = snapshot
			break
		}
	}

	if pvSnapshot == nil {
		return nil, nil
	}

	snapshotLocation := &api.VolumeSnapshotLocation{}
	err := client.Get(
		context.Background(),
		types.NamespacedName{Namespace: backup.Namespace, Name: pvSnapshot.Spec.Location},
		snapshotLocation,
	)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// add credential to config
	err = volume.UpdateVolumeSnapshotLocationWithCredentialConfig(snapshotLocation, credentialStore)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &snapshotInfo{
		providerSnapshotID: pvSnapshot.Status.ProviderSnapshotID,
		volumeType:         pvSnapshot.Spec.VolumeType,
		volumeAZ:           pvSnapshot.Spec.VolumeAZ,
		volumeIOPS:         pvSnapshot.Spec.VolumeIOPS,
		location:           snapshotLocation,
	}, nil
}
