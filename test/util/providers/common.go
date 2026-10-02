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

package providers

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/cockroachdb/errors"

	"github.com/vmware-tanzu/velero/internal/volume"
	velerotest "github.com/vmware-tanzu/velero/test"
	csi "github.com/vmware-tanzu/velero/test/util/csi"
	velero "github.com/vmware-tanzu/velero/test/util/velero"
)

type ObjectsInStorage interface {
	IsObjectsInBucket(cloudCredentialsFile, bslBucket, bslPrefix, bslConfig, backupObject string) (bool, error)
	DeleteObjectsInBucket(cloudCredentialsFile, bslBucket, bslPrefix, bslConfig, backupObject string) error
	IsSnapshotExisted(cloudCredentialsFile, bslConfig, backupName string, snapshotCheck velerotest.SnapshotCheckPoint) error
	GetObject(cloudCredentialsFile, bslBucket, bslPrefix, bslConfig, objectKey string) (io.ReadCloser, error)
}

func ObjectsShouldBeInBucket(objectStoreProvider, cloudCredentialsFile, bslBucket, bslPrefix, bslConfig, backupName, subPrefix string) error {
	fmt.Printf("|| VERIFICATION || - %s should exist in storage [%s %s]\n", backupName, bslPrefix, subPrefix)
	exist, err := IsObjectsInBucket(objectStoreProvider, cloudCredentialsFile, bslBucket, bslPrefix, bslConfig, backupName, subPrefix)
	if !exist {
		return errors.Wrap(err, fmt.Sprintf("|| UNEXPECTED ||Backup object %s is not exist in object store after backup as expected\n", backupName))
	}
	fmt.Printf("|| EXPECTED || - Backup %s exist in object storage bucket %s\n", backupName, bslBucket)
	return nil
}
func ObjectsShouldNotBeInBucket(objectStoreProvider, cloudCredentialsFile, bslBucket, bslPrefix, bslConfig, backupName, subPrefix string, retryTimes int) error {
	var err error
	var exist bool
	fmt.Printf("|| VERIFICATION || - %s %s should not exist in object store %s\n", subPrefix, backupName, bslPrefix)
	if cloudCredentialsFile == "" {
		return errors.New(fmt.Sprintf("|| ERROR || - Please provide credential file of cloud %s \n", objectStoreProvider))
	}
	for i := 0; i < retryTimes; i++ {
		exist, err = IsObjectsInBucket(objectStoreProvider, cloudCredentialsFile, bslBucket, bslPrefix, bslConfig, backupName, subPrefix)
		if err != nil {
			return errors.Wrapf(err, "|| UNEXPECTED || - Failed to get backup %s in object store\n", backupName)
		}
		if !exist {
			fmt.Printf("|| EXPECTED || - Backup %s is not in object store\n", backupName)
			return nil
		}
		time.Sleep(1 * time.Minute)
	}
	return errors.New(fmt.Sprintf("|| UNEXPECTED ||Backup object %s still exist in object store after backup deletion\n", backupName))
}

// This function returns a storage interface based on the cloud provider for querying objects and snapshots
// When cloudProvider is kind, pass in object storage provider instead. For example, AWS
// Snapshots are not supported on kind.
func getProvider(cloudProvider string) (ObjectsInStorage, error) {
	var s ObjectsInStorage
	switch cloudProvider {
	case velerotest.AWS, velerotest.Vsphere:
		aws := AWSStorage("")
		s = &aws
	case velerotest.GCP:
		gcs := GCSStorage("")
		s = &gcs
	case velerotest.Azure:
		az := AzureStorage("")
		s = &az
	default:
		return nil, errors.New(fmt.Sprintf("Cloud provider %s is not valid", cloudProvider))
	}
	return s, nil
}
func getFullPrefix(bslPrefix, subPrefix string) string {
	if bslPrefix == "" {
		bslPrefix = subPrefix + "/"
	} else {
		//subPrefix must have surfix "/", so that objects under it can be listed
		bslPrefix = strings.Trim(bslPrefix, "/") + "/" + strings.Trim(subPrefix, "/") + "/"
	}
	return bslPrefix
}
func IsObjectsInBucket(objectStoreProvider, cloudCredentialsFile, bslBucket, bslPrefix, bslConfig, backupName, subPrefix string) (bool, error) {
	bslPrefix = getFullPrefix(bslPrefix, subPrefix)
	s, err := getProvider(objectStoreProvider)
	if err != nil {
		return false, errors.Wrapf(err, "Object store provider %s is not valid", objectStoreProvider)
	}
	return s.IsObjectsInBucket(cloudCredentialsFile, bslBucket, bslPrefix, bslConfig, backupName)
}

func DeleteObjectsInBucket(objectStoreProvider, cloudCredentialsFile, bslBucket, bslPrefix, bslConfig, backupName, subPrefix string) error {
	bslPrefix = getFullPrefix(bslPrefix, subPrefix)
	fmt.Printf("|| VERIFICATION || - Delete backup %s in storage %s\n", backupName, bslPrefix)

	if cloudCredentialsFile == "" {
		return errors.New(fmt.Sprintf("|| ERROR || - Please provide credential file of cloud %s \n", objectStoreProvider))
	}
	s, err := getProvider(objectStoreProvider)
	if err != nil {
		return errors.Wrapf(err, "Object store provider %s is not valid", objectStoreProvider)
	}
	err = s.DeleteObjectsInBucket(cloudCredentialsFile, bslBucket, bslPrefix, bslConfig, backupName)
	if err != nil {
		return errors.Wrapf(err, "Fail to delete %s", bslPrefix)
	}
	return nil
}

func CheckSnapshotsInProvider(
	veleroCfg velerotest.VeleroConfig,
	backupName string,
	snapshotCheckPoint velerotest.SnapshotCheckPoint,
	checkStandbyCluster bool,
) error {
	fmt.Printf("|| VERIFICATION || - there should %d snapshots in provider, backup %s\n",
		snapshotCheckPoint.ExpectCount, backupName)

	if veleroCfg.CloudProvider == velerotest.VanillaZFS {
		fmt.Printf("Skip snapshot check for cloud provider %s", veleroCfg.CloudProvider)
		return nil
	}
	if veleroCfg.CloudProvider == velerotest.Vsphere && !veleroCfg.HasVspherePlugin {
		fmt.Printf("Skip snapshot check for vSphere environment that doesn't have Velero vSphere plugin.")
		return nil
	}
	if veleroCfg.CloudProvider == velerotest.Kind {
		if err := checkSnapshotsOnKind(veleroCfg, backupName, snapshotCheckPoint); err != nil {
			return errors.Wrapf(err, "|| UNEXPECTED || - Snapshots are not as expected after backup %s", backupName)
		}
		fmt.Printf("|| EXPECTED || - Snapshots of backup %s are as expected on %s\n", backupName, veleroCfg.CloudProvider)
		return nil
	}
	if veleroCfg.CloudCredentialsFile == "" {
		return errors.New(fmt.Sprintf("|| ERROR || - Please provide credential file of cloud %s \n", veleroCfg.CloudProvider))
	}

	cloudCredentialsFile := veleroCfg.CloudCredentialsFile
	bslBucket := veleroCfg.BSLBucket
	bslConfig := veleroCfg.BSLConfig
	if checkStandbyCluster {
		bslBucket = veleroCfg.AdditionalBSLBucket

		// Only vSphere environment's snapshot on standby cluster is related to BSL.
		if veleroCfg.CloudProvider == velerotest.Vsphere {
			cloudCredentialsFile = veleroCfg.AdditionalBSLCredentials
			bslConfig = veleroCfg.AdditionalBSLConfig
		}
	}

	err := isSnapshotExisted(
		veleroCfg.CloudProvider,
		cloudCredentialsFile,
		bslBucket,
		bslConfig,
		backupName,
		snapshotCheckPoint,
	)
	if err != nil {
		return errors.Wrapf(err, "|| UNEXPECTED || - Snapshots count is not as expected after backup %s", backupName)
	}

	fmt.Printf("|| EXPECTED || - Snapshots of backup %s exist in provider %s\n", backupName, veleroCfg.CloudProvider)
	return nil
}

// checkSnapshotsOnKind verifies a backup's CSI snapshots on a kind cluster,
// which has no cloud snapshot API to ask.
//
// While a backup is being created its VolumeSnapshotContents exist only
// briefly, so they cannot be counted afterwards the way the cloud providers
// count snapshots. The count is settled before this runs in any case:
// BuildSnapshotCheckPointFromVolumeInfo returns an error when a volume is not
// ready to use, and again when the number of snapshots does not match the
// number expected. What it does not look at is the handle it recorded, so a
// volume reported ready with an empty snapshot handle passes today. That is
// what is checked here.
//
// A backup expected to have no snapshots left, after its deletion, is checked
// the other way round: nothing for it may remain in the cluster.
func checkSnapshotsOnKind(
	veleroCfg velerotest.VeleroConfig,
	backupName string,
	snapshotCheckPoint velerotest.SnapshotCheckPoint,
) error {
	if snapshotCheckPoint.ExpectCount == 0 {
		index := map[string]string{"backupNameLabel": backupName}
		if snapshotCheckPoint.NamespaceBackedUp != "" {
			index["namespace"] = snapshotCheckPoint.NamespaceBackedUp
		}
		_, err := csi.CheckVolumeSnapshotCR(*veleroCfg.DefaultClient, index, 0)
		return err
	}

	for i, handle := range snapshotCheckPoint.SnapshotIDList {
		if handle == "" {
			return errors.Errorf(
				"CSI snapshot %d of %d was reported ready with an empty snapshot handle",
				i+1,
				len(snapshotCheckPoint.SnapshotIDList),
			)
		}
	}
	return nil
}

func isSnapshotExisted(cloudProvider, cloudCredentialsFile, bslBucket, bslConfig, backupName string, snapshotCheck velerotest.SnapshotCheckPoint) error {
	s, err := getProvider(cloudProvider)
	if err != nil {
		return errors.Wrapf(err, "Cloud provider %s is not valid", cloudProvider)
	}
	if cloudProvider == velerotest.Vsphere {
		var retSnapshotIDs []string
		ctx, ctxCancel := context.WithTimeout(context.Background(), time.Minute*2)
		defer ctxCancel()
		retSnapshotIDs, err = velero.GetVsphereSnapshotIDs(ctx, time.Hour, snapshotCheck.NamespaceBackedUp, snapshotCheck.PodName)
		if err != nil {
			return errors.Wrapf(err, "Fail to get snapshot CRs of backup%s", backupName)
		}

		bslPrefix := "plugins"
		subPrefix := "vsphere-astrolabe-repo/ivd/data"
		if snapshotCheck.ExpectCount == 0 {
			for _, snapshotID := range retSnapshotIDs {
				err := ObjectsShouldNotBeInBucket(cloudProvider, cloudCredentialsFile, bslBucket, bslPrefix, bslConfig, snapshotID, subPrefix, 5)
				if err != nil {
					return errors.Wrapf(err, "|| UNEXPECTED || - Snapshot %s of backup %s exist in object store", snapshotID, backupName)
				}
			}
		} else {
			if snapshotCheck.ExpectCount != len(retSnapshotIDs) {
				return errors.New(fmt.Sprintf("Snapshot CRs count %d is not equal to expected %d", len(retSnapshotIDs), snapshotCheck.ExpectCount))
			}
			for _, snapshotID := range retSnapshotIDs {
				err := ObjectsShouldBeInBucket(cloudProvider, cloudCredentialsFile, bslBucket, bslPrefix, bslConfig, snapshotID, subPrefix)
				if err != nil {
					return errors.Wrapf(err, "|| UNEXPECTED || - Snapshot %s of backup %s does not exist in object store", snapshotID, backupName)
				}
			}
		}
	} else {
		err = s.IsSnapshotExisted(cloudCredentialsFile, bslConfig, backupName, snapshotCheck)
		if err != nil {
			return errors.Wrapf(err, "Fail to get snapshot of backup %s", backupName)
		}
	}
	return nil
}

func GetVolumeInfoMetadataContent(
	objectStoreProvider,
	cloudCredentialsFile,
	bslBucket,
	bslPrefix,
	bslConfig,
	backupName,
	subPrefix string,
) (io.Reader, error) {
	bslPrefix = strings.Trim(getFullPrefix(bslPrefix, subPrefix), "/")
	volumeFileName := backupName + "-volumeinfo.json.gz"
	fmt.Printf("|| VERIFICATION || - Get backup %s volumeinfo file in storage %s\n", backupName, bslPrefix)
	s, err := getProvider(objectStoreProvider)
	if err != nil {
		return nil, errors.Wrapf(err, "Cloud provider %s is not valid", objectStoreProvider)
	}

	return s.GetObject(cloudCredentialsFile, bslBucket, bslPrefix, bslConfig, volumeFileName)
}

func GetVolumeInfo(
	objectStoreProvider,
	cloudCredentialsFile,
	bslBucket,
	bslPrefix,
	bslConfig,
	backupName,
	subPrefix string,
) ([]*volume.BackupVolumeInfo, error) {
	readCloser, err := GetVolumeInfoMetadataContent(objectStoreProvider,
		cloudCredentialsFile,
		bslBucket,
		bslPrefix,
		bslConfig,
		backupName,
		subPrefix,
	)
	if err != nil {
		return nil, err
	}

	gzr, err := gzip.NewReader(readCloser)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer gzr.Close()

	volumeInfos := make([]*volume.BackupVolumeInfo, 0)

	if err := json.NewDecoder(gzr).Decode(&volumeInfos); err != nil {
		return nil, errors.Wrap(err, "error decoding object data")
	}

	return volumeInfos, nil
}
