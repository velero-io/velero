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
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/pkg/errors"

	. "github.com/vmware-tanzu/velero/test"
	velero "github.com/vmware-tanzu/velero/test/util/velero"
)

type ObjectsInStorage interface {
	IsObjectsInBucket(cloudCredentialsFile, bslBucket, bslPrefix, bslConfig, backupObject string) (bool, error)
	DeleteObjectsInBucket(cloudCredentialsFile, bslBucket, bslPrefix, bslConfig, backupObject string) error
	IsSnapshotExisted(cloudCredentialsFile, bslConfig, backupName string, snapshotCheck SnapshotCheckPoint) error
}

func ObjectsShouldBeInBucket(cloudProvider, cloudCredentialsFile, bslBucket, bslPrefix, bslConfig, backupName, subPrefix string) error {
	fmt.Printf("|| VERIFICATION || - %s should exist in storage [%s %s]\n", backupName, bslPrefix, subPrefix)
	exist, err := IsObjectsInBucket(cloudProvider, cloudCredentialsFile, bslBucket, bslPrefix, bslConfig, backupName, subPrefix)
	if !exist {
		return errors.Wrap(err, fmt.Sprintf("|| UNEXPECTED ||Backup object %s is not exist in object store after backup as expected\n", backupName))
	}
	fmt.Printf("|| EXPECTED || - Backup %s exist in object storage bucket %s\n", backupName, bslBucket)
	return nil
}
func ObjectsShouldNotBeInBucket(cloudProvider, cloudCredentialsFile, bslBucket, bslPrefix, bslConfig, backupName, subPrefix string, retryTimes int) error {
	var err error
	var exist bool
	fmt.Printf("|| VERIFICATION || - %s %s should not exist in object store %s\n", subPrefix, backupName, bslPrefix)
	for i := 0; i < retryTimes; i++ {
		exist, err = IsObjectsInBucket(cloudProvider, cloudCredentialsFile, bslBucket, bslPrefix, bslConfig, backupName, subPrefix)
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
func getProvider(cloudProvider string) (ObjectsInStorage, error) {
	var s ObjectsInStorage
	switch cloudProvider {
	case "aws", "vsphere":
		aws := AWSStorage("")
		s = &aws
	case "gcp":
		gcs := GCSStorage("")
		s = &gcs
	case "azure":
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
func IsObjectsInBucket(cloudProvider, cloudCredentialsFile, bslBucket, bslPrefix, bslConfig, backupName, subPrefix string) (bool, error) {
	bslPrefix = getFullPrefix(bslPrefix, subPrefix)
	s, err := getProvider(cloudProvider)
	if err != nil {
		return false, errors.Wrapf(err, "Cloud provider %s is not valid", cloudProvider)
	}
	return s.IsObjectsInBucket(cloudCredentialsFile, bslBucket, bslPrefix, bslConfig, backupName)
}

func DeleteObjectsInBucket(cloudProvider, cloudCredentialsFile, bslBucket, bslPrefix, bslConfig, backupName, subPrefix string) error {
	bslPrefix = getFullPrefix(bslPrefix, subPrefix)
	fmt.Printf("|| VERIFICATION || - Delete backup %s in storage %s\n", backupName, bslPrefix)
	s, err := getProvider(cloudProvider)
	if err != nil {
		return errors.Wrapf(err, "Cloud provider %s is not valid", cloudProvider)
	}
	err = s.DeleteObjectsInBucket(cloudCredentialsFile, bslBucket, bslPrefix, bslConfig, backupName)
	if err != nil {
		return errors.Wrapf(err, "Fail to delete %s", bslPrefix)
	}
	return nil
}

func SnapshotsShouldNotExistInCloud(cloudProvider, cloudCredentialsFile, bslBucket, bslConfig, backupName string, snapshotCheckPoint SnapshotCheckPoint) error {
	fmt.Printf("|| VERIFICATION || - Snapshots should not exist in cloud, backup %s\n", backupName)
	snapshotCheckPoint.ExpectCount = 0
	err := IsSnapshotExisted(cloudProvider, cloudCredentialsFile, bslBucket, bslConfig, backupName, snapshotCheckPoint)
	if err != nil {
		return errors.Wrapf(err, "|| UNEXPECTED ||Snapshots %s exist in cloud after backup as expected", backupName)
	}
	fmt.Printf("|| EXPECTED || - Snapshots do not exist in cloud, backup %s\n", backupName)
	return nil
}

func SnapshotsShouldBeCreatedInCloud(cloudProvider, cloudCredentialsFile, bslBucket, bslConfig, backupName string, snapshotCheckPoint SnapshotCheckPoint) error {
	fmt.Printf("|| VERIFICATION || - Snapshots should exist in cloud, backup %s\n", backupName)
	err := IsSnapshotExisted(cloudProvider, cloudCredentialsFile, bslBucket, bslConfig, backupName, snapshotCheckPoint)
	if err != nil {
		return errors.Wrapf(err, "|| UNEXPECTED ||Snapshots %s do not exist in cloud after backup as expected", backupName)
	}
	fmt.Printf("|| EXPECTED || - Snapshots exist in cloud, backup %s\n", backupName)
	return nil
}

func IsSnapshotExisted(cloudProvider, cloudCredentialsFile, bslBucket, bslConfig, backupName string, snapshotCheck SnapshotCheckPoint) error {

	s, err := getProvider(cloudProvider)
	if err != nil {
		return errors.Wrapf(err, "Cloud provider %s is not valid", cloudProvider)
	}
	if cloudProvider == "vsphere" {
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
			return errors.Wrapf(err, "Fail to get snapshot of backup%s", backupName)
		}
	}
	return nil
}
