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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"context"

	"cloud.google.com/go/storage"
	"github.com/cockroachdb/errors"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"

	"github.com/vmware-tanzu/velero/test"
)

type GCSStorage string

func (s GCSStorage) IsObjectsInBucket(cloudCredentialsFile, bslBucket, bslPrefix, bslConfig, backupObject string) (bool, error) {
	q := &storage.Query{
		Prefix: bslPrefix,
	}

	ctx := context.Background()
	client, err := storage.NewClient(ctx, option.WithCredentialsFile(cloudCredentialsFile))
	if err != nil {
		return false, errors.Wrapf(err, "Fail to create gcloud client")
	}
	iter := client.Bucket(bslBucket).Objects(context.Background(), q)
	for {
		obj, err := iter.Next()
		if err == iterator.Done {
			//return false, errors.Wrapf(err, fmt.Sprintf("Backup %s was not found under prefix %s \n", backupObject, bslPrefix))
			return false, nil
		}
		if err != nil {
			return false, errors.WithStack(err)
		}
		if obj.Name == bslPrefix {
			fmt.Println("Ignore GCS prefix itself")
			continue
		}
		if strings.Contains(obj.Name, bslPrefix+backupObject+"/") {
			fmt.Printf("Found delete-object %s of %s in bucket %s \n", backupObject, obj.Name, bslBucket)
			return true, nil
		}
	}
}

func (s GCSStorage) DeleteObjectsInBucket(cloudCredentialsFile, bslBucket, bslPrefix, bslConfig, backupObject string) error {
	q := &storage.Query{
		Prefix: bslPrefix,
	}

	ctx := context.Background()
	client, err := storage.NewClient(ctx, option.WithCredentialsFile(cloudCredentialsFile))
	if err != nil {
		return errors.Wrapf(err, "Fail to create gcloud client")
	}
	bucket := client.Bucket(bslBucket)
	iter := bucket.Objects(context.Background(), q)
	for {
		obj, err := iter.Next()
		if err != nil {
			fmt.Printf("GCP bucket iterator exists due to %s\n", err)
			if err == iterator.Done {
				return nil
			}
			return errors.WithStack(err)
		}

		if obj.Name == bslPrefix {
			fmt.Println("Ignore GCS prefix itself")
			continue
		}
		// Only delete folder named as backupObject under prefix
		if strings.Contains(obj.Name, bslPrefix+backupObject+"/") {
			fmt.Printf("Delete item: %s\n", obj.Name)
			if err = bucket.Object(obj.Name).Delete(ctx); err != nil {
				return errors.Wrapf(err, "Fail to delete object %s in bucket %s", obj.Name, bslBucket)
			}
		}
	}
}

func (s GCSStorage) IsSnapshotExisted(cloudCredentialsFile, bslConfig, backupObject string, snapshotCheck test.SnapshotCheckPoint) error {
	ctx := context.Background()
	data, err := os.ReadFile(cloudCredentialsFile)
	if err != nil {
		return errors.Wrapf(err, "Failed reading gcloud credential file %s", cloudCredentialsFile)
	}

	creds, err := google.CredentialsFromJSON(ctx, data)
	if err != nil {
		return errors.Wrapf(err, "Failed getting credentials from JSON data %s", string(data))
	}

	computeService, err := compute.NewService(context.Background(), option.WithCredentialsFile(cloudCredentialsFile))
	if err != nil {
		return errors.Wrapf(err, "Fail to create gcloud compute service")
	}
	// Project ID for this request.
	project := creds.ProjectID
	req := computeService.Snapshots.List(project)
	snapshotCountFound := 0
	if err := req.Pages(ctx, func(page *compute.SnapshotList) error {
		for _, snapshot := range page.Items {
			snapshotDesc := map[string]string{}
			json.Unmarshal([]byte(snapshot.Description), &snapshotDesc)
			if backupObject == snapshotDesc["velero.io/backup"] {
				snapshotCountFound++
			}
		}
		return nil
	}); err != nil {
		return errors.Wrapf(err, "Failed listing snapshot pages")
	}

	if snapshotCountFound != snapshotCheck.ExpectCount {
		return errors.New(fmt.Sprintf("Snapshot count %d is not as expected %d\n", snapshotCountFound, len(snapshotCheck.SnapshotIDList)))
	} else {
		fmt.Printf("Snapshot count %d is as expected %d\n", snapshotCountFound, len(snapshotCheck.SnapshotIDList))
		return nil
	}
}

func (s GCSStorage) GetObject(cloudCredentialsFile, bslBucket, bslPrefix, bslConfig, objectKey string) (io.ReadCloser, error) {
	ctx := context.Background()
	client, err := storage.NewClient(ctx, option.WithCredentialsFile(cloudCredentialsFile))
	if err != nil {
		return nil, errors.Wrapf(err, "fail to create GCloud client")
	}

	return client.Bucket(bslBucket).Object(strings.Join([]string{bslPrefix, objectKey}, "/")).NewReader(ctx)
}
