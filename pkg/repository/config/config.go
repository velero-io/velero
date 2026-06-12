/*
Copyright 2018, 2019 the Velero contributors.

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

package config

import (
	"fmt"
	"path"
	"strings"

	"github.com/cockroachdb/errors"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/persistence"
)

type BackendType string

const (
	AWSBackend   BackendType = "velero.io/aws"
	AzureBackend BackendType = "velero.io/azure"
	GCPBackend   BackendType = "velero.io/gcp"
	FSBackend    BackendType = "velero.io/fs"

	// CredentialsFileKey is the key within a BSL config that is checked to see if
	// the BSL is using its own credentials, rather than those in the environment
	CredentialsFileKey = "credentialsFile"
)

// this func is assigned to a package-level variable so it can be
// replaced when unit-testing
var getAWSBucketRegion = GetAWSBucketRegion

// getRepoPrefix returns the prefix of the value of the --repo flag for
// restic commands, i.e. everything except the "/<repo-name>".
func getRepoPrefix(location *velerov1api.BackupStorageLocation) (string, error) {
	var bucket, prefix string

	if location.Spec.ObjectStorage != nil {
		layout := persistence.NewObjectStoreLayout(location.Spec.ObjectStorage.Prefix)

		bucket = location.Spec.ObjectStorage.Bucket
		prefix = layout.GetResticDir()
	}

	backendType := GetBackendType(location.Spec.Provider, location.Spec.Config)

	if repoPrefix := location.Spec.Config["resticRepoPrefix"]; repoPrefix != "" {
		return repoPrefix, nil
	}

	switch backendType {
	case AWSBackend:
		var url string
		// non-AWS, S3-compatible object store
		if s3Url := location.Spec.Config["s3Url"]; s3Url != "" {
			url = strings.TrimSuffix(s3Url, "/")
		} else {
			var err error
			region := location.Spec.Config["region"]
			if region == "" {
				region, err = getAWSBucketRegion(bucket, location.Spec.Config)
			}
			if err != nil {
				return "", errors.Wrapf(err, "failed to detect the region via bucket: %s", bucket)
			}
			url = fmt.Sprintf("s3-%s.amazonaws.com", region)
		}

		return fmt.Sprintf("s3:%s/%s", url, path.Join(bucket, prefix)), nil
	case AzureBackend:
		return fmt.Sprintf("azure:%s:/%s", bucket, prefix), nil
	case GCPBackend:
		return fmt.Sprintf("gs:%s:/%s", bucket, prefix), nil
	}

	return "", errors.Errorf("invalid backend type %s, provider %s", backendType, location.Spec.Provider)
}

// GetBackendType returns a backend type that is known by Velero.
// If the provider doesn't indicate a known backend type, but the endpoint is
// specified, Velero regards it as a S3 compatible object store and return AWSBackend as the type.
func GetBackendType(provider string, config map[string]string) BackendType {
	if !strings.Contains(provider, "/") {
		provider = "velero.io/" + provider
	}

	bt := BackendType(provider)
	if IsBackendTypeValid(bt) {
		return bt
	} else if config != nil && config["s3Url"] != "" {
		return AWSBackend
	} else {
		return bt
	}
}

func IsBackendTypeValid(backendType BackendType) bool {
	return (backendType == AWSBackend || backendType == AzureBackend || backendType == GCPBackend || backendType == FSBackend)
}

// GetRepoIdentifier returns the string to be used as the value of the --repo flag in
// restic commands for the given repository.
func GetRepoIdentifier(location *velerov1api.BackupStorageLocation, name string) (string, error) {
	prefix, err := getRepoPrefix(location)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s/%s", strings.TrimSuffix(prefix, "/"), name), nil
}
