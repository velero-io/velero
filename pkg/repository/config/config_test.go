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
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
)

func TestGetRepoIdentifier(t *testing.T) {
	testCases := []struct {
		name               string
		bsl                *velerov1api.BackupStorageLocation
		repoName           string
		getAWSBucketRegion func(s string, config map[string]string) (string, error)
		expected           string
		expectedErr        string
	}{
		{
			name: "error is returned if BSL uses unsupported provider and resticRepoPrefix is not set",
			bsl: &velerov1api.BackupStorageLocation{
				Spec: velerov1api.BackupStorageLocationSpec{
					Provider: "unsupported-provider",
					StorageType: velerov1api.StorageType{
						ObjectStorage: &velerov1api.ObjectStorageLocation{
							Bucket: "bucket-2",
							Prefix: "prefix-2",
						},
					},
				},
			},
			repoName:    "repo-1",
			expectedErr: "invalid backend type velero.io/unsupported-provider, provider unsupported-provider",
		},
		{
			name: "resticRepoPrefix in BSL config is used if set",
			bsl: &velerov1api.BackupStorageLocation{
				Spec: velerov1api.BackupStorageLocationSpec{
					Provider: "custom-repo-identifier",
					Config: map[string]string{
						"resticRepoPrefix": "custom:prefix:/restic",
					},
					StorageType: velerov1api.StorageType{
						ObjectStorage: &velerov1api.ObjectStorageLocation{
							Bucket: "bucket",
							Prefix: "prefix",
						},
					},
				},
			},
			repoName: "repo-1",
			expected: "custom:prefix:/restic/repo-1",
		},
		{
			name: "s3Url in BSL config is used",
			bsl: &velerov1api.BackupStorageLocation{
				Spec: velerov1api.BackupStorageLocationSpec{
					Provider: "custom-repo-identifier",
					Config: map[string]string{
						"s3Url": "s3Url",
					},
					StorageType: velerov1api.StorageType{
						ObjectStorage: &velerov1api.ObjectStorageLocation{
							Bucket: "bucket",
							Prefix: "prefix",
						},
					},
				},
			},
			repoName: "repo-1",
			expected: "s3:s3Url/bucket/prefix/restic/repo-1",
		},
		{
			name: "s3.amazonaws.com URL format is used if region cannot be determined for AWS BSL",
			bsl: &velerov1api.BackupStorageLocation{
				Spec: velerov1api.BackupStorageLocationSpec{
					Provider: "aws",
					StorageType: velerov1api.StorageType{
						ObjectStorage: &velerov1api.ObjectStorageLocation{
							Bucket: "bucket",
						},
					},
				},
			},
			repoName: "repo-1",
			getAWSBucketRegion: func(s string, config map[string]string) (string, error) {
				return "", errors.New("no region found")
			},
			expected:    "",
			expectedErr: "failed to detect the region via bucket: bucket: no region found",
		},
		{
			name: "s3.s3-<region>.amazonaws.com URL format is used if region can be determined for AWS BSL",
			bsl: &velerov1api.BackupStorageLocation{
				Spec: velerov1api.BackupStorageLocationSpec{
					Provider: "aws",
					StorageType: velerov1api.StorageType{
						ObjectStorage: &velerov1api.ObjectStorageLocation{
							Bucket: "bucket",
						},
					},
				},
			},
			repoName: "repo-1",
			getAWSBucketRegion: func(string, map[string]string) (string, error) {
				return "eu-west-1", nil
			},
			expected: "s3:s3-eu-west-1.amazonaws.com/bucket/restic/repo-1",
		},
		{
			name: "prefix is included in repo identifier if set for AWS BSL",
			bsl: &velerov1api.BackupStorageLocation{
				Spec: velerov1api.BackupStorageLocationSpec{
					Provider: "aws",
					StorageType: velerov1api.StorageType{
						ObjectStorage: &velerov1api.ObjectStorageLocation{
							Bucket: "bucket",
							Prefix: "prefix",
						},
					},
				},
			},
			repoName: "repo-1",
			getAWSBucketRegion: func(s string, config map[string]string) (string, error) {
				return "eu-west-1", nil
			},
			expected: "s3:s3-eu-west-1.amazonaws.com/bucket/prefix/restic/repo-1",
		},
		{
			name: "s3Url is used in repo identifier if set for AWS BSL",
			bsl: &velerov1api.BackupStorageLocation{
				Spec: velerov1api.BackupStorageLocationSpec{
					Provider: "aws",
					Config: map[string]string{
						"s3Url": "alternate-url",
					},
					StorageType: velerov1api.StorageType{
						ObjectStorage: &velerov1api.ObjectStorageLocation{
							Bucket: "bucket",
							Prefix: "prefix",
						},
					},
				},
			},
			repoName: "repo-1",
			getAWSBucketRegion: func(s string, config map[string]string) (string, error) {
				return "eu-west-1", nil
			},
			expected: "s3:alternate-url/bucket/prefix/restic/repo-1",
		},
		{
			name: "region is used in repo identifier if set for AWS BSL",
			bsl: &velerov1api.BackupStorageLocation{
				Spec: velerov1api.BackupStorageLocationSpec{
					Provider: "aws",
					Config: map[string]string{
						"region": "us-west-1",
					},
					StorageType: velerov1api.StorageType{
						ObjectStorage: &velerov1api.ObjectStorageLocation{
							Bucket: "bucket",
							Prefix: "prefix",
						},
					},
				},
			},
			repoName: "aws-repo",
			getAWSBucketRegion: func(s string, config map[string]string) (string, error) {
				return "eu-west-1", nil
			},
			expected: "s3:s3-us-west-1.amazonaws.com/bucket/prefix/restic/aws-repo",
		},
		{
			name: "trailing slash in s3Url is not included in repo identifier for AWS BSL",
			bsl: &velerov1api.BackupStorageLocation{
				Spec: velerov1api.BackupStorageLocationSpec{
					Provider: "aws",
					Config: map[string]string{
						"s3Url": "alternate-url-with-trailing-slash/",
					},
					StorageType: velerov1api.StorageType{
						ObjectStorage: &velerov1api.ObjectStorageLocation{
							Bucket: "bucket",
							Prefix: "prefix",
						},
					},
				},
			},
			repoName: "aws-repo",
			getAWSBucketRegion: func(s string, config map[string]string) (string, error) {
				return "eu-west-1", nil
			},
			expected: "s3:alternate-url-with-trailing-slash/bucket/prefix/restic/aws-repo",
		},
		{
			name: "repo identifier includes bucket and prefix for Azure BSL",
			bsl: &velerov1api.BackupStorageLocation{
				Spec: velerov1api.BackupStorageLocationSpec{
					Provider: "azure",
					StorageType: velerov1api.StorageType{
						ObjectStorage: &velerov1api.ObjectStorageLocation{
							Bucket: "azure-bucket",
							Prefix: "azure-prefix",
						},
					},
				},
			},
			repoName: "azure-repo",
			expected: "azure:azure-bucket:/azure-prefix/restic/azure-repo",
		},
		{
			name: "repo identifier includes bucket and prefix for GCP BSL",
			bsl: &velerov1api.BackupStorageLocation{
				Spec: velerov1api.BackupStorageLocationSpec{
					Provider: "gcp",
					StorageType: velerov1api.StorageType{
						ObjectStorage: &velerov1api.ObjectStorageLocation{
							Bucket: "gcp-bucket",
							Prefix: "gcp-prefix",
						},
					},
				},
			},
			repoName: "gcp-repo",
			expected: "gs:gcp-bucket:/gcp-prefix/restic/gcp-repo",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			getAWSBucketRegion = tc.getAWSBucketRegion
			id, err := GetRepoIdentifier(tc.bsl, tc.repoName)
			assert.Equal(t, tc.expected, id)
			if tc.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				require.EqualError(t, err, tc.expectedErr)
				assert.Empty(t, id)
			}
		})
	}
}
