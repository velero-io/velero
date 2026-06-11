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

package provider

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	velerocredentials "github.com/vmware-tanzu/velero/internal/credentials"
	credmock "github.com/vmware-tanzu/velero/internal/credentials/mocks"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/repository/udmrepo"
	reposervicenmocks "github.com/vmware-tanzu/velero/pkg/repository/udmrepo/mocks"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
)

func TestGetStorageCredentials(t *testing.T) {
	testCases := []struct {
		name              string
		backupLocation    velerov1api.BackupStorageLocation
		credFileStore     *credmock.FileStore
		credStoreError    error
		credStorePath     string
		getS3Credentials  func(map[string]string) (*aws.Credentials, error)
		getGCPCredentials func(map[string]string) string
		expected          map[string]string
		expectedErr       string
	}{
		{
			name:        "invalid credentials file store interface",
			expected:    map[string]string{},
			expectedErr: "invalid credentials interface",
		},
		{
			name: "invalid provider",
			backupLocation: velerov1api.BackupStorageLocation{
				Spec: velerov1api.BackupStorageLocationSpec{
					Provider: "invalid-provider",
				},
			},
			credFileStore: new(credmock.FileStore),
			expected:      map[string]string{},
			expectedErr:   "invalid storage provider",
		},
		{
			name: "credential section exists in BSL, file store fail",
			backupLocation: velerov1api.BackupStorageLocation{
				Spec: velerov1api.BackupStorageLocationSpec{
					Provider:   "aws",
					Credential: &corev1api.SecretKeySelector{},
				},
			},
			credFileStore:  new(credmock.FileStore),
			credStoreError: errors.New("fake error"),
			expected:       map[string]string{},
			expectedErr:    "error get credential file in bsl: fake error",
		},
		{
			name: "aws, Credential section not exists in BSL",
			backupLocation: velerov1api.BackupStorageLocation{
				Spec: velerov1api.BackupStorageLocationSpec{
					Provider: "velero.io/aws",
					Config: map[string]string{
						"credentialsFile": "credentials-from-config-map",
					},
				},
			},
			getS3Credentials: func(config map[string]string) (*aws.Credentials, error) {
				return &aws.Credentials{
					AccessKeyID: "from: " + config["credentialsFile"],
				}, nil
			},
			credFileStore: new(credmock.FileStore),
			expected: map[string]string{
				"accessKeyID":     "from: credentials-from-config-map",
				"providerName":    "",
				"secretAccessKey": "",
				"sessionToken":    "",
			},
		},
		{
			name: "aws, Credential section exists in BSL",
			backupLocation: velerov1api.BackupStorageLocation{
				Spec: velerov1api.BackupStorageLocationSpec{
					Provider: "velero.io/aws",
					Config: map[string]string{
						"credentialsFile": "credentials-from-config-map",
					},
					Credential: &corev1api.SecretKeySelector{},
				},
			},
			credFileStore: new(credmock.FileStore),
			credStorePath: "credentials-from-credential-key",
			getS3Credentials: func(config map[string]string) (*aws.Credentials, error) {
				return &aws.Credentials{
					AccessKeyID: "from: " + config["credentialsFile"],
				}, nil
			},

			expected: map[string]string{
				"accessKeyID":     "from: credentials-from-credential-key",
				"providerName":    "",
				"secretAccessKey": "",
				"sessionToken":    "",
			},
		},
		{
			name: "aws, get credentials fail",
			backupLocation: velerov1api.BackupStorageLocation{
				Spec: velerov1api.BackupStorageLocationSpec{
					Provider: "velero.io/aws",
					Config: map[string]string{
						"credentialsFile": "credentials-from-config-map",
					},
				},
			},
			getS3Credentials: func(config map[string]string) (*aws.Credentials, error) {
				return nil, errors.New("fake error")
			},
			credFileStore: new(credmock.FileStore),
			expected:      map[string]string{},
			expectedErr:   "error get s3 credentials: fake error",
		},
		{
			name: "aws, credential file not exist",
			backupLocation: velerov1api.BackupStorageLocation{
				Spec: velerov1api.BackupStorageLocationSpec{
					Provider: "velero.io/aws",
					Config:   map[string]string{},
				},
			},
			getS3Credentials: func(config map[string]string) (*aws.Credentials, error) {
				return nil, nil
			},
			credFileStore: new(credmock.FileStore),
			expected:      map[string]string{},
		},
		{
			name: "azure",
			backupLocation: velerov1api.BackupStorageLocation{
				Spec: velerov1api.BackupStorageLocationSpec{
					Provider:   "velero.io/azure",
					Credential: &corev1api.SecretKeySelector{},
				},
			},
			credFileStore: new(credmock.FileStore),
			expected:      map[string]string{},
		},
		{
			name: "gcp, Credential section not exists in BSL",
			backupLocation: velerov1api.BackupStorageLocation{
				Spec: velerov1api.BackupStorageLocationSpec{
					Provider: "velero.io/gcp",
					Config: map[string]string{
						"credentialsFile": "credentials-from-config-map",
					},
				},
			},
			getGCPCredentials: func(config map[string]string) string {
				return "credentials-from-config-map"
			},
			credFileStore: new(credmock.FileStore),
			expected: map[string]string{
				"credFile": "credentials-from-config-map",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			getS3Credentials = tc.getS3Credentials
			getGCPCredentials = tc.getGCPCredentials

			var fileStore velerocredentials.FileStore
			if tc.credFileStore != nil {
				tc.credFileStore.On("Path", mock.Anything, mock.Anything).Return(tc.credStorePath, tc.credStoreError)
				fileStore = tc.credFileStore
			}

			actual, err := getStorageCredentials(&tc.backupLocation, fileStore)

			require.Equal(t, tc.expected, actual)

			if tc.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.expectedErr)
			}
		})
	}
}

func TestGetStorageVariables(t *testing.T) {
	testCases := []struct {
		name              string
		backupLocation    velerov1api.BackupStorageLocation
		credFileStore     *credmock.FileStore
		repoName          string
		repoBackend       string
		repoConfig        map[string]string
		getS3BucketRegion func(bucket string, config map[string]string) (string, error)
		expected          map[string]string
		expectedErr       string
	}{
		{
			name: "invalid provider",
			backupLocation: velerov1api.BackupStorageLocation{
				Spec: velerov1api.BackupStorageLocationSpec{
					Provider: "invalid-provider",
				},
			},
			expected:    map[string]string{},
			expectedErr: "invalid storage provider",
		},
		{
			name: "aws, ObjectStorage section not exists in BSL, s3Url exist, https",
			backupLocation: velerov1api.BackupStorageLocation{
				Spec: velerov1api.BackupStorageLocationSpec{
					Provider: "velero.io/aws",
					Config: map[string]string{
						"bucket":                "fake-bucket",
						"prefix":                "fake-prefix",
						"region":                "fake-region/",
						"s3Url":                 "https://fake-url/",
						"insecureSkipTLSVerify": "true",
					},
				},
			},
			repoBackend: "fake-repo-type",
			expected: map[string]string{
				"bucket":        "fake-bucket",
				"prefix":        "fake-prefix/fake-repo-type/",
				"region":        "fake-region",
				"fspath":        "",
				"endpoint":      "fake-url",
				"doNotUseTLS":   "false",
				"skipTLSVerify": "true",
			},
		},
		{
			name: "aws, ObjectStorage section not exists in BSL, s3Url exist, invalid",
			backupLocation: velerov1api.BackupStorageLocation{
				Spec: velerov1api.BackupStorageLocationSpec{
					Provider: "velero.io/aws",
					Config: map[string]string{
						"bucket":                "fake-bucket",
						"prefix":                "fake-prefix",
						"region":                "fake-region/",
						"s3Url":                 "https://fake-url/fake-path",
						"insecureSkipTLSVerify": "true",
					},
				},
			},
			repoBackend: "fake-repo-type",
			expected:    map[string]string{},
			expectedErr: "path is not expected in s3Url https://fake-url/fake-path",
		},
		{
			name: "aws, ObjectStorage section not exists in BSL, s3Url not exist",
			backupLocation: velerov1api.BackupStorageLocation{
				Spec: velerov1api.BackupStorageLocationSpec{
					Provider: "velero.io/aws",
					Config: map[string]string{
						"bucket":                "fake-bucket",
						"prefix":                "fake-prefix",
						"insecureSkipTLSVerify": "false",
					},
				},
			},
			getS3BucketRegion: func(bucket string, config map[string]string) (string, error) {
				return "region from bucket: " + bucket, nil
			},
			repoBackend: "fake-repo-type",
			expected: map[string]string{
				"bucket":        "fake-bucket",
				"prefix":        "fake-prefix/fake-repo-type/",
				"region":        "region from bucket: fake-bucket",
				"fspath":        "",
				"endpoint":      "s3-region from bucket: fake-bucket.amazonaws.com",
				"doNotUseTLS":   "false",
				"skipTLSVerify": "false",
			},
		},
		{
			name: "aws, ObjectStorage section not exists in BSL, s3Url not exist, get region fail",
			backupLocation: velerov1api.BackupStorageLocation{
				Spec: velerov1api.BackupStorageLocationSpec{
					Provider: "velero.io/aws",
					Config:   map[string]string{},
				},
			},
			getS3BucketRegion: func(bucket string, config map[string]string) (string, error) {
				return "", errors.New("fake error")
			},
			expected:    map[string]string{},
			expectedErr: "error get s3 bucket region: fake error",
		},
		{
			name: "aws, ObjectStorage section exists in BSL, s3Url exist, http",
			backupLocation: velerov1api.BackupStorageLocation{
				Spec: velerov1api.BackupStorageLocationSpec{
					Provider: "velero.io/aws",
					Config: map[string]string{
						"bucket":                "fake-bucket-config",
						"prefix":                "fake-prefix-config",
						"region":                "fake-region",
						"s3Url":                 "http://fake-url/",
						"insecureSkipTLSVerify": "false",
					},
					StorageType: velerov1api.StorageType{
						ObjectStorage: &velerov1api.ObjectStorageLocation{
							Bucket: "fake-bucket-object-store",
							Prefix: "fake-prefix-object-store",
						},
					},
				},
			},
			getS3BucketRegion: func(bucket string, config map[string]string) (string, error) {
				return "region from bucket: " + bucket, nil
			},
			repoBackend: "fake-repo-type",
			expected: map[string]string{
				"bucket":        "fake-bucket-object-store",
				"prefix":        "fake-prefix-object-store/fake-repo-type/",
				"region":        "fake-region",
				"fspath":        "",
				"endpoint":      "fake-url",
				"doNotUseTLS":   "true",
				"skipTLSVerify": "false",
			},
		},
		{
			name: "aws, ObjectStorage section exists in BSL, s3Url exist, https, custom CA exist",
			backupLocation: velerov1api.BackupStorageLocation{
				Spec: velerov1api.BackupStorageLocationSpec{
					Provider: "velero.io/aws",
					Config: map[string]string{
						"bucket":                "fake-bucket-config",
						"prefix":                "fake-prefix-config",
						"region":                "fake-region",
						"s3Url":                 "https://fake-url/",
						"insecureSkipTLSVerify": "false",
					},
					StorageType: velerov1api.StorageType{
						ObjectStorage: &velerov1api.ObjectStorageLocation{
							Bucket: "fake-bucket-object-store",
							Prefix: "fake-prefix-object-store",
							CACert: []byte{0x01, 0x02, 0x03, 0x04, 0x05},
						},
					},
				},
			},
			getS3BucketRegion: func(bucket string, config map[string]string) (string, error) {
				return "region from bucket: " + bucket, nil
			},
			repoBackend: "fake-repo-type",
			expected: map[string]string{
				"bucket":        "fake-bucket-object-store",
				"prefix":        "fake-prefix-object-store/fake-repo-type/",
				"region":        "fake-region",
				"fspath":        "",
				"endpoint":      "fake-url",
				"doNotUseTLS":   "false",
				"skipTLSVerify": "false",
				"caCert":        base64.StdEncoding.EncodeToString([]byte{0x01, 0x02, 0x03, 0x04, 0x05}),
			},
		},
		{
			name: "azure",
			backupLocation: velerov1api.BackupStorageLocation{
				Spec: velerov1api.BackupStorageLocationSpec{
					Provider: "velero.io/azure",
					Config: map[string]string{
						"bucket": "fake-bucket-config",
						"prefix": "fake-prefix-config",
						"region": "fake-region",
						"fspath": "",
					},
					StorageType: velerov1api.StorageType{
						ObjectStorage: &velerov1api.ObjectStorageLocation{
							Bucket: "fake-bucket-object-store",
							Prefix: "fake-prefix-object-store",
						},
					},
				},
			},
			credFileStore: new(credmock.FileStore),
			repoBackend:   "fake-repo-type",
			expected: map[string]string{
				"bucket": "fake-bucket-object-store",
				"prefix": "fake-prefix-object-store/fake-repo-type/",
				"region": "fake-region",
				"fspath": "",
			},
		},
		{
			name: "fs",
			backupLocation: velerov1api.BackupStorageLocation{
				Spec: velerov1api.BackupStorageLocationSpec{
					Provider: "velero.io/fs",
					Config: map[string]string{
						"fspath": "fake-path",
						"prefix": "fake-prefix",
					},
				},
			},
			repoBackend: "fake-repo-type",
			expected: map[string]string{
				"fspath": "fake-path",
				"bucket": "",
				"prefix": "fake-prefix/fake-repo-type/",
				"region": "",
			},
		},
		{
			name: "fs with repo config",
			backupLocation: velerov1api.BackupStorageLocation{
				Spec: velerov1api.BackupStorageLocationSpec{
					Provider: "velero.io/fs",
					Config: map[string]string{
						"fspath": "fake-path",
						"prefix": "fake-prefix",
					},
				},
			},
			repoBackend: "fake-repo-type",
			repoConfig: map[string]string{
				udmrepo.StoreOptionCacheLimit: "1000",
			},
			expected: map[string]string{
				"fspath":       "fake-path",
				"bucket":       "",
				"prefix":       "fake-prefix/fake-repo-type/",
				"region":       "",
				"cacheLimitMB": "1000",
			},
		},
		{
			name: "fs with throttle config",
			backupLocation: velerov1api.BackupStorageLocation{
				Spec: velerov1api.BackupStorageLocationSpec{
					Provider: "velero.io/fs",
					Config: map[string]string{
						"fspath": "fake-path",
						"prefix": "fake-prefix",
					},
				},
			},
			repoBackend: "fake-repo-type",
			repoConfig: map[string]string{
				udmrepo.ThrottleOptionUploadBytes:   "838860800",
				udmrepo.ThrottleOptionDownloadBytes: "838860800",
				udmrepo.ThrottleOptionReadOps:       "100",
				udmrepo.ThrottleOptionWriteOps:      "100",
				udmrepo.ThrottleOptionListOps:       "50",
			},
			expected: map[string]string{
				"fspath":                "fake-path",
				"bucket":                "",
				"prefix":                "fake-prefix/fake-repo-type/",
				"region":                "",
				"ThrottleUploadBytes":   "838860800",
				"ThrottleDownloadBytes": "838860800",
				"ThrottleReadOPS":       "100",
				"ThrottleWriteOPS":      "100",
				"ThrottleListOPS":       "50",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			getS3BucketRegion = tc.getS3BucketRegion

			actual, err := getStorageVariables(&tc.backupLocation, tc.repoBackend, tc.repoName, tc.repoConfig, velerocredentials.CredentialGetter{})

			require.Equal(t, tc.expected, actual)

			if tc.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.expectedErr)
			}
		})
	}
}

func TestGetRepoPassword(t *testing.T) {
	testCases := []struct {
		name            string
		getter          *credmock.SecretStore
		credStoreReturn string
		credStoreError  error
		cached          string
		expected        string
		expectedErr     string
	}{
		{
			name:        "invalid secret interface",
			expectedErr: "invalid credentials interface",
		},
		{
			name:           "error from secret interface",
			getter:         new(credmock.SecretStore),
			credStoreError: errors.New("fake error"),
			expectedErr:    "error to get password: fake error",
		},
		{
			name:            "secret with whitespace",
			getter:          new(credmock.SecretStore),
			credStoreReturn: " fake-passwor d  ",
			expected:        "fake-passwor d",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var secretStore velerocredentials.SecretStore
			if tc.getter != nil {
				tc.getter.On("Get", mock.Anything, mock.Anything).Return(tc.credStoreReturn, tc.credStoreError)
				secretStore = tc.getter
			}

			urp := unifiedRepoProvider{
				credentialGetter: velerocredentials.CredentialGetter{
					FromSecret: secretStore,
				},
			}

			password, err := getRepoPassword(urp.credentialGetter.FromSecret)

			require.Equal(t, tc.expected, password)

			if tc.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.expectedErr)
			}
		})
	}
}

func TestGetStoreOptions(t *testing.T) {
	testCases := []struct {
		name        string
		funcTable   localFuncTable
		repoParam   any
		expected    map[string]string
		expectedErr string
	}{
		{
			name:        "wrong param type",
			repoParam:   struct{}{},
			expected:    map[string]string{},
			expectedErr: "invalid parameter, expect provider.RepoParam, actual struct {}",
		},
		{
			name: "get storage variable fail",
			repoParam: RepoParam{
				BackupLocation: &velerov1api.BackupStorageLocation{},
				BackupRepo:     &velerov1api.BackupRepository{},
			},
			funcTable: localFuncTable{
				getStorageVariables: func(*velerov1api.BackupStorageLocation, string, string, map[string]string, velerocredentials.CredentialGetter) (map[string]string, error) {
					return map[string]string{}, errors.New("fake-error-2")
				},
			},
			expected:    map[string]string{},
			expectedErr: "error to get storage variables: fake-error-2",
		},
		{
			name: "get storage credentials fail",
			repoParam: RepoParam{
				BackupLocation: &velerov1api.BackupStorageLocation{},
				BackupRepo:     &velerov1api.BackupRepository{},
			},
			funcTable: localFuncTable{
				getStorageVariables: func(*velerov1api.BackupStorageLocation, string, string, map[string]string, velerocredentials.CredentialGetter) (map[string]string, error) {
					return map[string]string{}, nil
				},
				getStorageCredentials: func(*velerov1api.BackupStorageLocation, velerocredentials.FileStore) (map[string]string, error) {
					return map[string]string{}, errors.New("fake-error-3")
				},
			},
			expected:    map[string]string{},
			expectedErr: "error to get repo credentials: fake-error-3",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			funcTable = tc.funcTable

			urp := unifiedRepoProvider{}

			options, err := urp.GetStoreOptions(tc.repoParam)

			require.Equal(t, tc.expected, options)

			if tc.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.expectedErr)
			}
		})
	}
}

func TestPrepareRepo(t *testing.T) {
	bsl := velerov1api.BackupStorageLocation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "fake-bsl",
			Namespace: velerov1api.DefaultNamespace,
		},
	}

	testCases := []struct {
		name            string
		funcTable       localFuncTable
		getter          *credmock.SecretStore
		repoService     *reposervicenmocks.BackupRepoService
		retFuncCreate   func(context.Context, udmrepo.RepoOptions) error
		retFuncCheck    func(context.Context, udmrepo.RepoOptions, bool) (bool, error)
		credStoreReturn string
		credStoreError  error
		readOnlyBSL     bool
		expectedErr     string
	}{
		{
			name:        "get repo option fail",
			repoService: new(reposervicenmocks.BackupRepoService),
			expectedErr: "error to get repo options: error to get repo password: invalid credentials interface",
		},
		{
			name:           "get repo option fail, get password fail",
			getter:         new(credmock.SecretStore),
			repoService:    new(reposervicenmocks.BackupRepoService),
			credStoreError: errors.New("fake-password-error"),
			expectedErr:    "error to get repo options: error to get repo password: error to get password: fake-password-error",
		},
		{
			name:            "get repo option fail, get store options fail",
			getter:          new(credmock.SecretStore),
			repoService:     new(reposervicenmocks.BackupRepoService),
			credStoreReturn: "fake-password",
			funcTable: localFuncTable{
				getStorageVariables: func(*velerov1api.BackupStorageLocation, string, string, map[string]string, velerocredentials.CredentialGetter) (map[string]string, error) {
					return map[string]string{}, errors.New("fake-store-option-error")
				},
			},
			expectedErr: "error to get repo options: error to get storage variables: fake-store-option-error",
		},
		{
			name:            "check error",
			getter:          new(credmock.SecretStore),
			credStoreReturn: "fake-password",
			funcTable: localFuncTable{
				getStorageVariables: func(*velerov1api.BackupStorageLocation, string, string, map[string]string, velerocredentials.CredentialGetter) (map[string]string, error) {
					return map[string]string{}, nil
				},
				getStorageCredentials: func(*velerov1api.BackupStorageLocation, velerocredentials.FileStore) (map[string]string, error) {
					return map[string]string{}, nil
				},
			},
			repoService: new(reposervicenmocks.BackupRepoService),
			retFuncCheck: func(ctx context.Context, repoOption udmrepo.RepoOptions, readOnly bool) (bool, error) {
				return false, errors.New("fake-error")
			},
			expectedErr: "error to check backup repo: fake-error",
		},
		{
			name:            "already initialized",
			getter:          new(credmock.SecretStore),
			credStoreReturn: "fake-password",
			funcTable: localFuncTable{
				getStorageVariables: func(*velerov1api.BackupStorageLocation, string, string, map[string]string, velerocredentials.CredentialGetter) (map[string]string, error) {
					return map[string]string{}, nil
				},
				getStorageCredentials: func(*velerov1api.BackupStorageLocation, velerocredentials.FileStore) (map[string]string, error) {
					return map[string]string{}, nil
				},
			},
			repoService: new(reposervicenmocks.BackupRepoService),
			retFuncCheck: func(ctx context.Context, repoOption udmrepo.RepoOptions, readOnly bool) (bool, error) {
				return true, nil
			},
			retFuncCreate: func(ctx context.Context, repoOption udmrepo.RepoOptions) error {
				return errors.New("fake-error")
			},
		},
		{
			name:            "bsl is readonly",
			readOnlyBSL:     true,
			getter:          new(credmock.SecretStore),
			credStoreReturn: "fake-password",
			funcTable: localFuncTable{
				getStorageVariables: func(*velerov1api.BackupStorageLocation, string, string, map[string]string, velerocredentials.CredentialGetter) (map[string]string, error) {
					return map[string]string{}, nil
				},
				getStorageCredentials: func(*velerov1api.BackupStorageLocation, velerocredentials.FileStore) (map[string]string, error) {
					return map[string]string{}, nil
				},
			},
			repoService: new(reposervicenmocks.BackupRepoService),
			retFuncCheck: func(ctx context.Context, repoOption udmrepo.RepoOptions, readOnly bool) (bool, error) {
				return false, nil
			},
			retFuncCreate: func(ctx context.Context, repoOption udmrepo.RepoOptions) error {
				return errors.New("fake-error-2")
			},
			expectedErr: "cannot create new backup repo for read-only backup storage location velero/fake-bsl",
		},
		{
			name:            "create fail",
			getter:          new(credmock.SecretStore),
			credStoreReturn: "fake-password",
			funcTable: localFuncTable{
				getStorageVariables: func(*velerov1api.BackupStorageLocation, string, string, map[string]string, velerocredentials.CredentialGetter) (map[string]string, error) {
					return map[string]string{}, nil
				},
				getStorageCredentials: func(*velerov1api.BackupStorageLocation, velerocredentials.FileStore) (map[string]string, error) {
					return map[string]string{}, nil
				},
			},
			repoService: new(reposervicenmocks.BackupRepoService),
			retFuncCheck: func(ctx context.Context, repoOption udmrepo.RepoOptions, readOnly bool) (bool, error) {
				return false, nil
			},
			retFuncCreate: func(ctx context.Context, repoOption udmrepo.RepoOptions) error {
				return errors.New("fake-error-1")
			},
			expectedErr: "error to create backup repo: fake-error-1",
		},
		{
			name:            "initialize error",
			getter:          new(credmock.SecretStore),
			credStoreReturn: "fake-password",
			funcTable: localFuncTable{
				getStorageVariables: func(*velerov1api.BackupStorageLocation, string, string, map[string]string, velerocredentials.CredentialGetter) (map[string]string, error) {
					return map[string]string{}, nil
				},
				getStorageCredentials: func(*velerov1api.BackupStorageLocation, velerocredentials.FileStore) (map[string]string, error) {
					return map[string]string{}, nil
				},
			},
			repoService: new(reposervicenmocks.BackupRepoService),
			retFuncCheck: func(ctx context.Context, repoOption udmrepo.RepoOptions, readOnly bool) (bool, error) {
				return false, nil
			},
			retFuncCreate: func(ctx context.Context, repoOption udmrepo.RepoOptions) error {
				return errors.New("fake-error-2")
			},
			expectedErr: "error to create backup repo: fake-error-2",
		},
		{
			name:            "initialize succeed",
			getter:          new(credmock.SecretStore),
			credStoreReturn: "fake-password",
			funcTable: localFuncTable{
				getStorageVariables: func(*velerov1api.BackupStorageLocation, string, string, map[string]string, velerocredentials.CredentialGetter) (map[string]string, error) {
					return map[string]string{}, nil
				},
				getStorageCredentials: func(*velerov1api.BackupStorageLocation, velerocredentials.FileStore) (map[string]string, error) {
					return map[string]string{}, nil
				},
			},
			repoService: new(reposervicenmocks.BackupRepoService),
			retFuncCheck: func(ctx context.Context, repoOption udmrepo.RepoOptions, readOnly bool) (bool, error) {
				return false, nil
			},
			retFuncCreate: func(ctx context.Context, repoOption udmrepo.RepoOptions) error {
				return nil
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			funcTable = tc.funcTable

			var secretStore velerocredentials.SecretStore
			if tc.getter != nil {
				tc.getter.On("Get", mock.Anything, mock.Anything).Return(tc.credStoreReturn, tc.credStoreError)
				secretStore = tc.getter
			}

			urp := unifiedRepoProvider{
				credentialGetter: velerocredentials.CredentialGetter{
					FromSecret: secretStore,
				},
				repoService: tc.repoService,
				log:         velerotest.NewLogger(),
			}

			tc.repoService.On("IsReady", mock.Anything, mock.Anything, mock.Anything).Return(tc.retFuncCheck)
			tc.repoService.On("Create", mock.Anything, mock.Anything, mock.Anything).Return(tc.retFuncCreate)

			if tc.readOnlyBSL {
				bsl.Spec.AccessMode = velerov1api.BackupStorageLocationAccessModeReadOnly
			} else {
				bsl.Spec.AccessMode = velerov1api.BackupStorageLocationAccessModeReadWrite
			}

			err := urp.PrepareRepo(t.Context(), RepoParam{
				BackupLocation: &bsl,
				BackupRepo:     &velerov1api.BackupRepository{},
			})

			if tc.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.expectedErr)
			}
		})
	}
}

func TestForget(t *testing.T) {
	var backupRepo *reposervicenmocks.BackupRepo

	testCases := []struct {
		name            string
		funcTable       localFuncTable
		getter          *credmock.SecretStore
		repoService     *reposervicenmocks.BackupRepoService
		backupRepo      *reposervicenmocks.BackupRepo
		retFuncOpen     []any
		retFuncDelete   any
		retFuncFlush    any
		credStoreReturn string
		credStoreError  error
		expectedErr     string
	}{
		{
			name:        "get repo option fail",
			expectedErr: "error to get repo options: error to get repo password: invalid credentials interface",
		},
		{
			name:            "repo open fail",
			getter:          new(credmock.SecretStore),
			credStoreReturn: "fake-password",
			funcTable: localFuncTable{
				getStorageVariables: func(*velerov1api.BackupStorageLocation, string, string, map[string]string, velerocredentials.CredentialGetter) (map[string]string, error) {
					return map[string]string{}, nil
				},
				getStorageCredentials: func(*velerov1api.BackupStorageLocation, velerocredentials.FileStore) (map[string]string, error) {
					return map[string]string{}, nil
				},
			},
			repoService: new(reposervicenmocks.BackupRepoService),
			retFuncOpen: []any{
				func(context.Context, udmrepo.RepoOptions) udmrepo.BackupRepo {
					return backupRepo
				},

				func(context.Context, udmrepo.RepoOptions) error {
					return errors.New("fake-error-2")
				},
			},
			expectedErr: "error to open backup repo: fake-error-2",
		},
		{
			name:            "delete fail",
			getter:          new(credmock.SecretStore),
			credStoreReturn: "fake-password",
			funcTable: localFuncTable{
				getStorageVariables: func(*velerov1api.BackupStorageLocation, string, string, map[string]string, velerocredentials.CredentialGetter) (map[string]string, error) {
					return map[string]string{}, nil
				},
				getStorageCredentials: func(*velerov1api.BackupStorageLocation, velerocredentials.FileStore) (map[string]string, error) {
					return map[string]string{}, nil
				},
			},
			repoService: new(reposervicenmocks.BackupRepoService),
			backupRepo:  new(reposervicenmocks.BackupRepo),
			retFuncOpen: []any{
				func(context.Context, udmrepo.RepoOptions) udmrepo.BackupRepo {
					return backupRepo
				},

				func(context.Context, udmrepo.RepoOptions) error {
					return nil
				},
			},
			retFuncDelete: func(context.Context, udmrepo.ID) error {
				return errors.New("fake-error-3")
			},
			expectedErr: "error to delete manifest: fake-error-3",
		},
		{
			name:            "flush fail",
			getter:          new(credmock.SecretStore),
			credStoreReturn: "fake-password",
			funcTable: localFuncTable{
				getStorageVariables: func(*velerov1api.BackupStorageLocation, string, string, map[string]string, velerocredentials.CredentialGetter) (map[string]string, error) {
					return map[string]string{}, nil
				},
				getStorageCredentials: func(*velerov1api.BackupStorageLocation, velerocredentials.FileStore) (map[string]string, error) {
					return map[string]string{}, nil
				},
			},
			repoService: new(reposervicenmocks.BackupRepoService),
			backupRepo:  new(reposervicenmocks.BackupRepo),
			retFuncOpen: []any{
				func(context.Context, udmrepo.RepoOptions) udmrepo.BackupRepo {
					return backupRepo
				},

				func(context.Context, udmrepo.RepoOptions) error {
					return nil
				},
			},
			retFuncDelete: func(context.Context, udmrepo.ID) error {
				return nil
			},
			retFuncFlush: func(context.Context) error {
				return errors.New("fake-error-4")
			},
			expectedErr: "error to flush repo: fake-error-4",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			funcTable = tc.funcTable

			var secretStore velerocredentials.SecretStore
			if tc.getter != nil {
				tc.getter.On("Get", mock.Anything, mock.Anything).Return(tc.credStoreReturn, tc.credStoreError)
				secretStore = tc.getter
			}

			urp := unifiedRepoProvider{
				credentialGetter: velerocredentials.CredentialGetter{
					FromSecret: secretStore,
				},
				repoService: tc.repoService,
				log:         velerotest.NewLogger(),
			}

			backupRepo = tc.backupRepo

			if tc.repoService != nil {
				tc.repoService.On("Open", mock.Anything, mock.Anything).Return(tc.retFuncOpen[0], tc.retFuncOpen[1])
			}

			if tc.backupRepo != nil {
				backupRepo.On("DeleteManifest", mock.Anything, mock.Anything).Return(tc.retFuncDelete)
				backupRepo.On("Flush", mock.Anything).Return(tc.retFuncFlush)
				backupRepo.On("Close", mock.Anything).Return(nil)
			}

			err := urp.Forget(t.Context(), "", RepoParam{
				BackupLocation: &velerov1api.BackupStorageLocation{},
				BackupRepo:     &velerov1api.BackupRepository{},
			})

			if tc.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.expectedErr)
			}
		})
	}
}

func TestBatchForget(t *testing.T) {
	var backupRepo *reposervicenmocks.BackupRepo

	testCases := []struct {
		name            string
		funcTable       localFuncTable
		getter          *credmock.SecretStore
		repoService     *reposervicenmocks.BackupRepoService
		backupRepo      *reposervicenmocks.BackupRepo
		retFuncOpen     []any
		retFuncDelete   any
		retFuncFlush    any
		credStoreReturn string
		credStoreError  error
		snapshots       []string
		expectedErr     []string
	}{
		{
			name:        "get repo option fail",
			expectedErr: []string{"error to get repo options: error to get repo password: invalid credentials interface"},
		},
		{
			name:            "repo open fail",
			getter:          new(credmock.SecretStore),
			credStoreReturn: "fake-password",
			funcTable: localFuncTable{
				getStorageVariables: func(*velerov1api.BackupStorageLocation, string, string, map[string]string, velerocredentials.CredentialGetter) (map[string]string, error) {
					return map[string]string{}, nil
				},
				getStorageCredentials: func(*velerov1api.BackupStorageLocation, velerocredentials.FileStore) (map[string]string, error) {
					return map[string]string{}, nil
				},
			},
			repoService: new(reposervicenmocks.BackupRepoService),
			retFuncOpen: []any{
				func(context.Context, udmrepo.RepoOptions) udmrepo.BackupRepo {
					return backupRepo
				},

				func(context.Context, udmrepo.RepoOptions) error {
					return errors.New("fake-error-2")
				},
			},
			expectedErr: []string{"error to open backup repo: fake-error-2"},
		},
		{
			name:            "delete fail",
			getter:          new(credmock.SecretStore),
			credStoreReturn: "fake-password",
			funcTable: localFuncTable{
				getStorageVariables: func(*velerov1api.BackupStorageLocation, string, string, map[string]string, velerocredentials.CredentialGetter) (map[string]string, error) {
					return map[string]string{}, nil
				},
				getStorageCredentials: func(*velerov1api.BackupStorageLocation, velerocredentials.FileStore) (map[string]string, error) {
					return map[string]string{}, nil
				},
			},
			repoService: new(reposervicenmocks.BackupRepoService),
			backupRepo:  new(reposervicenmocks.BackupRepo),
			retFuncOpen: []any{
				func(context.Context, udmrepo.RepoOptions) udmrepo.BackupRepo {
					return backupRepo
				},

				func(context.Context, udmrepo.RepoOptions) error {
					return nil
				},
			},
			retFuncDelete: func(context.Context, udmrepo.ID) error {
				return errors.New("fake-error-3")
			},
			snapshots:   []string{"snapshot-1", "snapshot-2"},
			expectedErr: []string{"error to delete manifest snapshot-1: fake-error-3", "error to delete manifest snapshot-2: fake-error-3"},
		},
		{
			name:            "flush fail",
			getter:          new(credmock.SecretStore),
			credStoreReturn: "fake-password",
			funcTable: localFuncTable{
				getStorageVariables: func(*velerov1api.BackupStorageLocation, string, string, map[string]string, velerocredentials.CredentialGetter) (map[string]string, error) {
					return map[string]string{}, nil
				},
				getStorageCredentials: func(*velerov1api.BackupStorageLocation, velerocredentials.FileStore) (map[string]string, error) {
					return map[string]string{}, nil
				},
			},
			repoService: new(reposervicenmocks.BackupRepoService),
			backupRepo:  new(reposervicenmocks.BackupRepo),
			retFuncOpen: []any{
				func(context.Context, udmrepo.RepoOptions) udmrepo.BackupRepo {
					return backupRepo
				},

				func(context.Context, udmrepo.RepoOptions) error {
					return nil
				},
			},
			retFuncDelete: func(context.Context, udmrepo.ID) error {
				return nil
			},
			retFuncFlush: func(context.Context) error {
				return errors.New("fake-error-4")
			},
			expectedErr: []string{"error to flush repo: fake-error-4"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			funcTable = tc.funcTable

			var secretStore velerocredentials.SecretStore
			if tc.getter != nil {
				tc.getter.On("Get", mock.Anything, mock.Anything).Return(tc.credStoreReturn, tc.credStoreError)
				secretStore = tc.getter
			}

			urp := unifiedRepoProvider{
				credentialGetter: velerocredentials.CredentialGetter{
					FromSecret: secretStore,
				},
				repoService: tc.repoService,
				log:         velerotest.NewLogger(),
			}

			backupRepo = tc.backupRepo

			if tc.repoService != nil {
				tc.repoService.On("Open", mock.Anything, mock.Anything).Return(tc.retFuncOpen[0], tc.retFuncOpen[1])
			}

			if tc.backupRepo != nil {
				backupRepo.On("DeleteManifest", mock.Anything, mock.Anything).Return(tc.retFuncDelete)
				backupRepo.On("Flush", mock.Anything).Return(tc.retFuncFlush)
				backupRepo.On("Close", mock.Anything).Return(nil)
			}

			errs := urp.BatchForget(t.Context(), tc.snapshots, RepoParam{
				BackupLocation: &velerov1api.BackupStorageLocation{},
				BackupRepo:     &velerov1api.BackupRepository{},
			})

			if tc.expectedErr == nil {
				assert.Empty(t, errs)
			} else {
				assert.Len(t, errs, len(tc.expectedErr))

				for i := range tc.expectedErr {
					assert.EqualError(t, errs[i], tc.expectedErr[i])
				}
			}
		})
	}
}

func TestInitRepo(t *testing.T) {
	bsl := velerov1api.BackupStorageLocation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "fake-bsl",
			Namespace: velerov1api.DefaultNamespace,
		},
	}

	testCases := []struct {
		name            string
		funcTable       localFuncTable
		getter          *credmock.SecretStore
		repoService     *reposervicenmocks.BackupRepoService
		retFuncInit     any
		credStoreReturn string
		credStoreError  error
		readOnlyBSL     bool
		expectedErr     string
	}{
		{
			name:        "bsl is readonly",
			readOnlyBSL: true,
			expectedErr: "cannot create new backup repo for read-only backup storage location velero/fake-bsl",
		},
		{
			name:        "get repo option fail",
			expectedErr: "error to get repo options: error to get repo password: invalid credentials interface",
		},
		{
			name:            "repo init fail",
			getter:          new(credmock.SecretStore),
			credStoreReturn: "fake-password",
			funcTable: localFuncTable{
				getStorageVariables: func(*velerov1api.BackupStorageLocation, string, string, map[string]string, velerocredentials.CredentialGetter) (map[string]string, error) {
					return map[string]string{}, nil
				},
				getStorageCredentials: func(*velerov1api.BackupStorageLocation, velerocredentials.FileStore) (map[string]string, error) {
					return map[string]string{}, nil
				},
			},
			repoService: new(reposervicenmocks.BackupRepoService),
			retFuncInit: func(context.Context, udmrepo.RepoOptions) error {
				return errors.New("fake-error-1")
			},
			expectedErr: "error to init backup repo: fake-error-1",
		},
		{
			name:            "succeed",
			getter:          new(credmock.SecretStore),
			credStoreReturn: "fake-password",
			funcTable: localFuncTable{
				getStorageVariables: func(*velerov1api.BackupStorageLocation, string, string, map[string]string, velerocredentials.CredentialGetter) (map[string]string, error) {
					return map[string]string{}, nil
				},
				getStorageCredentials: func(*velerov1api.BackupStorageLocation, velerocredentials.FileStore) (map[string]string, error) {
					return map[string]string{}, nil
				},
			},
			repoService: new(reposervicenmocks.BackupRepoService),
			retFuncInit: func(context.Context, udmrepo.RepoOptions) error {
				return nil
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			funcTable = tc.funcTable

			var secretStore velerocredentials.SecretStore
			if tc.getter != nil {
				tc.getter.On("Get", mock.Anything, mock.Anything).Return(tc.credStoreReturn, tc.credStoreError)
				secretStore = tc.getter
			}

			urp := unifiedRepoProvider{
				credentialGetter: velerocredentials.CredentialGetter{
					FromSecret: secretStore,
				},
				repoService: tc.repoService,
				log:         velerotest.NewLogger(),
			}

			if tc.repoService != nil {
				tc.repoService.On("Create", mock.Anything, mock.Anything).Return(tc.retFuncInit)
			}

			if tc.readOnlyBSL {
				bsl.Spec.AccessMode = velerov1api.BackupStorageLocationAccessModeReadOnly
			} else {
				bsl.Spec.AccessMode = velerov1api.BackupStorageLocationAccessModeReadWrite
			}

			err := urp.InitRepo(t.Context(), RepoParam{
				BackupLocation: &bsl,
				BackupRepo:     &velerov1api.BackupRepository{},
			})

			if tc.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.expectedErr)
			}
		})
	}
}

func TestConnectToRepo(t *testing.T) {
	testCases := []struct {
		name            string
		funcTable       localFuncTable
		getter          *credmock.SecretStore
		repoService     *reposervicenmocks.BackupRepoService
		retFuncInit     any
		credStoreReturn string
		credStoreError  error
		expectedErr     string
	}{
		{
			name:        "get repo option fail",
			expectedErr: "error to get repo options: error to get repo password: invalid credentials interface",
		},
		{
			name:            "repo init fail",
			getter:          new(credmock.SecretStore),
			credStoreReturn: "fake-password",
			funcTable: localFuncTable{
				getStorageVariables: func(*velerov1api.BackupStorageLocation, string, string, map[string]string, velerocredentials.CredentialGetter) (map[string]string, error) {
					return map[string]string{}, nil
				},
				getStorageCredentials: func(*velerov1api.BackupStorageLocation, velerocredentials.FileStore) (map[string]string, error) {
					return map[string]string{}, nil
				},
			},
			repoService: new(reposervicenmocks.BackupRepoService),
			retFuncInit: func(context.Context, udmrepo.RepoOptions) error {
				return errors.New("fake-error-1")
			},
			expectedErr: "error to connect backup repo: fake-error-1",
		},
		{
			name:            "succeed",
			getter:          new(credmock.SecretStore),
			credStoreReturn: "fake-password",
			funcTable: localFuncTable{
				getStorageVariables: func(*velerov1api.BackupStorageLocation, string, string, map[string]string, velerocredentials.CredentialGetter) (map[string]string, error) {
					return map[string]string{}, nil
				},
				getStorageCredentials: func(*velerov1api.BackupStorageLocation, velerocredentials.FileStore) (map[string]string, error) {
					return map[string]string{}, nil
				},
			},
			repoService: new(reposervicenmocks.BackupRepoService),
			retFuncInit: func(context.Context, udmrepo.RepoOptions) error {
				return nil
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			funcTable = tc.funcTable

			var secretStore velerocredentials.SecretStore
			if tc.getter != nil {
				tc.getter.On("Get", mock.Anything, mock.Anything).Return(tc.credStoreReturn, tc.credStoreError)
				secretStore = tc.getter
			}

			urp := unifiedRepoProvider{
				credentialGetter: velerocredentials.CredentialGetter{
					FromSecret: secretStore,
				},
				repoService: tc.repoService,
				log:         velerotest.NewLogger(),
			}

			if tc.repoService != nil {
				tc.repoService.On("Connect", mock.Anything, mock.Anything).Return(tc.retFuncInit)
			}

			err := urp.ConnectToRepo(t.Context(), RepoParam{
				BackupLocation: &velerov1api.BackupStorageLocation{},
				BackupRepo:     &velerov1api.BackupRepository{},
			})

			if tc.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.expectedErr)
			}
		})
	}
}

func TestBoostRepoConnect(t *testing.T) {
	var backupRepo *reposervicenmocks.BackupRepo

	testCases := []struct {
		name            string
		funcTable       localFuncTable
		getter          *credmock.SecretStore
		repoService     *reposervicenmocks.BackupRepoService
		backupRepo      *reposervicenmocks.BackupRepo
		retFuncInit     any
		retFuncOpen     []any
		credStoreReturn string
		credStoreError  error
		expectedErr     string
	}{
		{
			name:        "get repo option fail",
			expectedErr: "error to get repo options: error to get repo password: invalid credentials interface",
		},
		{
			name:            "repo not opened and connect fail",
			getter:          new(credmock.SecretStore),
			credStoreReturn: "fake-password",
			funcTable: localFuncTable{
				getStorageVariables: func(*velerov1api.BackupStorageLocation, string, string, map[string]string, velerocredentials.CredentialGetter) (map[string]string, error) {
					return map[string]string{}, nil
				},
				getStorageCredentials: func(*velerov1api.BackupStorageLocation, velerocredentials.FileStore) (map[string]string, error) {
					return map[string]string{}, nil
				},
			},
			repoService: new(reposervicenmocks.BackupRepoService),
			retFuncOpen: []any{
				func(context.Context, udmrepo.RepoOptions) udmrepo.BackupRepo {
					return backupRepo
				},

				func(context.Context, udmrepo.RepoOptions) error {
					return errors.New("fake-error-1")
				},
			},
			retFuncInit: func(context.Context, udmrepo.RepoOptions) error {
				return errors.New("fake-error-2")
			},
			expectedErr: "error to connect backup repo: fake-error-2",
		},
		{
			name:            "repo not opened and connect succeed",
			getter:          new(credmock.SecretStore),
			credStoreReturn: "fake-password",
			funcTable: localFuncTable{
				getStorageVariables: func(*velerov1api.BackupStorageLocation, string, string, map[string]string, velerocredentials.CredentialGetter) (map[string]string, error) {
					return map[string]string{}, nil
				},
				getStorageCredentials: func(*velerov1api.BackupStorageLocation, velerocredentials.FileStore) (map[string]string, error) {
					return map[string]string{}, nil
				},
			},
			repoService: new(reposervicenmocks.BackupRepoService),
			retFuncOpen: []any{
				func(context.Context, udmrepo.RepoOptions) udmrepo.BackupRepo {
					return backupRepo
				},

				func(context.Context, udmrepo.RepoOptions) error {
					return errors.New("fake-error-1")
				},
			},
			retFuncInit: func(context.Context, udmrepo.RepoOptions) error {
				return nil
			},
		},
		{
			name:            "repo is opened",
			getter:          new(credmock.SecretStore),
			credStoreReturn: "fake-password",
			funcTable: localFuncTable{
				getStorageVariables: func(*velerov1api.BackupStorageLocation, string, string, map[string]string, velerocredentials.CredentialGetter) (map[string]string, error) {
					return map[string]string{}, nil
				},
				getStorageCredentials: func(*velerov1api.BackupStorageLocation, velerocredentials.FileStore) (map[string]string, error) {
					return map[string]string{}, nil
				},
			},
			repoService: new(reposervicenmocks.BackupRepoService),
			backupRepo:  new(reposervicenmocks.BackupRepo),
			retFuncOpen: []any{
				func(context.Context, udmrepo.RepoOptions) udmrepo.BackupRepo {
					return backupRepo
				},

				func(context.Context, udmrepo.RepoOptions) error {
					return nil
				},
			},
			retFuncInit: func(context.Context, udmrepo.RepoOptions) error {
				return nil
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			funcTable = tc.funcTable

			var secretStore velerocredentials.SecretStore
			if tc.getter != nil {
				tc.getter.On("Get", mock.Anything, mock.Anything).Return(tc.credStoreReturn, tc.credStoreError)
				secretStore = tc.getter
			}

			urp := unifiedRepoProvider{
				credentialGetter: velerocredentials.CredentialGetter{
					FromSecret: secretStore,
				},
				repoService: tc.repoService,
				log:         velerotest.NewLogger(),
			}

			backupRepo = tc.backupRepo

			if tc.repoService != nil {
				tc.repoService.On("Open", mock.Anything, mock.Anything).Return(tc.retFuncOpen[0], tc.retFuncOpen[1])
				tc.repoService.On("Connect", mock.Anything, mock.Anything).Return(tc.retFuncInit)
			}

			if tc.backupRepo != nil {
				backupRepo.On("Close", mock.Anything).Return(nil)
			}

			err := urp.BoostRepoConnect(t.Context(), RepoParam{
				BackupLocation: &velerov1api.BackupStorageLocation{},
				BackupRepo:     &velerov1api.BackupRepository{},
			})

			if tc.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.expectedErr)
			}
		})
	}
}

func TestPruneRepo(t *testing.T) {
	testCases := []struct {
		name            string
		funcTable       localFuncTable
		getter          *credmock.SecretStore
		repoService     *reposervicenmocks.BackupRepoService
		retFuncMaintain any
		credStoreReturn string
		credStoreError  error
		expectedErr     string
	}{
		{
			name:        "get repo option fail",
			expectedErr: "error to get repo options: error to get repo password: invalid credentials interface",
		},
		{
			name:            "repo maintain fail",
			getter:          new(credmock.SecretStore),
			credStoreReturn: "fake-password",
			funcTable: localFuncTable{
				getStorageVariables: func(*velerov1api.BackupStorageLocation, string, string, map[string]string, velerocredentials.CredentialGetter) (map[string]string, error) {
					return map[string]string{}, nil
				},
				getStorageCredentials: func(*velerov1api.BackupStorageLocation, velerocredentials.FileStore) (map[string]string, error) {
					return map[string]string{}, nil
				},
			},
			repoService: new(reposervicenmocks.BackupRepoService),
			retFuncMaintain: func(context.Context, udmrepo.RepoOptions) error {
				return errors.New("fake-error-1")
			},
			expectedErr: "error to prune backup repo: fake-error-1",
		},
		{
			name:            "succeed",
			getter:          new(credmock.SecretStore),
			credStoreReturn: "fake-password",
			funcTable: localFuncTable{
				getStorageVariables: func(*velerov1api.BackupStorageLocation, string, string, map[string]string, velerocredentials.CredentialGetter) (map[string]string, error) {
					return map[string]string{}, nil
				},
				getStorageCredentials: func(*velerov1api.BackupStorageLocation, velerocredentials.FileStore) (map[string]string, error) {
					return map[string]string{}, nil
				},
			},
			repoService: new(reposervicenmocks.BackupRepoService),
			retFuncMaintain: func(context.Context, udmrepo.RepoOptions) error {
				return nil
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			funcTable = tc.funcTable

			var secretStore velerocredentials.SecretStore
			if tc.getter != nil {
				tc.getter.On("Get", mock.Anything, mock.Anything).Return(tc.credStoreReturn, tc.credStoreError)
				secretStore = tc.getter
			}

			urp := unifiedRepoProvider{
				credentialGetter: velerocredentials.CredentialGetter{
					FromSecret: secretStore,
				},
				repoService: tc.repoService,
				log:         velerotest.NewLogger(),
			}

			if tc.repoService != nil {
				tc.repoService.On("Maintain", mock.Anything, mock.Anything).Return(tc.retFuncMaintain)
			}

			err := urp.PruneRepo(t.Context(), RepoParam{
				BackupLocation: &velerov1api.BackupStorageLocation{},
				BackupRepo:     &velerov1api.BackupRepository{},
			})

			if tc.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.expectedErr)
			}
		})
	}
}

func TestGetStorageType(t *testing.T) {
	testCases := []struct {
		name           string
		backupLocation *velerov1api.BackupStorageLocation
		expectedRet    string
	}{
		{
			name:           "wrong backend type",
			backupLocation: &velerov1api.BackupStorageLocation{},
		},
		{
			name: "aws provider",
			backupLocation: &velerov1api.BackupStorageLocation{
				Spec: velerov1api.BackupStorageLocationSpec{
					Provider: "velero.io/aws",
				},
			},
			expectedRet: "s3",
		},
		{
			name: "azure provider",
			backupLocation: &velerov1api.BackupStorageLocation{
				Spec: velerov1api.BackupStorageLocationSpec{
					Provider: "velero.io/azure",
				},
			},
			expectedRet: "azure",
		},
		{
			name: "gcp provider",
			backupLocation: &velerov1api.BackupStorageLocation{
				Spec: velerov1api.BackupStorageLocationSpec{
					Provider: "velero.io/gcp",
				},
			},
			expectedRet: "gcs",
		},
		{
			name: "fs provider",
			backupLocation: &velerov1api.BackupStorageLocation{
				Spec: velerov1api.BackupStorageLocationSpec{
					Provider: "velero.io/fs",
				},
			},
			expectedRet: "filesystem",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ret := getStorageType(tc.backupLocation)
			assert.Equal(t, tc.expectedRet, ret)
		})
	}
}
