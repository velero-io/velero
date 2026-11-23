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

package backend

import (
	"testing"

	velerotest "github.com/velero-io/velero/pkg/test"

	"github.com/kopia/kopia/repo/blob/s3"
	"github.com/stretchr/testify/assert"

	"github.com/velero-io/velero/pkg/repository/udmrepo"
)

func TestS3Setup(t *testing.T) {
	testCases := []struct {
		name            string
		flags           map[string]string
		expectedOptions s3.Options
		expectedErr     string
	}{
		{
			name:        "must have bucket name",
			flags:       map[string]string{},
			expectedErr: "key " + udmrepo.StoreOptionOssBucket + " not found",
		},
		{
			name: "with bucket only",
			flags: map[string]string{
				udmrepo.StoreOptionOssBucket: "fake-bucket",
			},
			expectedOptions: s3.Options{
				BucketName: "fake-bucket",
			},
		},
		{
			name: "with others",
			flags: map[string]string{
				udmrepo.StoreOptionOssBucket:   "fake-bucket",
				udmrepo.StoreOptionS3KeyID:     "fake-ak",
				udmrepo.StoreOptionS3SecretKey: "fake-sk",
				udmrepo.StoreOptionS3Endpoint:  "fake-endpoint",
				udmrepo.StoreOptionOssRegion:   "fake-region",
				udmrepo.StoreOptionPrefix:      "fake-prefix",
				udmrepo.StoreOptionS3Token:     "fake-token",
			},
			expectedOptions: s3.Options{
				BucketName:      "fake-bucket",
				AccessKeyID:     "fake-ak",
				SecretAccessKey: "fake-sk",
				Endpoint:        "fake-endpoint",
				Region:          "fake-region",
				Prefix:          "fake-prefix",
				SessionToken:    "fake-token",
			},
		},
		{
			name: "with wrong tls",
			flags: map[string]string{
				udmrepo.StoreOptionOssBucket:          "fake-bucket",
				udmrepo.StoreOptionS3DisableTLS:       "fake-bool",
				udmrepo.StoreOptionS3DisableTLSVerify: "fake-bool",
			},
			expectedOptions: s3.Options{
				BucketName: "fake-bucket",
			},
		},
		{
			name: "with correct tls",
			flags: map[string]string{
				udmrepo.StoreOptionOssBucket:          "fake-bucket",
				udmrepo.StoreOptionS3DisableTLS:       "true",
				udmrepo.StoreOptionS3DisableTLSVerify: "false",
			},
			expectedOptions: s3.Options{
				BucketName:     "fake-bucket",
				DoNotUseTLS:    true,
				DoNotVerifyTLS: false,
			},
		},
		{
			name: "with wrong ca",
			flags: map[string]string{
				udmrepo.StoreOptionOssBucket: "fake-bucket",
				udmrepo.StoreOptionCACert:    "fake-base-64",
			},
			expectedOptions: s3.Options{
				BucketName: "fake-bucket",
			},
		},
		{
			name: "with correct ca",
			flags: map[string]string{
				udmrepo.StoreOptionOssBucket: "fake-bucket",
				udmrepo.StoreOptionCACert:    "ZmFrZS1jYQ==",
			},
			expectedOptions: s3.Options{
				BucketName: "fake-bucket",
				RootCA:     []byte{'f', 'a', 'k', 'e', '-', 'c', 'a'},
			},
		},
	}

	logger := velerotest.NewLogger()
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			s3Flags := S3Backend{}

			err := s3Flags.Setup(t.Context(), tc.flags, logger)

			if tc.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.expectedErr)
			}
		})
	}
}
