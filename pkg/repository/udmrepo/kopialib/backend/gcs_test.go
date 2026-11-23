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

	"github.com/kopia/kopia/repo/blob/gcs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/velero-io/velero/pkg/repository/udmrepo"
)

func TestGcsSetup(t *testing.T) {
	testCases := []struct {
		name            string
		flags           map[string]string
		expectedOptions gcs.Options
		expectedErr     string
	}{
		{
			name:        "must have bucket name",
			flags:       map[string]string{},
			expectedErr: "key " + udmrepo.StoreOptionOssBucket + " not found",
		},
		{
			name: "must have credential file",
			flags: map[string]string{
				udmrepo.StoreOptionOssBucket: "fake-bucket",
			},
			expectedErr: "key " + udmrepo.StoreOptionCredentialFile + " not found",
		},
		{
			name: "with prefix",
			flags: map[string]string{
				udmrepo.StoreOptionOssBucket:      "fake-bucket",
				udmrepo.StoreOptionCredentialFile: "fake-credential",
				udmrepo.StoreOptionPrefix:         "fake-prefix",
			},
			expectedOptions: gcs.Options{
				BucketName:                    "fake-bucket",
				ServiceAccountCredentialsFile: "fake-credential",
				Prefix:                        "fake-prefix",
			},
		},
		{
			name: "with wrong readonly",
			flags: map[string]string{
				udmrepo.StoreOptionOssBucket:      "fake-bucket",
				udmrepo.StoreOptionCredentialFile: "fake-credential",
				udmrepo.StoreOptionGcsReadonly:    "fake-bool",
			},
			expectedOptions: gcs.Options{
				BucketName:                    "fake-bucket",
				ServiceAccountCredentialsFile: "fake-credential",
			},
		},
		{
			name: "with correct readonly",
			flags: map[string]string{
				udmrepo.StoreOptionOssBucket:      "fake-bucket",
				udmrepo.StoreOptionCredentialFile: "fake-credential",
				udmrepo.StoreOptionGcsReadonly:    "true",
			},
			expectedOptions: gcs.Options{
				BucketName:                    "fake-bucket",
				ServiceAccountCredentialsFile: "fake-credential",
				ReadOnly:                      true,
			},
		},
	}

	logger := velerotest.NewLogger()
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gcsFlags := GCSBackend{}

			err := gcsFlags.Setup(t.Context(), tc.flags, logger)

			if tc.expectedErr == "" {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedOptions, gcsFlags.options)
			} else {
				assert.EqualError(t, err, tc.expectedErr)
			}
		})
	}
}
