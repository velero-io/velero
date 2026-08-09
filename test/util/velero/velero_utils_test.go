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

package velero

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_getVersionWithoutPatch(t *testing.T) {
	versionTests := []struct {
		caseName string
		version  string
		result   string
	}{
		{
			caseName: "main version",
			version:  "main",
			result:   "main",
		},
		{
			caseName: "release version",
			version:  "release-1.18-dev",
			result:   "v1.18",
		},
		{
			caseName: "tag version",
			version:  "v1.17.2",
			result:   "v1.17",
		},
	}

	for _, test := range versionTests {
		t.Run(test.caseName, func(t *testing.T) {
			res := getVersionWithoutPatch(test.version)
			require.Equal(t, test.result, res)
		})
	}
}

func Test_createBackupLocationArgs(t *testing.T) {
	// argValue returns the value following flag, and whether flag was present.
	argValue := func(args []string, flag string) (string, bool) {
		for i, a := range args {
			if a == flag && i+1 < len(args) {
				return args[i+1], true
			}
		}
		return "", false
	}

	const (
		namespace = "velero"
		bslName   = "additional-bsl"
		provider  = "aws"
		bucket    = "additional-bucket"
		config    = "region=minio,s3ForcePathStyle=\"true\",s3Url=https://minio.example.com:9000"
		caCert    = "/tmp/minio-certs/public.crt"
	)

	t.Run("emits --cacert when a CA bundle is configured", func(t *testing.T) {
		args := createBackupLocationArgs(
			namespace, bslName, provider, bucket, "", config,
			"bsl-credentials", "creds-aws", caCert,
		)

		require.Equal(t, []string{
			"--namespace", namespace,
			"create", "backup-location", bslName,
			"--provider", provider,
			"--bucket", bucket,
		}, args[:9], "leading subcommand shape changed")

		value, found := argValue(args, "--cacert")
		require.True(t, found, "expected --cacert to be emitted, got %v", args)
		require.Equal(t, caCert, value, "--cacert must be followed by the bundle path")
	})

	t.Run("omits --cacert when no CA bundle is configured", func(t *testing.T) {
		args := createBackupLocationArgs(
			namespace, bslName, provider, bucket, "", config,
			"bsl-credentials", "creds-aws", "",
		)

		_, found := argValue(args, "--cacert")
		require.False(t, found, "did not expect --cacert, got %v", args)
	})
}
