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

package metrics

import (
	"github.com/cockroachdb/errors"

	"github.com/vmware-tanzu/velero/test/util/providers"
)

func GetMinioDiskUsage(cloudCredentialsFile string, bslBucket string, bslPrefix string, bslConfig string) (int64, error) {
	var aws providers.AWSStorage
	toatalSize, err := aws.GetMinioBucketSize(cloudCredentialsFile, bslBucket, bslPrefix, bslConfig)
	if err != nil {
		return 0, errors.Errorf("a Failed to get minio bucket size with err %v", err)
	} else {
		return toatalSize, nil
	}
}
