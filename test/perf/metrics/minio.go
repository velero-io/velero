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

	"github.com/vmware-tanzu/velero/test/util/metrics"
)

const MinioDesc = "Minio disk usage"

type MinioMetrics struct {
	Metrics              map[string]string
	CloudCredentialsFile string
	BslBucket            string
	BslPrefix            string
	BslConfig            string
}

func (m *MinioMetrics) Update() error {
	if bucketSize, err := metrics.GetMinioDiskUsage(m.CloudCredentialsFile,
		m.BslBucket, m.BslPrefix, m.BslConfig); err != nil {
		return errors.WithStack(err)
	} else {
		m.Metrics["minio"] = formatMemoryDiskValue(bucketSize)
	}
	return nil
}

func (m *MinioMetrics) GetMetrics() map[string]string {
	return m.Metrics
}

func (m *MinioMetrics) GetMetricsName() string {
	return MinioDesc
}
