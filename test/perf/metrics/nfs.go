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
	"context"

	"github.com/cockroachdb/errors"

	"github.com/vmware-tanzu/velero/test/util/metrics"
)

const NFSDesc = "NFS disk usage"

type NFSMetrics struct {
	Metrics       map[string]string
	NFSServerPath string
	Ctx           context.Context
}

func (n *NFSMetrics) Update() error {
	if usedSpace, err := metrics.GetNFSPathDiskUsage(n.Ctx, n.NFSServerPath); err != nil {
		return errors.WithStack(err)
	} else {
		n.Metrics["nfs"] = usedSpace
	}

	return nil
}

func (n *NFSMetrics) GetMetrics() map[string]string {
	return n.Metrics
}

func (n *NFSMetrics) GetMetricsName() string {
	return NFSDesc
}
