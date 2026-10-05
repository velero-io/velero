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
	"fmt"
	"strings"
	"time"

	"github.com/cockroachdb/errors"

	metricsclientset "k8s.io/metrics/pkg/client/clientset/versioned"

	"github.com/vmware-tanzu/velero/test/util/metrics"
)

const PodResourceDesc = "Resource consumption"
const PodMetricsTimeout = 5 * time.Minute

type PodMetrics struct {
	Client             *metricsclientset.Clientset
	Metrics            map[string]int64
	count              int64
	PodName, Namespace string
	Ctx                context.Context
}

func (p *PodMetrics) Update() error {
	cpu, mem, err := metrics.GetPodUsageMetrics(p.Ctx, p.Client, p.PodName, p.Namespace, PodMetricsTimeout)
	if err != nil {
		return errors.WithStack(err)
	}
	keyMaxCPU := p.PodName + ":MaxCPU"
	curCPU := cpu.MilliValue()
	if curCPU > p.Metrics[keyMaxCPU] {
		p.Metrics[keyMaxCPU] = curCPU
	}

	keyMaxMem := p.PodName + ":MaxMemory"
	curMem := mem.MilliValue()
	if curMem > p.Metrics[keyMaxMem] {
		p.Metrics[keyMaxMem] = curMem
	}

	keyAvgCPU := p.PodName + ":AverageCPU"
	preAvgCPU := p.Metrics[keyAvgCPU]
	p.Metrics[keyAvgCPU] = (preAvgCPU*p.count + curCPU) / (p.count + 1)

	keyAvgMem := p.PodName + ":AverageMemory"
	preAvgMem := p.Metrics[keyAvgMem]
	p.Metrics[keyAvgMem] = (preAvgMem*p.count + curMem) / (p.count + 1)
	p.count++

	return nil
}

func (p *PodMetrics) GetMetrics() map[string]string {
	tmpMetrics := make(map[string]string)
	for k := range p.Metrics {
		if strings.Contains(k, "CPU") {
			tmpMetrics[k] = formatCPUValue(p.Metrics[k])
		} else if strings.Contains(k, "Memory") {
			tmpMetrics[k] = formatMemoryDiskValue(p.Metrics[k] / 1024)
		}
	}
	return tmpMetrics
}

func (p *PodMetrics) GetMetricsName() string {
	return PodResourceDesc
}

func formatCPUValue(milliValue int64) string {
	if milliValue < 1000 {
		return fmt.Sprintf("%d mili core", milliValue)
	}
	coreValue := float64(milliValue) / 1000.0
	return fmt.Sprintf("%.2f core", coreValue)
}

func formatMemoryDiskValue(memoryValue int64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"}

	if memoryValue == 0 {
		return "0 B"
	}

	base := int64(1024)
	exp := int64(0)
	for memoryValue >= base && exp < int64(len(units)-1) {
		memoryValue /= base
		exp++
	}

	return fmt.Sprintf("%d %s", memoryValue, units[exp])
}
