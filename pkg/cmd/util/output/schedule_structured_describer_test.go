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

package output

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/util/boolptr"
)

func TestDescribeScheduleInSF_Default(t *testing.T) {
	schedule := builder.ForSchedule("velero", "schedule-1").
		CronSchedule("@daily").
		Result()

	output := DescribeScheduleInSF(schedule, "json")
	require.NotEmpty(t, output)

	var data map[string]any
	err := json.Unmarshal([]byte(output), &data)
	require.NoError(t, err)

	metadata, ok := data["metadata"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "schedule-1", metadata["name"])
	assert.Equal(t, "velero", metadata["namespace"])

	assert.Equal(t, "New", data["phase"])
	assert.Equal(t, false, data["paused"])

	spec, ok := data["spec"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "@daily", spec["schedule"])
	assert.Equal(t, false, spec["paused"])

	template, ok := spec["template"].(map[string]any)
	require.True(t, ok)
	namespaces, ok := template["namespaces"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "*", namespaces["included"])

	status, ok := data["status"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "<never>", status["lastBackup"])
}

func TestDescribeScheduleInSF_Full(t *testing.T) {
	now := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	metaNow := metav1.Time{Time: now}
	skippedTime := metav1.Time{Time: now.Add(-1 * time.Hour)}

	schedule := builder.ForSchedule("velero", "schedule-full").
		Phase(velerov1api.SchedulePhaseEnabled).
		CronSchedule("0 0 * * *").
		ValidationError("validation error 1").
		ValidationError("validation error 2").
		Template(
			builder.ForBackup("velero", "ignored").
				IncludedNamespaces("app-ns").
				ExcludedNamespaces("kube-system").
				IncludedResources("pods", "services").
				Result().Spec,
		).
		Result()

	schedule.Spec.Paused = true
	schedule.Spec.Template.ResourcePolicy = &corev1api.TypedLocalObjectReference{Kind: "ConfigMap", Name: "policy-cm"}
	schedule.Spec.Template.UploaderConfig = &velerov1api.UploaderConfigForBackup{ParallelFilesUpload: 4}
	schedule.Status.LastBackup = &metaNow
	schedule.Status.LastSkipped = &skippedTime
	schedule.Spec.UseOwnerReferencesInBackup = boolptr.True()
	schedule.Spec.SkipImmediately = boolptr.False()

	output := DescribeScheduleInSF(schedule, "json")
	require.NotEmpty(t, output)

	var data map[string]any
	err := json.Unmarshal([]byte(output), &data)
	require.NoError(t, err)

	assert.Equal(t, "Enabled", data["phase"])
	assert.Equal(t, true, data["paused"])

	valErrors, ok := data["validationErrors"].([]any)
	require.True(t, ok)
	assert.Len(t, valErrors, 2)
	assert.Equal(t, "validation error 1", valErrors[0])
	assert.Equal(t, "validation error 2", valErrors[1])

	uploaderConfig, ok := data["uploaderConfig"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, float64(4), uploaderConfig["parallelFilesUpload"])

	resourcePolicies, ok := data["resourcePolicies"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "ConfigMap", resourcePolicies["type"])
	assert.Equal(t, "policy-cm", resourcePolicies["name"])

	spec, ok := data["spec"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "0 0 * * *", spec["schedule"])
	assert.Equal(t, true, spec["paused"])
	assert.Equal(t, true, spec["useOwnerReferencesInBackup"])
	assert.Equal(t, false, spec["skipImmediately"])

	template, ok := spec["template"].(map[string]any)
	require.True(t, ok)
	namespaces, ok := template["namespaces"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "app-ns", namespaces["included"])
	assert.Equal(t, "kube-system", namespaces["excluded"])

	status, ok := data["status"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, fmt.Sprintf("%v", now), status["lastBackup"])
	assert.Equal(t, fmt.Sprintf("%v", now.Add(-1*time.Hour)), status["lastSkipped"])
}
