/*
Copyright 2019, 2020 the Velero contributors.

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

package install

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	corev1api "k8s.io/api/core/v1"

	"github.com/vmware-tanzu/velero/pkg/util/kube"
)

func TestDeployment(t *testing.T) {
	deploy := Deployment("velero")

	assert.Equal(t, "velero", deploy.ObjectMeta.Namespace)

	deploy = Deployment("velero", WithRestoreOnly(true))
	assert.Equal(t, "--restore-only", deploy.Spec.Template.Spec.Containers[0].Args[1])

	deploy = Deployment("velero", WithEnvFromSecretKey("my-var", "my-secret", "my-key"))
	envSecret := deploy.Spec.Template.Spec.Containers[0].Env[3]
	assert.Equal(t, "my-var", envSecret.Name)
	assert.Equal(t, "my-secret", envSecret.ValueFrom.SecretKeyRef.LocalObjectReference.Name)
	assert.Equal(t, "my-key", envSecret.ValueFrom.SecretKeyRef.Key)

	deploy = Deployment("velero", WithImage("velero/velero:v0.11"))
	assert.Equal(t, "velero/velero:v0.11", deploy.Spec.Template.Spec.Containers[0].Image)
	assert.Equal(t, corev1api.PullIfNotPresent, deploy.Spec.Template.Spec.Containers[0].ImagePullPolicy)

	deploy = Deployment("velero", WithSecret(true))
	assert.Len(t, deploy.Spec.Template.Spec.Containers[0].Env, 7)
	assert.Len(t, deploy.Spec.Template.Spec.Volumes, 3)

	deploy = Deployment("velero", WithDefaultRepoMaintenanceFrequency(24*time.Hour))
	assert.Len(t, deploy.Spec.Template.Spec.Containers[0].Args, 2)
	assert.Equal(t, "--default-repo-maintain-frequency=24h0m0s", deploy.Spec.Template.Spec.Containers[0].Args[1])

	deploy = Deployment("velero", WithGarbageCollectionFrequency(24*time.Hour))
	assert.Len(t, deploy.Spec.Template.Spec.Containers[0].Args, 2)
	assert.Equal(t, "--garbage-collection-frequency=24h0m0s", deploy.Spec.Template.Spec.Containers[0].Args[1])

	deploy = Deployment("velero", WithFeatures([]string{"EnableCSI", "foo", "bar", "baz"}))
	assert.Len(t, deploy.Spec.Template.Spec.Containers[0].Args, 2)
	assert.Equal(t, "--features=EnableCSI,foo,bar,baz", deploy.Spec.Template.Spec.Containers[0].Args[1])

	deploy = Deployment("velero", WithPlugins([]string{
		"harbor-repo.vmware.com/harbor-ci/velero/velero-plugin-for-aws:v1.2.0",
		" \n vsphereveleroplugin/velero-plugin-for-vsphere:v1.1.1 ",
	}))
	assert.Len(t, deploy.Spec.Template.Spec.InitContainers, 2)
	assert.Equal(t, "harbor-repo.vmware.com/harbor-ci/velero/velero-plugin-for-aws:v1.2.0", deploy.Spec.Template.Spec.InitContainers[0].Image)
	assert.Equal(t, "vsphereveleroplugin/velero-plugin-for-vsphere:v1.1.1", deploy.Spec.Template.Spec.InitContainers[1].Image)
	assert.Equal(t, "vsphereveleroplugin-velero-plugin-for-vsphere", deploy.Spec.Template.Spec.InitContainers[1].Name)

	deploy = Deployment("velero", WithUploaderType("kopia"))
	assert.Len(t, deploy.Spec.Template.Spec.Containers[0].Args, 2)
	assert.Equal(t, "--uploader-type=kopia", deploy.Spec.Template.Spec.Containers[0].Args[1])

	deploy = Deployment("velero", WithServiceAccountName("test-sa"))
	assert.Equal(t, "test-sa", deploy.Spec.Template.Spec.ServiceAccountName)

	deploy = Deployment("velero", WithDisableInformerCache(true))
	assert.Len(t, deploy.Spec.Template.Spec.Containers[0].Args, 2)
	assert.Equal(t, "--disable-informer-cache=true", deploy.Spec.Template.Spec.Containers[0].Args[1])

	deploy = Deployment("velero", WithKeepLatestMaintenanceJobs(3))
	assert.Len(t, deploy.Spec.Template.Spec.Containers[0].Args, 2)
	assert.Equal(t, "--keep-latest-maintenance-jobs=3", deploy.Spec.Template.Spec.Containers[0].Args[1])

	deploy = Deployment(
		"velero",
		WithPodResources(
			kube.PodResources{
				CPURequest:    "100m",
				MemoryRequest: "256Mi",
				CPULimit:      "200m",
				MemoryLimit:   "512Mi",
			},
		),
	)
	assert.Len(t, deploy.Spec.Template.Spec.Containers[0].Args, 5)
	assert.Equal(t, "--maintenance-job-cpu-limit=200m", deploy.Spec.Template.Spec.Containers[0].Args[1])
	assert.Equal(t, "--maintenance-job-cpu-request=100m", deploy.Spec.Template.Spec.Containers[0].Args[2])
	assert.Equal(t, "--maintenance-job-mem-limit=512Mi", deploy.Spec.Template.Spec.Containers[0].Args[3])
	assert.Equal(t, "--maintenance-job-mem-request=256Mi", deploy.Spec.Template.Spec.Containers[0].Args[4])

	deploy = Deployment("velero", WithBackupRepoConfigMap("test-backup-repo-config"))
	assert.Len(t, deploy.Spec.Template.Spec.Containers[0].Args, 2)
	assert.Equal(t, "--backup-repository-configmap=test-backup-repo-config", deploy.Spec.Template.Spec.Containers[0].Args[1])

	deploy = Deployment("velero", WithRepoMaintenanceJobConfigMap("test-repo-maintenance-config"))
	assert.Len(t, deploy.Spec.Template.Spec.Containers[0].Args, 2)
	assert.Equal(t, "--repo-maintenance-job-configmap=test-repo-maintenance-config", deploy.Spec.Template.Spec.Containers[0].Args[1])

	assert.Equal(t, &corev1api.Affinity{
		NodeAffinity: &corev1api.NodeAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: &corev1api.NodeSelector{
				NodeSelectorTerms: []corev1api.NodeSelectorTerm{
					{
						MatchExpressions: []corev1api.NodeSelectorRequirement{
							{
								Key:      "kubernetes.io/os",
								Values:   []string{"windows"},
								Operator: corev1api.NodeSelectorOpNotIn,
							},
						},
					},
				},
			},
		},
	}, deploy.Spec.Template.Spec.Affinity)
}

func TestDeploymentWithPriorityClassName(t *testing.T) {
	testCases := []struct {
		name              string
		priorityClassName string
		expectedValue     string
	}{
		{
			name:              "with priority class name",
			priorityClassName: "high-priority",
			expectedValue:     "high-priority",
		},
		{
			name:              "without priority class name",
			priorityClassName: "",
			expectedValue:     "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a deployment with the priority class name option
			var opts []podTemplateOption
			if tc.priorityClassName != "" {
				opts = append(opts, WithPriorityClassName(tc.priorityClassName))
			}

			deployment := Deployment("velero", opts...)

			// Verify the priority class name is set correctly
			assert.Equal(t, tc.expectedValue, deployment.Spec.Template.Spec.PriorityClassName)
		})
	}
}
