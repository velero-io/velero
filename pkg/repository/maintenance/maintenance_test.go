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

package maintenance

import (
	"context"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1api "k8s.io/api/apps/v1"
	batchv1api "k8s.io/api/batch/v1"
	corev1api "k8s.io/api/core/v1"
	schedulingv1 "k8s.io/api/scheduling/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	velerolabel "github.com/vmware-tanzu/velero/pkg/label"
	"github.com/vmware-tanzu/velero/pkg/repository/provider"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
	velerotypes "github.com/vmware-tanzu/velero/pkg/types"
	"github.com/vmware-tanzu/velero/pkg/util/boolptr"
	"github.com/vmware-tanzu/velero/pkg/util/kube"
	"github.com/vmware-tanzu/velero/pkg/util/logging"
)

func TestGenerateJobName(t *testing.T) {
	testCases := []struct {
		repo          string
		expectedStart string
	}{
		{
			repo:          "example",
			expectedStart: "example-maintain-job-",
		},
		{
			repo:          strings.Repeat("a", 60),
			expectedStart: "repo-maintain-job-",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.repo, func(t *testing.T) {
			// Call the function to test
			jobName := GenerateJobName(tc.repo)

			// Check if the generated job name starts with the expected prefix
			if !strings.HasPrefix(jobName, tc.expectedStart) {
				t.Errorf("generated job name does not start with expected prefix")
			}

			// Check if the length of the generated job name exceeds the Kubernetes limit
			if len(jobName) > 63 {
				t.Errorf("generated job name exceeds Kubernetes limit")
			}
		})
	}
}
func TestDeleteOldJobs(t *testing.T) {
	// Set up test repo and keep value
	repo := &velerov1api.BackupRepository{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "label with more than 63 characters should be modified",
			Namespace: velerov1api.DefaultNamespace,
		},
	}
	keep := 1

	jobArray := []client.Object{
		&batchv1api.Job{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "job-0",
				Namespace: velerov1api.DefaultNamespace,
				Labels:    map[string]string{RepositoryNameLabel: velerolabel.ReturnNameOrHash(repo.Name)},
			},
			Spec: batchv1api.JobSpec{},
		},
		&batchv1api.Job{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "job-1",
				Namespace: velerov1api.DefaultNamespace,
				Labels:    map[string]string{RepositoryNameLabel: velerolabel.ReturnNameOrHash(repo.Name)},
			},
			Spec: batchv1api.JobSpec{},
		},
	}

	newJob := &batchv1api.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "job-new",
			Namespace: velerov1api.DefaultNamespace,
			Labels:    map[string]string{RepositoryNameLabel: velerolabel.ReturnNameOrHash(repo.Name)},
		},
		Spec: batchv1api.JobSpec{},
	}

	// Create a fake Kubernetes client with 2 jobs.
	scheme := runtime.NewScheme()
	_ = batchv1api.AddToScheme(scheme)
	cli := fake.NewClientBuilder().WithScheme(scheme).WithObjects(jobArray...).Build()

	// Create a new job
	require.NoError(t, cli.Create(t.Context(), newJob))

	// Call the function
	require.NoError(t, DeleteOldJobs(cli, *repo, keep, velerotest.NewLogger()))

	// Get the remaining jobs
	jobList := &batchv1api.JobList{}
	require.NoError(t, cli.List(t.Context(), jobList, client.MatchingLabels(map[string]string{RepositoryNameLabel: repo.Name})))

	// We expect the number of jobs to be equal to 'keep'
	assert.Len(t, jobList.Items, keep)

	// Only the new created job should be left.
	assert.Equal(t, jobList.Items[0].Name, newJob.Name)
}

func TestWaitForJobComplete(t *testing.T) {
	// Set up test job
	job := &batchv1api.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-job",
			Namespace: "default",
		},
		Status: batchv1api.JobStatus{},
	}

	schemeFail := runtime.NewScheme()

	scheme := runtime.NewScheme()
	batchv1api.AddToScheme(scheme)

	waitCompletionBackOff1 := wait.Backoff{
		Duration: time.Second,
		Steps:    math.MaxInt,
		Factor:   2,
		Cap:      time.Second * 12,
	}

	waitCompletionBackOff2 := wait.Backoff{
		Duration: time.Second,
		Steps:    math.MaxInt,
		Factor:   2,
		Cap:      time.Second * 2,
	}

	// Define test cases
	tests := []struct {
		description   string // Test case description
		kubeClientObj []runtime.Object
		runtimeScheme *runtime.Scheme
		jobStatus     batchv1api.JobStatus // Job status to set for the test
		logBackOff    wait.Backoff
		updateAfter   time.Duration
		expectedLogs  int
		expectError   bool // Whether an error is expected
	}{
		{
			description:   "wait error",
			runtimeScheme: schemeFail,
			expectError:   true,
		},
		{
			description:   "Job Succeeded",
			runtimeScheme: scheme,
			kubeClientObj: []runtime.Object{
				job,
			},
			jobStatus: batchv1api.JobStatus{
				Succeeded: 1,
			},
			expectError: false,
		},
		{
			description:   "Job Failed",
			runtimeScheme: scheme,
			kubeClientObj: []runtime.Object{
				job,
			},
			jobStatus: batchv1api.JobStatus{
				Failed: 1,
			},
			expectError: false,
		},
		{
			description:   "Log backoff not to cap",
			runtimeScheme: scheme,
			kubeClientObj: []runtime.Object{
				job,
			},
			logBackOff:   waitCompletionBackOff1,
			updateAfter:  time.Second * 8,
			expectedLogs: 3,
		},
		{
			description:   "Log backoff to cap",
			runtimeScheme: scheme,
			kubeClientObj: []runtime.Object{
				job,
			},
			logBackOff:   waitCompletionBackOff2,
			updateAfter:  time.Second * 6,
			expectedLogs: 3,
		},
	}

	// Run tests
	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			// Set the job status
			job.Status = tc.jobStatus
			// Create a fake Kubernetes client
			fakeClientBuilder := fake.NewClientBuilder()
			fakeClientBuilder = fakeClientBuilder.WithScheme(tc.runtimeScheme)
			fakeClient := fakeClientBuilder.WithRuntimeObjects(tc.kubeClientObj...).Build()

			buffer := []string{}
			logger := velerotest.NewMultipleLogger(&buffer)

			waitCompletionBackOff = tc.logBackOff

			if tc.updateAfter != 0 {
				go func() {
					time.Sleep(tc.updateAfter)

					original := job.DeepCopy()
					job.Status.Succeeded = 1
					err := fakeClient.Status().Patch(t.Context(), job, client.MergeFrom(original))
					require.NoError(t, err)
				}()
			}

			// Call the function
			_, err := waitForJobComplete(t.Context(), fakeClient, job.Namespace, job.Name, logger)

			// Check if the error matches the expectation
			if tc.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			assert.LessOrEqual(t, len(buffer), tc.expectedLogs)
		})
	}
}

func TestGetResultFromJob(t *testing.T) {
	// Set up test job
	job := &batchv1api.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-job",
			Namespace: "default",
		},
	}

	// Set up test pod with no status
	pod := &corev1api.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
			Labels:    map[string]string{"job-name": job.Name},
		},
	}

	// Create a fake Kubernetes client
	cli := fake.NewClientBuilder().Build()

	// test an error should be returned
	result, err := getResultFromJob(cli, job)
	require.EqualError(t, err, "no pod found for job test-job")
	assert.Empty(t, result)

	cli = fake.NewClientBuilder().WithObjects(job, pod).Build()

	// test an error should be returned
	result, err = getResultFromJob(cli, job)
	require.EqualError(t, err, "no container statuses found for job test-job")
	assert.Empty(t, result)

	// Set a non-terminated container status to the pod
	pod.Status = corev1api.PodStatus{
		ContainerStatuses: []corev1api.ContainerStatus{
			{
				State: corev1api.ContainerState{},
			},
		},
	}

	// Test an error should be returned
	cli = fake.NewClientBuilder().WithObjects(job, pod).Build()
	result, err = getResultFromJob(cli, job)
	require.EqualError(t, err, "container for job test-job is not terminated")
	assert.Empty(t, result)

	// Set a terminated container status to the pod
	pod.Status = corev1api.PodStatus{
		ContainerStatuses: []corev1api.ContainerStatus{
			{
				State: corev1api.ContainerState{
					Terminated: &corev1api.ContainerStateTerminated{},
				},
			},
		},
	}

	// This call should return the termination message with no error
	cli = fake.NewClientBuilder().WithObjects(job, pod).Build()
	result, err = getResultFromJob(cli, job)
	require.NoError(t, err)
	assert.Empty(t, result)

	// Set a terminated container status with invalidate message to the pod
	pod.Status = corev1api.PodStatus{
		ContainerStatuses: []corev1api.ContainerStatus{
			{
				State: corev1api.ContainerState{
					Terminated: &corev1api.ContainerStateTerminated{
						Message: "fake-message",
					},
				},
			},
		},
	}

	cli = fake.NewClientBuilder().WithObjects(job, pod).Build()
	result, err = getResultFromJob(cli, job)
	require.EqualError(t, err, "error to locate repo maintenance error indicator from termination message")
	assert.Empty(t, result)

	// Set a terminated container status with empty maintenance error to the pod
	pod.Status = corev1api.PodStatus{
		ContainerStatuses: []corev1api.ContainerStatus{
			{
				State: corev1api.ContainerState{
					Terminated: &corev1api.ContainerStateTerminated{
						Message: "Repo maintenance error: ",
					},
				},
			},
		},
	}

	cli = fake.NewClientBuilder().WithObjects(job, pod).Build()
	result, err = getResultFromJob(cli, job)
	require.EqualError(t, err, "nothing after repo maintenance error indicator in termination message")
	assert.Empty(t, result)

	// Set a terminated container status with maintenance error to the pod
	pod.Status = corev1api.PodStatus{
		ContainerStatuses: []corev1api.ContainerStatus{
			{
				State: corev1api.ContainerState{
					Terminated: &corev1api.ContainerStateTerminated{
						Message: "Repo maintenance error: fake-error",
					},
				},
			},
		},
	}

	cli = fake.NewClientBuilder().WithObjects(job, pod).Build()
	result, err = getResultFromJob(cli, job)
	require.NoError(t, err)
	assert.Equal(t, "fake-error", result)
}

func TestGetJobConfig(t *testing.T) {
	keepLatestMaintenanceJobs := 1
	ctx := t.Context()
	logger := logrus.New()
	veleroNamespace := "velero"
	repoMaintenanceJobConfig := "repo-maintenance-job-config"
	repo := &velerov1api.BackupRepository{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: veleroNamespace,
			Name:      repoMaintenanceJobConfig,
		},
		Spec: velerov1api.BackupRepositorySpec{
			BackupStorageLocation: "default",
			RepositoryType:        "kopia",
			VolumeNamespace:       "test",
		},
	}

	testCases := []struct {
		name           string
		repoJobConfig  *corev1api.ConfigMap
		expectedConfig *velerotypes.JobConfigs
		expectedError  error
	}{
		{
			name:           "Config not exist",
			expectedConfig: nil,
			expectedError:  nil,
		},
		{
			name: "Invalid JSON",
			repoJobConfig: &corev1api.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: veleroNamespace,
					Name:      repoMaintenanceJobConfig,
				},
				Data: map[string]string{
					"test-default-kopia": "{\"cpuRequest:\"100m\"}",
				},
			},
			expectedConfig: nil,
			expectedError:  fmt.Errorf("fail to unmarshal configs from %s", repoMaintenanceJobConfig),
		},
		{
			name: "Find config specific for BackupRepository",
			repoJobConfig: &corev1api.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: veleroNamespace,
					Name:      repoMaintenanceJobConfig,
				},
				Data: map[string]string{
					"test-default-kopia": "{\"podResources\":{\"cpuRequest\":\"100m\",\"cpuLimit\":\"200m\",\"memoryRequest\":\"100Mi\",\"memoryLimit\":\"200Mi\"},\"loadAffinity\":[{\"nodeSelector\":{\"matchExpressions\":[{\"key\":\"cloud.google.com/machine-family\",\"operator\":\"In\",\"values\":[\"e2\"]}]}}]}",
				},
			},
			expectedConfig: &velerotypes.JobConfigs{
				PodResources: &kube.PodResources{
					CPURequest:    "100m",
					CPULimit:      "200m",
					MemoryRequest: "100Mi",
					MemoryLimit:   "200Mi",
				},
				LoadAffinities: []*kube.LoadAffinity{
					{
						NodeSelector: metav1.LabelSelector{
							MatchExpressions: []metav1.LabelSelectorRequirement{
								{
									Key:      "cloud.google.com/machine-family",
									Operator: metav1.LabelSelectorOpIn,
									Values:   []string{"e2"},
								},
							},
						},
					},
				},
			},
			expectedError: nil,
		},
		{
			name: "Find config specific for global",
			repoJobConfig: &corev1api.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: veleroNamespace,
					Name:      repoMaintenanceJobConfig,
				},
				Data: map[string]string{
					GlobalKeyForRepoMaintenanceJobCM: "{\"podResources\":{\"cpuRequest\":\"50m\",\"cpuLimit\":\"100m\",\"memoryRequest\":\"50Mi\",\"memoryLimit\":\"100Mi\"},\"loadAffinity\":[{\"nodeSelector\":{\"matchExpressions\":[{\"key\":\"cloud.google.com/machine-family\",\"operator\":\"In\",\"values\":[\"n2\"]}]}}]}",
				},
			},
			expectedConfig: &velerotypes.JobConfigs{
				PodResources: &kube.PodResources{
					CPURequest:    "50m",
					CPULimit:      "100m",
					MemoryRequest: "50Mi",
					MemoryLimit:   "100Mi",
				},
				LoadAffinities: []*kube.LoadAffinity{
					{
						NodeSelector: metav1.LabelSelector{
							MatchExpressions: []metav1.LabelSelectorRequirement{
								{
									Key:      "cloud.google.com/machine-family",
									Operator: metav1.LabelSelectorOpIn,
									Values:   []string{"n2"},
								},
							},
						},
					},
				},
			},
			expectedError: nil,
		},
		{
			name: "Specific config supersede global config",
			repoJobConfig: &corev1api.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: veleroNamespace,
					Name:      repoMaintenanceJobConfig,
				},
				Data: map[string]string{
					GlobalKeyForRepoMaintenanceJobCM: "{\"keepLatestMaintenanceJobs\":1,\"podResources\":{\"cpuRequest\":\"50m\",\"cpuLimit\":\"100m\",\"memoryRequest\":\"50Mi\",\"memoryLimit\":\"100Mi\"},\"loadAffinity\":[{\"nodeSelector\":{\"matchExpressions\":[{\"key\":\"cloud.google.com/machine-family\",\"operator\":\"In\",\"values\":[\"n2\"]}]}}]}",
					"test-default-kopia":             "{\"podResources\":{\"cpuRequest\":\"100m\",\"cpuLimit\":\"200m\",\"memoryRequest\":\"100Mi\",\"memoryLimit\":\"200Mi\"},\"loadAffinity\":[{\"nodeSelector\":{\"matchExpressions\":[{\"key\":\"cloud.google.com/machine-family\",\"operator\":\"In\",\"values\":[\"e2\"]}]}}]}",
				},
			},
			expectedConfig: &velerotypes.JobConfigs{
				KeepLatestMaintenanceJobs: &keepLatestMaintenanceJobs,
				PodResources: &kube.PodResources{
					CPURequest:    "100m",
					CPULimit:      "200m",
					MemoryRequest: "100Mi",
					MemoryLimit:   "200Mi",
				},
				LoadAffinities: []*kube.LoadAffinity{
					{
						NodeSelector: metav1.LabelSelector{
							MatchExpressions: []metav1.LabelSelectorRequirement{
								{
									Key:      "cloud.google.com/machine-family",
									Operator: metav1.LabelSelectorOpIn,
									Values:   []string{"e2"},
								},
							},
						},
					},
				},
			},
			expectedError: nil,
		},
		{
			name: "Configs only exist in global section should supersede specific config",
			repoJobConfig: &corev1api.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: veleroNamespace,
					Name:      repoMaintenanceJobConfig,
				},
				Data: map[string]string{
					GlobalKeyForRepoMaintenanceJobCM: "{\"keepLatestMaintenanceJobs\":1,\"podResources\":{\"cpuRequest\":\"50m\",\"cpuLimit\":\"100m\",\"memoryRequest\":\"50Mi\",\"memoryLimit\":\"100Mi\"},\"loadAffinity\":[{\"nodeSelector\":{\"matchExpressions\":[{\"key\":\"cloud.google.com/machine-family\",\"operator\":\"In\",\"values\":[\"n2\"]}]}}],\"priorityClassName\":\"global-priority\",\"podAnnotations\":{\"global-key\":\"global-value\"},\"podLabels\":{\"global-key\":\"global-value\"}}",
					"test-default-kopia":             "{\"podResources\":{\"cpuRequest\":\"100m\",\"cpuLimit\":\"200m\",\"memoryRequest\":\"100Mi\",\"memoryLimit\":\"200Mi\"},\"loadAffinity\":[{\"nodeSelector\":{\"matchExpressions\":[{\"key\":\"cloud.google.com/machine-family\",\"operator\":\"In\",\"values\":[\"e2\"]}]}}],\"priorityClassName\":\"specific-priority\",\"podAnnotations\":{\"specific-key\":\"specific-value\"},\"podLabels\":{\"specific-key\":\"specific-value\"}}",
				},
			},
			expectedConfig: &velerotypes.JobConfigs{
				KeepLatestMaintenanceJobs: &keepLatestMaintenanceJobs,
				PodResources: &kube.PodResources{
					CPURequest:    "100m",
					CPULimit:      "200m",
					MemoryRequest: "100Mi",
					MemoryLimit:   "200Mi",
				},
				LoadAffinities: []*kube.LoadAffinity{
					{
						NodeSelector: metav1.LabelSelector{
							MatchExpressions: []metav1.LabelSelectorRequirement{
								{
									Key:      "cloud.google.com/machine-family",
									Operator: metav1.LabelSelectorOpIn,
									Values:   []string{"e2"},
								},
							},
						},
					},
				},
				PriorityClassName: "global-priority",
				PodAnnotations:    map[string]string{"global-key": "global-value"},
				PodLabels:         map[string]string{"global-key": "global-value"},
			},
			expectedError: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var fakeClient client.Client
			if tc.repoJobConfig != nil {
				fakeClient = velerotest.NewFakeControllerRuntimeClient(t, tc.repoJobConfig)
			} else {
				fakeClient = velerotest.NewFakeControllerRuntimeClient(t)
			}

			jobConfig, err := getJobConfig(
				ctx,
				fakeClient,
				logger,
				veleroNamespace,
				repoMaintenanceJobConfig,
				repo,
			)

			if tc.expectedError != nil {
				require.ErrorContains(t, err, tc.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tc.expectedConfig, jobConfig)
		})
	}
}

func TestWaitAllJobsComplete(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second*2)

	veleroNamespace := "velero"
	repo := &velerov1api.BackupRepository{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: veleroNamespace,
			Name:      "label with more than 63 characters should be modified",
		},
		Spec: velerov1api.BackupRepositorySpec{
			BackupStorageLocation: "default",
			RepositoryType:        "kopia",
			VolumeNamespace:       "test",
		},
	}

	now := time.Now().Round(time.Second)

	jobOtherLabel := &batchv1api.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "job1",
			Namespace:         veleroNamespace,
			Labels:            map[string]string{RepositoryNameLabel: "other-repo"},
			CreationTimestamp: metav1.Time{Time: now},
		},
	}

	jobIncomplete := &batchv1api.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "job1",
			Namespace:         veleroNamespace,
			Labels:            map[string]string{RepositoryNameLabel: velerolabel.ReturnNameOrHash(repo.Name)},
			CreationTimestamp: metav1.Time{Time: now},
		},
	}

	jobSucceeded1 := &batchv1api.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "job1",
			Namespace:         veleroNamespace,
			Labels:            map[string]string{RepositoryNameLabel: velerolabel.ReturnNameOrHash(repo.Name)},
			CreationTimestamp: metav1.Time{Time: now},
		},
		Status: batchv1api.JobStatus{
			StartTime:      &metav1.Time{Time: now},
			CompletionTime: &metav1.Time{Time: now.Add(time.Hour)},
			Succeeded:      1,
		},
	}

	jobPodSucceeded1 := builder.ForPod(veleroNamespace, "job1").Labels(map[string]string{"job-name": "job1"}).ContainerStatuses(&corev1api.ContainerStatus{
		State: corev1api.ContainerState{
			Terminated: &corev1api.ContainerStateTerminated{},
		},
	}).Result()

	jobFailed1 := &batchv1api.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "job2",
			Namespace:         veleroNamespace,
			Labels:            map[string]string{RepositoryNameLabel: velerolabel.ReturnNameOrHash(repo.Name)},
			CreationTimestamp: metav1.Time{Time: now.Add(time.Hour)},
		},
		Status: batchv1api.JobStatus{
			StartTime: &metav1.Time{Time: now.Add(time.Hour)},
			Failed:    1,
		},
	}

	jobPodFailed1 := builder.ForPod(veleroNamespace, "job2").Labels(map[string]string{"job-name": "job2"}).ContainerStatuses(&corev1api.ContainerStatus{
		State: corev1api.ContainerState{
			Terminated: &corev1api.ContainerStateTerminated{
				Message: "Repo maintenance error: fake-message-2",
			},
		},
	}).Result()

	jobSucceeded2 := &batchv1api.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "job3",
			Namespace:         veleroNamespace,
			Labels:            map[string]string{RepositoryNameLabel: velerolabel.ReturnNameOrHash(repo.Name)},
			CreationTimestamp: metav1.Time{Time: now.Add(time.Hour * 2)},
		},
		Status: batchv1api.JobStatus{
			StartTime:      &metav1.Time{Time: now.Add(time.Hour * 2)},
			CompletionTime: &metav1.Time{Time: now.Add(time.Hour * 3)},
			Succeeded:      1,
		},
	}

	jobPodSucceeded2 := builder.ForPod(veleroNamespace, "job3").Labels(map[string]string{"job-name": "job3"}).ContainerStatuses(&corev1api.ContainerStatus{
		State: corev1api.ContainerState{
			Terminated: &corev1api.ContainerStateTerminated{},
		},
	}).Result()

	jobSucceeded3 := &batchv1api.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "job4",
			Namespace:         veleroNamespace,
			Labels:            map[string]string{RepositoryNameLabel: velerolabel.ReturnNameOrHash(repo.Name)},
			CreationTimestamp: metav1.Time{Time: now.Add(time.Hour * 3)},
		},
		Status: batchv1api.JobStatus{
			StartTime:      &metav1.Time{Time: now.Add(time.Hour * 3)},
			CompletionTime: &metav1.Time{Time: now.Add(time.Hour * 4)},
			Succeeded:      1,
		},
	}

	jobPodSucceeded3 := builder.ForPod(veleroNamespace, "job4").Labels(map[string]string{"job-name": "job4"}).ContainerStatuses(&corev1api.ContainerStatus{
		State: corev1api.ContainerState{
			Terminated: &corev1api.ContainerStateTerminated{},
		},
	}).Result()

	schemeFail := runtime.NewScheme()

	scheme := runtime.NewScheme()
	batchv1api.AddToScheme(scheme)
	corev1api.AddToScheme(scheme)

	testCases := []struct {
		name           string
		ctx            context.Context
		kubeClientObj  []runtime.Object
		runtimeScheme  *runtime.Scheme
		expectedStatus []velerov1api.BackupRepositoryMaintenanceStatus
		expectedError  string
	}{
		{
			name:          "list job error",
			runtimeScheme: schemeFail,
			expectedError: "error listing maintenance job for repo label with more than 63 characters should be modified: no kind is registered for the type v1.JobList in scheme",
		},
		{
			name:          "job not exist",
			runtimeScheme: scheme,
		},
		{
			name:          "no matching job",
			runtimeScheme: scheme,
			kubeClientObj: []runtime.Object{
				jobOtherLabel,
			},
		},
		{
			name:          "wait complete error",
			ctx:           ctx,
			runtimeScheme: scheme,
			kubeClientObj: []runtime.Object{
				jobIncomplete,
			},
			expectedError: "error waiting maintenance job[job1] complete: context deadline exceeded",
		},
		{
			name:          "get result error on succeeded job",
			ctx:           t.Context(),
			runtimeScheme: scheme,
			kubeClientObj: []runtime.Object{
				jobSucceeded1,
			},
			expectedStatus: []velerov1api.BackupRepositoryMaintenanceStatus{
				{
					Result:            velerov1api.BackupRepositoryMaintenanceSucceeded,
					StartTimestamp:    &metav1.Time{Time: now},
					CompleteTimestamp: &metav1.Time{Time: now.Add(time.Hour)},
				},
			},
		},
		{
			name:          "get result error on failed job",
			ctx:           t.Context(),
			runtimeScheme: scheme,
			kubeClientObj: []runtime.Object{
				jobFailed1,
			},
			expectedStatus: []velerov1api.BackupRepositoryMaintenanceStatus{
				{
					Result:         velerov1api.BackupRepositoryMaintenanceFailed,
					StartTimestamp: &metav1.Time{Time: now.Add(time.Hour)},
					Message:        "Repo maintenance failed but result is not retrieveable, err: no pod found for job job2",
				},
			},
		},
		{
			name:          "less than limit",
			ctx:           t.Context(),
			runtimeScheme: scheme,
			kubeClientObj: []runtime.Object{
				jobFailed1,
				jobSucceeded1,
				jobPodSucceeded1,
				jobPodFailed1,
			},
			expectedStatus: []velerov1api.BackupRepositoryMaintenanceStatus{
				{
					Result:            velerov1api.BackupRepositoryMaintenanceSucceeded,
					StartTimestamp:    &metav1.Time{Time: now},
					CompleteTimestamp: &metav1.Time{Time: now.Add(time.Hour)},
				},
				{
					Result:         velerov1api.BackupRepositoryMaintenanceFailed,
					StartTimestamp: &metav1.Time{Time: now.Add(time.Hour)},
					Message:        "fake-message-2",
				},
			},
		},
		{
			name:          "equal to limit",
			ctx:           t.Context(),
			runtimeScheme: scheme,
			kubeClientObj: []runtime.Object{
				jobSucceeded2,
				jobFailed1,
				jobSucceeded1,
				jobPodSucceeded1,
				jobPodFailed1,
				jobPodSucceeded2,
			},
			expectedStatus: []velerov1api.BackupRepositoryMaintenanceStatus{
				{
					Result:            velerov1api.BackupRepositoryMaintenanceSucceeded,
					StartTimestamp:    &metav1.Time{Time: now},
					CompleteTimestamp: &metav1.Time{Time: now.Add(time.Hour)},
				},
				{
					Result:         velerov1api.BackupRepositoryMaintenanceFailed,
					StartTimestamp: &metav1.Time{Time: now.Add(time.Hour)},
					Message:        "fake-message-2",
				},
				{
					Result:            velerov1api.BackupRepositoryMaintenanceSucceeded,
					StartTimestamp:    &metav1.Time{Time: now.Add(time.Hour * 2)},
					CompleteTimestamp: &metav1.Time{Time: now.Add(time.Hour * 3)},
				},
			},
		},
		{
			name:          "more than limit",
			ctx:           t.Context(),
			runtimeScheme: scheme,
			kubeClientObj: []runtime.Object{
				jobSucceeded3,
				jobSucceeded2,
				jobFailed1,
				jobSucceeded1,
				jobPodSucceeded1,
				jobPodFailed1,
				jobPodSucceeded2,
				jobPodSucceeded3,
			},
			expectedStatus: []velerov1api.BackupRepositoryMaintenanceStatus{
				{
					Result:         velerov1api.BackupRepositoryMaintenanceFailed,
					StartTimestamp: &metav1.Time{Time: now.Add(time.Hour)},
					Message:        "fake-message-2",
				},
				{
					Result:            velerov1api.BackupRepositoryMaintenanceSucceeded,
					StartTimestamp:    &metav1.Time{Time: now.Add(time.Hour * 2)},
					CompleteTimestamp: &metav1.Time{Time: now.Add(time.Hour * 3)},
				},
				{
					Result:            velerov1api.BackupRepositoryMaintenanceSucceeded,
					StartTimestamp:    &metav1.Time{Time: now.Add(time.Hour * 3)},
					CompleteTimestamp: &metav1.Time{Time: now.Add(time.Hour * 4)},
				},
			},
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			fakeClientBuilder := fake.NewClientBuilder()
			fakeClientBuilder = fakeClientBuilder.WithScheme(test.runtimeScheme)

			fakeClient := fakeClientBuilder.WithRuntimeObjects(test.kubeClientObj...).Build()

			history, err := WaitAllJobsComplete(test.ctx, fakeClient, repo, 3, velerotest.NewLogger())

			if test.expectedError != "" {
				require.ErrorContains(t, err, test.expectedError)
			} else {
				require.NoError(t, err)
			}

			assert.Len(t, history, len(test.expectedStatus))
			for i := 0; i < len(test.expectedStatus); i++ {
				assert.Equal(t, test.expectedStatus[i].Result, history[i].Result)
				assert.Equal(t, test.expectedStatus[i].Message, history[i].Message)
				assert.Equal(t, test.expectedStatus[i].StartTimestamp.Time, history[i].StartTimestamp.Time)

				if test.expectedStatus[i].CompleteTimestamp == nil {
					assert.Nil(t, history[i].CompleteTimestamp)
				} else {
					assert.Equal(t, test.expectedStatus[i].CompleteTimestamp.Time, history[i].CompleteTimestamp.Time)
				}
			}
		})
	}

	cancel()
}

func TestBuildJob(t *testing.T) {
	deploy := appsv1api.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "velero",
			Namespace: "velero",
			Labels: map[string]string{
				"component": "velero",
			},
		},
		Spec: appsv1api.DeploymentSpec{
			Template: corev1api.PodTemplateSpec{
				Spec: corev1api.PodSpec{
					SecurityContext: &corev1api.PodSecurityContext{
						RunAsNonRoot: boolptr.True(),
					},
					Containers: []corev1api.Container{
						{
							Name:  "velero",
							Image: "velero-image",
							SecurityContext: &corev1api.SecurityContext{
								RunAsNonRoot: boolptr.True(),
							},
							Env: []corev1api.EnvVar{
								{
									Name:  "test-name",
									Value: "test-value",
								},
							},
							EnvFrom: []corev1api.EnvFromSource{
								{
									ConfigMapRef: &corev1api.ConfigMapEnvSource{
										LocalObjectReference: corev1api.LocalObjectReference{
											Name: "test-configmap",
										},
									},
								},
								{
									SecretRef: &corev1api.SecretEnvSource{
										LocalObjectReference: corev1api.LocalObjectReference{
											Name: "test-secret",
										},
									},
								},
							},
						},
					},
					ImagePullSecrets: []corev1api.LocalObjectReference{
						{
							Name: "imagePullSecret1",
						},
					},
				},
			},
		},
	}

	deploy2 := deploy.DeepCopy()
	deploy2.Spec.Template.Labels = map[string]string{"azure.workload.identity/use": "fake-label-value"}
	deploy2.Spec.Template.Spec.SecurityContext = nil
	deploy2.Spec.Template.Spec.Containers[0].SecurityContext = nil

	testCases := []struct {
		name                       string
		m                          *velerotypes.JobConfigs
		deploy                     *appsv1api.Deployment
		logLevel                   logrus.Level
		logFormat                  *logging.FormatFlag
		expectedJobName            string
		expectedError              bool
		expectedEnv                []corev1api.EnvVar
		expectedEnvFrom            []corev1api.EnvFromSource
		expectedPodLabel           map[string]string
		expectedPodAnnotation      map[string]string
		expectedSecurityContext    *corev1api.SecurityContext
		expectedPodSecurityContext *corev1api.PodSecurityContext
		expectedImagePullSecrets   []corev1api.LocalObjectReference
		backupRepository           *velerov1api.BackupRepository
	}{
		{
			name: "Valid maintenance job without third party labels",
			m: &velerotypes.JobConfigs{
				PodResources: &kube.PodResources{
					CPURequest:    "100m",
					MemoryRequest: "128Mi",
					CPULimit:      "200m",
					MemoryLimit:   "256Mi",
				},
			},
			deploy:          &deploy,
			logLevel:        logrus.InfoLevel,
			logFormat:       logging.NewFormatFlag(),
			expectedJobName: "test-123-maintain-job",
			expectedError:   false,
			expectedEnv: []corev1api.EnvVar{
				{
					Name:  "test-name",
					Value: "test-value",
				},
			},
			expectedEnvFrom: []corev1api.EnvFromSource{
				{
					ConfigMapRef: &corev1api.ConfigMapEnvSource{
						LocalObjectReference: corev1api.LocalObjectReference{
							Name: "test-configmap",
						},
					},
				},
				{
					SecretRef: &corev1api.SecretEnvSource{
						LocalObjectReference: corev1api.LocalObjectReference{
							Name: "test-secret",
						},
					},
				},
			},
			expectedPodLabel: map[string]string{
				RepositoryNameLabel: "test-123",
			},
			expectedSecurityContext: &corev1api.SecurityContext{
				RunAsNonRoot: boolptr.True(),
			},
			expectedPodSecurityContext: &corev1api.PodSecurityContext{
				RunAsNonRoot: boolptr.True(),
			},
			expectedImagePullSecrets: []corev1api.LocalObjectReference{
				{
					Name: "imagePullSecret1",
				},
			},
		},
		{
			name: "Valid maintenance job with third party labels",
			m: &velerotypes.JobConfigs{
				PodResources: &kube.PodResources{
					CPURequest:    "100m",
					MemoryRequest: "128Mi",
					CPULimit:      "200m",
					MemoryLimit:   "256Mi",
				},
			},
			deploy:          deploy2,
			logLevel:        logrus.InfoLevel,
			logFormat:       logging.NewFormatFlag(),
			expectedJobName: "test-123-maintain-job",
			expectedError:   false,
			expectedEnv: []corev1api.EnvVar{
				{
					Name:  "test-name",
					Value: "test-value",
				},
			},
			expectedEnvFrom: []corev1api.EnvFromSource{
				{
					ConfigMapRef: &corev1api.ConfigMapEnvSource{
						LocalObjectReference: corev1api.LocalObjectReference{
							Name: "test-configmap",
						},
					},
				},
				{
					SecretRef: &corev1api.SecretEnvSource{
						LocalObjectReference: corev1api.LocalObjectReference{
							Name: "test-secret",
						},
					},
				},
			},
			expectedPodLabel: map[string]string{
				RepositoryNameLabel:           "test-123",
				"azure.workload.identity/use": "fake-label-value",
			},
			expectedSecurityContext:    nil,
			expectedPodSecurityContext: nil,
			expectedImagePullSecrets: []corev1api.LocalObjectReference{
				{
					Name: "imagePullSecret1",
				},
			},
		},
		{
			name: "Error getting Velero server deployment",
			m: &velerotypes.JobConfigs{
				PodResources: &kube.PodResources{
					CPURequest:    "100m",
					MemoryRequest: "128Mi",
					CPULimit:      "200m",
					MemoryLimit:   "256Mi",
				},
			},
			logLevel:        logrus.InfoLevel,
			logFormat:       logging.NewFormatFlag(),
			expectedJobName: "",
			expectedError:   true,
		},
		{
			name: "Valid maintenance job customized labels and annotations",
			m: &velerotypes.JobConfigs{
				PodResources: &kube.PodResources{
					CPURequest:    "100m",
					MemoryRequest: "128Mi",
					CPULimit:      "200m",
					MemoryLimit:   "256Mi",
				},
				PodLabels: map[string]string{
					"global-label-1": "global-label-value-1",
					"global-label-2": "global-label-value-2",
				},
				PodAnnotations: map[string]string{
					"global-annotation-1": "global-annotation-value-1",
					"global-annotation-2": "global-annotation-value-2",
				},
			},
			deploy:          deploy2,
			logLevel:        logrus.InfoLevel,
			logFormat:       logging.NewFormatFlag(),
			expectedError:   false,
			expectedJobName: "test-123-maintain-job",
			expectedEnv: []corev1api.EnvVar{
				{
					Name:  "test-name",
					Value: "test-value",
				},
			},
			expectedEnvFrom: []corev1api.EnvFromSource{
				{
					ConfigMapRef: &corev1api.ConfigMapEnvSource{
						LocalObjectReference: corev1api.LocalObjectReference{
							Name: "test-configmap",
						},
					},
				},
				{
					SecretRef: &corev1api.SecretEnvSource{
						LocalObjectReference: corev1api.LocalObjectReference{
							Name: "test-secret",
						},
					},
				},
			},
			expectedPodLabel: map[string]string{
				"global-label-1":    "global-label-value-1",
				"global-label-2":    "global-label-value-2",
				RepositoryNameLabel: "test-123",
			},
			expectedPodAnnotation: map[string]string{
				"global-annotation-1": "global-annotation-value-1",
				"global-annotation-2": "global-annotation-value-2",
			},
			expectedSecurityContext:    nil,
			expectedPodSecurityContext: nil,
			expectedImagePullSecrets: []corev1api.LocalObjectReference{
				{
					Name: "imagePullSecret1",
				},
			},
		},
		{
			name: "Valid maintenance job with third party labels and BackupRepository name longer than 63",
			m: &velerotypes.JobConfigs{
				PodResources: &kube.PodResources{
					CPURequest:    "100m",
					MemoryRequest: "128Mi",
					CPULimit:      "200m",
					MemoryLimit:   "256Mi",
				},
			},
			deploy:        deploy2,
			logLevel:      logrus.InfoLevel,
			logFormat:     logging.NewFormatFlag(),
			expectedError: false,
			expectedEnv: []corev1api.EnvVar{
				{
					Name:  "test-name",
					Value: "test-value",
				},
			},
			expectedEnvFrom: []corev1api.EnvFromSource{
				{
					ConfigMapRef: &corev1api.ConfigMapEnvSource{
						LocalObjectReference: corev1api.LocalObjectReference{
							Name: "test-configmap",
						},
					},
				},
				{
					SecretRef: &corev1api.SecretEnvSource{
						LocalObjectReference: corev1api.LocalObjectReference{
							Name: "test-secret",
						},
					},
				},
			},
			expectedPodLabel: map[string]string{
				RepositoryNameLabel:           velerolabel.ReturnNameOrHash("label with more than 63 characters should be modified"),
				"azure.workload.identity/use": "fake-label-value",
			},
			expectedSecurityContext:    nil,
			expectedPodSecurityContext: nil,
			expectedImagePullSecrets: []corev1api.LocalObjectReference{
				{
					Name: "imagePullSecret1",
				},
			},
			backupRepository: &velerov1api.BackupRepository{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "velero",
					Name:      "label with more than 63 characters should be modified",
				},
				Spec: velerov1api.BackupRepositorySpec{
					VolumeNamespace: "test-123",
					RepositoryType:  "kopia",
				},
			},
		},
	}

	param := provider.RepoParam{
		BackupRepo: &velerov1api.BackupRepository{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "velero",
				Name:      "test-123",
			},
			Spec: velerov1api.BackupRepositorySpec{
				VolumeNamespace: "test-123",
				RepositoryType:  "kopia",
			},
		},
		BackupLocation: &velerov1api.BackupStorageLocation{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "velero",
				Name:      "test-location",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.backupRepository != nil {
				param.BackupRepo = tc.backupRepository
			}

			// Create a fake clientset with resources
			objs := []runtime.Object{param.BackupLocation, param.BackupRepo}

			if tc.deploy != nil {
				objs = append(objs, tc.deploy)
			}
			scheme := runtime.NewScheme()
			_ = appsv1api.AddToScheme(scheme)
			_ = velerov1api.AddToScheme(scheme)
			cli := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objs...).Build()

			// Call the function to test
			job, err := buildJob(
				cli,
				t.Context(),
				param.BackupRepo,
				param.BackupLocation.Name,
				tc.m,
				tc.logLevel,
				tc.logFormat,
				logrus.New(),
			)

			// Check the error
			if tc.expectedError {
				require.Error(t, err)
				assert.Nil(t, job)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, job)
				assert.Contains(t, job.Name, tc.expectedJobName)
				assert.Equal(t, param.BackupRepo.Namespace, job.Namespace)
				assert.Equal(t, param.BackupRepo.Name, job.Labels[RepositoryNameLabel])

				assert.Equal(t, param.BackupRepo.Name, job.Spec.Template.ObjectMeta.Labels[RepositoryNameLabel])

				// Check container
				assert.Len(t, job.Spec.Template.Spec.Containers, 1)
				container := job.Spec.Template.Spec.Containers[0]
				assert.Equal(t, "velero-repo-maintenance-container", container.Name)
				assert.Equal(t, "velero-image", container.Image)
				assert.Equal(t, corev1api.PullIfNotPresent, container.ImagePullPolicy)

				// Check container env
				assert.Equal(t, tc.expectedEnv, container.Env)
				assert.Equal(t, tc.expectedEnvFrom, container.EnvFrom)

				// Check security context
				assert.Equal(t, tc.expectedPodSecurityContext, job.Spec.Template.Spec.SecurityContext)
				assert.Equal(t, tc.expectedSecurityContext, container.SecurityContext)

				// Check resources
				expectedResources := corev1api.ResourceRequirements{
					Requests: corev1api.ResourceList{
						corev1api.ResourceCPU:    resource.MustParse(tc.m.PodResources.CPURequest),
						corev1api.ResourceMemory: resource.MustParse(tc.m.PodResources.MemoryRequest),
					},
					Limits: corev1api.ResourceList{
						corev1api.ResourceCPU:    resource.MustParse(tc.m.PodResources.CPULimit),
						corev1api.ResourceMemory: resource.MustParse(tc.m.PodResources.MemoryLimit),
					},
				}
				assert.Equal(t, expectedResources, container.Resources)

				// Check args
				expectedArgs := []string{
					"repo-maintenance",
					fmt.Sprintf("--repo-name=%s", param.BackupRepo.Spec.VolumeNamespace),
					fmt.Sprintf("--repo-type=%s", param.BackupRepo.Spec.RepositoryType),
					fmt.Sprintf("--backup-storage-location=%s", param.BackupLocation.Name),
					fmt.Sprintf("--log-level=%s", tc.logLevel.String()),
					fmt.Sprintf("--log-format=%s", tc.logFormat.String()),
				}
				assert.Equal(t, expectedArgs, container.Args)

				assert.Equal(t, tc.expectedPodLabel, job.Spec.Template.Labels)

				assert.Equal(t, tc.expectedImagePullSecrets, job.Spec.Template.Spec.ImagePullSecrets)
			}
		})
	}
}

func TestGetKeepLatestMaintenanceJobs(t *testing.T) {
	tests := []struct {
		name                     string
		repoMaintenanceJobConfig string
		configMap                *corev1api.ConfigMap
		repo                     *velerov1api.BackupRepository
		expectedValue            int
		expectError              bool
	}{
		{
			name:                     "no config map name provided",
			repoMaintenanceJobConfig: "",
			configMap:                nil,
			repo:                     mockBackupRepo(),
			expectedValue:            3,
			expectError:              false,
		},
		{
			name:                     "config map not found",
			repoMaintenanceJobConfig: "non-existent-config",
			configMap:                nil,
			repo:                     mockBackupRepo(),
			expectedValue:            3,
			expectError:              false,
		},
		{
			name:                     "config map with global keepLatestMaintenanceJobs",
			repoMaintenanceJobConfig: "repo-job-config",
			configMap: &corev1api.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "velero",
					Name:      "repo-job-config",
				},
				Data: map[string]string{
					"global": `{"keepLatestMaintenanceJobs": 5}`,
				},
			},
			repo:          mockBackupRepo(),
			expectedValue: 5,
			expectError:   false,
		},
		{
			name:                     "config map with specific repo keepLatestMaintenanceJobs overriding global",
			repoMaintenanceJobConfig: "repo-job-config",
			configMap: &corev1api.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "velero",
					Name:      "repo-job-config",
				},
				Data: map[string]string{
					"global":                `{"keepLatestMaintenanceJobs": 5}`,
					"test-ns-default-kopia": `{"keepLatestMaintenanceJobs": 10}`,
				},
			},
			repo:          mockBackupRepo(),
			expectedValue: 10,
			expectError:   false,
		},
		{
			name:                     "config map with no keepLatestMaintenanceJobs specified",
			repoMaintenanceJobConfig: "repo-job-config",
			configMap: &corev1api.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "velero",
					Name:      "repo-job-config",
				},
				Data: map[string]string{
					"global": `{"podResources": {"cpuRequest": "100m"}}`,
				},
			},
			repo:          mockBackupRepo(),
			expectedValue: 3,
			expectError:   false,
		},
		{
			name:                     "config map with invalid JSON",
			repoMaintenanceJobConfig: "repo-job-config",
			configMap: &corev1api.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "velero",
					Name:      "repo-job-config",
				},
				Data: map[string]string{
					"global": `{"keepLatestMaintenanceJobs": invalid}`,
				},
			},
			repo:          mockBackupRepo(),
			expectedValue: 3,
			expectError:   true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			corev1api.AddToScheme(scheme)

			var objects []runtime.Object
			if test.configMap != nil {
				objects = append(objects, test.configMap)
			}

			client := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objects...).Build()
			logger := velerotest.NewLogger()

			result, err := GetKeepLatestMaintenanceJobs(
				t.Context(),
				client,
				logger,
				"velero",
				test.repoMaintenanceJobConfig,
				test.repo,
			)

			if test.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, test.expectedValue, result)
			}
		})
	}
}

func mockBackupRepo() *velerov1api.BackupRepository {
	return &velerov1api.BackupRepository{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "velero",
			Name:      "test-repo",
		},
		Spec: velerov1api.BackupRepositorySpec{
			VolumeNamespace:       "test-ns",
			BackupStorageLocation: "default",
			RepositoryType:        "kopia",
		},
	}
}

func TestGetPriorityClassName(t *testing.T) {
	testCases := []struct {
		name                string
		config              *velerotypes.JobConfigs
		priorityClassExists bool
		expectedValue       string
		expectedLogContains string
		expectedLogLevel    string
	}{
		{
			name:                "empty priority class name should return empty string",
			config:              &velerotypes.JobConfigs{PriorityClassName: ""},
			expectedValue:       "",
			expectedLogContains: "",
		},
		{
			name:                "nil config should return empty string",
			config:              nil,
			expectedValue:       "",
			expectedLogContains: "",
		},
		{
			name:                "existing priority class should log info and return name",
			config:              &velerotypes.JobConfigs{PriorityClassName: "high-priority"},
			priorityClassExists: true,
			expectedValue:       "high-priority",
			expectedLogContains: "Validated priority class \\\"high-priority\\\" exists in cluster",
			expectedLogLevel:    "info",
		},
		{
			name:                "non-existing priority class should log warning and still return name",
			config:              &velerotypes.JobConfigs{PriorityClassName: "missing-priority"},
			priorityClassExists: false,
			expectedValue:       "missing-priority",
			expectedLogContains: "Priority class \\\"missing-priority\\\" not found in cluster",
			expectedLogLevel:    "warning",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a new scheme and add necessary API types
			localScheme := runtime.NewScheme()
			err := schedulingv1.AddToScheme(localScheme)
			require.NoError(t, err)

			// Create fake client builder
			clientBuilder := fake.NewClientBuilder().WithScheme(localScheme)

			// Add priority class if it should exist
			if tc.priorityClassExists {
				priorityClass := &schedulingv1.PriorityClass{
					ObjectMeta: metav1.ObjectMeta{
						Name: tc.config.PriorityClassName,
					},
					Value: 1000,
				}
				clientBuilder = clientBuilder.WithObjects(priorityClass)
			}

			client := clientBuilder.Build()

			// Capture logs
			var logBuffer strings.Builder
			logger := logrus.New()
			logger.SetOutput(&logBuffer)
			logger.SetLevel(logrus.InfoLevel)

			// Call the function
			result := getPriorityClassName(t.Context(), client, tc.config, logger)

			// Verify the result
			assert.Equal(t, tc.expectedValue, result)

			// Verify log output
			logOutput := logBuffer.String()
			if tc.expectedLogContains != "" {
				assert.Contains(t, logOutput, tc.expectedLogContains)
			}

			// Verify log level
			if tc.expectedLogLevel == "warning" {
				assert.Contains(t, logOutput, "level=warning")
			} else if tc.expectedLogLevel == "info" {
				assert.Contains(t, logOutput, "level=info")
			}
		})
	}
}

func TestBuildJobWithPriorityClassName(t *testing.T) {
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
			// Create a new scheme and add necessary API types
			localScheme := runtime.NewScheme()
			err := velerov1api.AddToScheme(localScheme)
			require.NoError(t, err)
			err = appsv1api.AddToScheme(localScheme)
			require.NoError(t, err)
			err = batchv1api.AddToScheme(localScheme)
			require.NoError(t, err)
			err = schedulingv1.AddToScheme(localScheme)
			require.NoError(t, err)
			// Create a fake client
			client := fake.NewClientBuilder().WithScheme(localScheme).Build()

			// Create a deployment with the specified priority class name
			deployment := &appsv1api.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "velero",
					Namespace: "velero",
					Labels: map[string]string{
						"component": "velero",
					},
				},
				Spec: appsv1api.DeploymentSpec{
					Template: corev1api.PodTemplateSpec{
						Spec: corev1api.PodSpec{
							Containers: []corev1api.Container{
								{
									Name:  "velero",
									Image: "velero/velero:latest",
								},
							},
							PriorityClassName: tc.priorityClassName,
						},
					},
				},
			}

			// Create a backup repository
			repo := &velerov1api.BackupRepository{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-repo",
					Namespace: "velero",
				},
				Spec: velerov1api.BackupRepositorySpec{
					VolumeNamespace:       "velero",
					BackupStorageLocation: "default",
				},
			}

			// Create the deployment in the fake client
			err = client.Create(t.Context(), deployment)
			require.NoError(t, err)

			// Create minimal job configs and resources
			jobConfig := &velerotypes.JobConfigs{
				PriorityClassName: tc.priorityClassName,
			}
			logLevel := logrus.InfoLevel
			logFormat := logging.NewFormatFlag()
			logFormat.Set("text")

			// Call buildJob
			job, err := buildJob(client, t.Context(), repo, "default", jobConfig, logLevel, logFormat, logrus.New())
			require.NoError(t, err)

			// Verify the priority class name is set correctly
			assert.Equal(t, tc.expectedValue, job.Spec.Template.Spec.PriorityClassName)
		})
	}
}

func TestBuildTolerationsForMaintenanceJob(t *testing.T) {
	windowsToleration := corev1api.Toleration{
		Key:      "os",
		Operator: "Equal",
		Effect:   "NoSchedule",
		Value:    "windows",
	}

	testCases := []struct {
		name                  string
		deploymentTolerations []corev1api.Toleration
		expectedTolerations   []corev1api.Toleration
	}{
		{
			name:                  "no tolerations should only include Windows toleration",
			deploymentTolerations: nil,
			expectedTolerations: []corev1api.Toleration{
				windowsToleration,
			},
		},
		{
			name:                  "empty tolerations should only include Windows toleration",
			deploymentTolerations: []corev1api.Toleration{},
			expectedTolerations: []corev1api.Toleration{
				windowsToleration,
			},
		},
		{
			name: "non-allowed toleration should not be inherited",
			deploymentTolerations: []corev1api.Toleration{
				{
					Key:      "vng-ondemand",
					Operator: "Equal",
					Effect:   "NoSchedule",
					Value:    "amd64",
				},
			},
			expectedTolerations: []corev1api.Toleration{
				windowsToleration,
			},
		},
		{
			name: "allowed toleration should be inherited",
			deploymentTolerations: []corev1api.Toleration{
				{
					Key:      "kubernetes.azure.com/scalesetpriority",
					Operator: "Equal",
					Effect:   "NoSchedule",
					Value:    "spot",
				},
			},
			expectedTolerations: []corev1api.Toleration{
				windowsToleration,
				{
					Key:      "kubernetes.azure.com/scalesetpriority",
					Operator: "Equal",
					Effect:   "NoSchedule",
					Value:    "spot",
				},
			},
		},
		{
			name: "mixed allowed and non-allowed tolerations should only inherit allowed",
			deploymentTolerations: []corev1api.Toleration{
				{
					Key:      "vng-ondemand", // not in allowlist
					Operator: "Equal",
					Effect:   "NoSchedule",
					Value:    "amd64",
				},
				{
					Key:      "CriticalAddonsOnly", // in allowlist
					Operator: "Exists",
					Effect:   "NoSchedule",
				},
				{
					Key:      "custom-key", // not in allowlist
					Operator: "Equal",
					Effect:   "NoSchedule",
					Value:    "custom-value",
				},
			},
			expectedTolerations: []corev1api.Toleration{
				windowsToleration,
				{
					Key:      "CriticalAddonsOnly",
					Operator: "Exists",
					Effect:   "NoSchedule",
				},
			},
		},
		{
			name: "multiple allowed tolerations should all be inherited",
			deploymentTolerations: []corev1api.Toleration{
				{
					Key:      "kubernetes.azure.com/scalesetpriority",
					Operator: "Equal",
					Effect:   "NoSchedule",
					Value:    "spot",
				},
				{
					Key:      "CriticalAddonsOnly",
					Operator: "Exists",
					Effect:   "NoSchedule",
				},
			},
			expectedTolerations: []corev1api.Toleration{
				windowsToleration,
				{
					Key:      "kubernetes.azure.com/scalesetpriority",
					Operator: "Equal",
					Effect:   "NoSchedule",
					Value:    "spot",
				},
				{
					Key:      "CriticalAddonsOnly",
					Operator: "Exists",
					Effect:   "NoSchedule",
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a deployment with the specified tolerations
			deployment := &appsv1api.Deployment{
				Spec: appsv1api.DeploymentSpec{
					Template: corev1api.PodTemplateSpec{
						Spec: corev1api.PodSpec{
							Tolerations: tc.deploymentTolerations,
						},
					},
				},
			}

			result := buildTolerationsForMaintenanceJob(deployment)
			assert.Equal(t, tc.expectedTolerations, result)
		})
	}
}

func TestBuildJobWithTolerationsInheritance(t *testing.T) {
	// Define allowed tolerations that would be set on Velero deployment
	allowedTolerations := []corev1api.Toleration{
		{
			Key:      "kubernetes.azure.com/scalesetpriority",
			Operator: "Equal",
			Effect:   "NoSchedule",
			Value:    "spot",
		},
		{
			Key:      "CriticalAddonsOnly",
			Operator: "Exists",
			Effect:   "NoSchedule",
		},
	}

	// Mixed tolerations (allowed and non-allowed)
	mixedTolerations := []corev1api.Toleration{
		{
			Key:      "vng-ondemand", // not in allowlist
			Operator: "Equal",
			Effect:   "NoSchedule",
			Value:    "amd64",
		},
		{
			Key:      "CriticalAddonsOnly", // in allowlist
			Operator: "Exists",
			Effect:   "NoSchedule",
		},
	}

	// Windows toleration that should always be present
	windowsToleration := corev1api.Toleration{
		Key:      "os",
		Operator: "Equal",
		Effect:   "NoSchedule",
		Value:    "windows",
	}

	testCases := []struct {
		name                  string
		deploymentTolerations []corev1api.Toleration
		expectedTolerations   []corev1api.Toleration
	}{
		{
			name:                  "no tolerations on deployment should only have Windows toleration",
			deploymentTolerations: nil,
			expectedTolerations: []corev1api.Toleration{
				windowsToleration,
			},
		},
		{
			name:                  "allowed tolerations should be inherited along with Windows toleration",
			deploymentTolerations: allowedTolerations,
			expectedTolerations: []corev1api.Toleration{
				windowsToleration,
				{
					Key:      "kubernetes.azure.com/scalesetpriority",
					Operator: "Equal",
					Effect:   "NoSchedule",
					Value:    "spot",
				},
				{
					Key:      "CriticalAddonsOnly",
					Operator: "Exists",
					Effect:   "NoSchedule",
				},
			},
		},
		{
			name:                  "mixed tolerations should only inherit allowed ones",
			deploymentTolerations: mixedTolerations,
			expectedTolerations: []corev1api.Toleration{
				windowsToleration,
				{
					Key:      "CriticalAddonsOnly",
					Operator: "Exists",
					Effect:   "NoSchedule",
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a new scheme and add necessary API types
			localScheme := runtime.NewScheme()
			err := velerov1api.AddToScheme(localScheme)
			require.NoError(t, err)
			err = appsv1api.AddToScheme(localScheme)
			require.NoError(t, err)
			err = batchv1api.AddToScheme(localScheme)
			require.NoError(t, err)

			// Create a deployment with the specified tolerations
			deployment := &appsv1api.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "velero",
					Namespace: "velero",
					Labels: map[string]string{
						"component": "velero",
					},
				},
				Spec: appsv1api.DeploymentSpec{
					Template: corev1api.PodTemplateSpec{
						Spec: corev1api.PodSpec{
							Containers: []corev1api.Container{
								{
									Name:  "velero",
									Image: "velero/velero:latest",
								},
							},
							Tolerations: tc.deploymentTolerations,
						},
					},
				},
			}

			// Create a backup repository
			repo := &velerov1api.BackupRepository{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-repo",
					Namespace: "velero",
				},
				Spec: velerov1api.BackupRepositorySpec{
					VolumeNamespace:       "velero",
					BackupStorageLocation: "default",
				},
			}

			// Create fake client and add the deployment
			client := fake.NewClientBuilder().WithScheme(localScheme).WithObjects(deployment).Build()

			// Create minimal job configs and resources
			jobConfig := &velerotypes.JobConfigs{}
			logLevel := logrus.InfoLevel
			logFormat := logging.NewFormatFlag()
			logFormat.Set("text")

			// Call buildJob
			job, err := buildJob(client, t.Context(), repo, "default", jobConfig, logLevel, logFormat, logrus.New())
			require.NoError(t, err)

			// Verify the tolerations are set correctly
			assert.Equal(t, tc.expectedTolerations, job.Spec.Template.Spec.Tolerations)
		})
	}
}
