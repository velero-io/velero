/*
Copyright 2017 the Velero contributors.

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

package actions

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	batchv1api "k8s.io/api/batch/v1"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/velero-io/velero/pkg/plugin/velero"
	velerotest "github.com/velero-io/velero/pkg/test"
)

func TestJobActionExecute(t *testing.T) {
	tests := []struct {
		name        string
		obj         batchv1api.Job
		expectedErr bool
		expectedRes batchv1api.Job
	}{
		{
			name: "missing spec.selector and/or spec.template should not error",
			obj: batchv1api.Job{
				ObjectMeta: metav1.ObjectMeta{Name: "job-1"},
			},
			expectedRes: batchv1api.Job{
				ObjectMeta: metav1.ObjectMeta{Name: "job-1"},
			},
		},
		{
			name: "missing spec.selector.matchLabels should not error",
			obj: batchv1api.Job{
				ObjectMeta: metav1.ObjectMeta{Name: "job-1"},
				Spec: batchv1api.JobSpec{
					Selector: new(metav1.LabelSelector),
				},
			},
			expectedRes: batchv1api.Job{
				ObjectMeta: metav1.ObjectMeta{Name: "job-1"},
				Spec: batchv1api.JobSpec{
					Selector: new(metav1.LabelSelector),
				},
			},
		},
		{
			name: "spec.selector.matchLabels[controller-uid] is removed",
			obj: batchv1api.Job{
				ObjectMeta: metav1.ObjectMeta{Name: "job-1"},
				Spec: batchv1api.JobSpec{
					Selector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"controller-uid": "foo",
							"hello":          "world",
						},
					},
				},
			},
			expectedRes: batchv1api.Job{
				ObjectMeta: metav1.ObjectMeta{Name: "job-1"},
				Spec: batchv1api.JobSpec{
					Selector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"hello": "world",
						},
					},
				},
			},
		},
		{
			name: "missing spec.template.metadata.labels should not error",
			obj: batchv1api.Job{
				ObjectMeta: metav1.ObjectMeta{Name: "job-1"},
				Spec: batchv1api.JobSpec{
					Template: corev1api.PodTemplateSpec{},
				},
			},
			expectedRes: batchv1api.Job{
				ObjectMeta: metav1.ObjectMeta{Name: "job-1"},
				Spec: batchv1api.JobSpec{
					Template: corev1api.PodTemplateSpec{},
				},
			},
		},
		{
			name: "spec.template.metadata.labels[controller-uid] is removed",
			obj: batchv1api.Job{
				ObjectMeta: metav1.ObjectMeta{Name: "job-1"},
				Spec: batchv1api.JobSpec{
					Template: corev1api.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Labels: map[string]string{
								"controller-uid": "foo",
								"hello":          "world",
							},
						},
					},
				},
			},
			expectedRes: batchv1api.Job{
				ObjectMeta: metav1.ObjectMeta{Name: "job-1"},
				Spec: batchv1api.JobSpec{
					Template: corev1api.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Labels: map[string]string{
								"hello": "world",
							},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			action := NewJobAction(velerotest.NewLogger())

			unstructuredJob, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&test.obj)
			require.NoError(t, err)

			res, err := action.Execute(&velero.RestoreItemActionExecuteInput{
				Item:           &unstructured.Unstructured{Object: unstructuredJob},
				ItemFromBackup: &unstructured.Unstructured{Object: unstructuredJob},
				Restore:        nil,
			})

			if assert.Equal(t, test.expectedErr, err != nil) {
				var job batchv1api.Job
				require.NoError(t, runtime.DefaultUnstructuredConverter.FromUnstructured(res.UpdatedItem.UnstructuredContent(), &job))

				assert.Equal(t, test.expectedRes, job)
			}
		})
	}
}
