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

package kube

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	schedulingv1 "k8s.io/api/scheduling/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	velerotesting "github.com/velero-io/velero/pkg/test"
)

func TestValidatePriorityClass(t *testing.T) {
	tests := []struct {
		name              string
		priorityClassName string
		existingPCs       []runtime.Object
		clientReactors    []k8stesting.ReactionFunc
		expectedLogs      []string
		expectedLogLevel  string
		expectedResult    bool
	}{
		{
			name:              "empty priority class name should return without logging",
			priorityClassName: "",
			existingPCs:       nil,
			expectedLogs:      nil,
			expectedResult:    true,
		},
		{
			name:              "existing priority class should log info message",
			priorityClassName: "high-priority",
			existingPCs: []runtime.Object{
				&schedulingv1.PriorityClass{
					ObjectMeta: metav1.ObjectMeta{
						Name: "high-priority",
					},
					Value: 100,
				},
			},
			expectedLogs:     []string{"Validated priority class \\\"high-priority\\\" exists in cluster"},
			expectedLogLevel: "info",
			expectedResult:   true,
		},
		{
			name:              "non-existing priority class should log warning",
			priorityClassName: "does-not-exist",
			existingPCs:       nil,
			expectedLogs:      []string{"Priority class \\\"does-not-exist\\\" not found in cluster. Pod creation may fail if the priority class doesn't exist when pods are scheduled."},
			expectedLogLevel:  "warning",
			expectedResult:    false,
		},
		{
			name:              "API error should log warning with error",
			priorityClassName: "test-priority",
			existingPCs:       nil,
			clientReactors: []k8stesting.ReactionFunc{
				func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
					if action.GetVerb() == "get" && action.GetResource().Resource == "priorityclasses" {
						return true, nil, fmt.Errorf("API server error")
					}
					return false, nil, nil
				},
			},
			expectedLogs:     []string{"Failed to validate priority class \\\"test-priority\\\""},
			expectedLogLevel: "warning",
			expectedResult:   false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Create fake client with existing priority classes
			kubeClient := fake.NewSimpleClientset(test.existingPCs...)

			// Add any custom reactors
			for _, reactor := range test.clientReactors {
				kubeClient.PrependReactor("*", "*", reactor)
			}

			// Create test logger with buffer
			buffer := []string{}
			logger := velerotesting.NewMultipleLogger(&buffer)

			// Call the function
			result := ValidatePriorityClass(t.Context(), kubeClient, test.priorityClassName, logger)

			// Check result
			assert.Equal(t, test.expectedResult, result, "ValidatePriorityClass returned unexpected result")

			// Check logs
			if test.expectedLogs == nil {
				assert.Empty(t, buffer)
			} else {
				assert.Len(t, buffer, len(test.expectedLogs))

				for i, expectedLog := range test.expectedLogs {
					assert.Contains(t, buffer[i], expectedLog)
					if test.expectedLogLevel == "info" {
						assert.Contains(t, buffer[i], "level=info")
					} else if test.expectedLogLevel == "warning" {
						assert.Contains(t, buffer[i], "level=warning")
					}
				}
			}
		})
	}
}
