/*
Copyright The Velero Contributors.

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

package exposer

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1api "k8s.io/api/core/v1"
)

func TestDeduplicateTolerations(t *testing.T) {
	tests := []struct {
		name     string
		input    []corev1api.Toleration
		expected []corev1api.Toleration
	}{
		{
			name:     "nil input",
			input:    nil,
			expected: []corev1api.Toleration{},
		},
		{
			name:     "empty input",
			input:    []corev1api.Toleration{},
			expected: []corev1api.Toleration{},
		},
		{
			name: "no duplicates",
			input: []corev1api.Toleration{
				{Key: "os", Operator: "Equal", Value: "windows", Effect: "NoSchedule"},
				{Key: "os", Operator: "Equal", Value: "windows", Effect: "NoExecute"},
			},
			expected: []corev1api.Toleration{
				{Key: "os", Operator: "Equal", Value: "windows", Effect: "NoSchedule"},
				{Key: "os", Operator: "Equal", Value: "windows", Effect: "NoExecute"},
			},
		},
		{
			name: "duplicates removed",
			input: []corev1api.Toleration{
				{Key: "os", Operator: "Equal", Value: "windows", Effect: "NoSchedule"},
				{Key: "os", Operator: "Equal", Value: "windows", Effect: "NoExecute"},
				{Key: "os", Operator: "Equal", Value: "windows", Effect: "NoSchedule"},
				{Key: "os", Operator: "Equal", Value: "windows", Effect: "NoExecute"},
			},
			expected: []corev1api.Toleration{
				{Key: "os", Operator: "Equal", Value: "windows", Effect: "NoSchedule"},
				{Key: "os", Operator: "Equal", Value: "windows", Effect: "NoExecute"},
			},
		},
		{
			name: "preserves order of first occurrence",
			input: []corev1api.Toleration{
				{Key: "custom-taint", Operator: "Equal", Value: "true", Effect: "NoExecute"},
				{Key: "os", Operator: "Equal", Value: "windows", Effect: "NoSchedule"},
				{Key: "os", Operator: "Equal", Value: "windows", Effect: "NoSchedule"},
			},
			expected: []corev1api.Toleration{
				{Key: "custom-taint", Operator: "Equal", Value: "true", Effect: "NoExecute"},
				{Key: "os", Operator: "Equal", Value: "windows", Effect: "NoSchedule"},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := deduplicateTolerations(test.input)
			assert.Equal(t, test.expected, result)
		})
	}
}
