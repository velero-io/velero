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

package kube

import (
	corev1api "k8s.io/api/core/v1"
)

// DeduplicateTolerations removes duplicate tolerations from the slice.
// A toleration is considered a duplicate if another toleration with the same
// Key, Operator, Value, and Effect already exists in the slice.
func DeduplicateTolerations(tolerations []corev1api.Toleration) []corev1api.Toleration {
	seen := make(map[string]struct{})
	result := make([]corev1api.Toleration, 0, len(tolerations))
	for _, t := range tolerations {
		key := t.Key + "|" + string(t.Operator) + "|" + t.Value + "|" + string(t.Effect)
		if _, exists := seen[key]; !exists {
			seen[key] = struct{}{}
			result = append(result, t)
		}
	}
	return result
}
