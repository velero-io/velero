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

package builder

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRestoreBuilder_ResourcePoliciesConfigmap(t *testing.T) {
	restore := ForRestore("velero", "my-restore").
		ResourcePoliciesConfigmap("my-policy-cm").
		Result()

	assert.Equal(t, "velero", restore.Namespace)
	assert.Equal(t, "my-restore", restore.Name)
	assert.NotNil(t, restore.Spec.ResourcePolicy)
	assert.Equal(t, "configmap", restore.Spec.ResourcePolicy.Kind)
	assert.Equal(t, "my-policy-cm", restore.Spec.ResourcePolicy.Name)
	assert.Equal(t, (*string)(nil), restore.Spec.ResourcePolicy.APIGroup)
}
