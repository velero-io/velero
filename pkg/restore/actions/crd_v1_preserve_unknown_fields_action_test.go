/*
Copyright 2020 the Velero contributors.

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
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/velero-io/velero/pkg/builder"
	"github.com/velero-io/velero/pkg/plugin/velero"
	"github.com/velero-io/velero/pkg/test"
)

func TestExecuteForACRDWithAnIntOnAFloat64FieldShouldWork(t *testing.T) {
	// ref. reopen of https://github.com/velero-io/velero/issues/2319

	b := builder.ForV1CustomResourceDefinition("test.velero.io")
	// 5 here is just an int value, it could be any other whole number.
	schema := builder.ForJSONSchemaPropsBuilder().Maximum(5).Result()
	b.Version(builder.ForV1CustomResourceDefinitionVersion("v1").Served(true).Storage(true).Schema(schema).Result())
	c := b.Result()

	// Marshall in and out of JSON because the problem doesn't manifest when we use ToUnstructured directly
	// This should simulate the JSON passing over the wire in an HTTP request/response with a dynamic client
	js, err := json.Marshal(c)
	require.NoError(t, err)

	var u unstructured.Unstructured
	err = json.Unmarshal(js, &u)
	require.NoError(t, err)

	a := NewCRDV1PreserveUnknownFieldsAction(test.NewLogger())

	_, err = a.Execute(&velero.RestoreItemActionExecuteInput{Item: &u})
	require.NoError(t, err)
}
