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

package actions

import (
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"

	"github.com/velero-io/velero/pkg/plugin/velero"
	velerotest "github.com/velero-io/velero/pkg/test"
)

func TestAPIServiceActionExecuteSkipsRestore(t *testing.T) {
	obj := apiregistrationv1.APIService{
		ObjectMeta: metav1.ObjectMeta{
			Name: "v1.test.velero.io",
		},
	}

	unstructuredAPIService, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&obj)
	require.NoError(t, err)

	action := NewAPIServiceAction(velerotest.NewLogger())
	res, err := action.Execute(&velero.RestoreItemActionExecuteInput{
		Item:           &unstructured.Unstructured{Object: unstructuredAPIService},
		ItemFromBackup: &unstructured.Unstructured{Object: unstructuredAPIService},
	})
	require.NoError(t, err)

	var apiService apiregistrationv1.APIService
	require.NoError(t, runtime.DefaultUnstructuredConverter.FromUnstructured(res.UpdatedItem.UnstructuredContent(), &apiService))
	require.Equal(t, obj, apiService)
	require.True(t, res.SkipRestore)
}
