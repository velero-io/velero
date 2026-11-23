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
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	apiextfakes "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	velerodiscovery "github.com/velero-io/velero/pkg/discovery"

	v1 "github.com/velero-io/velero/pkg/apis/velero/v1"
	"github.com/velero-io/velero/pkg/builder"
	velerotest "github.com/velero-io/velero/pkg/test"
)

func TestRemapCRDVersionAction(t *testing.T) {
	backup := &v1.Backup{}
	clientset := apiextfakes.NewSimpleClientset()
	betaClient := clientset.ApiextensionsV1beta1().CustomResourceDefinitions()

	// build a v1beta1 CRD with the same name and add it to the fake client that the plugin is going to call.
	// keep the same one for all 3 tests, since there's little value in recreating it
	b := builder.ForCustomResourceDefinitionV1Beta1("test.velero.io")
	c := b.Result()
	_, err := betaClient.Create(t.Context(), c, metav1.CreateOptions{})
	require.NoError(t, err)
	a := NewRemapCRDVersionAction(velerotest.NewLogger(), betaClient, fakeDiscoveryHelper())

	t.Run("Test a v1 CRD without any Schema information", func(t *testing.T) {
		b := builder.ForV1CustomResourceDefinition("test.velero.io")
		// Set a version that does not include and schema information.
		b.Version(builder.ForV1CustomResourceDefinitionVersion("v1").Served(true).Storage(true).Result())
		c := b.Result()

		obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&c)
		require.NoError(t, err)

		// Execute the plugin, which will call the fake client
		item, _, err := a.Execute(&unstructured.Unstructured{Object: obj}, backup)
		require.NoError(t, err)
		assert.Equal(t, "apiextensions.k8s.io/v1beta1", item.UnstructuredContent()["apiVersion"])
	})

	t.Run("Test a v1 CRD with a NonStructuralSchema Condition", func(t *testing.T) {
		b := builder.ForV1CustomResourceDefinition("test.velero.io")
		b.Condition(builder.ForV1CustomResourceDefinitionCondition().Type(apiextv1.NonStructuralSchema).Result())
		c := b.Result()
		obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&c)
		require.NoError(t, err)

		item, _, err := a.Execute(&unstructured.Unstructured{Object: obj}, backup)
		require.NoError(t, err)
		assert.Equal(t, "apiextensions.k8s.io/v1beta1", item.UnstructuredContent()["apiVersion"])
	})

	t.Run("Having an integer on a float64 field should work (issue 2319)", func(t *testing.T) {
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

		_, _, err = a.Execute(&u, backup)
		require.NoError(t, err)
	})

	t.Run("Having Spec.PreserveUnknownFields set to true will return a v1beta1 version of the CRD", func(t *testing.T) {
		b := builder.ForV1CustomResourceDefinition("test.velero.io")
		b.PreserveUnknownFields(true)
		c := b.Result()
		obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&c)
		require.NoError(t, err)

		item, _, err := a.Execute(&unstructured.Unstructured{Object: obj}, backup)
		require.NoError(t, err)
		assert.Equal(t, "apiextensions.k8s.io/v1beta1", item.UnstructuredContent()["apiVersion"])
	})

	t.Run("When the cluster only supports v1 CRD, v1 CRD will be returned even the input has Spec.PreserveUnknownFields set to true (issue 4080)", func(t *testing.T) {
		a.discoveryHelper = &velerotest.FakeDiscoveryHelper{
			APIGroupsList: []metav1.APIGroup{
				{
					Name: apiextv1.GroupName,
					Versions: []metav1.GroupVersionForDiscovery{
						{
							Version: apiextv1.SchemeGroupVersion.Version,
						},
					},
				},
			},
		}
		b := builder.ForV1CustomResourceDefinition("test.velero.io")
		b.PreserveUnknownFields(true)
		c := b.Result()
		obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&c)
		require.NoError(t, err)

		item, _, err := a.Execute(&unstructured.Unstructured{Object: obj}, backup)
		require.NoError(t, err)
		assert.Equal(t, "apiextensions.k8s.io/v1", item.UnstructuredContent()["apiVersion"])
		// set it back to the default one
		a.discoveryHelper = fakeDiscoveryHelper()
	})
}

// TestRemapCRDVersionActionData tests the RemapCRDVersionAction plugin against actual CRD to confirm that the v1beta1 version is returned when the v1 version is passed in to the plugin.
func TestRemapCRDVersionActionData(t *testing.T) {
	backup := &v1.Backup{}
	clientset := apiextfakes.NewSimpleClientset()
	betaClient := clientset.ApiextensionsV1beta1().CustomResourceDefinitions()
	a := NewRemapCRDVersionAction(velerotest.NewLogger(), betaClient, fakeDiscoveryHelper())

	tests := []struct {
		crd                     string
		expectAdditionalColumns bool
	}{
		{
			crd:                     "elasticsearches.elasticsearch.k8s.elastic.co",
			expectAdditionalColumns: true,
		},
		{
			crd:                     "kibanas.kibana.k8s.elastic.co",
			expectAdditionalColumns: true,
		},
		{
			crd: "gcpsamples.gcp.stacks.crossplane.io",
		},
		{
			crd: "alertmanagers.monitoring.coreos.com",
		},
		{
			crd: "prometheuses.monitoring.coreos.com",
		},
	}

	for _, test := range tests {
		tName := fmt.Sprintf("%s CRD passed in as v1 should be returned as v1beta1", test.crd)
		t.Run(tName, func(t *testing.T) {
			// We don't need a Go struct of the v1 data, just an unstructured to pass into the plugin.
			v1File := fmt.Sprintf("testdata/v1/%s.json", test.crd)
			f, err := os.ReadFile(v1File)
			require.NoError(t, err)

			var obj unstructured.Unstructured
			err = json.Unmarshal(f, &obj)
			require.NoError(t, err)

			// Load a v1beta1 struct into the beta client to be returned
			v1beta1File := fmt.Sprintf("testdata/v1beta1/%s.json", test.crd)
			f, err = os.ReadFile(v1beta1File)
			require.NoError(t, err)

			var crd apiextv1beta1.CustomResourceDefinition
			err = json.Unmarshal(f, &crd)
			require.NoError(t, err)

			_, err = betaClient.Create(t.Context(), &crd, metav1.CreateOptions{})
			require.NoError(t, err)

			// Run method under test
			item, _, err := a.Execute(&obj, backup)
			require.NoError(t, err)

			assert.Equal(t, "apiextensions.k8s.io/v1beta1", item.UnstructuredContent()["apiVersion"])
			assert.Equal(t, crd.Kind, item.GetObjectKind().GroupVersionKind().GroupKind().Kind)
			name, _, err := unstructured.NestedString(item.UnstructuredContent(), "metadata", "name")
			require.NoError(t, err)
			assert.Equal(t, crd.Name, name)
			uid, _, err := unstructured.NestedString(item.UnstructuredContent(), "metadata", "uid")
			require.NoError(t, err)
			assert.Equal(t, string(crd.UID), uid)

			// For ElasticSearch and Kibana, problems manifested when additionalPrinterColumns was moved from the top-level spec down to the
			// versions slice.
			if test.expectAdditionalColumns {
				_, ok := item.UnstructuredContent()["spec"].(map[string]any)["additionalPrinterColumns"]
				assert.True(t, ok)
			}

			// Clean up the item created in the test.
			betaClient.Delete(t.Context(), crd.Name, metav1.DeleteOptions{})
		})
	}
}

func fakeDiscoveryHelper() velerodiscovery.Helper {
	return &velerotest.FakeDiscoveryHelper{
		APIGroupsList: []metav1.APIGroup{
			{
				Name: apiextv1.GroupName,
				Versions: []metav1.GroupVersionForDiscovery{
					{
						Version: apiextv1beta1.SchemeGroupVersion.Version,
					},
					{
						Version: apiextv1.SchemeGroupVersion.Version,
					},
				},
			},
		},
	}
}
