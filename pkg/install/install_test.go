package install

import (
	"bytes"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	appsv1api "k8s.io/api/apps/v1"
	corev1api "k8s.io/api/core/v1"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1crds "github.com/vmware-tanzu/velero/config/crd/v1/crds"
	"github.com/vmware-tanzu/velero/pkg/test"
)

func TestInstall(t *testing.T) {
	dc := &test.FakeDynamicClient{}
	dc.On("Create", mock.Anything).Return(&unstructured.Unstructured{}, nil)

	factory := &test.FakeDynamicFactory{}
	factory.On("ClientForGroupVersionResource", mock.Anything, mock.Anything, mock.Anything).Return(dc, nil)

	c := fake.NewClientBuilder().WithObjects(
		&apiextv1.CustomResourceDefinition{
			ObjectMeta: metav1.ObjectMeta{
				Name: "backuprepositories.velero.io",
			},

			Status: apiextv1.CustomResourceDefinitionStatus{
				Conditions: []apiextv1.CustomResourceDefinitionCondition{
					{
						Type:   apiextv1.Established,
						Status: apiextv1.ConditionTrue,
					},
					{
						Type:   apiextv1.NamesAccepted,
						Status: apiextv1.ConditionTrue,
					},
				},
			},
		},
	).Build()

	resources := &unstructured.UnstructuredList{}
	require.NoError(t, appendUnstructured(resources, v1crds.CRDs[0]))
	require.NoError(t, appendUnstructured(resources, Namespace("velero")))

	assert.NoError(t, Install(factory, c, resources, os.Stdout, false))
}

func Test_crdsAreReady(t *testing.T) {
	c := fake.NewClientBuilder().WithObjects(
		&apiextv1beta1.CustomResourceDefinition{
			ObjectMeta: metav1.ObjectMeta{
				Name: "backuprepositories.velero.io",
			},

			Status: apiextv1beta1.CustomResourceDefinitionStatus{
				Conditions: []apiextv1beta1.CustomResourceDefinitionCondition{
					{
						Type:   apiextv1beta1.Established,
						Status: apiextv1beta1.ConditionTrue,
					},
					{
						Type:   apiextv1beta1.NamesAccepted,
						Status: apiextv1beta1.ConditionTrue,
					},
				},
			},
		},
	).Build()

	crd := &apiextv1beta1.CustomResourceDefinition{
		TypeMeta: metav1.TypeMeta{
			Kind:       "CustomResourceDefinition",
			APIVersion: "v1beta1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "backuprepositories.velero.io",
		},
	}
	obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(crd)
	require.NoError(t, err)

	crds := []*unstructured.Unstructured{
		{
			Object: obj,
		},
	}

	ready, err := crdsAreReady(c, crds)
	require.NoError(t, err)
	assert.True(t, ready)
}

func TestDeploymentIsReady(t *testing.T) {
	deployment := &appsv1api.Deployment{
		Status: appsv1api.DeploymentStatus{
			Conditions: []appsv1api.DeploymentCondition{
				{
					Type:               appsv1api.DeploymentAvailable,
					Status:             corev1api.ConditionTrue,
					LastTransitionTime: metav1.NewTime(time.Now().Add(-15 * time.Second)),
				},
			},
		},
	}
	obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(deployment)
	require.NoError(t, err)

	dc := &test.FakeDynamicClient{}
	dc.On("Get", mock.Anything, mock.Anything).Return(&unstructured.Unstructured{Object: obj}, nil)

	factory := &test.FakeDynamicFactory{}
	factory.On("ClientForGroupVersionResource", mock.Anything, mock.Anything, mock.Anything).Return(dc, nil)

	ready, err := DeploymentIsReady(factory, "velero")
	require.NoError(t, err)
	assert.True(t, ready)

	// test failing condition
	deploymentFailing := &appsv1api.Deployment{
		Status: appsv1api.DeploymentStatus{
			Conditions: []appsv1api.DeploymentCondition{
				{
					Type:    appsv1api.DeploymentReplicaFailure,
					Status:  corev1api.ConditionTrue,
					Message: "test failure",
				},
			},
		},
	}
	objFailing, err := runtime.DefaultUnstructuredConverter.ToUnstructured(deploymentFailing)
	require.NoError(t, err)

	dcFailing := &test.FakeDynamicClient{}
	dcFailing.On("Get", mock.Anything, mock.Anything).Return(&unstructured.Unstructured{Object: objFailing}, nil)

	factoryFailing := &test.FakeDynamicFactory{}
	factoryFailing.On("ClientForGroupVersionResource", mock.Anything, mock.Anything, mock.Anything).Return(dcFailing, nil)

	readyFailing, errFailing := DeploymentIsReady(factoryFailing, "velero")
	require.Error(t, errFailing)
	assert.False(t, readyFailing)

	// test progressing failure condition
	deploymentProgressing := &appsv1api.Deployment{
		Status: appsv1api.DeploymentStatus{
			Conditions: []appsv1api.DeploymentCondition{
				{
					Type:    appsv1api.DeploymentProgressing,
					Status:  corev1api.ConditionFalse,
					Message: "test progressing false",
				},
			},
		},
	}
	objProgressing, err := runtime.DefaultUnstructuredConverter.ToUnstructured(deploymentProgressing)
	require.NoError(t, err)

	dcProgressing := &test.FakeDynamicClient{}
	dcProgressing.On("Get", mock.Anything, mock.Anything).Return(&unstructured.Unstructured{Object: objProgressing}, nil)

	factoryProgressing := &test.FakeDynamicFactory{}
	factoryProgressing.On("ClientForGroupVersionResource", mock.Anything, mock.Anything, mock.Anything).Return(dcProgressing, nil)

	readyProgressing, errProgressing := DeploymentIsReady(factoryProgressing, "velero")
	require.Error(t, errProgressing)
	assert.False(t, readyProgressing)
}

func TestNodeAgentIsReady(t *testing.T) {
	daemonset := &appsv1api.DaemonSet{
		Status: appsv1api.DaemonSetStatus{
			NumberAvailable:        1,
			DesiredNumberScheduled: 1,
		},
	}
	obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(daemonset)
	require.NoError(t, err)

	dc := &test.FakeDynamicClient{}
	dc.On("Get", mock.Anything, mock.Anything).Return(&unstructured.Unstructured{Object: obj}, nil)

	factory := &test.FakeDynamicFactory{}
	factory.On("ClientForGroupVersionResource", mock.Anything, mock.Anything, mock.Anything).Return(dc, nil)

	ready, err := NodeAgentIsReady(factory, "velero")
	require.NoError(t, err)
	assert.True(t, ready)
}

func TestNodeAgentWindowsIsReady(t *testing.T) {
	daemonset := &appsv1api.DaemonSet{
		Status: appsv1api.DaemonSetStatus{
			NumberAvailable:        0,
			DesiredNumberScheduled: 0,
		},
	}
	obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(daemonset)
	require.NoError(t, err)

	dc := &test.FakeDynamicClient{}
	dc.On("Get", mock.Anything, mock.Anything).Return(&unstructured.Unstructured{Object: obj}, nil)

	factory := &test.FakeDynamicFactory{}
	factory.On("ClientForGroupVersionResource", mock.Anything, mock.Anything, mock.Anything).Return(dc, nil)

	ready, err := NodeAgentWindowsIsReady(factory, "velero")
	require.NoError(t, err)
	assert.True(t, ready)
}

func TestCreateOrApplyResourceError(t *testing.T) {
	r := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata": map[string]any{
				"name":      "test-configmap",
				"namespace": "velero",
			},
		},
	}

	dc := &test.FakeDynamicClient{}
	expectedErr := errors.New("create error")
	dc.On("Create", mock.Anything).Return(&unstructured.Unstructured{}, expectedErr)

	factory := &test.FakeDynamicFactory{}
	factory.On("ClientForGroupVersionResource", mock.Anything, mock.Anything, mock.Anything).Return(dc, nil)

	var buf bytes.Buffer
	err := createOrApplyResource(r, factory, &buf, false)

	require.Error(t, err)
	require.Contains(t, err.Error(), expectedErr.Error())
}

func TestCreateOrApplyResourceAlreadyExists(t *testing.T) {
	r := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata": map[string]any{
				"name":      "test-configmap",
				"namespace": "velero",
			},
		},
	}

	dc := &test.FakeDynamicClient{}
	alreadyExistsErr := apierrors.NewAlreadyExists(schema.GroupResource{Resource: "configmaps"}, "test-configmap")
	// We need to return a non-nil unstructured object even though it's not used
	dc.On("Create", mock.Anything).Return(&unstructured.Unstructured{}, alreadyExistsErr)

	factory := &test.FakeDynamicFactory{}
	factory.On("ClientForGroupVersionResource", mock.Anything, mock.Anything, mock.Anything).Return(dc, nil)

	var buf bytes.Buffer
	err := createOrApplyResource(r, factory, &buf, false)

	require.NoError(t, err)
}

func TestCreateOrApplyResourceClientError(t *testing.T) {
	r := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata": map[string]any{
				"name":      "test-configmap",
				"namespace": "velero",
			},
		},
	}

	factory := &test.FakeDynamicFactory{}
	expectedErr := errors.New("client creation error")
	// Return error from ClientForGroupVersionResource
	factory.On("ClientForGroupVersionResource", mock.Anything, mock.Anything, mock.Anything).Return(&test.FakeDynamicClient{}, expectedErr)

	var buf bytes.Buffer
	err := createOrApplyResource(r, factory, &buf, false)

	require.Error(t, err)
	require.Contains(t, err.Error(), expectedErr.Error())
}

func TestCreateOrApplyResourceApplyError(t *testing.T) {
	r := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata": map[string]any{
				"name":      "test-configmap",
				"namespace": "velero",
			},
		},
	}

	dc := &test.FakeDynamicClient{}
	expectedErr := errors.New("apply error")
	// Mock Apply to return an error
	dc.On("Apply", mock.Anything, mock.Anything, mock.Anything).Return(&unstructured.Unstructured{}, expectedErr)

	factory := &test.FakeDynamicFactory{}
	factory.On("ClientForGroupVersionResource", mock.Anything, mock.Anything, mock.Anything).Return(dc, nil)

	var buf bytes.Buffer
	err := createOrApplyResource(r, factory, &buf, true) // true for apply flag to use Apply

	require.Error(t, err)
	require.Contains(t, err.Error(), expectedErr.Error())
}

func TestInstallErrorAfterCreateClient(t *testing.T) {
	// Create a test non-CRD resource
	nonCRDResource := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata": map[string]any{
				"name": "test-configmap",
			},
		},
	}

	resources := &unstructured.UnstructuredList{
		Items: []unstructured.Unstructured{*nonCRDResource},
	}

	// Mock the factory to return a client that will succeed on ClientForGroupVersionResource
	// but fail on Create
	dc := &test.FakeDynamicClient{}
	expectedErr := errors.New("create error after successful client creation")
	dc.On("Create", mock.Anything).Return(&unstructured.Unstructured{}, expectedErr)

	factory := &test.FakeDynamicFactory{}
	factory.On("ClientForGroupVersionResource", mock.Anything, mock.Anything, mock.Anything).Return(dc, nil)

	c := fake.NewClientBuilder().Build()

	var buf bytes.Buffer
	err := Install(factory, c, resources, &buf, false)

	require.Error(t, err)
	require.Contains(t, err.Error(), expectedErr.Error())
}

func TestInstallErrorOnCRDResource(t *testing.T) {
	crdResource := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "apiextensions.k8s.io/v1",
			"kind":       "CustomResourceDefinition",
			"metadata": map[string]any{
				"name": "test-crd",
			},
		},
	}

	resources := &unstructured.UnstructuredList{
		Items: []unstructured.Unstructured{*crdResource},
	}

	dc := &test.FakeDynamicClient{}
	expectedErr := errors.New("error creating CRD resource")
	// We need to return a non-nil unstructured object even though it's not used
	dc.On("Create", mock.Anything).Return(&unstructured.Unstructured{}, expectedErr)

	factory := &test.FakeDynamicFactory{}
	factory.On("ClientForGroupVersionResource", mock.Anything, mock.Anything, mock.Anything).Return(dc, nil)

	c := fake.NewClientBuilder().Build()

	var buf bytes.Buffer
	err := Install(factory, c, resources, &buf, false)

	require.Error(t, err)
	require.Contains(t, err.Error(), expectedErr.Error())
}

func TestInstallWithApplyFlag(t *testing.T) {
	// Create a test resource
	testResource := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata": map[string]any{
				"name":      "test-configmap",
				"namespace": "velero",
			},
			"data": map[string]any{
				"key1": "value1",
			},
		},
	}

	resources := &unstructured.UnstructuredList{
		Items: []unstructured.Unstructured{*testResource},
	}

	// Test case 1: Without apply flag (create)
	{
		dc := &test.FakeDynamicClient{}
		// Expect Create to be called
		dc.On("Create", mock.Anything).Return(testResource, nil)
		// Apply should not be called

		factory := &test.FakeDynamicFactory{}
		factory.On("ClientForGroupVersionResource", mock.Anything, mock.Anything, mock.Anything).Return(dc, nil)

		c := fake.NewClientBuilder().Build()

		err := Install(factory, c, resources, os.Stdout, false)
		require.NoError(t, err)

		// Verify that Create was called and Apply was not
		dc.AssertCalled(t, "Create", mock.Anything)
		dc.AssertNotCalled(t, "Apply", mock.Anything, mock.Anything, mock.Anything)
	}

	// Test case 2: With apply flag
	{
		dc := &test.FakeDynamicClient{}
		// Create should not be called
		// Expect Apply to be called
		dc.On("Apply", mock.Anything, mock.Anything, mock.Anything).Return(testResource, nil)

		factory := &test.FakeDynamicFactory{}
		factory.On("ClientForGroupVersionResource", mock.Anything, mock.Anything, mock.Anything).Return(dc, nil)

		c := fake.NewClientBuilder().Build()

		err := Install(factory, c, resources, os.Stdout, true)
		require.NoError(t, err)

		// Verify that Apply was called and Create was not
		dc.AssertCalled(t, "Apply", mock.Anything, mock.Anything, mock.Anything)
		dc.AssertNotCalled(t, "Create", mock.Anything)
	}
}
