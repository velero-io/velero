package uninstall

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1api "k8s.io/api/apps/v1"
	corev1api "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	velerov2alpha1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v2alpha1"
	factorymocks "github.com/vmware-tanzu/velero/pkg/client/mocks"
	"github.com/vmware-tanzu/velero/pkg/controller"
)

func buildScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = corev1api.AddToScheme(scheme)
	_ = appsv1api.AddToScheme(scheme)
	_ = rbacv1.AddToScheme(scheme)
	_ = apiextv1.AddToScheme(scheme)
	_ = apiextv1beta1.AddToScheme(scheme)
	_ = velerov1api.AddToScheme(scheme)
	_ = velerov2alpha1api.AddToScheme(scheme)
	return scheme
}

func TestRun(t *testing.T) {
	scheme := buildScheme()
	namespace := "velero-custom"

	tests := []struct {
		name          string
		initialObjs   []kbclient.Object
		expectedError bool
	}{
		{
			name:          "Namespace does not exist",
			initialObjs:   []kbclient.Object{},
			expectedError: false,
		},
		{
			name: "CRDs missing but namespace exists",
			initialObjs: []kbclient.Object{
				&corev1api.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: namespace,
					},
				},
			},
			expectedError: false,
		},
		{
			name: "CRDs exist and namespace exists",
			initialObjs: []kbclient.Object{
				&corev1api.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: namespace,
					},
				},
				&apiextv1.CustomResourceDefinition{
					ObjectMeta: metav1.ObjectMeta{
						Name: "restores.velero.io",
					},
				},
			},
			expectedError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tc.initialObjs...).Build()
			err := Run(context.Background(), client, namespace)
			if tc.expectedError {
				require.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestForcedlyDeleteResources(t *testing.T) {
	scheme := buildScheme()
	namespace := "velero-custom"

	restoreWithFinalizer := &velerov1api.Restore{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-restore",
			Namespace: namespace,
			Finalizers: []string{
				controller.ExternalResourcesFinalizer,
			},
		},
	}

	deploy := &appsv1api.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "velero",
			Namespace: namespace,
		},
	}

	client := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(restoreWithFinalizer).WithObjects(restoreWithFinalizer, deploy).Build()

	resToDelete := []kbclient.ObjectList{
		&velerov1api.RestoreList{},
	}

	err := forcedlyDeleteResources(context.Background(), client, namespace, resToDelete)
	require.NoError(t, err)

	// Verify finalizer is removed
	err = client.Get(context.Background(), types.NamespacedName{Name: "test-restore", Namespace: namespace}, restoreWithFinalizer)
	require.NoError(t, err)
	assert.Empty(t, restoreWithFinalizer.ObjectMeta.Finalizers)

	// Verify deployment is deleted
	err = client.Get(context.Background(), types.NamespacedName{Name: "velero", Namespace: namespace}, &appsv1api.Deployment{})
	require.Error(t, err)
	assert.True(t, apierrors.IsNotFound(err))
}

func TestCheckResources(t *testing.T) {
	scheme := buildScheme()

	v1crd := &apiextv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "restores.velero.io",
		},
	}

	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(v1crd).Build()

	resToDelete, err := checkResources(context.Background(), client)
	require.NoError(t, err)
	assert.Len(t, resToDelete, 1)
	_, ok := resToDelete[0].(*velerov1api.RestoreList)
	assert.True(t, ok)
}

func TestNewCommand(t *testing.T) {
	scheme := buildScheme()

	tests := []struct {
		name        string
		args        []string
		input       string
		expectError bool
		expectRun   bool
	}{
		{
			name:        "force flag skips confirmation",
			args:        []string{"--force"},
			input:       "",
			expectError: false,
			expectRun:   true,
		},
		{
			name:        "interactive cancellation",
			args:        []string{},
			input:       "N\n",
			expectError: false,
			expectRun:   false,
		},
		{
			name:        "interactive confirmation",
			args:        []string{},
			input:       "Y\n",
			expectError: false,
			expectRun:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := &factorymocks.Factory{}
			client := fake.NewClientBuilder().WithScheme(scheme).Build()

			if tc.expectRun {
				f.On("KubebuilderClient").Return(client, nil)
				f.On("Namespace").Return("velero")
			}

			cmd := NewCommand(f)
			cmd.SetArgs(tc.args)

			// Mock stdin
			oldStdin := os.Stdin
			defer func() { os.Stdin = oldStdin }()

			r, w, err := os.Pipe()
			require.NoError(t, err)
			os.Stdin = r

			go func() {
				defer w.Close()
				if tc.input != "" {
					w.Write([]byte(tc.input))
				}
			}()

			err = cmd.Execute()
			if tc.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			f.AssertExpectations(t)
		})
	}
}

func TestWaitDeletingResourcesTimeout(t *testing.T) {
	scheme := buildScheme()
	namespace := "velero"

	restoreWithFinalizer := &velerov1api.Restore{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-restore",
			Namespace: namespace,
			Finalizers: []string{
				controller.ExternalResourcesFinalizer,
			},
		},
	}

	client := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(restoreWithFinalizer).WithObjects(restoreWithFinalizer).Build()

	resToDelete := []kbclient.ObjectList{
		&velerov1api.RestoreList{},
	}

	// Create a context that is already canceled to trigger timeout immediately
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := waitDeletingResources(ctx, client, namespace, resToDelete)
	require.Error(t, err)
}

func TestDeleteResourcesGracefulTimeoutToForcedDelete(t *testing.T) {
	scheme := buildScheme()
	namespace := "velero-custom"

	restoreWithFinalizer := &velerov1api.Restore{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-restore",
			Namespace: namespace,
			Finalizers: []string{
				controller.ExternalResourcesFinalizer,
			},
		},
	}
	deploy := &appsv1api.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "velero",
			Namespace: namespace,
		},
	}
	v1crd := &apiextv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "restores.velero.io",
		},
	}

	client := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(restoreWithFinalizer).WithObjects(restoreWithFinalizer, deploy, v1crd).Build()

	// Shrink the maximum duration to ensure wait.PollUntilContextTimeout triggers timeout quickly
	originalDuration := gracefulDeletionMaximumDuration
	gracefulDeletionMaximumDuration = 10 * time.Millisecond
	defer func() {
		gracefulDeletionMaximumDuration = originalDuration
	}()

	err := deleteResources(context.Background(), client, namespace)
	require.NoError(t, err)

	// Verify restore is deleted (finalizer was removed and DeletionTimestamp was set)
	err = client.Get(context.Background(), types.NamespacedName{Name: "test-restore", Namespace: namespace}, restoreWithFinalizer)
	require.Error(t, err)
	assert.True(t, apierrors.IsNotFound(err))

	// Verify deployment is deleted
	err = client.Get(context.Background(), types.NamespacedName{Name: "velero", Namespace: namespace}, &appsv1api.Deployment{})
	require.Error(t, err)
	assert.True(t, apierrors.IsNotFound(err))
}
