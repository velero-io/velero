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

package controller

import (
	"context"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1api "k8s.io/api/apps/v1"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/bslworker"
)

func workerBSL(name string) *velerov1api.BackupStorageLocation {
	return &velerov1api.BackupStorageLocation{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "velero"},
		Spec: velerov1api.BackupStorageLocationSpec{
			Provider: "velero.io/azure",
			Worker: &velerov1api.BackupStorageLocationWorker{
				ServiceAccountName: name + "-sa",
			},
		},
	}
}

func veleroServerDeploymentObj() *appsv1api.Deployment {
	return &appsv1api.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: veleroDeploymentName, Namespace: "velero"},
		Spec: appsv1api.DeploymentSpec{
			Template: corev1api.PodTemplateSpec{
				Spec: corev1api.PodSpec{
					ServiceAccountName: "velero",
					Containers: []corev1api.Container{
						{Name: "velero", Image: "velero/velero:v1.16.0"},
					},
				},
			},
		},
	}
}

func newWorkerReconciler(t *testing.T, objs ...client.Object) *BackupStorageLocationWorkerReconciler {
	t.Helper()
	require.NoError(t, velerov1api.AddToScheme(scheme.Scheme))
	ca, err := bslworker.GenerateCA("velero-bsl-worker-ca")
	require.NoError(t, err)
	c := fake.NewClientBuilder().
		WithScheme(scheme.Scheme).
		WithObjects(objs...).
		Build()
	return NewBackupStorageLocationWorkerReconciler(
		c, c, "velero", ca, nil, "info", "text", logrus.New(),
	)
}

func TestWorkerReconcileCreatesResources(t *testing.T) {
	bsl := workerBSL("tenant-a")
	r := newWorkerReconciler(t, bsl, veleroServerDeploymentObj())

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "tenant-a", Namespace: "velero"},
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Finalizer added.
	var got velerov1api.BackupStorageLocation
	require.NoError(t, r.client.Get(ctx, types.NamespacedName{Name: "tenant-a", Namespace: "velero"}, &got))
	assert.True(t, controllerutil.ContainsFinalizer(&got, bslWorkerFinalizer))

	// TLS secret created with CA + server cert/key.
	var secret corev1api.Secret
	require.NoError(t, r.client.Get(ctx, types.NamespacedName{Name: bslworker.WorkerTLSSecretName("tenant-a"), Namespace: "velero"}, &secret))
	assert.Contains(t, secret.Data, bslworker.CACertFileName)
	assert.Contains(t, secret.Data, bslworker.ServerCertFileName)
	assert.Contains(t, secret.Data, bslworker.ServerKeyFileName)

	// Service created.
	var svc corev1api.Service
	require.NoError(t, r.client.Get(ctx, types.NamespacedName{Name: bslworker.WorkerServiceName("tenant-a"), Namespace: "velero"}, &svc))

	// Deployment created under the tenant's ServiceAccount.
	var dep appsv1api.Deployment
	require.NoError(t, r.client.Get(ctx, types.NamespacedName{Name: bslworker.WorkerDeploymentName("tenant-a"), Namespace: "velero"}, &dep))
	assert.Equal(t, "tenant-a-sa", dep.Spec.Template.Spec.ServiceAccountName)
}

func TestWorkerReconcileTeardownOnDelete(t *testing.T) {
	bsl := workerBSL("tenant-b")
	now := metav1.Now()
	bsl.DeletionTimestamp = &now
	controllerutil.AddFinalizer(bsl, bslWorkerFinalizer)

	// Pre-existing worker resources that must be torn down.
	dep := &appsv1api.Deployment{ObjectMeta: metav1.ObjectMeta{Name: bslworker.WorkerDeploymentName("tenant-b"), Namespace: "velero"}}
	svc := &corev1api.Service{ObjectMeta: metav1.ObjectMeta{Name: bslworker.WorkerServiceName("tenant-b"), Namespace: "velero"}}
	secret := &corev1api.Secret{ObjectMeta: metav1.ObjectMeta{Name: bslworker.WorkerTLSSecretName("tenant-b"), Namespace: "velero"}}

	r := newWorkerReconciler(t, bsl, dep, svc, secret)

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "tenant-b", Namespace: "velero"},
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Worker resources deleted.
	assert.True(t, apierrors.IsNotFound(r.client.Get(ctx, types.NamespacedName{Name: bslworker.WorkerDeploymentName("tenant-b"), Namespace: "velero"}, &appsv1api.Deployment{})))
	assert.True(t, apierrors.IsNotFound(r.client.Get(ctx, types.NamespacedName{Name: bslworker.WorkerServiceName("tenant-b"), Namespace: "velero"}, &corev1api.Service{})))
	assert.True(t, apierrors.IsNotFound(r.client.Get(ctx, types.NamespacedName{Name: bslworker.WorkerTLSSecretName("tenant-b"), Namespace: "velero"}, &corev1api.Secret{})))

	// BSL finalizer removed (object gc'd once finalizer gone under a deletion timestamp).
	var got velerov1api.BackupStorageLocation
	err = r.client.Get(ctx, types.NamespacedName{Name: "tenant-b", Namespace: "velero"}, &got)
	if err == nil {
		assert.False(t, controllerutil.ContainsFinalizer(&got, bslWorkerFinalizer))
	} else {
		assert.True(t, apierrors.IsNotFound(err))
	}
}

func TestWorkerReconcileTeardownWhenWorkerRemoved(t *testing.T) {
	// BSL still exists but Worker was cleared; finalizer present -> tear down.
	bsl := &velerov1api.BackupStorageLocation{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "tenant-c",
			Namespace:  "velero",
			Finalizers: []string{bslWorkerFinalizer},
		},
		Spec: velerov1api.BackupStorageLocationSpec{Provider: "velero.io/azure"},
	}
	dep := &appsv1api.Deployment{ObjectMeta: metav1.ObjectMeta{Name: bslworker.WorkerDeploymentName("tenant-c"), Namespace: "velero"}}

	r := newWorkerReconciler(t, bsl, dep)

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "tenant-c", Namespace: "velero"},
	})
	require.NoError(t, err)

	ctx := context.Background()
	assert.True(t, apierrors.IsNotFound(r.client.Get(ctx, types.NamespacedName{Name: bslworker.WorkerDeploymentName("tenant-c"), Namespace: "velero"}, &appsv1api.Deployment{})))

	var got velerov1api.BackupStorageLocation
	require.NoError(t, r.client.Get(ctx, types.NamespacedName{Name: "tenant-c", Namespace: "velero"}, &got))
	assert.False(t, controllerutil.ContainsFinalizer(&got, bslWorkerFinalizer))
}

// TestWorkerReconcileTeardownCrossNamespaceAfterWorkerCleared exercises the
// regression where a worker created in a tenant namespace was orphaned when
// spec.worker (and thus its namespace) was cleared. The controller must use the
// recorded namespace annotation to tear the tenant-namespace resources down.
func TestWorkerReconcileTeardownCrossNamespaceAfterWorkerCleared(t *testing.T) {
	bsl := workerBSL("tenant-d")
	bsl.Spec.Worker.Namespace = "tenant-d-ns"
	r := newWorkerReconciler(t, bsl, veleroServerDeploymentObj())
	ctx := context.Background()
	nn := types.NamespacedName{Name: "tenant-d", Namespace: "velero"}

	// First reconcile creates worker resources in the tenant namespace and records it.
	_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: nn})
	require.NoError(t, err)

	var got velerov1api.BackupStorageLocation
	require.NoError(t, r.client.Get(ctx, nn, &got))
	assert.Equal(t, "tenant-d-ns", got.Annotations[workerNamespaceAnnotation])
	require.NoError(t, r.client.Get(ctx, types.NamespacedName{Name: bslworker.WorkerDeploymentName("tenant-d"), Namespace: "tenant-d-ns"}, &appsv1api.Deployment{}))

	// Clear spec.worker (supported transition) and reconcile again.
	original := got.DeepCopy()
	got.Spec.Worker = nil
	require.NoError(t, r.client.Patch(ctx, &got, client.MergeFrom(original)))

	_, err = r.Reconcile(ctx, ctrl.Request{NamespacedName: nn})
	require.NoError(t, err)

	// Tenant-namespace resources must be gone, not orphaned.
	assert.True(t, apierrors.IsNotFound(r.client.Get(ctx, types.NamespacedName{Name: bslworker.WorkerDeploymentName("tenant-d"), Namespace: "tenant-d-ns"}, &appsv1api.Deployment{})))
	assert.True(t, apierrors.IsNotFound(r.client.Get(ctx, types.NamespacedName{Name: bslworker.WorkerServiceName("tenant-d"), Namespace: "tenant-d-ns"}, &corev1api.Service{})))
	assert.True(t, apierrors.IsNotFound(r.client.Get(ctx, types.NamespacedName{Name: bslworker.WorkerTLSSecretName("tenant-d"), Namespace: "tenant-d-ns"}, &corev1api.Secret{})))

	// Finalizer and recorded namespace annotation removed.
	require.NoError(t, r.client.Get(ctx, nn, &got))
	assert.False(t, controllerutil.ContainsFinalizer(&got, bslWorkerFinalizer))
	assert.NotContains(t, got.Annotations, workerNamespaceAnnotation)
}
