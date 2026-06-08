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

package test

import (
	"testing"

	volumegroupsnapshotv1beta2 "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumegroupsnapshot/v1beta2"

	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	"github.com/stretchr/testify/require"
	appsv1api "k8s.io/api/apps/v1"
	batchv1api "k8s.io/api/batch/v1"
	corev1api "k8s.io/api/core/v1"
	storagev1api "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	k8sfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	velerov2alpha1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v2alpha1"
)

func NewFakeControllerRuntimeClientBuilder(t *testing.T) *k8sfake.ClientBuilder {
	t.Helper()
	scheme := runtime.NewScheme()

	require.NoError(t, velerov1api.AddToScheme(scheme))
	require.NoError(t, velerov2alpha1api.AddToScheme(scheme))
	require.NoError(t, corev1api.AddToScheme(scheme))
	require.NoError(t, appsv1api.AddToScheme(scheme))
	require.NoError(t, snapshotv1api.AddToScheme(scheme))
	require.NoError(t, storagev1api.AddToScheme(scheme))
	require.NoError(t, volumegroupsnapshotv1beta2.AddToScheme(scheme))

	return k8sfake.NewClientBuilder().WithScheme(scheme)
}

func NewFakeControllerRuntimeClient(t *testing.T, initObjs ...runtime.Object) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()

	require.NoError(t, velerov1api.AddToScheme(scheme))
	require.NoError(t, velerov2alpha1api.AddToScheme(scheme))
	require.NoError(t, corev1api.AddToScheme(scheme))
	require.NoError(t, appsv1api.AddToScheme(scheme))
	require.NoError(t, snapshotv1api.AddToScheme(scheme))
	require.NoError(t, storagev1api.AddToScheme(scheme))
	require.NoError(t, batchv1api.AddToScheme(scheme))
	require.NoError(t, volumegroupsnapshotv1beta2.AddToScheme(scheme))

	return k8sfake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(initObjs...).Build()
}

func NewFakeControllerRuntimeWatchClient(
	t *testing.T,
	initObjs ...runtime.Object,
) client.WithWatch {
	t.Helper()
	return NewFakeControllerRuntimeClientBuilder(t).WithRuntimeObjects(initObjs...).Build()
}
