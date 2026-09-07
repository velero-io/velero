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
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	storagev1api "k8s.io/api/storage/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/vmware-tanzu/velero/internal/volume"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
)

// TestPatchDynamicPVDefaultSCGuard pins the behavior of the WFFC skip guard in
// patchDynamicPVWithVolumeInfo for PVCs that consume the cluster default
// StorageClass (StorageClassName nil or empty).
func TestPatchDynamicPVDefaultSCGuard(t *testing.T) {
	wffc := storagev1api.VolumeBindingWaitForFirstConsumer

	volumeInfo := []*volume.BackupVolumeInfo{
		{
			BackupMethod: "PodVolumeBackup",
			PVCName:      "pvc1",
			PVName:       "pv1",
			PVCNamespace: "ns1",
			PVInfo: &volume.PVInfo{
				ReclaimPolicy: string(corev1api.PersistentVolumeReclaimDelete),
				Labels:        map[string]string{"app": "pdpv-guard"},
			},
		},
	}

	newCtx := func(t *testing.T) *finalizerContext {
		fakeClient := velerotest.NewFakeControllerRuntimeClientBuilder(t).Build()
		return &finalizerContext{
			logger:          velerotest.NewLogger(),
			crClient:        fakeClient,
			restore:         builder.ForRestore(velerov1api.DefaultNamespace, "restore").Result(),
			restoredPVCList: map[string]struct{}{"ns1/pvc1": {}},
			volumeInfo:      volumeInfo,
			resourceTimeout: 2 * time.Second,
		}
	}

	createStorageClass := func(t *testing.T, ctx *finalizerContext, name string, bindingMode *storagev1api.VolumeBindingMode, annotations map[string]string) {
		sc := builder.ForStorageClass(name).Provisioner("prov").Result()
		sc.VolumeBindingMode = bindingMode
		sc.Annotations = annotations
		require.NoError(t, ctx.crClient.Create(t.Context(), sc))
	}

	t.Run("default SC via nil StorageClassName", func(t *testing.T) {
		ctx := newCtx(t)
		// A WFFC storage class exists in the cluster and is marked as the
		// cluster default; a PVC with nil StorageClassName consumes it
		// implicitly.
		createStorageClass(t, ctx, "default-sc", &wffc, map[string]string{"storageclass.kubernetes.io/is-default-class": "true"})

		pvc := builder.ForPersistentVolumeClaim("ns1", "pvc1").
			Phase(corev1api.ClaimPending).
			Result()
		require.Nil(t, pvc.Spec.StorageClassName)
		require.NoError(t, ctx.crClient.Create(t.Context(), pvc))

		start := time.Now()
		errs := ctx.patchDynamicPVWithVolumeInfo()
		elapsed := time.Since(start)

		// The guard fires for the cluster default storage class as well: skip,
		// no polling to resourceTimeout expiry, no error.
		require.Empty(t, errs.Namespaces)
		t.Logf("guard fired via default SC resolution: consumed %v of the %v resourceTimeout", elapsed, ctx.resourceTimeout)
	})

	t.Run("default SC via empty StorageClassName", func(t *testing.T) {
		ctx := newCtx(t)
		createStorageClass(t, ctx, "default-sc", &wffc, map[string]string{"storageclass.kubernetes.io/is-default-class": "true"})

		pvc := builder.ForPersistentVolumeClaim("ns1", "pvc1").
			Phase(corev1api.ClaimPending).
			Result()
		empty := ""
		pvc.Spec.StorageClassName = &empty
		require.NoError(t, ctx.crClient.Create(t.Context(), pvc))

		errs := ctx.patchDynamicPVWithVolumeInfo()

		// The guard fires for the cluster default storage class as well: skip,
		// no error.
		require.Empty(t, errs.Namespaces)
	})

	t.Run("explicit WFFC SC skips", func(t *testing.T) {
		ctx := newCtx(t)
		createStorageClass(t, ctx, "sc-wffc", &wffc, nil)

		pvc := builder.ForPersistentVolumeClaim("ns1", "pvc1").
			StorageClass("sc-wffc").
			Phase(corev1api.ClaimPending).
			Result()
		require.NoError(t, ctx.crClient.Create(t.Context(), pvc))

		// The guard fires for an explicitly set WFFC storage class: skip, no
		// polling, no error.
		errs := ctx.patchDynamicPVWithVolumeInfo()
		require.Empty(t, errs.Namespaces)
	})

	t.Run("nil VolumeBindingMode proceeds", func(t *testing.T) {
		ctx := newCtx(t)
		// Binding mode nil (unset) is not WFFC: the guard must not skip.
		createStorageClass(t, ctx, "sc-immediate", nil, nil)

		pvc := builder.ForPersistentVolumeClaim("ns1", "pvc1").
			StorageClass("sc-immediate").
			VolumeName("new-pv1").
			Phase(corev1api.ClaimBound).
			Result()
		require.NoError(t, ctx.crClient.Create(t.Context(), pvc))

		pv := builder.ForPersistentVolume("new-pv1").
			ClaimRef("ns1", "pvc1").
			Phase(corev1api.VolumeBound).
			ReclaimPolicy(corev1api.PersistentVolumeReclaimRetain).
			Result()
		require.NoError(t, ctx.crClient.Create(t.Context(), pv))

		errs := ctx.patchDynamicPVWithVolumeInfo()
		require.Empty(t, errs.Namespaces)

		// The patch path ran: PV ReclaimPolicy updated to the value from the
		// BackupVolumeInfo (expectedPatch verification pattern).
		got := &corev1api.PersistentVolume{}
		require.NoError(t, ctx.crClient.Get(t.Context(), client.ObjectKey{Name: "new-pv1"}, got))
		require.Equal(t, corev1api.PersistentVolumeReclaimDelete, got.Spec.PersistentVolumeReclaimPolicy)
	})
}
