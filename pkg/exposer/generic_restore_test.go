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

package exposer

import (
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1api "k8s.io/api/apps/v1"
	corev1api "k8s.io/api/core/v1"
	storagev1api "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	clientTesting "k8s.io/client-go/testing"

	velerov1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
	"github.com/vmware-tanzu/velero/pkg/util/datamover"
	"github.com/vmware-tanzu/velero/pkg/util/kube"
)

func TestRestoreExpose(t *testing.T) {
	scName := "fake-sc"
	restore := &velerov1.Restore{
		TypeMeta: metav1.TypeMeta{
			APIVersion: velerov1.SchemeGroupVersion.String(),
			Kind:       "Restore",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: velerov1.DefaultNamespace,
			Name:      "fake-restore",
			UID:       "fake-uid",
		},
	}

	targetPVCObj := &corev1api.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "fake-ns",
			Name:      "fake-target-pvc",
		},
		Spec: corev1api.PersistentVolumeClaimSpec{
			StorageClassName: &scName,
		},
	}

	modeFilesystem := corev1api.PersistentVolumeFilesystem
	targetPVCObjWithVolumeMode := &corev1api.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "fake-ns",
			Name:      "fake-target-pvc",
		},
		Spec: corev1api.PersistentVolumeClaimSpec{
			StorageClassName: &scName,
			VolumeMode:       &modeFilesystem,
		},
	}

	storageClass := &storagev1api.StorageClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "fake-sc",
		},
	}

	targetPVCObjBound := &corev1api.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "fake-ns",
			Name:      "fake-target-pvc",
		},
		Spec: corev1api.PersistentVolumeClaimSpec{
			VolumeName: "fake-pv",
		},
	}

	daemonSet := &appsv1api.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "velero",
			Name:      "node-agent",
		},
		TypeMeta: metav1.TypeMeta{
			Kind:       "DaemonSet",
			APIVersion: appsv1api.SchemeGroupVersion.String(),
		},
		Spec: appsv1api.DaemonSetSpec{
			Template: corev1api.PodTemplateSpec{
				Spec: corev1api.PodSpec{
					Containers: []corev1api.Container{
						{
							Image: "fake-image",
						},
					},
				},
			},
		},
	}

	tests := []struct {
		name            string
		kubeClientObj   []runtime.Object
		ownerRestore    *velerov1.Restore
		targetPVCName   string
		targetNamespace string
		kubeReactors    []reactor
		cacheVolume     *CacheConfigs
		dataMover       string
		expectBackupPod bool
		expectBackupPVC bool
		expectCachePVC  bool
		err             string
	}{
		{
			name:            "wait target pvc consumed fail",
			targetPVCName:   "fake-target-pvc",
			targetNamespace: "fake-ns",
			ownerRestore:    restore,
			err:             "error to wait target PVC consumed, fake-ns/fake-target-pvc: error to wait for PVC: error to get pvc fake-ns/fake-target-pvc: persistentvolumeclaims \"fake-target-pvc\" not found",
		},
		{
			name:            "target pvc is already bound",
			targetPVCName:   "fake-target-pvc",
			targetNamespace: "fake-ns",
			ownerRestore:    restore,
			kubeClientObj: []runtime.Object{
				targetPVCObjBound,
				storageClass,
			},
			err: "Target PVC fake-ns/fake-target-pvc has already been bound, abort",
		},
		{
			name:            "create restore pod fail",
			targetPVCName:   "fake-target-pvc",
			targetNamespace: "fake-ns",
			ownerRestore:    restore,
			kubeClientObj: []runtime.Object{
				targetPVCObj,
				daemonSet,
				storageClass,
			},
			kubeReactors: []reactor{
				{
					verb:     "create",
					resource: "pods",
					reactorFunc: func(action clientTesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, errors.New("fake-create-error")
					},
				},
			},
			err: "error to create restore pod: fake-create-error",
		},
		{
			name:            "create restore pvc fail",
			targetPVCName:   "fake-target-pvc",
			targetNamespace: "fake-ns",
			ownerRestore:    restore,
			kubeClientObj: []runtime.Object{
				targetPVCObj,
				daemonSet,
				storageClass,
			},
			kubeReactors: []reactor{
				{
					verb:     "create",
					resource: "persistentvolumeclaims",
					reactorFunc: func(action clientTesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, errors.New("fake-create-error")
					},
				},
			},
			err: "error to create restore pvc: fake-create-error",
		},
		{
			name:            "succeed",
			targetPVCName:   "fake-target-pvc",
			targetNamespace: "fake-ns",
			ownerRestore:    restore,
			kubeClientObj: []runtime.Object{
				targetPVCObj,
				daemonSet,
				storageClass,
			},
			expectBackupPod: true,
			expectBackupPVC: true,
		},
		{
			name:            "succeed, cache config, no cache volume",
			targetPVCName:   "fake-target-pvc",
			targetNamespace: "fake-ns",
			ownerRestore:    restore,
			kubeClientObj: []runtime.Object{
				targetPVCObj,
				daemonSet,
				storageClass,
			},
			cacheVolume:     &CacheConfigs{},
			expectBackupPod: true,
			expectBackupPVC: true,
		},
		{
			name:            "create cache volume fail",
			targetPVCName:   "fake-target-pvc",
			targetNamespace: "fake-ns",
			ownerRestore:    restore,
			kubeClientObj: []runtime.Object{
				targetPVCObj,
				daemonSet,
				storageClass,
			},
			cacheVolume: &CacheConfigs{Limit: 1024},
			kubeReactors: []reactor{
				{
					verb:     "create",
					resource: "persistentvolumeclaims",
					reactorFunc: func(action clientTesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, errors.New("fake-create-error")
					},
				},
			},
			err: "error to create cache pvc: fake-create-error",
		},
		{
			name:            "succeed with cache volume",
			targetPVCName:   "fake-target-pvc",
			targetNamespace: "fake-ns",
			ownerRestore:    restore,
			kubeClientObj: []runtime.Object{
				targetPVCObj,
				daemonSet,
				storageClass,
			},
			cacheVolume:     &CacheConfigs{Limit: 1024},
			expectBackupPod: true,
			expectBackupPVC: true,
			expectCachePVC:  true,
		},
		{
			name:            "succeed with velero-block data mover",
			targetPVCName:   "fake-target-pvc",
			targetNamespace: "fake-ns",
			ownerRestore:    restore,
			kubeClientObj: []runtime.Object{
				targetPVCObj,
				daemonSet,
				storageClass,
			},
			dataMover:       datamover.DataMoverTypeVeleroBlock,
			expectBackupPod: true,
			expectBackupPVC: true,
		},
		{
			name:            "succeed with velero-block data mover and existing volume mode",
			targetPVCName:   "fake-target-pvc",
			targetNamespace: "fake-ns",
			ownerRestore:    restore,
			kubeClientObj: []runtime.Object{
				targetPVCObjWithVolumeMode,
				daemonSet,
				storageClass,
			},
			dataMover:       datamover.DataMoverTypeVeleroBlock,
			expectBackupPod: true,
			expectBackupPVC: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakeKubeClient := fake.NewSimpleClientset(test.kubeClientObj...)

			for _, reactor := range test.kubeReactors {
				fakeKubeClient.Fake.PrependReactor(reactor.verb, reactor.resource, reactor.reactorFunc)
			}

			exposer := genericRestoreExposer{
				kubeClient: fakeKubeClient,
				log:        velerotest.NewLogger(),
			}

			var ownerObject corev1api.ObjectReference
			if test.ownerRestore != nil {
				ownerObject = corev1api.ObjectReference{
					Kind:       test.ownerRestore.Kind,
					Namespace:  test.ownerRestore.Namespace,
					Name:       test.ownerRestore.Name,
					UID:        test.ownerRestore.UID,
					APIVersion: test.ownerRestore.APIVersion,
				}
			}

			err := exposer.Expose(
				t.Context(),
				ownerObject,
				GenericRestoreExposeParam{
					TargetPVCName:    test.targetPVCName,
					TargetNamespace:  test.targetNamespace,
					HostingPodLabels: map[string]string{},
					Resources:        corev1api.ResourceRequirements{},
					ExposeTimeout:    time.Millisecond,
					LoadAffinity:     nil,
					CacheVolume:      test.cacheVolume,
					DataMover:        test.dataMover,
				},
			)

			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
			}

			_, err = exposer.kubeClient.CoreV1().Pods(ownerObject.Namespace).Get(t.Context(), ownerObject.Name, metav1.GetOptions{})
			if test.expectBackupPod {
				require.NoError(t, err)
			} else {
				require.True(t, apierrors.IsNotFound(err))
			}

			pvc, err := exposer.kubeClient.CoreV1().PersistentVolumeClaims(ownerObject.Namespace).Get(t.Context(), ownerObject.Name, metav1.GetOptions{})
			if test.expectBackupPVC {
				require.NoError(t, err)
				if test.dataMover == datamover.DataMoverTypeVeleroBlock {
					require.NotNil(t, pvc.Spec.VolumeMode)
					require.Equal(t, corev1api.PersistentVolumeBlock, *pvc.Spec.VolumeMode)
				}
			} else {
				require.True(t, apierrors.IsNotFound(err))
			}

			_, err = exposer.kubeClient.CoreV1().PersistentVolumeClaims(ownerObject.Namespace).Get(t.Context(), getCachePVCName(ownerObject), metav1.GetOptions{})
			if test.expectCachePVC {
				require.NoError(t, err)
			} else {
				require.True(t, apierrors.IsNotFound(err))
			}
		})
	}
}

func TestRebindVolume(t *testing.T) {
	restore := &velerov1.Restore{
		TypeMeta: metav1.TypeMeta{
			APIVersion: velerov1.SchemeGroupVersion.String(),
			Kind:       "Restore",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: velerov1.DefaultNamespace,
			Name:      "fake-restore",
			UID:       "fake-uid",
		},
	}

	modeFilesystem := corev1api.PersistentVolumeFilesystem
	modeBlock := corev1api.PersistentVolumeBlock

	targetPVCObjChangeMode := &corev1api.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "fake-ns",
			Name:      "fake-target-pvc",
		},
		Spec: corev1api.PersistentVolumeClaimSpec{
			VolumeMode: &modeBlock,
		},
	}

	targetPVCObjSameMode := &corev1api.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "fake-ns",
			Name:      "fake-target-pvc",
		},
		Spec: corev1api.PersistentVolumeClaimSpec{
			VolumeMode: &modeFilesystem,
		},
	}

	restorePVCObj := &corev1api.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: velerov1.DefaultNamespace,
			Name:      "fake-restore",
		},
		Spec: corev1api.PersistentVolumeClaimSpec{
			VolumeName: "fake-restore-pv",
		},
	}

	restorePVObj := &corev1api.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name: "fake-restore-pv",
		},
		Spec: corev1api.PersistentVolumeSpec{
			PersistentVolumeReclaimPolicy: corev1api.PersistentVolumeReclaimDelete,
			VolumeMode:                    &modeFilesystem,
		},
	}

	restorePod := &corev1api.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: velerov1.DefaultNamespace,
			Name:      "fake-restore",
		},
	}

	tests := []struct {
		name            string
		kubeClientObj   []runtime.Object
		ownerRestore    *velerov1.Restore
		targetPVCName   string
		targetNamespace string
		kubeReactors    []reactor
		err             string
	}{
		{
			name:            "get target pvc fail",
			targetPVCName:   "fake-target-pvc",
			targetNamespace: "fake-ns",
			ownerRestore:    restore,
			err:             "error to get target PVC fake-ns/fake-target-pvc: persistentvolumeclaims \"fake-target-pvc\" not found",
		},
		{
			name:            "wait restore pvc bound fail",
			targetPVCName:   "fake-target-pvc",
			targetNamespace: "fake-ns",
			ownerRestore:    restore,
			kubeClientObj: []runtime.Object{
				targetPVCObjSameMode,
			},
			err: "error to get PV from restore PVC fake-restore: error to wait for rediness of PVC: error to get pvc velero/fake-restore: persistentvolumeclaims \"fake-restore\" not found",
		},
		{
			name:            "[change mode] retain target pv fail",
			targetPVCName:   "fake-target-pvc",
			targetNamespace: "fake-ns",
			ownerRestore:    restore,
			kubeClientObj: []runtime.Object{
				targetPVCObjChangeMode,
				restorePVCObj,
				restorePVObj,
			},
			kubeReactors: []reactor{
				{
					verb:     "patch",
					resource: "persistentvolumes",
					reactorFunc: func(action clientTesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, errors.New("fake-patch-error")
					},
				},
			},
			err: "error to retain PV fake-restore-pv: error patching PV: fake-patch-error",
		},
		{
			name:            "[change mode] delete restore pod fail",
			targetPVCName:   "fake-target-pvc",
			targetNamespace: "fake-ns",
			ownerRestore:    restore,
			kubeClientObj: []runtime.Object{
				targetPVCObjChangeMode,
				restorePVCObj,
				restorePVObj,
				restorePod,
			},
			kubeReactors: []reactor{
				{
					verb:     "delete",
					resource: "pods",
					reactorFunc: func(action clientTesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, errors.New("fake-delete-error")
					},
				},
			},
			err: "error to delete restore pod fake-restore: error to delete pod fake-restore: fake-delete-error",
		},
		{
			name:            "[change mode] delete restore pvc fail",
			targetPVCName:   "fake-target-pvc",
			targetNamespace: "fake-ns",
			ownerRestore:    restore,
			kubeClientObj: []runtime.Object{
				targetPVCObjChangeMode,
				restorePVCObj,
				restorePVObj,
				restorePod,
			},
			kubeReactors: []reactor{
				{
					verb:     "delete",
					resource: "persistentvolumeclaims",
					reactorFunc: func(action clientTesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, errors.New("fake-delete-error")
					},
				},
			},
			err: "error to delete restore PVC fake-restore: error to delete pvc fake-restore: fake-delete-error",
		},
		{
			name:            "[change mode] wait volume detached fail",
			targetPVCName:   "fake-target-pvc",
			targetNamespace: "fake-ns",
			ownerRestore:    restore,
			kubeClientObj: []runtime.Object{
				targetPVCObjChangeMode,
				restorePVCObj,
				restorePVObj,
				restorePod,
			},
			kubeReactors: []reactor{
				{
					verb:     "list",
					resource: "volumeattachments",
					reactorFunc: func(action clientTesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, errors.New("fake-list-error")
					},
				},
			},
			err: "error waiting for restore PV fake-restore-pv to detach: error listing volumeattachment: error listing volumeattachment: fake-list-error",
		},
		{
			name:            "[change mode] rebind pv fail",
			targetPVCName:   "fake-target-pvc",
			targetNamespace: "fake-ns",
			ownerRestore:    restore,
			kubeClientObj: []runtime.Object{
				targetPVCObjChangeMode,
				restorePVCObj,
				restorePVObj,
				restorePod,
			},
			kubeReactors: []reactor{
				{
					verb:     "create",
					resource: "persistentvolumes",
					reactorFunc: func(action clientTesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, errors.New("fake-create-error")
					},
				},
			},
			err: "error rebinding PV for target PVC fake-target-pvc: fake-create-error",
		},
		{
			name:            "[change mode] delete retained pv fail",
			targetPVCName:   "fake-target-pvc",
			targetNamespace: "fake-ns",
			ownerRestore:    restore,
			kubeClientObj: []runtime.Object{
				targetPVCObjChangeMode,
				restorePVCObj,
				restorePVObj,
				restorePod,
			},
			kubeReactors: []reactor{
				{
					verb:     "delete",
					resource: "persistentvolumes",
					reactorFunc: func(action clientTesting.Action) (handled bool, ret runtime.Object, err error) {
						// we want it to fail on the PV deletion but not the pod/pvc deletions
						if action.(clientTesting.DeleteAction).GetName() == "fake-restore-pv" {
							return true, nil, errors.New("fake-delete-error")
						}
						return false, nil, nil
					},
				},
			},
			err: "error deleting restore PV fake-restore-pv: error to delete pv fake-restore-pv: fake-delete-error",
		},
		{
			name:            "[change mode] rebind target pvc fail",
			targetPVCName:   "fake-target-pvc",
			targetNamespace: "fake-ns",
			ownerRestore:    restore,
			kubeClientObj: []runtime.Object{
				targetPVCObjChangeMode,
				restorePVCObj,
				restorePVObj,
				restorePod,
			},
			kubeReactors: []reactor{
				{
					verb:     "patch",
					resource: "persistentvolumeclaims",
					reactorFunc: func(action clientTesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, errors.New("fake-patch-error")
					},
				},
			},
			err: "error to rebind target PVC fake-ns/fake-target-pvc to",
		},
		{
			name:            "[change mode] wait rebind PV ready fail",
			targetPVCName:   "fake-target-pvc",
			targetNamespace: "fake-ns",
			ownerRestore:    restore,
			kubeClientObj: []runtime.Object{
				targetPVCObjChangeMode,
				restorePVCObj,
				restorePVObj,
				restorePod,
			},
			err: "error to wait rebind PV ready, rebind PV",
		},
		{
			name:            "[same mode] retain target pv fail",
			targetPVCName:   "fake-target-pvc",
			targetNamespace: "fake-ns",
			ownerRestore:    restore,
			kubeClientObj: []runtime.Object{
				targetPVCObjSameMode,
				restorePVCObj,
				restorePVObj,
			},
			kubeReactors: []reactor{
				{
					verb:     "patch",
					resource: "persistentvolumes",
					reactorFunc: func(action clientTesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, errors.New("fake-patch-error")
					},
				},
			},
			err: "error to retain PV fake-restore-pv: error patching PV: fake-patch-error",
		},
		{
			name:            "[same mode] delete restore pod fail",
			targetPVCName:   "fake-target-pvc",
			targetNamespace: "fake-ns",
			ownerRestore:    restore,
			kubeClientObj: []runtime.Object{
				targetPVCObjSameMode,
				restorePVCObj,
				restorePVObj,
				restorePod,
			},
			kubeReactors: []reactor{
				{
					verb:     "delete",
					resource: "pods",
					reactorFunc: func(action clientTesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, errors.New("fake-delete-error")
					},
				},
			},
			err: "error to delete restore pod fake-restore: error to delete pod fake-restore: fake-delete-error",
		},
		{
			name:            "[same mode] delete restore pvc fail",
			targetPVCName:   "fake-target-pvc",
			targetNamespace: "fake-ns",
			ownerRestore:    restore,
			kubeClientObj: []runtime.Object{
				targetPVCObjSameMode,
				restorePVCObj,
				restorePVObj,
				restorePod,
			},
			kubeReactors: []reactor{
				{
					verb:     "delete",
					resource: "persistentvolumeclaims",
					reactorFunc: func(action clientTesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, errors.New("fake-delete-error")
					},
				},
			},
			err: "error to delete restore PVC fake-restore: error to delete pvc fake-restore: fake-delete-error",
		},
		{
			name:            "[same mode] wait volume detached fail",
			targetPVCName:   "fake-target-pvc",
			targetNamespace: "fake-ns",
			ownerRestore:    restore,
			kubeClientObj: []runtime.Object{
				targetPVCObjSameMode,
				restorePVCObj,
				restorePVObj,
				restorePod,
			},
			kubeReactors: []reactor{
				{
					verb:     "list",
					resource: "volumeattachments",
					reactorFunc: func(action clientTesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, errors.New("fake-list-error")
					},
				},
			},
			err: "error waiting for restore PV fake-restore-pv to detach: error listing volumeattachment: error listing volumeattachment: fake-list-error",
		},
		{
			name:            "[same mode] rebind target pvc fail",
			targetPVCName:   "fake-target-pvc",
			targetNamespace: "fake-ns",
			ownerRestore:    restore,
			kubeClientObj: []runtime.Object{
				targetPVCObjSameMode,
				restorePVCObj,
				restorePVObj,
				restorePod,
			},
			kubeReactors: []reactor{
				{
					verb:     "patch",
					resource: "persistentvolumeclaims",
					reactorFunc: func(action clientTesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, errors.New("fake-patch-error")
					},
				},
			},
			err: "error to rebind target PVC fake-ns/fake-target-pvc to fake-restore-pv: error patching PVC: fake-patch-error",
		},
		{
			name:            "[same mode] reset pv binding fail",
			targetPVCName:   "fake-target-pvc",
			targetNamespace: "fake-ns",
			ownerRestore:    restore,
			kubeClientObj: []runtime.Object{
				targetPVCObjSameMode,
				restorePVCObj,
				restorePVObj,
				restorePod,
			},
			kubeReactors: []reactor{
				{
					verb:     "patch",
					resource: "persistentvolumes",
					reactorFunc: func(action clientTesting.Action) (handled bool, ret runtime.Object, err error) {
						// we need it to succeed on set reclaim policy, but fail on reset binding
						patchAction := action.(clientTesting.PatchAction)
						patchString := string(patchAction.GetPatch())
						if patchString != `{"spec":{"persistentVolumeReclaimPolicy":"Retain"}}` {
							return true, nil, errors.New("fake-patch-error-reset")
						}
						return false, nil, nil
					},
				},
			},
			err: "error to reset binding info for restore PV fake-restore-pv: error patching PV: fake-patch-error-reset",
		},
		{
			name:            "[same mode] wait restore PV bound fail",
			targetPVCName:   "fake-target-pvc",
			targetNamespace: "fake-ns",
			ownerRestore:    restore,
			kubeClientObj: []runtime.Object{
				targetPVCObjSameMode,
				restorePVCObj,
				restorePVObj,
				restorePod,
			},
			err: "error to wait restore PV bound, restore PV fake-restore-pv: error to wait for bound of PV: context deadline exceeded",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakeKubeClient := fake.NewSimpleClientset(test.kubeClientObj...)

			for _, reactor := range test.kubeReactors {
				fakeKubeClient.Fake.PrependReactor(reactor.verb, reactor.resource, reactor.reactorFunc)
			}

			exposer := genericRestoreExposer{
				kubeClient: fakeKubeClient,
				log:        velerotest.NewLogger(),
			}

			var ownerObject corev1api.ObjectReference
			if test.ownerRestore != nil {
				ownerObject = corev1api.ObjectReference{
					Kind:       test.ownerRestore.Kind,
					Namespace:  test.ownerRestore.Namespace,
					Name:       test.ownerRestore.Name,
					UID:        test.ownerRestore.UID,
					APIVersion: test.ownerRestore.APIVersion,
				}
			}

			err := exposer.RebindVolume(t.Context(), ownerObject, GenericRestoreRebindVolumeParam{
				TargetPVCName:    test.targetPVCName,
				TargetNamespace:  test.targetNamespace,
				OperationTimeout: time.Millisecond,
			})
			if test.err != "" {
				assert.ErrorContains(t, err, test.err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
func TestRestorePeekExpose(t *testing.T) {
	restore := &velerov1.Restore{
		TypeMeta: metav1.TypeMeta{
			APIVersion: velerov1.SchemeGroupVersion.String(),
			Kind:       "Restore",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: velerov1.DefaultNamespace,
			Name:      "fake-restore",
			UID:       "fake-uid",
		},
	}

	restorePodUrecoverable := &corev1api.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: restore.Namespace,
			Name:      restore.Name,
		},
		Status: corev1api.PodStatus{
			Phase: corev1api.PodFailed,
		},
	}

	restorePod := &corev1api.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: restore.Namespace,
			Name:      restore.Name,
		},
	}

	tests := []struct {
		name          string
		kubeClientObj []runtime.Object
		ownerRestore  *velerov1.Restore
		err           string
	}{
		{
			name:         "restore pod is not found",
			ownerRestore: restore,
		},
		{
			name:         "pod is unrecoverable",
			ownerRestore: restore,
			kubeClientObj: []runtime.Object{
				restorePodUrecoverable,
			},
			err: "Pod is in abnormal state [Failed], message []",
		},
		{
			name:         "succeed",
			ownerRestore: restore,
			kubeClientObj: []runtime.Object{
				restorePod,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakeKubeClient := fake.NewSimpleClientset(test.kubeClientObj...)

			exposer := genericRestoreExposer{
				kubeClient: fakeKubeClient,
				log:        velerotest.NewLogger(),
			}

			var ownerObject corev1api.ObjectReference
			if test.ownerRestore != nil {
				ownerObject = corev1api.ObjectReference{
					Kind:       test.ownerRestore.Kind,
					Namespace:  test.ownerRestore.Namespace,
					Name:       test.ownerRestore.Name,
					UID:        test.ownerRestore.UID,
					APIVersion: test.ownerRestore.APIVersion,
				}
			}

			err := exposer.PeekExposed(t.Context(), ownerObject)
			if test.err == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, test.err)
			}
		})
	}
}

func Test_ReastoreDiagnoseExpose(t *testing.T) {
	restore := &velerov1.Restore{
		TypeMeta: metav1.TypeMeta{
			APIVersion: velerov1.SchemeGroupVersion.String(),
			Kind:       "Restore",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: velerov1.DefaultNamespace,
			Name:      "fake-restore",
			UID:       "fake-uid",
		},
	}

	restorePodWithoutNodeName := corev1api.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: velerov1.DefaultNamespace,
			Name:      "fake-restore",
			UID:       "fake-pod-uid",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: restore.APIVersion,
					Kind:       restore.Kind,
					Name:       restore.Name,
					UID:        restore.UID,
				},
			},
		},
		Status: corev1api.PodStatus{
			Phase: corev1api.PodPending,
			Conditions: []corev1api.PodCondition{
				{
					Type:    corev1api.PodInitialized,
					Status:  corev1api.ConditionTrue,
					Message: "fake-pod-message",
				},
			},
			Message: "fake-pod-message-1",
		},
	}

	restorePodWithNodeName := corev1api.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: velerov1.DefaultNamespace,
			Name:      "fake-restore",
			UID:       "fake-pod-uid",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: restore.APIVersion,
					Kind:       restore.Kind,
					Name:       restore.Name,
					UID:        restore.UID,
				},
			},
		},
		Spec: corev1api.PodSpec{
			NodeName: "fake-node",
		},
		Status: corev1api.PodStatus{
			Phase: corev1api.PodPending,
			Conditions: []corev1api.PodCondition{
				{
					Type:    corev1api.PodInitialized,
					Status:  corev1api.ConditionTrue,
					Message: "fake-pod-message",
				},
			},
		},
	}

	restorePVCWithoutVolumeName := corev1api.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: velerov1.DefaultNamespace,
			Name:      "fake-restore",
			UID:       "fake-pvc-uid",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: restore.APIVersion,
					Kind:       restore.Kind,
					Name:       restore.Name,
					UID:        restore.UID,
				},
			},
		},
		Status: corev1api.PersistentVolumeClaimStatus{
			Phase: corev1api.ClaimPending,
		},
	}

	restorePVCWithVolumeName := corev1api.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: velerov1.DefaultNamespace,
			Name:      "fake-restore",
			UID:       "fake-pvc-uid",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: restore.APIVersion,
					Kind:       restore.Kind,
					Name:       restore.Name,
					UID:        restore.UID,
				},
			},
		},
		Spec: corev1api.PersistentVolumeClaimSpec{
			VolumeName: "fake-pv",
		},
		Status: corev1api.PersistentVolumeClaimStatus{
			Phase: corev1api.ClaimPending,
		},
	}

	restorePV := corev1api.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name: "fake-pv",
		},
		Status: corev1api.PersistentVolumeStatus{
			Phase:   corev1api.VolumePending,
			Message: "fake-pv-message",
		},
	}

	cachePVCWithVolumeName := corev1api.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: velerov1.DefaultNamespace,
			Name:      "fake-restore-cache",
			UID:       "fake-cache-pvc-uid",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: restore.APIVersion,
					Kind:       restore.Kind,
					Name:       restore.Name,
					UID:        restore.UID,
				},
			},
		},
		Spec: corev1api.PersistentVolumeClaimSpec{
			VolumeName: "fake-pv-cache",
		},
		Status: corev1api.PersistentVolumeClaimStatus{
			Phase: corev1api.ClaimPending,
		},
	}

	cachePV := corev1api.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name: "fake-pv-cache",
		},
		Status: corev1api.PersistentVolumeStatus{
			Phase:   corev1api.VolumePending,
			Message: "fake-pv-message",
		},
	}

	nodeAgentPod := corev1api.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: velerov1.DefaultNamespace,
			Name:      "node-agent-pod-1",
			Labels:    map[string]string{"role": "node-agent"},
		},
		Spec: corev1api.PodSpec{
			NodeName: "fake-node",
		},
		Status: corev1api.PodStatus{
			Phase: corev1api.PodRunning,
		},
	}

	tests := []struct {
		name          string
		ownerRestore  *velerov1.Restore
		kubeClientObj []runtime.Object
		expected      string
	}{
		{
			name:         "no pod, pvc",
			ownerRestore: restore,
			expected: `begin diagnose restore exposer
error getting restore pod fake-restore, err: pods "fake-restore" not found
error getting restore pvc fake-restore, err: persistentvolumeclaims "fake-restore" not found
end diagnose restore exposer`,
		},
		{
			name:         "pod without node name, pvc without volume name, vs without status",
			ownerRestore: restore,
			kubeClientObj: []runtime.Object{
				&restorePodWithoutNodeName,
				&restorePVCWithoutVolumeName,
			},
			expected: `begin diagnose restore exposer
Pod velero/fake-restore, phase Pending, node name , message fake-pod-message-1
Pod condition Initialized, status True, reason , message fake-pod-message
PVC velero/fake-restore, phase Pending, binding to 
end diagnose restore exposer`,
		},
		{
			name:         "pod without node name, pvc without volume name",
			ownerRestore: restore,
			kubeClientObj: []runtime.Object{
				&restorePodWithoutNodeName,
				&restorePVCWithoutVolumeName,
			},
			expected: `begin diagnose restore exposer
Pod velero/fake-restore, phase Pending, node name , message fake-pod-message-1
Pod condition Initialized, status True, reason , message fake-pod-message
PVC velero/fake-restore, phase Pending, binding to 
end diagnose restore exposer`,
		},
		{
			name:         "pod with node name, no node agent",
			ownerRestore: restore,
			kubeClientObj: []runtime.Object{
				&restorePodWithNodeName,
				&restorePVCWithoutVolumeName,
			},
			expected: `begin diagnose restore exposer
Pod velero/fake-restore, phase Pending, node name fake-node, message 
Pod condition Initialized, status True, reason , message fake-pod-message
node-agent is not running in node fake-node, err: daemonset pod not found in node fake-node
PVC velero/fake-restore, phase Pending, binding to 
end diagnose restore exposer`,
		},
		{
			name:         "pod with node name, node agent is running",
			ownerRestore: restore,
			kubeClientObj: []runtime.Object{
				&restorePodWithNodeName,
				&restorePVCWithoutVolumeName,
				&nodeAgentPod,
			},
			expected: `begin diagnose restore exposer
Pod velero/fake-restore, phase Pending, node name fake-node, message 
Pod condition Initialized, status True, reason , message fake-pod-message
PVC velero/fake-restore, phase Pending, binding to 
end diagnose restore exposer`,
		},
		{
			name:         "pvc with volume name, no pv",
			ownerRestore: restore,
			kubeClientObj: []runtime.Object{
				&restorePodWithNodeName,
				&restorePVCWithVolumeName,
				&nodeAgentPod,
			},
			expected: `begin diagnose restore exposer
Pod velero/fake-restore, phase Pending, node name fake-node, message 
Pod condition Initialized, status True, reason , message fake-pod-message
PVC velero/fake-restore, phase Pending, binding to fake-pv
error getting restore pv fake-pv, err: persistentvolumes "fake-pv" not found
end diagnose restore exposer`,
		},
		{
			name:         "pvc with volume name, pv exists",
			ownerRestore: restore,
			kubeClientObj: []runtime.Object{
				&restorePodWithNodeName,
				&restorePVCWithVolumeName,
				&restorePV,
				&nodeAgentPod,
			},
			expected: `begin diagnose restore exposer
Pod velero/fake-restore, phase Pending, node name fake-node, message 
Pod condition Initialized, status True, reason , message fake-pod-message
PVC velero/fake-restore, phase Pending, binding to fake-pv
PV fake-pv, phase Pending, reason , message fake-pv-message
end diagnose restore exposer`,
		},
		{
			name:         "cache pvc with volume name, no pv",
			ownerRestore: restore,
			kubeClientObj: []runtime.Object{
				&restorePodWithNodeName,
				&restorePVCWithVolumeName,
				&cachePVCWithVolumeName,
				&nodeAgentPod,
			},
			expected: `begin diagnose restore exposer
Pod velero/fake-restore, phase Pending, node name fake-node, message 
Pod condition Initialized, status True, reason , message fake-pod-message
PVC velero/fake-restore, phase Pending, binding to fake-pv
error getting restore pv fake-pv, err: persistentvolumes "fake-pv" not found
PVC velero/fake-restore-cache, phase Pending, binding to fake-pv-cache
error getting cache pv fake-pv-cache, err: persistentvolumes "fake-pv-cache" not found
end diagnose restore exposer`,
		},
		{
			name:         "cache pvc with volume name, pv exists",
			ownerRestore: restore,
			kubeClientObj: []runtime.Object{
				&restorePodWithNodeName,
				&restorePVCWithVolumeName,
				&cachePVCWithVolumeName,
				&restorePV,
				&cachePV,
				&nodeAgentPod,
			},
			expected: `begin diagnose restore exposer
Pod velero/fake-restore, phase Pending, node name fake-node, message 
Pod condition Initialized, status True, reason , message fake-pod-message
PVC velero/fake-restore, phase Pending, binding to fake-pv
PV fake-pv, phase Pending, reason , message fake-pv-message
PVC velero/fake-restore-cache, phase Pending, binding to fake-pv-cache
PV fake-pv-cache, phase Pending, reason , message fake-pv-message
end diagnose restore exposer`,
		},
		{
			name:         "with events",
			ownerRestore: restore,
			kubeClientObj: []runtime.Object{
				&restorePodWithNodeName,
				&restorePVCWithVolumeName,
				&restorePV,
				&nodeAgentPod,
				&corev1api.Event{
					ObjectMeta:     metav1.ObjectMeta{Namespace: velerov1.DefaultNamespace, Name: "event-1"},
					Type:           corev1api.EventTypeWarning,
					InvolvedObject: corev1api.ObjectReference{UID: "fake-uid-1"},
					Reason:         "reason-1",
					Message:        "message-1",
				},
				&corev1api.Event{
					ObjectMeta:     metav1.ObjectMeta{Namespace: velerov1.DefaultNamespace, Name: "event-2"},
					Type:           corev1api.EventTypeWarning,
					InvolvedObject: corev1api.ObjectReference{UID: "fake-pod-uid"},
					Reason:         "reason-2",
					Message:        "message-2",
				},
				&corev1api.Event{
					ObjectMeta:     metav1.ObjectMeta{Namespace: velerov1.DefaultNamespace, Name: "event-3"},
					Type:           corev1api.EventTypeWarning,
					InvolvedObject: corev1api.ObjectReference{UID: "fake-pvc-uid"},
					Reason:         "reason-3",
					Message:        "message-3",
				},
				&corev1api.Event{
					ObjectMeta:     metav1.ObjectMeta{Namespace: "other-namespace", Name: "event-4"},
					Type:           corev1api.EventTypeWarning,
					InvolvedObject: corev1api.ObjectReference{UID: "fake-pod-uid"},
					Reason:         "reason-4",
					Message:        "message-4",
				},
				&corev1api.Event{
					ObjectMeta:     metav1.ObjectMeta{Namespace: velerov1.DefaultNamespace, Name: "event-5"},
					Type:           corev1api.EventTypeWarning,
					InvolvedObject: corev1api.ObjectReference{UID: "fake-pod-uid"},
					Reason:         "reason-5",
					Message:        "message-5",
				},
			},
			expected: `begin diagnose restore exposer
Pod velero/fake-restore, phase Pending, node name fake-node, message 
Pod condition Initialized, status True, reason , message fake-pod-message
Pod event reason reason-2, message message-2
Pod event reason reason-5, message message-5
PVC velero/fake-restore, phase Pending, binding to fake-pv
PVC event reason reason-3, message message-3
PV fake-pv, phase Pending, reason , message fake-pv-message
end diagnose restore exposer`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakeKubeClient := fake.NewSimpleClientset(test.kubeClientObj...)

			e := genericRestoreExposer{
				kubeClient: fakeKubeClient,
				log:        velerotest.NewLogger(),
			}

			var ownerObject corev1api.ObjectReference
			if test.ownerRestore != nil {
				ownerObject = corev1api.ObjectReference{
					Kind:       test.ownerRestore.Kind,
					Namespace:  test.ownerRestore.Namespace,
					Name:       test.ownerRestore.Name,
					UID:        test.ownerRestore.UID,
					APIVersion: test.ownerRestore.APIVersion,
				}
			}

			diag := e.DiagnoseExpose(t.Context(), ownerObject)
			assert.Equal(t, test.expected, diag)
		})
	}
}

func TestCreateRestorePod(t *testing.T) {
	scName := "storage-class-01"

	daemonSet := &appsv1api.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "velero",
			Name:      "node-agent",
		},
		TypeMeta: metav1.TypeMeta{
			Kind:       "DaemonSet",
			APIVersion: appsv1api.SchemeGroupVersion.String(),
		},
		Spec: appsv1api.DaemonSetSpec{
			Template: corev1api.PodTemplateSpec{
				Spec: corev1api.PodSpec{
					Containers: []corev1api.Container{
						{
							Image: "fake-image",
						},
					},
				},
			},
		},
	}

	daemonSetWin := &appsv1api.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "velero",
			Name:      "node-agent-windows",
		},
		TypeMeta: metav1.TypeMeta{
			Kind:       "DaemonSet",
			APIVersion: appsv1api.SchemeGroupVersion.String(),
		},
		Spec: appsv1api.DaemonSetSpec{
			Template: corev1api.PodTemplateSpec{
				Spec: corev1api.PodSpec{
					Containers: []corev1api.Container{
						{
							Image: "fake-image",
						},
					},
				},
			},
		},
	}

	targetPVCObj := &corev1api.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "fake-ns",
			Name:      "fake-target-pvc",
		},
		Spec: corev1api.PersistentVolumeClaimSpec{
			StorageClassName: &scName,
		},
	}

	tests := []struct {
		name          string
		kubeClientObj []runtime.Object
		selectedNode  string
		affinity      *kube.LoadAffinity
		nodeOS        string
		expectedPod   *corev1api.Pod
	}{
		{
			name:          "linux",
			kubeClientObj: []runtime.Object{daemonSet, daemonSetWin, targetPVCObj},
			selectedNode:  "",
			affinity: &kube.LoadAffinity{
				NodeSelector: metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{
						{
							Key:      "kubernetes.io/os",
							Operator: metav1.LabelSelectorOpIn,
							Values:   []string{"linux"},
						},
					},
				},
				StorageClass: scName,
			},
			nodeOS: "linux",
		},
		{
			name:          "windows",
			kubeClientObj: []runtime.Object{daemonSet, daemonSetWin, targetPVCObj},
			selectedNode:  "",
			affinity: &kube.LoadAffinity{
				NodeSelector: metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{
						{
							Key:      "kubernetes.io/os",
							Operator: metav1.LabelSelectorOpIn,
							Values:   []string{"windows"},
						},
					},
				},
				StorageClass: scName,
			},
			nodeOS: "windows",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakeKubeClient := fake.NewSimpleClientset(test.kubeClientObj...)

			exposer := genericRestoreExposer{
				kubeClient: fakeKubeClient,
				log:        velerotest.NewLogger(),
			}

			pod, err := exposer.createRestorePod(
				t.Context(),
				corev1api.ObjectReference{
					Namespace: velerov1.DefaultNamespace,
					Name:      "data-download",
				},
				targetPVCObj,
				time.Second*3,
				nil,
				nil,
				nil,
				test.selectedNode,
				corev1api.ResourceRequirements{},
				test.nodeOS,
				test.affinity,
				"", // priority class name
				nil,
			)

			require.NoError(t, err)
			if test.expectedPod != nil {
				assert.Equal(t, test.expectedPod, pod)
			}
		})
	}
}
