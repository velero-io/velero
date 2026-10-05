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
	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
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
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	velerov2alpha1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v2alpha1"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
	velerotypes "github.com/vmware-tanzu/velero/pkg/types"
	"github.com/vmware-tanzu/velero/pkg/util"
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
	targetPVObj := &corev1api.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name: "fake-target-pv",
		},
	}

	modeBlock := corev1api.PersistentVolumeBlock
	targetPVObjWithDifferentVolumeMode := &corev1api.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name: "fake-target-pv",
		},
		Spec: corev1api.PersistentVolumeSpec{
			VolumeMode: &modeBlock,
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

	targetPVCObjWithNode := &corev1api.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "fake-ns",
			Name:      "fake-target-pvc-with-node",
			Annotations: map[string]string{
				"volume.kubernetes.io/selected-node": "fake-node",
			},
		},
		Spec: corev1api.PersistentVolumeClaimSpec{
			StorageClassName: &scName,
		},
	}

	volumeBindingMode := storagev1api.VolumeBindingWaitForFirstConsumer
	storageClassWaitForFirstConsumer := &storagev1api.StorageClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "fake-sc",
		},
		VolumeBindingMode: &volumeBindingMode,
	}

	restorePVCObjBound := &corev1api.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: velerov1.DefaultNamespace,
			Name:      "fake-restore",
		},
		Spec: corev1api.PersistentVolumeClaimSpec{
			VolumeName:       "fake-restore-pv",
			StorageClassName: &scName,
		},
		Status: corev1api.PersistentVolumeClaimStatus{
			Phase: corev1api.ClaimBound,
		},
	}

	restorePVObjWithTopology := &corev1api.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name: "fake-restore-pv",
		},
		Spec: corev1api.PersistentVolumeSpec{
			StorageClassName: "fake-sc",
			NodeAffinity: &corev1api.VolumeNodeAffinity{
				Required: &corev1api.NodeSelector{
					NodeSelectorTerms: []corev1api.NodeSelectorTerm{
						{
							MatchExpressions: []corev1api.NodeSelectorRequirement{
								{
									Key:      "topology.kubernetes.io/zone",
									Operator: corev1api.NodeSelectorOpIn,
									Values:   []string{"zone-1"},
								},
							},
						},
					},
				},
			},
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
		name                 string
		kubeClientObj        []runtime.Object
		ownerRestore         *velerov1.Restore
		targetPVCName        string
		targetNamespace      string
		targetPVName         string
		kubeReactors         []reactor
		cacheVolume          *CacheConfigs
		dataMover            string
		expectBackupPod      bool
		expectBackupPVC      bool
		expectCachePVC       bool
		expectBackupPV       bool
		expectedNodeSelector map[string]string
		expectedNodeAffinity *corev1api.NodeAffinity
		err                  string
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
			err: "error to create restore pvc: fail to create the restore PVC fake-restore in namespace velero: fake-create-error",
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
			name:            "succeed with target PV set",
			targetPVCName:   "fake-target-pvc",
			targetNamespace: "fake-ns",
			targetPVName:    "fake-target-pv",
			ownerRestore:    restore,
			kubeClientObj: []runtime.Object{
				targetPVCObj,
				targetPVObj,
				daemonSet,
				storageClass,
			},
			kubeReactors: []reactor{
				{
					verb:     "get",
					resource: "persistentvolumeclaims",
					reactorFunc: func(action clientTesting.Action) (handled bool, ret runtime.Object, err error) {
						getAction := action.(clientTesting.GetAction)
						if getAction.GetName() == "fake-restore" {
							return true, &corev1api.PersistentVolumeClaim{
								ObjectMeta: metav1.ObjectMeta{
									Name:      "fake-restore",
									Namespace: velerov1.DefaultNamespace,
								},
								Spec: corev1api.PersistentVolumeClaimSpec{
									VolumeName: "fake-target-pv",
								},
								Status: corev1api.PersistentVolumeClaimStatus{
									Phase: corev1api.ClaimBound,
								},
							}, nil
						}
						return false, nil, nil
					},
				},
			},
			expectBackupPod: true,
			expectBackupPVC: true,
		},
		{
			name:            "succeed with invalid selected node and volume topology",
			targetPVCName:   "fake-target-pvc-with-node",
			targetNamespace: "fake-ns",
			ownerRestore:    restore,
			kubeClientObj: []runtime.Object{
				targetPVCObjWithNode,
				daemonSet,
				storageClassWaitForFirstConsumer,
				restorePVObjWithTopology,
			},
			kubeReactors: []reactor{
				{
					verb:     "get",
					resource: "persistentvolumeclaims",
					reactorFunc: func(action clientTesting.Action) (handled bool, ret runtime.Object, err error) {
						getAction := action.(clientTesting.GetAction)
						if getAction.GetName() == "fake-restore" {
							return true, restorePVCObjBound, nil
						}
						return false, nil, nil
					},
				},
			},
			expectBackupPod:      true,
			expectBackupPVC:      true,
			expectedNodeSelector: map[string]string{},
			expectedNodeAffinity: &corev1api.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &corev1api.NodeSelector{
					NodeSelectorTerms: []corev1api.NodeSelectorTerm{
						{
							MatchExpressions: []corev1api.NodeSelectorRequirement{
								{
									Key:      "topology.kubernetes.io/zone",
									Operator: corev1api.NodeSelectorOpIn,
									Values:   []string{"zone-1"},
								},
								{
									Key:      "kubernetes.io/os",
									Operator: corev1api.NodeSelectorOpNotIn,
									Values:   []string{"windows"},
								},
							},
						},
					},
				},
			},
		},
		{
			name:            "create temporary PV fail",
			targetPVCName:   "fake-target-pvc",
			targetNamespace: "fake-ns",
			targetPVName:    "fake-target-pv",
			ownerRestore:    restore,
			kubeClientObj: []runtime.Object{
				targetPVCObj,
				targetPVObjWithDifferentVolumeMode,
				daemonSet,
				storageClass,
			},
			kubeReactors: []reactor{
				{
					verb:     "create",
					resource: "persistentvolumes",
					reactorFunc: func(action clientTesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, errors.New("fake-create-pv-error")
					},
				},
			},
			err: "error to create restore pvc: fail to create the temporary PV fake-restore: fake-create-pv-error",
		},
		{
			name:            "delete original PV fail",
			targetPVCName:   "fake-target-pvc",
			targetNamespace: "fake-ns",
			targetPVName:    "fake-target-pv",
			ownerRestore:    restore,
			kubeClientObj: []runtime.Object{
				targetPVCObj,
				targetPVObjWithDifferentVolumeMode,
				daemonSet,
				storageClass,
			},
			kubeReactors: []reactor{
				{
					verb:     "delete",
					resource: "persistentvolumes",
					reactorFunc: func(action clientTesting.Action) (handled bool, ret runtime.Object, err error) {
						deleteAction := action.(clientTesting.DeleteAction)
						if deleteAction.GetName() == "fake-target-pv" {
							return true, nil, errors.New("fake-delete-pv-error")
						}
						return false, nil, nil
					},
				},
			},
			err: "error to create restore pvc: fail to delete the target PV fake-target-pv: fake-delete-pv-error",
		},
		{
			name:            "succeed with target PV set and different volume mode",
			targetPVCName:   "fake-target-pvc",
			targetNamespace: "fake-ns",
			targetPVName:    "fake-target-pv",
			ownerRestore:    restore,
			kubeClientObj: []runtime.Object{
				targetPVCObj,
				targetPVObjWithDifferentVolumeMode,
				daemonSet,
				storageClass,
			},
			kubeReactors: []reactor{
				{
					verb:     "get",
					resource: "persistentvolumeclaims",
					reactorFunc: func(action clientTesting.Action) (handled bool, ret runtime.Object, err error) {
						getAction := action.(clientTesting.GetAction)
						if getAction.GetName() == "fake-restore" {
							return true, &corev1api.PersistentVolumeClaim{
								ObjectMeta: metav1.ObjectMeta{
									Name:      "fake-restore",
									Namespace: velerov1.DefaultNamespace,
								},
								Spec: corev1api.PersistentVolumeClaimSpec{
									VolumeName: "fake-restore",
								},
								Status: corev1api.PersistentVolumeClaimStatus{
									Phase: corev1api.ClaimBound,
								},
							}, nil
						}
						return false, nil, nil
					},
				},
			},
			expectBackupPod: true,
			expectBackupPVC: true,
			expectBackupPV:  true,
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
					TargetPVName:     test.targetPVName,
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

			pod, err := exposer.kubeClient.CoreV1().Pods(ownerObject.Namespace).Get(t.Context(), ownerObject.Name, metav1.GetOptions{})
			if test.expectBackupPod {
				require.NoError(t, err)
				if test.expectedNodeSelector != nil {
					assert.Equal(t, test.expectedNodeSelector, pod.Spec.NodeSelector)
				}
				if test.expectedNodeAffinity != nil {
					require.NotNil(t, pod.Spec.Affinity)
					assert.Equal(t, test.expectedNodeAffinity, pod.Spec.Affinity.NodeAffinity)
				}
			} else {
				require.True(t, apierrors.IsNotFound(err), "expected IsNotFound, got %v", err)
			}

			pvc, err := exposer.kubeClient.CoreV1().PersistentVolumeClaims(ownerObject.Namespace).Get(t.Context(), ownerObject.Name, metav1.GetOptions{})
			if test.expectBackupPVC {
				require.NoError(t, err)
				if test.dataMover == datamover.DataMoverTypeVeleroBlock {
					require.NotNil(t, pvc.Spec.VolumeMode)
					require.Equal(t, corev1api.PersistentVolumeBlock, *pvc.Spec.VolumeMode)
				}
			} else {
				require.True(t, apierrors.IsNotFound(err), "expected IsNotFound, got %v", err)
			}

			_, err = exposer.kubeClient.CoreV1().PersistentVolumeClaims(ownerObject.Namespace).Get(t.Context(), getCachePVCName(ownerObject), metav1.GetOptions{})
			if test.expectCachePVC {
				require.NoError(t, err)
			} else {
				require.True(t, apierrors.IsNotFound(err), "expected IsNotFound, got %v", err)
			}

			_, err = exposer.kubeClient.CoreV1().PersistentVolumes().Get(t.Context(), ownerObject.Name, metav1.GetOptions{})
			if test.expectBackupPV {
				require.NoError(t, err)
			} else {
				require.True(t, apierrors.IsNotFound(err), "expected IsNotFound, got %v", err)
			}

			if test.targetPVName != "" && !test.expectBackupPV && test.err == "" {
				// if targetPVName was provided, and sameVolumeMode was true, the original PV should still exist
				_, err = exposer.kubeClient.CoreV1().PersistentVolumes().Get(t.Context(), test.targetPVName, metav1.GetOptions{})
				require.NoError(t, err)
			} else if test.targetPVName != "" && test.expectBackupPV {
				// if targetPVName was provided, and sameVolumeMode was false (expectBackupPV is true), the original PV should be deleted
				_, err = exposer.kubeClient.CoreV1().PersistentVolumes().Get(t.Context(), test.targetPVName, metav1.GetOptions{})
				require.True(t, apierrors.IsNotFound(err), "expected original PV %s to be deleted, but it still exists", test.targetPVName)
			}
		})
	}
}

func TestRestoreExpose_SecretCopy(t *testing.T) {
	scName := "fake-sc"
	restore := &velerov1.Restore{
		TypeMeta:   metav1.TypeMeta{APIVersion: velerov1.SchemeGroupVersion.String(), Kind: "Restore"},
		ObjectMeta: metav1.ObjectMeta{Namespace: velerov1.DefaultNamespace, Name: "fake-restore", UID: "fake-uid"},
	}
	ownerObject := corev1api.ObjectReference{
		Kind:       restore.Kind,
		Namespace:  restore.Namespace,
		Name:       restore.Name,
		UID:        restore.UID,
		APIVersion: restore.APIVersion,
	}
	targetPVCObj := &corev1api.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Namespace: "fake-ns", Name: "fake-target-pvc"},
		Spec:       corev1api.PersistentVolumeClaimSpec{StorageClassName: &scName},
	}
	storageClass := &storagev1api.StorageClass{ObjectMeta: metav1.ObjectMeta{Name: "fake-sc"}}
	daemonSet := &appsv1api.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "velero", Name: "node-agent"},
		TypeMeta:   metav1.TypeMeta{Kind: "DaemonSet", APIVersion: appsv1api.SchemeGroupVersion.String()},
		Spec: appsv1api.DaemonSetSpec{
			Template: corev1api.PodTemplateSpec{
				Spec: corev1api.PodSpec{Containers: []corev1api.Container{{Image: "fake-image"}}},
			},
		},
	}

	t.Run("copies secret and configmap from target namespace", func(t *testing.T) {
		srcSecret := &corev1api.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "kms-token", Namespace: "fake-ns"},
			Data:       map[string][]byte{"token": []byte("vault-token")},
			Type:       corev1api.SecretTypeOpaque,
		}
		srcCM := &corev1api.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: "kms-config", Namespace: "fake-ns"},
			Data:       map[string]string{"vaultAddress": "https://vault.example.com"},
		}
		fakeKubeClient := fake.NewSimpleClientset(targetPVCObj, storageClass, daemonSet, srcSecret, srcCM)
		exposer := genericRestoreExposer{kubeClient: fakeKubeClient, log: velerotest.NewLogger()}

		err := exposer.Expose(t.Context(), ownerObject, GenericRestoreExposeParam{
			TargetPVCName:    "fake-target-pvc",
			TargetNamespace:  "fake-ns",
			HostingPodLabels: map[string]string{},
			Resources:        corev1api.ResourceRequirements{},
			ExposeTimeout:    time.Millisecond,
			RestorePVCConfig: velerotypes.RestorePVC{
				SecretNames:    []string{"kms-token"},
				ConfigMapNames: []string{"kms-config"},
			},
		})
		require.NoError(t, err)

		copiedSecret, err := fakeKubeClient.CoreV1().Secrets(ownerObject.Namespace).Get(t.Context(), "kms-token", metav1.GetOptions{})
		require.NoError(t, err)
		assert.Equal(t, []byte("vault-token"), copiedSecret.Data["token"])
		assert.Equal(t, string(ownerObject.UID), copiedSecret.Labels[BackupPVCSecretLabel])

		copiedCM, err := fakeKubeClient.CoreV1().ConfigMaps(ownerObject.Namespace).Get(t.Context(), "kms-config", metav1.GetOptions{})
		require.NoError(t, err)
		assert.Equal(t, "https://vault.example.com", copiedCM.Data["vaultAddress"])
		assert.Equal(t, string(ownerObject.UID), copiedCM.Labels[BackupPVCSecretLabel])
	})

	t.Run("returns error when source secret missing", func(t *testing.T) {
		fakeKubeClient := fake.NewSimpleClientset(targetPVCObj, storageClass, daemonSet)
		exposer := genericRestoreExposer{kubeClient: fakeKubeClient, log: velerotest.NewLogger()}

		err := exposer.Expose(t.Context(), ownerObject, GenericRestoreExposeParam{
			TargetPVCName:    "fake-target-pvc",
			TargetNamespace:  "fake-ns",
			HostingPodLabels: map[string]string{},
			Resources:        corev1api.ResourceRequirements{},
			ExposeTimeout:    time.Millisecond,
			RestorePVCConfig: velerotypes.RestorePVC{SecretNames: []string{"missing-secret"}},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "error copying secret")
	})
}

func TestGetVolumeID(t *testing.T) {
	vscName := "fake-vsc"
	snapshotHandle := "fake-snapshot-handle"

	tests := []struct {
		name          string
		snapshot      *velerov2alpha1api.CSISnapshotSpec
		targetPVName  string
		ctrlClientObj []runtime.Object
		kubeClientObj []runtime.Object
		expectedID    string
		expectedErr   string
	}{
		{
			name: "VS not found in ctrlClient",
			snapshot: &velerov2alpha1api.CSISnapshotSpec{
				VolumeSnapshot:          "non-existent-vs",
				VolumeSnapshotNamespace: "fake-ns",
			},
			expectedErr: "error to get volume snapshot fake-ns/non-existent-vs",
		},
		{
			name: "GetVSCForVS error - VS has no bound VSC",
			snapshot: &velerov2alpha1api.CSISnapshotSpec{
				VolumeSnapshot:          "fake-vs",
				VolumeSnapshotNamespace: "fake-ns",
			},
			ctrlClientObj: []runtime.Object{
				&snapshotv1api.VolumeSnapshot{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "fake-ns",
						Name:      "fake-vs",
					},
					Status: nil,
				},
			},
			expectedErr: "error to get volume snapshot content for volume snapshot fake-ns/fake-vs: invalid snapshot info in volume snapshot fake-vs",
		},
		{
			name: "GetVSCForVS error - VSC not found in ctrlClient",
			snapshot: &velerov2alpha1api.CSISnapshotSpec{
				VolumeSnapshot:          "fake-vs",
				VolumeSnapshotNamespace: "fake-ns",
			},
			ctrlClientObj: []runtime.Object{
				&snapshotv1api.VolumeSnapshot{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "fake-ns",
						Name:      "fake-vs",
					},
					Status: &snapshotv1api.VolumeSnapshotStatus{
						BoundVolumeSnapshotContentName: &vscName,
					},
				},
			},
			expectedErr: "error to get volume snapshot content for volume snapshot fake-ns/fake-vs: error getting volume snapshot content from API",
		},
		{
			name: "GetCBTInfo error - target PV not found",
			snapshot: &velerov2alpha1api.CSISnapshotSpec{
				VolumeSnapshot:          "fake-vs",
				VolumeSnapshotNamespace: "fake-ns",
			},
			targetPVName: "missing-pv",
			ctrlClientObj: []runtime.Object{
				&snapshotv1api.VolumeSnapshot{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "fake-ns",
						Name:      "fake-vs",
					},
					Status: &snapshotv1api.VolumeSnapshotStatus{
						BoundVolumeSnapshotContentName: &vscName,
					},
				},
				&snapshotv1api.VolumeSnapshotContent{
					ObjectMeta: metav1.ObjectMeta{
						Name: vscName,
					},
					Status: &snapshotv1api.VolumeSnapshotContentStatus{
						SnapshotHandle: &snapshotHandle,
					},
				},
			},
			expectedErr: "error to get CBT info: failed to get pv missing-pv",
		},
		{
			name: "GetCBTInfo error - empty volumeID on PV",
			snapshot: &velerov2alpha1api.CSISnapshotSpec{
				VolumeSnapshot:          "fake-vs",
				VolumeSnapshotNamespace: "fake-ns",
			},
			targetPVName: "fake-pv",
			ctrlClientObj: []runtime.Object{
				&snapshotv1api.VolumeSnapshot{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "fake-ns",
						Name:      "fake-vs",
					},
					Status: &snapshotv1api.VolumeSnapshotStatus{
						BoundVolumeSnapshotContentName: &vscName,
					},
				},
				&snapshotv1api.VolumeSnapshotContent{
					ObjectMeta: metav1.ObjectMeta{
						Name: vscName,
					},
					Status: &snapshotv1api.VolumeSnapshotContentStatus{
						SnapshotHandle: &snapshotHandle,
					},
				},
			},
			kubeClientObj: []runtime.Object{
				&corev1api.PersistentVolume{
					ObjectMeta: metav1.ObjectMeta{
						Name: "fake-pv",
					},
				},
			},
			expectedErr: "error to get CBT info: volumeID must not be empty for CBT",
		},
		{
			name: "success with VKS annotations",
			snapshot: &velerov2alpha1api.CSISnapshotSpec{
				VolumeSnapshot:          "fake-vs",
				VolumeSnapshotNamespace: "fake-ns",
			},
			ctrlClientObj: []runtime.Object{
				&snapshotv1api.VolumeSnapshot{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "fake-ns",
						Name:      "fake-vs",
						Annotations: map[string]string{
							util.VSphereCNSChangeIDAnno: "c-1",
							util.VSphereCNSSnapshotAnno: "vol-vks+snap-1",
						},
					},
					Status: &snapshotv1api.VolumeSnapshotStatus{
						BoundVolumeSnapshotContentName: &vscName,
					},
				},
				&snapshotv1api.VolumeSnapshotContent{
					ObjectMeta: metav1.ObjectMeta{
						Name: vscName,
					},
				},
			},
			expectedID: "vol-vks",
		},
		{
			name: "success with PV CSI volume handle",
			snapshot: &velerov2alpha1api.CSISnapshotSpec{
				VolumeSnapshot:          "fake-vs",
				VolumeSnapshotNamespace: "fake-ns",
			},
			targetPVName: "fake-pv",
			ctrlClientObj: []runtime.Object{
				&snapshotv1api.VolumeSnapshot{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "fake-ns",
						Name:      "fake-vs",
					},
					Status: &snapshotv1api.VolumeSnapshotStatus{
						BoundVolumeSnapshotContentName: &vscName,
					},
				},
				&snapshotv1api.VolumeSnapshotContent{
					ObjectMeta: metav1.ObjectMeta{
						Name: vscName,
					},
					Status: &snapshotv1api.VolumeSnapshotContentStatus{
						SnapshotHandle: &snapshotHandle,
					},
				},
			},
			kubeClientObj: []runtime.Object{
				&corev1api.PersistentVolume{
					ObjectMeta: metav1.ObjectMeta{
						Name: "fake-pv",
					},
					Spec: corev1api.PersistentVolumeSpec{
						PersistentVolumeSource: corev1api.PersistentVolumeSource{
							CSI: &corev1api.CSIPersistentVolumeSource{
								VolumeHandle: "csi-vol-789",
							},
						},
					},
				},
			},
			expectedID: "csi-vol-789",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakeKubeClient := fake.NewSimpleClientset(test.kubeClientObj...)
			fakeCtrlClient := velerotest.NewFakeControllerRuntimeClient(t, test.ctrlClientObj...)

			exposer := genericRestoreExposer{
				kubeClient: fakeKubeClient,
				ctrlClient: fakeCtrlClient,
				log:        velerotest.NewLogger(),
			}

			volID, err := exposer.getVolumeID(t.Context(), test.snapshot, test.targetPVName)
			if test.expectedErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.expectedErr)
				assert.Empty(t, volID)
			} else {
				require.NoError(t, err)
				assert.Equal(t, test.expectedID, volID)
			}
		})
	}
}

func TestRestoreExpose_CSISnapshot(t *testing.T) {
	scName := "fake-sc"
	restore := &velerov1.Restore{
		TypeMeta:   metav1.TypeMeta{APIVersion: velerov1.SchemeGroupVersion.String(), Kind: "Restore"},
		ObjectMeta: metav1.ObjectMeta{Namespace: velerov1.DefaultNamespace, Name: "fake-restore", UID: "fake-uid"},
	}
	ownerObject := corev1api.ObjectReference{
		Kind:       restore.Kind,
		Namespace:  restore.Namespace,
		Name:       restore.Name,
		UID:        restore.UID,
		APIVersion: restore.APIVersion,
	}
	targetPVCObj := &corev1api.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Namespace: "fake-ns", Name: "fake-target-pvc"},
		Spec:       corev1api.PersistentVolumeClaimSpec{StorageClassName: &scName},
	}
	storageClass := &storagev1api.StorageClass{ObjectMeta: metav1.ObjectMeta{Name: "fake-sc"}}
	daemonSet := &appsv1api.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "velero", Name: "node-agent"},
		TypeMeta:   metav1.TypeMeta{Kind: "DaemonSet", APIVersion: appsv1api.SchemeGroupVersion.String()},
		Spec: appsv1api.DaemonSetSpec{
			Template: corev1api.PodTemplateSpec{
				Spec: corev1api.PodSpec{Containers: []corev1api.Container{{Image: "fake-image"}}},
			},
		},
	}

	vscName := "fake-vsc"

	t.Run("getVolumeID fails - falls back to full restore and creates pod without volume ID", func(t *testing.T) {
		fakeKubeClient := fake.NewSimpleClientset(targetPVCObj, storageClass, daemonSet)
		fakeCtrlClient := velerotest.NewFakeControllerRuntimeClient(t)
		exposer := genericRestoreExposer{
			kubeClient: fakeKubeClient,
			ctrlClient: fakeCtrlClient,
			log:        velerotest.NewLogger(),
		}

		err := exposer.Expose(t.Context(), ownerObject, GenericRestoreExposeParam{
			TargetPVCName:    "fake-target-pvc",
			TargetNamespace:  "fake-ns",
			HostingPodLabels: map[string]string{},
			Resources:        corev1api.ResourceRequirements{},
			ExposeTimeout:    time.Millisecond,
			CSI: &GenericRestoreExposeCSI{
				Snapshot: &velerov2alpha1api.CSISnapshotSpec{
					VolumeSnapshot:          "non-existent-vs",
					VolumeSnapshotNamespace: "fake-ns",
				},
			},
		})
		require.NoError(t, err)

		pod, err := fakeKubeClient.CoreV1().Pods(ownerObject.Namespace).Get(t.Context(), ownerObject.Name, metav1.GetOptions{})
		require.NoError(t, err)
		require.Len(t, pod.Spec.Containers, 1)
		for _, arg := range pod.Spec.Containers[0].Args {
			assert.NotContains(t, arg, "--volume-id=")
			assert.NotContains(t, arg, "--vs-namespace=")
		}
	})

	t.Run("getVolumeID succeeds - passes volume ID to restore pod", func(t *testing.T) {
		fakeKubeClient := fake.NewSimpleClientset(targetPVCObj, storageClass, daemonSet)
		fakeCtrlClient := velerotest.NewFakeControllerRuntimeClient(t,
			&snapshotv1api.VolumeSnapshot{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "fake-ns",
					Name:      "fake-vs",
					Annotations: map[string]string{
						util.VSphereCNSChangeIDAnno: "c-1",
						util.VSphereCNSSnapshotAnno: "vol-123+snap-1",
					},
				},
				Status: &snapshotv1api.VolumeSnapshotStatus{
					BoundVolumeSnapshotContentName: &vscName,
				},
			},
			&snapshotv1api.VolumeSnapshotContent{
				ObjectMeta: metav1.ObjectMeta{
					Name: vscName,
				},
			},
		)
		exposer := genericRestoreExposer{
			kubeClient: fakeKubeClient,
			ctrlClient: fakeCtrlClient,
			log:        velerotest.NewLogger(),
		}

		err := exposer.Expose(t.Context(), ownerObject, GenericRestoreExposeParam{
			TargetPVCName:    "fake-target-pvc",
			TargetNamespace:  "fake-ns",
			HostingPodLabels: map[string]string{},
			Resources:        corev1api.ResourceRequirements{},
			ExposeTimeout:    time.Millisecond,
			CSI: &GenericRestoreExposeCSI{
				Snapshot: &velerov2alpha1api.CSISnapshotSpec{
					VolumeSnapshot:          "fake-vs",
					VolumeSnapshotNamespace: "fake-ns",
				},
			},
		})
		require.NoError(t, err)

		pod, err := fakeKubeClient.CoreV1().Pods(ownerObject.Namespace).Get(t.Context(), ownerObject.Name, metav1.GetOptions{})
		require.NoError(t, err)
		require.Len(t, pod.Spec.Containers, 1)
		assert.Contains(t, pod.Spec.Containers[0].Args, "--volume-id=vol-123")
		assert.Contains(t, pod.Spec.Containers[0].Args, "--vs-namespace=fake-ns")
	})
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
		Status: corev1api.PersistentVolumeClaimStatus{
			Phase: corev1api.ClaimBound,
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
node-agent is not running in node fake-node, err: daemonset pod not found in running state in node fake-node
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

func TestValidateSelectedNode(t *testing.T) {
	tests := []struct {
		name          string
		node          string
		dataMover     string
		kubeClientObj []runtime.Object
		expected      bool
	}{
		{
			name:     "empty node",
			node:     "",
			expected: true,
		},
		{
			name: "node os is linux",
			node: "fake-node",
			kubeClientObj: []runtime.Object{
				&corev1api.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: "fake-node",
						Labels: map[string]string{
							corev1api.LabelOSStable: kube.NodeOSLinux,
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "node os is windows",
			node: "fake-node",
			kubeClientObj: []runtime.Object{
				&corev1api.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: "fake-node",
						Labels: map[string]string{
							corev1api.LabelOSStable: kube.NodeOSWindows,
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "node without os label",
			node: "fake-node",
			kubeClientObj: []runtime.Object{
				&corev1api.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: "fake-node",
					},
				},
			},
			expected: false,
		},
		{
			name:     "node not found",
			node:     "fake-node",
			expected: false,
		},
		{
			name:      "block data mover with linux node",
			node:      "fake-node",
			dataMover: datamover.DataMoverTypeVeleroBlock,
			kubeClientObj: []runtime.Object{
				&corev1api.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: "fake-node",
						Labels: map[string]string{
							corev1api.LabelOSStable: kube.NodeOSLinux,
						},
					},
				},
			},
			expected: true,
		},
		{
			name:      "block data mover with windows node",
			node:      "fake-node",
			dataMover: datamover.DataMoverTypeVeleroBlock,
			kubeClientObj: []runtime.Object{
				&corev1api.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: "fake-node",
						Labels: map[string]string{
							corev1api.LabelOSStable: kube.NodeOSWindows,
						},
					},
				},
			},
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakeKubeClient := fake.NewSimpleClientset(test.kubeClientObj...)

			exposer := genericRestoreExposer{
				kubeClient: fakeKubeClient,
				log:        velerotest.NewLogger(),
			}

			actual := exposer.validateSelectedNode(t.Context(), test.node, test.dataMover, exposer.log)
			assert.Equal(t, test.expected, actual)
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
		name                 string
		kubeClientObj        []runtime.Object
		selectedNode         string
		affinity             *kube.LoadAffinity
		nodeOS               string
		expectedPod          *corev1api.Pod
		expectedNodeSelector map[string]string
	}{
		{
			name:          "linux",
			kubeClientObj: []runtime.Object{daemonSet, daemonSetWin, targetPVCObj},
			selectedNode:  "",
			affinity: &kube.LoadAffinity{
				NodeSelector: metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{
						{
							Key:      corev1api.LabelOSStable,
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
							Key:      corev1api.LabelOSStable,
							Operator: metav1.LabelSelectorOpIn,
							Values:   []string{"windows"},
						},
					},
				},
				StorageClass: scName,
			},
			nodeOS: "windows",
		},
		{
			// A selected node is pinned through the node selector, and the
			// affinity from the node-agent config is ignored.
			name:          "selected node",
			kubeClientObj: []runtime.Object{daemonSet, daemonSetWin, targetPVCObj},
			selectedNode:  "fake-selected-node",
			affinity: &kube.LoadAffinity{
				NodeSelector: metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{
						{
							Key:      corev1api.LabelOSStable,
							Operator: metav1.LabelSelectorOpIn,
							Values:   []string{"linux"},
						},
					},
				},
				StorageClass: scName,
			},
			nodeOS: "linux",
			expectedNodeSelector: map[string]string{
				corev1api.LabelHostname: "fake-selected-node",
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
				"", // volumeSnapshotNamespace
				"", // volumeID
				nil,
				nil, // volumeTopology
			)

			require.NoError(t, err)
			if test.expectedPod != nil {
				assert.Equal(t, test.expectedPod, pod)
			}
			if test.expectedNodeSelector != nil {
				assert.Equal(t, test.expectedNodeSelector, pod.Spec.NodeSelector)
			}
		})
	}
}

func TestGenericRestoreCleanUp(t *testing.T) {
	ownerObject := corev1api.ObjectReference{
		Kind:       "Restore",
		Namespace:  "velero",
		Name:       "restore-item",
		UID:        "owner-uid",
		APIVersion: "velero.io/v1",
	}

	tests := []struct {
		name                 string
		param                *GenericRestoreCleanUpParam
		ctrlClientObjects    []crclient.Object
		expectSnapshotExists bool
	}{
		{
			name: "param has nil snapshot: pod, pvcs, pvs, secrets, cms cleaned up",
			param: &GenericRestoreCleanUpParam{
				Snapshot: nil,
			},
		},
		{
			name: "param snapshot with CleanUp false: snapshot is not deleted",
			param: &GenericRestoreCleanUpParam{
				Snapshot: &velerov2alpha1api.CSISnapshotSpec{
					VolumeSnapshot:          "test-vs",
					VolumeSnapshotNamespace: "velero",
					CleanUp:                 false,
				},
			},
			ctrlClientObjects: []crclient.Object{
				&snapshotv1api.VolumeSnapshot{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-vs",
						Namespace: "velero",
					},
				},
			},
			expectSnapshotExists: true,
		},
		{
			name: "param snapshot with CleanUp true: snapshot is deleted",
			param: &GenericRestoreCleanUpParam{
				Snapshot: &velerov2alpha1api.CSISnapshotSpec{
					VolumeSnapshot:          "test-vs",
					VolumeSnapshotNamespace: "velero",
					CleanUp:                 true,
				},
			},
			ctrlClientObjects: []crclient.Object{
				&snapshotv1api.VolumeSnapshot{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-vs",
						Namespace: "velero",
					},
				},
			},
			expectSnapshotExists: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			restorePod := &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "restore-item",
					Namespace: "velero",
				},
			}
			restorePVC := &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "restore-item",
					Namespace: "velero",
				},
				Spec: corev1api.PersistentVolumeClaimSpec{
					VolumeName: "pv-restore",
				},
			}
			restorePV := &corev1api.PersistentVolume{
				ObjectMeta: metav1.ObjectMeta{
					Name: "pv-restore",
				},
			}
			cachePVC := &corev1api.PersistentVolumeClaim{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "restore-item-cache",
					Namespace: "velero",
				},
				Spec: corev1api.PersistentVolumeClaimSpec{
					VolumeName: "pv-cache",
				},
			}
			cachePV := &corev1api.PersistentVolume{
				ObjectMeta: metav1.ObjectMeta{
					Name: "pv-cache",
				},
			}
			secret := &corev1api.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "owned-secret",
					Namespace: "velero",
					Labels:    map[string]string{BackupPVCSecretLabel: string(ownerObject.UID)},
				},
			}
			cm := &corev1api.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "owned-cm",
					Namespace: "velero",
					Labels:    map[string]string{BackupPVCSecretLabel: string(ownerObject.UID)},
				},
			}
			unrelatedSecret := &corev1api.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "other-secret",
					Namespace: "velero",
					Labels:    map[string]string{BackupPVCSecretLabel: "other-uid"},
				},
			}
			unrelatedCM := &corev1api.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "other-cm",
					Namespace: "velero",
					Labels:    map[string]string{BackupPVCSecretLabel: "other-uid"},
				},
			}

			fakeKubeClient := fake.NewSimpleClientset(
				restorePod, restorePVC, restorePV, cachePVC, cachePV,
				secret, cm, unrelatedSecret, unrelatedCM,
			)

			runtimeObjs := make([]runtime.Object, len(tc.ctrlClientObjects))
			for i, obj := range tc.ctrlClientObjects {
				runtimeObjs[i] = obj
			}
			fakeCtrlClient := velerotest.NewFakeControllerRuntimeClient(t, runtimeObjs...)

			e := &genericRestoreExposer{
				kubeClient: fakeKubeClient,
				ctrlClient: fakeCtrlClient,
				log:        velerotest.NewLogger(),
			}

			e.CleanUp(t.Context(), ownerObject, tc.param)

			// Verify restore pod is deleted
			_, err := fakeKubeClient.CoreV1().Pods("velero").Get(t.Context(), "restore-item", metav1.GetOptions{})
			require.True(t, apierrors.IsNotFound(err), "restore pod should be deleted")

			// Verify restore PVC is deleted and PV reclaim policy is set to Delete
			_, err = fakeKubeClient.CoreV1().PersistentVolumeClaims("velero").Get(t.Context(), "restore-item", metav1.GetOptions{})
			require.True(t, apierrors.IsNotFound(err), "restore PVC should be deleted")
			retrievedPV, err := fakeKubeClient.CoreV1().PersistentVolumes().Get(t.Context(), "pv-restore", metav1.GetOptions{})
			require.NoError(t, err)
			assert.Equal(t, corev1api.PersistentVolumeReclaimDelete, retrievedPV.Spec.PersistentVolumeReclaimPolicy)

			// Verify cache PVC is deleted and cache PV reclaim policy is set to Delete
			_, err = fakeKubeClient.CoreV1().PersistentVolumeClaims("velero").Get(t.Context(), "restore-item-cache", metav1.GetOptions{})
			require.True(t, apierrors.IsNotFound(err), "cache PVC should be deleted")
			retrievedCachePV, err := fakeKubeClient.CoreV1().PersistentVolumes().Get(t.Context(), "pv-cache", metav1.GetOptions{})
			require.NoError(t, err)
			assert.Equal(t, corev1api.PersistentVolumeReclaimDelete, retrievedCachePV.Spec.PersistentVolumeReclaimPolicy)

			// Verify owned secrets and configmaps are deleted
			_, err = fakeKubeClient.CoreV1().Secrets("velero").Get(t.Context(), "owned-secret", metav1.GetOptions{})
			require.True(t, apierrors.IsNotFound(err), "owned secret should be deleted")
			_, err = fakeKubeClient.CoreV1().ConfigMaps("velero").Get(t.Context(), "owned-cm", metav1.GetOptions{})
			require.True(t, apierrors.IsNotFound(err), "owned configmap should be deleted")

			// Verify unrelated secrets and configmaps are preserved
			_, err = fakeKubeClient.CoreV1().Secrets("velero").Get(t.Context(), "other-secret", metav1.GetOptions{})
			require.NoError(t, err, "unrelated secret should not be deleted")
			_, err = fakeKubeClient.CoreV1().ConfigMaps("velero").Get(t.Context(), "other-cm", metav1.GetOptions{})
			require.NoError(t, err, "unrelated configmap should not be deleted")

			// Verify VolumeSnapshot state if applicable
			if tc.param.Snapshot != nil {
				vs := &snapshotv1api.VolumeSnapshot{}
				err = fakeCtrlClient.Get(t.Context(), crclient.ObjectKey{
					Namespace: tc.param.Snapshot.VolumeSnapshotNamespace,
					Name:      tc.param.Snapshot.VolumeSnapshot,
				}, vs)
				if tc.expectSnapshotExists {
					require.NoError(t, err, "VolumeSnapshot should still exist")
				} else {
					require.True(t, apierrors.IsNotFound(err), "VolumeSnapshot should be deleted")
				}
			}
		})
	}
}
