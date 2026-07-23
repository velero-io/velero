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
	"context"
	"fmt"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	snapshotFake "github.com/kubernetes-csi/external-snapshotter/client/v8/clientset/versioned/fake"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1api "k8s.io/api/apps/v1"
	corev1api "k8s.io/api/core/v1"
	storagev1api "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"
	clientTesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"
	clientFake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	velerov1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
	velerotypes "github.com/vmware-tanzu/velero/pkg/types"
	"github.com/vmware-tanzu/velero/pkg/util"
	"github.com/vmware-tanzu/velero/pkg/util/boolptr"
	"github.com/vmware-tanzu/velero/pkg/util/datamover"
	"github.com/vmware-tanzu/velero/pkg/util/kube"
)

type reactor struct {
	verb        string
	resource    string
	reactorFunc clientTesting.ReactionFunc
}

func TestExpose(t *testing.T) {
	vscName := "fake-vsc"
	backup := &velerov1.Backup{
		TypeMeta: metav1.TypeMeta{
			APIVersion: velerov1.SchemeGroupVersion.String(),
			Kind:       "Backup",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: velerov1.DefaultNamespace,
			Name:      "fake-backup",
			UID:       "fake-uid",
		},
	}

	var restoreSize int64 = 123456

	scObj := &storagev1api.StorageClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "fake-sc",
		},
	}

	snapshotClass := "fake-snapshot-class"
	vsObject := &snapshotv1api.VolumeSnapshot{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "fake-vs",
			Namespace: "fake-ns",
			Annotations: map[string]string{
				"fake-key-1": "fake-value-1",
				"fake-key-2": "fake-value-2",
			},
		},
		Spec: snapshotv1api.VolumeSnapshotSpec{
			Source: snapshotv1api.VolumeSnapshotSource{
				VolumeSnapshotContentName: &vscName,
			},
			VolumeSnapshotClassName: &snapshotClass,
		},
		Status: &snapshotv1api.VolumeSnapshotStatus{
			BoundVolumeSnapshotContentName: &vscName,
			ReadyToUse:                     boolptr.True(),
			RestoreSize:                    resource.NewQuantity(restoreSize, ""),
		},
	}

	vsObjectWithoutRestoreSize := &snapshotv1api.VolumeSnapshot{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "fake-vs",
			Namespace: "fake-ns",
			Annotations: map[string]string{
				"fake-key-1": "fake-value-1",
				"fake-key-2": "fake-value-2",
			},
		},
		Spec: snapshotv1api.VolumeSnapshotSpec{
			Source: snapshotv1api.VolumeSnapshotSource{
				VolumeSnapshotContentName: &vscName,
			},
			VolumeSnapshotClassName: &snapshotClass,
		},
		Status: &snapshotv1api.VolumeSnapshotStatus{
			BoundVolumeSnapshotContentName: &vscName,
			ReadyToUse:                     boolptr.True(),
		},
	}

	snapshotHandle := "fake-handle"
	vscObj := &snapshotv1api.VolumeSnapshotContent{
		ObjectMeta: metav1.ObjectMeta{
			Name: vscName,
			Annotations: map[string]string{
				"fake-key-3": "fake-value-3",
				"fake-key-4": "fake-value-4",
			},
		},
		Spec: snapshotv1api.VolumeSnapshotContentSpec{
			DeletionPolicy:          snapshotv1api.VolumeSnapshotContentDelete,
			Driver:                  "fake-driver",
			VolumeSnapshotClassName: &snapshotClass,
		},
		Status: &snapshotv1api.VolumeSnapshotContentStatus{
			RestoreSize:    &restoreSize,
			SnapshotHandle: &snapshotHandle,
		},
	}

	vscObjWithLabels := vscObj
	vscObjWithLabels.Labels = map[string]string{
		"snapshot.storage.kubernetes.io/managed-by": "worker",
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
							Name: "node-agent",
						},
					},
				},
			},
		},
	}

	pvName := "pv-1"
	volumeAttachement1 := &storagev1api.VolumeAttachment{
		ObjectMeta: metav1.ObjectMeta{
			Name: "va1",
		},
		Spec: storagev1api.VolumeAttachmentSpec{
			Source: storagev1api.VolumeAttachmentSource{
				PersistentVolumeName: &pvName,
			},
			NodeName: "node-1",
		},
	}

	volumeAttachement2 := &storagev1api.VolumeAttachment{
		ObjectMeta: metav1.ObjectMeta{
			Name: "va2",
		},
		Spec: storagev1api.VolumeAttachmentSpec{
			Source: storagev1api.VolumeAttachmentSource{
				PersistentVolumeName: &pvName,
			},
			NodeName: "node-2",
		},
	}

	sourcePV := &corev1api.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name: "fake-pv",
		},
		Spec: corev1api.PersistentVolumeSpec{
			PersistentVolumeSource: corev1api.PersistentVolumeSource{
				CSI: &corev1api.CSIPersistentVolumeSource{
					VolumeHandle: "csi-volume-handle",
				},
			},
		},
	}

	tests := []struct {
		name                          string
		snapshotClientObj             []runtime.Object
		kubeClientObj                 []runtime.Object
		ownerBackup                   *velerov1.Backup
		exposeParam                   CSISnapshotExposeParam
		snapReactors                  []reactor
		kubeReactors                  []reactor
		err                           string
		expectedVolumeSize            *resource.Quantity
		expectedReadOnlyPVC           bool
		expectedBackupPVCStorageClass string
		expectedAffinity              *corev1api.Affinity
		expectedPVCAnnotation         map[string]string
	}{
		{
			name:        "get volume topology fail",
			ownerBackup: backup,
			exposeParam: CSISnapshotExposeParam{
				SnapshotName:     "fake-vs",
				OperationTimeout: time.Millisecond,
				ExposeTimeout:    time.Millisecond,
				StorageClass:     "fake-sc",
				SourcePVName:     "fake-pv",
			},
			err: "error getting volume topology for PV fake-pv, storage class fake-sc: error getting storage class fake-sc: storageclasses.storage.k8s.io \"fake-sc\" not found",
		},
		{
			name:        "wait vs ready fail",
			ownerBackup: backup,
			exposeParam: CSISnapshotExposeParam{
				SnapshotName:     "fake-vs",
				OperationTimeout: time.Millisecond,
				ExposeTimeout:    time.Millisecond,
				StorageClass:     "fake-sc",
				SourcePVName:     "fake-pv",
			},
			kubeClientObj: []runtime.Object{
				scObj,
			},
			err: "error wait volume snapshot ready: error to get VolumeSnapshot /fake-vs: volumesnapshots.snapshot.storage.k8s.io \"fake-vs\" not found",
		},
		{
			name:        "get vsc fail",
			ownerBackup: backup,
			exposeParam: CSISnapshotExposeParam{
				SnapshotName:     "fake-vs",
				SourceNamespace:  "fake-ns",
				OperationTimeout: time.Millisecond,
				ExposeTimeout:    time.Millisecond,
				StorageClass:     "fake-sc",
				SourcePVName:     "fake-pv",
			},
			snapshotClientObj: []runtime.Object{
				vsObject,
			},
			kubeClientObj: []runtime.Object{
				scObj,
			},
			err: "error to get volume snapshot content: error getting volume snapshot content from API: volumesnapshotcontents.snapshot.storage.k8s.io \"fake-vsc\" not found",
		},
		{
			name:        "delete vs fail",
			ownerBackup: backup,
			exposeParam: CSISnapshotExposeParam{
				SnapshotName:     "fake-vs",
				SourceNamespace:  "fake-ns",
				OperationTimeout: time.Millisecond,
				ExposeTimeout:    time.Millisecond,
				StorageClass:     "fake-sc",
				SourcePVName:     "fake-pv",
			},
			snapshotClientObj: []runtime.Object{
				vsObject,
				vscObj,
			},
			snapReactors: []reactor{
				{
					verb:     "delete",
					resource: "volumesnapshots",
					reactorFunc: func(action clientTesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, errors.New("fake-delete-error")
					},
				},
			},
			kubeClientObj: []runtime.Object{
				scObj,
			},
			err: "error to delete volume snapshot: error to delete volume snapshot: fake-delete-error",
		},
		{
			name:        "delete vsc fail",
			ownerBackup: backup,
			exposeParam: CSISnapshotExposeParam{
				SnapshotName:     "fake-vs",
				SourceNamespace:  "fake-ns",
				OperationTimeout: time.Millisecond,
				ExposeTimeout:    time.Millisecond,
				StorageClass:     "fake-sc",
				SourcePVName:     "fake-pv",
			},
			snapshotClientObj: []runtime.Object{
				vsObject,
				vscObj,
			},
			snapReactors: []reactor{
				{
					verb:     "delete",
					resource: "volumesnapshotcontents",
					reactorFunc: func(action clientTesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, errors.New("fake-delete-error")
					},
				},
			},
			kubeClientObj: []runtime.Object{
				scObj,
			},
			err: "error to delete volume snapshot content: error to delete volume snapshot content: fake-delete-error",
		},
		{
			name:        "create backup vs fail",
			ownerBackup: backup,
			exposeParam: CSISnapshotExposeParam{
				SnapshotName:     "fake-vs",
				SourceNamespace:  "fake-ns",
				OperationTimeout: time.Millisecond,
				ExposeTimeout:    time.Millisecond,
				StorageClass:     "fake-sc",
				SourcePVName:     "fake-pv",
			},
			snapshotClientObj: []runtime.Object{
				vsObject,
				vscObj,
			},
			snapReactors: []reactor{
				{
					verb:     "create",
					resource: "volumesnapshots",
					reactorFunc: func(action clientTesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, errors.New("fake-create-error")
					},
				},
			},
			kubeClientObj: []runtime.Object{
				scObj,
			},
			err: "error to create backup volume snapshot: fake-create-error",
		},
		{
			name:        "create backup vsc fail",
			ownerBackup: backup,
			exposeParam: CSISnapshotExposeParam{
				SnapshotName:     "fake-vs",
				SourceNamespace:  "fake-ns",
				OperationTimeout: time.Millisecond,
				ExposeTimeout:    time.Millisecond,
				StorageClass:     "fake-sc",
				SourcePVName:     "fake-pv",
			},
			snapshotClientObj: []runtime.Object{
				vsObject,
				vscObj,
			},
			snapReactors: []reactor{
				{
					verb:     "create",
					resource: "volumesnapshotcontents",
					reactorFunc: func(action clientTesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, errors.New("fake-create-error")
					},
				},
			},
			kubeClientObj: []runtime.Object{
				scObj,
			},
			err: "error to create backup volume snapshot content: fake-create-error",
		},
		{
			name:        "create backup pvc fail, invalid access mode",
			ownerBackup: backup,
			exposeParam: CSISnapshotExposeParam{
				SnapshotName:    "fake-vs",
				SourceNamespace: "fake-ns",
				AccessMode:      "fake-mode",
				StorageClass:    "fake-sc",
				SourcePVName:    "fake-pv",
			},
			snapshotClientObj: []runtime.Object{
				vsObject,
				vscObj,
			},
			kubeClientObj: []runtime.Object{
				scObj,
			},
			err: "error to create backup pvc: unsupported access mode fake-mode",
		},
		{
			name:        "create backup pvc fail",
			ownerBackup: backup,
			exposeParam: CSISnapshotExposeParam{
				SnapshotName:     "fake-vs",
				SourceNamespace:  "fake-ns",
				OperationTimeout: time.Millisecond,
				ExposeTimeout:    time.Millisecond,
				AccessMode:       AccessModeFileSystem,
				StorageClass:     "fake-sc",
				SourcePVName:     "fake-pv",
			},
			snapshotClientObj: []runtime.Object{
				vsObject,
				vscObj,
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
			kubeClientObj: []runtime.Object{
				scObj,
			},
			err: "error to create backup pvc: error to create pvc: fake-create-error",
		},
		{
			name:        "create backup pod fail",
			ownerBackup: backup,
			exposeParam: CSISnapshotExposeParam{
				SnapshotName:     "fake-vs",
				SourceNamespace:  "fake-ns",
				AccessMode:       AccessModeFileSystem,
				OperationTimeout: time.Millisecond,
				ExposeTimeout:    time.Millisecond,
				StorageClass:     "fake-sc",
				SourcePVName:     "fake-pv",
			},
			snapshotClientObj: []runtime.Object{
				vsObject,
				vscObj,
			},
			kubeClientObj: []runtime.Object{
				daemonSet,
				scObj,
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
			err: "error to create backup pod: fake-create-error",
		},
		{
			name:        "success",
			ownerBackup: backup,
			exposeParam: CSISnapshotExposeParam{
				SnapshotName:     "fake-vs",
				SourceNamespace:  "fake-ns",
				AccessMode:       AccessModeFileSystem,
				OperationTimeout: time.Millisecond,
				ExposeTimeout:    time.Millisecond,
				StorageClass:     "fake-sc",
				SourcePVName:     "fake-pv",
			},
			snapshotClientObj: []runtime.Object{
				vsObject,
				vscObj,
			},
			kubeClientObj: []runtime.Object{
				daemonSet,
				scObj,
			},
			expectedAffinity: &corev1api.Affinity{
				NodeAffinity: &corev1api.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &corev1api.NodeSelector{
						NodeSelectorTerms: []corev1api.NodeSelectorTerm{
							{
								MatchExpressions: []corev1api.NodeSelectorRequirement{
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
		},
		{
			name:        "success-with-labels",
			ownerBackup: backup,
			exposeParam: CSISnapshotExposeParam{
				SnapshotName:     "fake-vs",
				SourceNamespace:  "fake-ns",
				AccessMode:       AccessModeFileSystem,
				OperationTimeout: time.Millisecond,
				ExposeTimeout:    time.Millisecond,
				StorageClass:     "fake-sc",
				SourcePVName:     "fake-pv",
			},
			snapshotClientObj: []runtime.Object{
				vsObject,
				vscObjWithLabels,
			},
			kubeClientObj: []runtime.Object{
				daemonSet,
				scObj,
			},
			expectedAffinity: &corev1api.Affinity{
				NodeAffinity: &corev1api.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &corev1api.NodeSelector{
						NodeSelectorTerms: []corev1api.NodeSelectorTerm{
							{
								MatchExpressions: []corev1api.NodeSelectorRequirement{
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
		},
		{
			name:        "restore size from exposeParam",
			ownerBackup: backup,
			exposeParam: CSISnapshotExposeParam{
				SnapshotName:     "fake-vs",
				SourceNamespace:  "fake-ns",
				AccessMode:       AccessModeFileSystem,
				OperationTimeout: time.Millisecond,
				ExposeTimeout:    time.Millisecond,
				VolumeSize:       *resource.NewQuantity(567890, ""),
				StorageClass:     "fake-sc",
				SourcePVName:     "fake-pv",
			},
			snapshotClientObj: []runtime.Object{
				vsObjectWithoutRestoreSize,
				vscObj,
			},
			kubeClientObj: []runtime.Object{
				daemonSet,
				scObj,
			},
			expectedVolumeSize: resource.NewQuantity(567890, ""),
			expectedAffinity: &corev1api.Affinity{
				NodeAffinity: &corev1api.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &corev1api.NodeSelector{
						NodeSelectorTerms: []corev1api.NodeSelectorTerm{
							{
								MatchExpressions: []corev1api.NodeSelectorRequirement{
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
		},
		{
			name:        "backupPod mounts read only backupPVC",
			ownerBackup: backup,
			exposeParam: CSISnapshotExposeParam{
				SnapshotName:     "fake-vs",
				SourceNamespace:  "fake-ns",
				StorageClass:     "fake-sc",
				SourcePVName:     "fake-pv",
				AccessMode:       AccessModeFileSystem,
				OperationTimeout: time.Millisecond,
				ExposeTimeout:    time.Millisecond,
				BackupPVCConfig: map[string]velerotypes.BackupPVC{
					"fake-sc": {
						StorageClass: "fake-sc-read-only",
						ReadOnly:     true,
					},
				},
			},
			snapshotClientObj: []runtime.Object{
				vsObject,
				vscObj,
			},
			kubeClientObj: []runtime.Object{
				daemonSet,
				scObj,
			},
			expectedReadOnlyPVC: true,
			expectedAffinity: &corev1api.Affinity{
				NodeAffinity: &corev1api.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &corev1api.NodeSelector{
						NodeSelectorTerms: []corev1api.NodeSelectorTerm{
							{
								MatchExpressions: []corev1api.NodeSelectorRequirement{
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
		},
		{
			name:        "backupPod mounts read only backupPVC and storageClass specified in backupPVC config",
			ownerBackup: backup,
			exposeParam: CSISnapshotExposeParam{
				SnapshotName:     "fake-vs",
				SourceNamespace:  "fake-ns",
				StorageClass:     "fake-sc",
				SourcePVName:     "fake-pv",
				AccessMode:       AccessModeFileSystem,
				OperationTimeout: time.Millisecond,
				ExposeTimeout:    time.Millisecond,
				BackupPVCConfig: map[string]velerotypes.BackupPVC{
					"fake-sc": {
						StorageClass: "fake-sc-read-only",
						ReadOnly:     true,
					},
				},
			},
			snapshotClientObj: []runtime.Object{
				vsObject,
				vscObj,
			},
			kubeClientObj: []runtime.Object{
				daemonSet,
				scObj,
			},
			expectedReadOnlyPVC:           true,
			expectedBackupPVCStorageClass: "fake-sc-read-only",
			expectedAffinity: &corev1api.Affinity{
				NodeAffinity: &corev1api.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &corev1api.NodeSelector{
						NodeSelectorTerms: []corev1api.NodeSelectorTerm{
							{
								MatchExpressions: []corev1api.NodeSelectorRequirement{
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
		},
		{
			name:        "backupPod mounts backupPVC with storageClass specified in backupPVC config",
			ownerBackup: backup,
			exposeParam: CSISnapshotExposeParam{
				SnapshotName:     "fake-vs",
				SourceNamespace:  "fake-ns",
				StorageClass:     "fake-sc",
				SourcePVName:     "fake-pv",
				AccessMode:       AccessModeFileSystem,
				OperationTimeout: time.Millisecond,
				ExposeTimeout:    time.Millisecond,
				BackupPVCConfig: map[string]velerotypes.BackupPVC{
					"fake-sc": {
						StorageClass: "fake-sc-read-only",
					},
				},
			},
			snapshotClientObj: []runtime.Object{
				vsObject,
				vscObj,
			},
			kubeClientObj: []runtime.Object{
				daemonSet,
				scObj,
			},
			expectedBackupPVCStorageClass: "fake-sc-read-only",
			expectedAffinity: &corev1api.Affinity{
				NodeAffinity: &corev1api.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &corev1api.NodeSelector{
						NodeSelectorTerms: []corev1api.NodeSelectorTerm{
							{
								MatchExpressions: []corev1api.NodeSelectorRequirement{
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
		},
		{
			name:        "Affinity per StorageClass",
			ownerBackup: backup,
			exposeParam: CSISnapshotExposeParam{
				SnapshotName:     "fake-vs",
				SourceNamespace:  "fake-ns",
				StorageClass:     "fake-sc",
				SourcePVName:     "fake-pv",
				AccessMode:       AccessModeFileSystem,
				OperationTimeout: time.Millisecond,
				ExposeTimeout:    time.Millisecond,
				Affinity: []*kube.LoadAffinity{
					{
						NodeSelector: metav1.LabelSelector{
							MatchExpressions: []metav1.LabelSelectorRequirement{
								{
									Key:      "kubernetes.io/os",
									Operator: metav1.LabelSelectorOpIn,
									Values:   []string{"Linux"},
								},
							},
						},
						StorageClass: "fake-sc",
					},
				},
			},
			snapshotClientObj: []runtime.Object{
				vsObject,
				vscObj,
			},
			kubeClientObj: []runtime.Object{
				daemonSet,
				scObj,
			},
			expectedAffinity: &corev1api.Affinity{
				NodeAffinity: &corev1api.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &corev1api.NodeSelector{
						NodeSelectorTerms: []corev1api.NodeSelectorTerm{
							{
								MatchExpressions: []corev1api.NodeSelectorRequirement{
									{
										Key:      "kubernetes.io/os",
										Operator: corev1api.NodeSelectorOpIn,
										Values:   []string{"Linux"},
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
		},
		{
			name:        "Affinity per StorageClass with expectedBackupPVCStorageClass",
			ownerBackup: backup,
			exposeParam: CSISnapshotExposeParam{
				SnapshotName:     "fake-vs",
				SourceNamespace:  "fake-ns",
				StorageClass:     "fake-sc",
				SourcePVName:     "fake-pv",
				AccessMode:       AccessModeFileSystem,
				OperationTimeout: time.Millisecond,
				ExposeTimeout:    time.Millisecond,
				BackupPVCConfig: map[string]velerotypes.BackupPVC{
					"fake-sc": {
						StorageClass: "fake-sc-read-only",
					},
				},
				Affinity: []*kube.LoadAffinity{
					{
						NodeSelector: metav1.LabelSelector{
							MatchExpressions: []metav1.LabelSelectorRequirement{
								{
									Key:      "kubernetes.io/arch",
									Operator: metav1.LabelSelectorOpIn,
									Values:   []string{"amd64"},
								},
							},
						},
						StorageClass: "fake-sc-read-only",
					},
				},
			},
			snapshotClientObj: []runtime.Object{
				vsObject,
				vscObj,
			},
			kubeClientObj: []runtime.Object{
				daemonSet,
				scObj,
			},
			expectedBackupPVCStorageClass: "fake-sc-read-only",
			expectedAffinity: &corev1api.Affinity{
				NodeAffinity: &corev1api.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &corev1api.NodeSelector{
						NodeSelectorTerms: []corev1api.NodeSelectorTerm{
							{
								MatchExpressions: []corev1api.NodeSelectorRequirement{
									{
										Key:      "kubernetes.io/arch",
										Operator: corev1api.NodeSelectorOpIn,
										Values:   []string{"amd64"},
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
		},
		{
			name:        "Affinity in exposeParam is nil",
			ownerBackup: backup,
			exposeParam: CSISnapshotExposeParam{
				SnapshotName:     "fake-vs",
				SourceNamespace:  "fake-ns",
				StorageClass:     "fake-sc",
				SourcePVName:     "fake-pv",
				AccessMode:       AccessModeFileSystem,
				OperationTimeout: time.Millisecond,
				ExposeTimeout:    time.Millisecond,
				BackupPVCConfig: map[string]velerotypes.BackupPVC{
					"fake-sc": {
						StorageClass: "fake-sc-read-only",
					},
				},
				Affinity: nil,
			},
			snapshotClientObj: []runtime.Object{
				vsObject,
				vscObj,
			},
			kubeClientObj: []runtime.Object{
				daemonSet,
				scObj,
			},
			expectedBackupPVCStorageClass: "fake-sc-read-only",
			expectedAffinity: &corev1api.Affinity{
				NodeAffinity: &corev1api.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &corev1api.NodeSelector{
						NodeSelectorTerms: []corev1api.NodeSelectorTerm{
							{
								MatchExpressions: []corev1api.NodeSelectorRequirement{
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
		},
		{
			name:        "IntolerateSourceNode, get source node fail",
			ownerBackup: backup,
			exposeParam: CSISnapshotExposeParam{
				SnapshotName:     "fake-vs",
				SourceNamespace:  "fake-ns",
				SourcePVName:     pvName,
				StorageClass:     "fake-sc",
				AccessMode:       AccessModeFileSystem,
				OperationTimeout: time.Millisecond,
				ExposeTimeout:    time.Millisecond,
				BackupPVCConfig: map[string]velerotypes.BackupPVC{
					"fake-sc": {
						Annotations: map[string]string{util.VSphereCNSFastCloneAnno: "true"},
					},
				},
				Affinity: nil,
			},
			snapshotClientObj: []runtime.Object{
				vsObject,
				vscObj,
			},
			kubeClientObj: []runtime.Object{
				daemonSet,
				scObj,
			},
			kubeReactors: []reactor{
				{
					verb:     "list",
					resource: "volumeattachments",
					reactorFunc: func(action clientTesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, errors.New("fake-create-error")
					},
				},
			},
			expectedAffinity: &corev1api.Affinity{
				NodeAffinity: &corev1api.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &corev1api.NodeSelector{
						NodeSelectorTerms: []corev1api.NodeSelectorTerm{
							{
								MatchExpressions: []corev1api.NodeSelectorRequirement{
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
			expectedPVCAnnotation: nil,
		},
		{
			name:        "IntolerateSourceNode, get empty source node",
			ownerBackup: backup,
			exposeParam: CSISnapshotExposeParam{
				SnapshotName:     "fake-vs",
				SourceNamespace:  "fake-ns",
				SourcePVName:     pvName,
				StorageClass:     "fake-sc",
				AccessMode:       AccessModeFileSystem,
				OperationTimeout: time.Millisecond,
				ExposeTimeout:    time.Millisecond,
				BackupPVCConfig: map[string]velerotypes.BackupPVC{
					"fake-sc": {
						Annotations: map[string]string{util.VSphereCNSFastCloneAnno: "true"},
					},
				},
				Affinity: nil,
			},
			snapshotClientObj: []runtime.Object{
				vsObject,
				vscObj,
			},
			kubeClientObj: []runtime.Object{
				daemonSet,
				scObj,
			},
			expectedAffinity: &corev1api.Affinity{
				NodeAffinity: &corev1api.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &corev1api.NodeSelector{
						NodeSelectorTerms: []corev1api.NodeSelectorTerm{
							{
								MatchExpressions: []corev1api.NodeSelectorRequirement{
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
			expectedPVCAnnotation: map[string]string{util.VSphereCNSFastCloneAnno: "true"},
		},
		{
			name:        "IntolerateSourceNode, get source nodes",
			ownerBackup: backup,
			exposeParam: CSISnapshotExposeParam{
				SnapshotName:     "fake-vs",
				SourceNamespace:  "fake-ns",
				SourcePVName:     pvName,
				StorageClass:     "fake-sc",
				AccessMode:       AccessModeFileSystem,
				OperationTimeout: time.Millisecond,
				ExposeTimeout:    time.Millisecond,
				BackupPVCConfig: map[string]velerotypes.BackupPVC{
					"fake-sc": {
						Annotations: map[string]string{util.VSphereCNSFastCloneAnno: "true"},
					},
				},
				Affinity: nil,
			},
			snapshotClientObj: []runtime.Object{
				vsObject,
				vscObj,
			},
			kubeClientObj: []runtime.Object{
				daemonSet,
				volumeAttachement1,
				volumeAttachement2,
				scObj,
			},
			expectedAffinity: &corev1api.Affinity{
				NodeAffinity: &corev1api.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &corev1api.NodeSelector{
						NodeSelectorTerms: []corev1api.NodeSelectorTerm{
							{
								MatchExpressions: []corev1api.NodeSelectorRequirement{
									{
										Key:      "kubernetes.io/os",
										Operator: corev1api.NodeSelectorOpNotIn,
										Values:   []string{"windows"},
									},
									{
										Key:      "kubernetes.io/hostname",
										Operator: corev1api.NodeSelectorOpNotIn,
										Values:   []string{"node-1", "node-2"},
									},
								},
							},
						},
					},
				},
			},
			expectedPVCAnnotation: map[string]string{util.VSphereCNSFastCloneAnno: "true"},
		},
		{
			name:        "block data mover success",
			ownerBackup: backup,
			exposeParam: CSISnapshotExposeParam{
				SnapshotName:     "fake-vs",
				SourceNamespace:  "fake-ns",
				AccessMode:       AccessModeFileSystem,
				OperationTimeout: time.Millisecond,
				ExposeTimeout:    time.Millisecond,
				StorageClass:     "fake-sc",
				SourcePVName:     "fake-pv",
				DataMover:        datamover.DataMoverTypeVeleroBlock,
			},
			snapshotClientObj: []runtime.Object{
				vsObject,
				vscObj,
			},
			kubeClientObj: []runtime.Object{
				daemonSet,
				scObj,
				sourcePV,
			},
			expectedAffinity: &corev1api.Affinity{
				NodeAffinity: &corev1api.NodeAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: &corev1api.NodeSelector{
						NodeSelectorTerms: []corev1api.NodeSelectorTerm{
							{
								MatchExpressions: []corev1api.NodeSelectorRequirement{
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
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakeSnapshotClient := snapshotFake.NewSimpleClientset(test.snapshotClientObj...)
			fakeKubeClient := fake.NewSimpleClientset(test.kubeClientObj...)

			for _, reactor := range test.snapReactors {
				fakeSnapshotClient.Fake.PrependReactor(reactor.verb, reactor.resource, reactor.reactorFunc)
			}

			for _, reactor := range test.kubeReactors {
				fakeKubeClient.Fake.PrependReactor(reactor.verb, reactor.resource, reactor.reactorFunc)
			}

			exposer := csiSnapshotExposer{
				kubeClient:        fakeKubeClient,
				csiSnapshotClient: fakeSnapshotClient.SnapshotV1(),
				log:               velerotest.NewLogger(),
			}

			var ownerObject corev1api.ObjectReference
			if test.ownerBackup != nil {
				ownerObject = corev1api.ObjectReference{
					Kind:       test.ownerBackup.Kind,
					Namespace:  test.ownerBackup.Namespace,
					Name:       test.ownerBackup.Name,
					UID:        test.ownerBackup.UID,
					APIVersion: test.ownerBackup.APIVersion,
				}
			}

			err := exposer.Expose(t.Context(), ownerObject, &test.exposeParam)
			if err == nil {
				require.NoError(t, err)

				backupPod, err := exposer.kubeClient.CoreV1().Pods(ownerObject.Namespace).Get(t.Context(), ownerObject.Name, metav1.GetOptions{})
				require.NoError(t, err)

				backupPVC, err := exposer.kubeClient.CoreV1().PersistentVolumeClaims(ownerObject.Namespace).Get(t.Context(), ownerObject.Name, metav1.GetOptions{})
				require.NoError(t, err)

				backupVS, err := exposer.csiSnapshotClient.VolumeSnapshots(ownerObject.Namespace).Get(t.Context(), ownerObject.Name, metav1.GetOptions{})
				require.NoError(t, err)

				backupVSC, err := exposer.csiSnapshotClient.VolumeSnapshotContents().Get(t.Context(), ownerObject.Name, metav1.GetOptions{})
				require.NoError(t, err)

				assert.Equal(t, vsObject.Annotations, backupVS.Annotations)
				assert.Equal(t, *vsObject.Spec.VolumeSnapshotClassName, *backupVS.Spec.VolumeSnapshotClassName)
				assert.Equal(t, *backupVS.Spec.Source.VolumeSnapshotContentName, backupVSC.Name)

				anno := make(map[string]string)
				maps.Copy(anno, vscObj.Annotations)
				anno[kube.KubeAnnAllowVolumeModeChange] = "true"

				assert.Equal(t, anno, backupVSC.Annotations)
				assert.Equal(t, vscObj.Labels, backupVSC.Labels)
				assert.Equal(t, vscObj.Spec.DeletionPolicy, backupVSC.Spec.DeletionPolicy)
				assert.Equal(t, vscObj.Spec.Driver, backupVSC.Spec.Driver)
				assert.Equal(t, *vscObj.Spec.VolumeSnapshotClassName, *backupVSC.Spec.VolumeSnapshotClassName)

				if test.expectedVolumeSize != nil {
					assert.Equal(t, *test.expectedVolumeSize, backupPVC.Spec.Resources.Requests[corev1api.ResourceStorage])
				} else {
					assert.Equal(t, *resource.NewQuantity(restoreSize, ""), backupPVC.Spec.Resources.Requests[corev1api.ResourceStorage])
				}

				if test.expectedReadOnlyPVC {
					gotReadOnlyAccessMode := false
					for _, accessMode := range backupPVC.Spec.AccessModes {
						if accessMode == corev1api.ReadOnlyMany {
							gotReadOnlyAccessMode = true
						}
					}
					assert.Equal(t, test.expectedReadOnlyPVC, gotReadOnlyAccessMode)
				}

				if test.expectedBackupPVCStorageClass != "" {
					assert.Equal(t, test.expectedBackupPVCStorageClass, *backupPVC.Spec.StorageClassName)
				}

				if test.expectedAffinity != nil {
					assert.Equal(t, test.expectedAffinity, backupPod.Spec.Affinity)
				} else {
					assert.Nil(t, backupPod.Spec.Affinity)
				}

				if test.expectedPVCAnnotation != nil {
					assert.Equal(t, test.expectedPVCAnnotation, backupPVC.Annotations)
				} else {
					assert.Empty(t, backupPVC.Annotations)
				}
			} else {
				assert.EqualError(t, err, test.err)
			}
		})
	}
}

func TestGetExpose(t *testing.T) {
	backup := &velerov1.Backup{
		TypeMeta: metav1.TypeMeta{
			APIVersion: velerov1.SchemeGroupVersion.String(),
			Kind:       "Backup",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: velerov1.DefaultNamespace,
			Name:      "fake-backup",
			UID:       "fake-uid",
		},
	}

	backupPod := &corev1api.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: backup.Namespace,
			Name:      backup.Name,
		},
		Spec: corev1api.PodSpec{
			Volumes: []corev1api.Volume{
				{
					Name: "fake-volume",
				},
				{
					Name: "fake-volume-2",
				},
				{
					Name: string(backup.UID),
				},
			},
		},
	}

	backupPodWithoutVolume := &corev1api.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: backup.Namespace,
			Name:      backup.Name,
		},
		Spec: corev1api.PodSpec{
			Volumes: []corev1api.Volume{
				{
					Name: "fake-volume-1",
				},
				{
					Name: "fake-volume-2",
				},
			},
		},
	}

	backupPVC := &corev1api.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: backup.Namespace,
			Name:      backup.Name,
		},
		Spec: corev1api.PersistentVolumeClaimSpec{
			VolumeName: "fake-pv-name",
		},
	}

	backupPV := &corev1api.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name: "fake-pv-name",
		},
	}

	scheme := runtime.NewScheme()
	corev1api.AddToScheme(scheme)

	tests := []struct {
		name            string
		kubeClientObj   []runtime.Object
		ownerBackup     *velerov1.Backup
		exposeWaitParam CSISnapshotExposeWaitParam
		Timeout         time.Duration
		err             string
		expectedResult  *ExposeResult
	}{
		{
			name:        "backup pod is not found",
			ownerBackup: backup,
			exposeWaitParam: CSISnapshotExposeWaitParam{
				NodeName: "fake-node",
			},
		},
		{
			name:        "wait pvc bound fail",
			ownerBackup: backup,
			exposeWaitParam: CSISnapshotExposeWaitParam{
				NodeName: "fake-node",
			},
			kubeClientObj: []runtime.Object{
				backupPod,
			},
			Timeout: time.Second,
			err:     "error to wait backup PVC bound, fake-backup: error to wait for rediness of PVC: error to get pvc velero/fake-backup: persistentvolumeclaims \"fake-backup\" not found",
		},
		{
			name:        "backup volume not found in pod",
			ownerBackup: backup,
			exposeWaitParam: CSISnapshotExposeWaitParam{
				NodeName: "fake-node",
			},
			kubeClientObj: []runtime.Object{
				backupPodWithoutVolume,
				backupPVC,
				backupPV,
			},
			Timeout: time.Second,
			err:     "backup pod fake-backup doesn't have the expected backup volume",
		},
		{
			name:        "succeed",
			ownerBackup: backup,
			exposeWaitParam: CSISnapshotExposeWaitParam{
				NodeName: "fake-node",
			},
			kubeClientObj: []runtime.Object{
				backupPod,
				backupPVC,
				backupPV,
			},
			Timeout: time.Second,
			expectedResult: &ExposeResult{
				ByPod: ExposeByPod{
					HostingPod: backupPod,
					VolumeName: string(backup.UID),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakeKubeClient := fake.NewSimpleClientset(test.kubeClientObj...)

			fakeClientBuilder := clientFake.NewClientBuilder()
			fakeClientBuilder = fakeClientBuilder.WithScheme(scheme)

			fakeClient := fakeClientBuilder.WithRuntimeObjects(test.kubeClientObj...).Build()

			exposer := csiSnapshotExposer{
				kubeClient: fakeKubeClient,
				log:        velerotest.NewLogger(),
			}

			var ownerObject corev1api.ObjectReference
			if test.ownerBackup != nil {
				ownerObject = corev1api.ObjectReference{
					Kind:       test.ownerBackup.Kind,
					Namespace:  test.ownerBackup.Namespace,
					Name:       test.ownerBackup.Name,
					UID:        test.ownerBackup.UID,
					APIVersion: test.ownerBackup.APIVersion,
				}
			}

			test.exposeWaitParam.NodeClient = fakeClient

			result, err := exposer.GetExposed(t.Context(), ownerObject, test.Timeout, &test.exposeWaitParam)
			if test.err == "" {
				require.NoError(t, err)

				if test.expectedResult == nil {
					assert.Nil(t, result)
				} else {
					require.NoError(t, err)
					assert.Equal(t, test.expectedResult.ByPod.VolumeName, result.ByPod.VolumeName)
					assert.Equal(t, test.expectedResult.ByPod.HostingPod.Name, result.ByPod.HostingPod.Name)
				}
			} else {
				assert.EqualError(t, err, test.err)
			}
		})
	}
}

func TestPeekExpose(t *testing.T) {
	backup := &velerov1.Backup{
		TypeMeta: metav1.TypeMeta{
			APIVersion: velerov1.SchemeGroupVersion.String(),
			Kind:       "Backup",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: velerov1.DefaultNamespace,
			Name:      "fake-backup",
			UID:       "fake-uid",
		},
	}

	backupPodUrecoverable := &corev1api.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: backup.Namespace,
			Name:      backup.Name,
		},
		Status: corev1api.PodStatus{
			Phase: corev1api.PodFailed,
		},
	}

	backupPod := &corev1api.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: backup.Namespace,
			Name:      backup.Name,
		},
	}

	scheme := runtime.NewScheme()
	corev1api.AddToScheme(scheme)

	tests := []struct {
		name          string
		kubeClientObj []runtime.Object
		ownerBackup   *velerov1.Backup
		err           string
	}{
		{
			name:        "backup pod is not found",
			ownerBackup: backup,
		},
		{
			name:        "pod is unrecoverable",
			ownerBackup: backup,
			kubeClientObj: []runtime.Object{
				backupPodUrecoverable,
			},
			err: "Pod is in abnormal state [Failed], message []",
		},
		{
			name:        "succeed",
			ownerBackup: backup,
			kubeClientObj: []runtime.Object{
				backupPod,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakeKubeClient := fake.NewSimpleClientset(test.kubeClientObj...)

			exposer := csiSnapshotExposer{
				kubeClient: fakeKubeClient,
				log:        velerotest.NewLogger(),
			}

			var ownerObject corev1api.ObjectReference
			if test.ownerBackup != nil {
				ownerObject = corev1api.ObjectReference{
					Kind:       test.ownerBackup.Kind,
					Namespace:  test.ownerBackup.Namespace,
					Name:       test.ownerBackup.Name,
					UID:        test.ownerBackup.UID,
					APIVersion: test.ownerBackup.APIVersion,
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

func Test_csiSnapshotExposer_createBackupPVC(t *testing.T) {
	backup := &velerov1.Backup{
		TypeMeta: metav1.TypeMeta{
			APIVersion: velerov1.SchemeGroupVersion.String(),
			Kind:       "Backup",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: velerov1.DefaultNamespace,
			Name:      "fake-backup",
			UID:       "fake-uid",
		},
	}

	dataSource := &corev1api.TypedLocalObjectReference{
		APIGroup: &snapshotv1api.SchemeGroupVersion.Group,
		Kind:     "VolumeSnapshot",
		Name:     "fake-snapshot",
	}
	volumeMode := corev1api.PersistentVolumeFilesystem

	backupPVC := corev1api.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   velerov1.DefaultNamespace,
			Name:        "fake-backup",
			Annotations: map[string]string{},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: backup.APIVersion,
					Kind:       backup.Kind,
					Name:       backup.Name,
					UID:        backup.UID,
					Controller: ptr.To(true),
				},
			},
		},
		Spec: corev1api.PersistentVolumeClaimSpec{
			AccessModes: []corev1api.PersistentVolumeAccessMode{
				corev1api.ReadWriteOnce,
			},
			VolumeMode:       &volumeMode,
			DataSource:       dataSource,
			DataSourceRef:    nil,
			StorageClassName: ptr.To("fake-storage-class"),
			Resources: corev1api.VolumeResourceRequirements{
				Requests: corev1api.ResourceList{
					corev1api.ResourceStorage: resource.MustParse("1Gi"),
				},
			},
		},
	}

	backupPVCReadOnly := corev1api.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   velerov1.DefaultNamespace,
			Name:        "fake-backup",
			Annotations: map[string]string{},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: backup.APIVersion,
					Kind:       backup.Kind,
					Name:       backup.Name,
					UID:        backup.UID,
					Controller: ptr.To(true),
				},
			},
		},
		Spec: corev1api.PersistentVolumeClaimSpec{
			AccessModes: []corev1api.PersistentVolumeAccessMode{
				corev1api.ReadOnlyMany,
			},
			VolumeMode:       &volumeMode,
			DataSource:       dataSource,
			DataSourceRef:    nil,
			StorageClassName: ptr.To("fake-storage-class"),
			Resources: corev1api.VolumeResourceRequirements{
				Requests: corev1api.ResourceList{
					corev1api.ResourceStorage: resource.MustParse("1Gi"),
				},
			},
		},
	}

	tests := []struct {
		name              string
		ownerBackup       *velerov1.Backup
		backupVS          string
		storageClass      string
		accessMode        string
		resource          resource.Quantity
		readOnly          bool
		kubeClientObj     []runtime.Object
		snapshotClientObj []runtime.Object
		want              *corev1api.PersistentVolumeClaim
		wantErr           assert.ErrorAssertionFunc
	}{
		{
			name:         "backupPVC gets created successfully with parameters from source PVC",
			ownerBackup:  backup,
			backupVS:     "fake-snapshot",
			storageClass: "fake-storage-class",
			accessMode:   AccessModeFileSystem,
			resource:     resource.MustParse("1Gi"),
			readOnly:     false,
			want:         &backupPVC,
			wantErr:      assert.NoError,
		},
		{
			name:         "backupPVC gets created successfully with parameters from source PVC but accessMode from backupPVC Config as read only",
			ownerBackup:  backup,
			backupVS:     "fake-snapshot",
			storageClass: "fake-storage-class",
			accessMode:   AccessModeFileSystem,
			resource:     resource.MustParse("1Gi"),
			readOnly:     true,
			want:         &backupPVCReadOnly,
			wantErr:      assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeKubeClient := fake.NewSimpleClientset(tt.kubeClientObj...)
			fakeSnapshotClient := snapshotFake.NewSimpleClientset(tt.snapshotClientObj...)
			e := &csiSnapshotExposer{
				kubeClient:        fakeKubeClient,
				csiSnapshotClient: fakeSnapshotClient.SnapshotV1(),
				log:               velerotest.NewLogger(),
			}
			var ownerObject corev1api.ObjectReference
			if tt.ownerBackup != nil {
				ownerObject = corev1api.ObjectReference{
					Kind:       tt.ownerBackup.Kind,
					Namespace:  tt.ownerBackup.Namespace,
					Name:       tt.ownerBackup.Name,
					UID:        tt.ownerBackup.UID,
					APIVersion: tt.ownerBackup.APIVersion,
				}
			}
			got, err := e.createBackupPVC(t.Context(), ownerObject, tt.backupVS, tt.storageClass, tt.accessMode, tt.resource, tt.readOnly, map[string]string{}, "")
			if !tt.wantErr(t, err, fmt.Sprintf("createBackupPVC(%v, %v, %v, %v, %v, %v)", ownerObject, tt.backupVS, tt.storageClass, tt.accessMode, tt.resource, tt.readOnly)) {
				return
			}
			assert.Equalf(t, tt.want, got, "createBackupPVC(%v, %v, %v, %v, %v, %v)", ownerObject, tt.backupVS, tt.storageClass, tt.accessMode, tt.resource, tt.readOnly)
		})
	}
}

func Test_csiSnapshotExposer_DiagnoseExpose(t *testing.T) {
	backup := &velerov1.Backup{
		TypeMeta: metav1.TypeMeta{
			APIVersion: velerov1.SchemeGroupVersion.String(),
			Kind:       "Backup",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: velerov1.DefaultNamespace,
			Name:      "fake-backup",
			UID:       "fake-uid",
		},
	}

	backupPodWithoutNodeName := corev1api.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: velerov1.DefaultNamespace,
			Name:      "fake-backup",
			UID:       "fake-pod-uid",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: backup.APIVersion,
					Kind:       backup.Kind,
					Name:       backup.Name,
					UID:        backup.UID,
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

	backupPodWithNodeName := corev1api.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: velerov1.DefaultNamespace,
			Name:      "fake-backup",
			UID:       "fake-pod-uid",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: backup.APIVersion,
					Kind:       backup.Kind,
					Name:       backup.Name,
					UID:        backup.UID,
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

	backupPVCWithoutVolumeName := corev1api.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: velerov1.DefaultNamespace,
			Name:      "fake-backup",
			UID:       "fake-pvc-uid",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: backup.APIVersion,
					Kind:       backup.Kind,
					Name:       backup.Name,
					UID:        backup.UID,
				},
			},
		},
		Status: corev1api.PersistentVolumeClaimStatus{
			Phase: corev1api.ClaimPending,
		},
	}

	backupPVCWithVolumeName := corev1api.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: velerov1.DefaultNamespace,
			Name:      "fake-backup",
			UID:       "fake-pvc-uid",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: backup.APIVersion,
					Kind:       backup.Kind,
					Name:       backup.Name,
					UID:        backup.UID,
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

	backupPV := corev1api.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name: "fake-pv",
		},
		Status: corev1api.PersistentVolumeStatus{
			Phase:   corev1api.VolumePending,
			Message: "fake-pv-message",
		},
	}

	readyToUse := false
	vscMessage := "fake-vsc-message"
	backupVSC := snapshotv1api.VolumeSnapshotContent{
		ObjectMeta: metav1.ObjectMeta{
			Name: "fake-vsc",
		},
		Status: &snapshotv1api.VolumeSnapshotContentStatus{
			ReadyToUse: &readyToUse,
			Error: &snapshotv1api.VolumeSnapshotError{
				Message: &vscMessage,
			},
		},
	}

	backupVSWithoutStatus := snapshotv1api.VolumeSnapshot{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: velerov1.DefaultNamespace,
			Name:      "fake-backup",
			UID:       "fake-vs-uid",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: backup.APIVersion,
					Kind:       backup.Kind,
					Name:       backup.Name,
					UID:        backup.UID,
				},
			},
		},
	}

	backupVSWithoutVSC := snapshotv1api.VolumeSnapshot{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: velerov1.DefaultNamespace,
			Name:      "fake-backup",
			UID:       "fake-vs-uid",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: backup.APIVersion,
					Kind:       backup.Kind,
					Name:       backup.Name,
					UID:        backup.UID,
				},
			},
		},
		Status: &snapshotv1api.VolumeSnapshotStatus{},
	}

	vsMessage := "fake-vs-message"
	backupVSWithVSC := snapshotv1api.VolumeSnapshot{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: velerov1.DefaultNamespace,
			Name:      "fake-backup",
			UID:       "fake-vs-uid",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: backup.APIVersion,
					Kind:       backup.Kind,
					Name:       backup.Name,
					UID:        backup.UID,
				},
			},
		},
		Status: &snapshotv1api.VolumeSnapshotStatus{
			BoundVolumeSnapshotContentName: &backupVSC.Name,
			Error: &snapshotv1api.VolumeSnapshotError{
				Message: &vsMessage,
			},
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
		name              string
		ownerBackup       *velerov1.Backup
		kubeClientObj     []runtime.Object
		snapshotClientObj []runtime.Object
		expected          string
	}{
		{
			name:        "no pod, pvc, vs",
			ownerBackup: backup,
			expected: `begin diagnose CSI exposer
error getting backup pod fake-backup, err: pods "fake-backup" not found
error getting backup pvc fake-backup, err: persistentvolumeclaims "fake-backup" not found
error getting backup vs fake-backup, err: volumesnapshots.snapshot.storage.k8s.io "fake-backup" not found
end diagnose CSI exposer`,
		},
		{
			name:        "pod without node name, pvc without volume name, vs without status",
			ownerBackup: backup,
			kubeClientObj: []runtime.Object{
				&backupPodWithoutNodeName,
				&backupPVCWithoutVolumeName,
			},
			snapshotClientObj: []runtime.Object{
				&backupVSWithoutStatus,
			},
			expected: `begin diagnose CSI exposer
Pod velero/fake-backup, phase Pending, node name , message fake-pod-message-1
Pod condition Initialized, status True, reason , message fake-pod-message
PVC velero/fake-backup, phase Pending, binding to 
VS velero/fake-backup, bind to , readyToUse false, errMessage 
end diagnose CSI exposer`,
		},
		{
			name:        "pod without node name, pvc without volume name, vs without VSC",
			ownerBackup: backup,
			kubeClientObj: []runtime.Object{
				&backupPodWithoutNodeName,
				&backupPVCWithoutVolumeName,
			},
			snapshotClientObj: []runtime.Object{
				&backupVSWithoutVSC,
			},
			expected: `begin diagnose CSI exposer
Pod velero/fake-backup, phase Pending, node name , message fake-pod-message-1
Pod condition Initialized, status True, reason , message fake-pod-message
PVC velero/fake-backup, phase Pending, binding to 
VS velero/fake-backup, bind to , readyToUse false, errMessage 
end diagnose CSI exposer`,
		},
		{
			name:        "pod with node name, no node agent",
			ownerBackup: backup,
			kubeClientObj: []runtime.Object{
				&backupPodWithNodeName,
				&backupPVCWithoutVolumeName,
			},
			snapshotClientObj: []runtime.Object{
				&backupVSWithoutVSC,
			},
			expected: `begin diagnose CSI exposer
Pod velero/fake-backup, phase Pending, node name fake-node, message 
Pod condition Initialized, status True, reason , message fake-pod-message
node-agent is not running in node fake-node, err: daemonset pod not found in node fake-node
PVC velero/fake-backup, phase Pending, binding to 
VS velero/fake-backup, bind to , readyToUse false, errMessage 
end diagnose CSI exposer`,
		},
		{
			name:        "pod with node name, node agent is running",
			ownerBackup: backup,
			kubeClientObj: []runtime.Object{
				&backupPodWithNodeName,
				&backupPVCWithoutVolumeName,
				&nodeAgentPod,
			},
			snapshotClientObj: []runtime.Object{
				&backupVSWithoutVSC,
			},
			expected: `begin diagnose CSI exposer
Pod velero/fake-backup, phase Pending, node name fake-node, message 
Pod condition Initialized, status True, reason , message fake-pod-message
PVC velero/fake-backup, phase Pending, binding to 
VS velero/fake-backup, bind to , readyToUse false, errMessage 
end diagnose CSI exposer`,
		},
		{
			name:        "pvc with volume name, no pv",
			ownerBackup: backup,
			kubeClientObj: []runtime.Object{
				&backupPodWithNodeName,
				&backupPVCWithVolumeName,
				&nodeAgentPod,
			},
			snapshotClientObj: []runtime.Object{
				&backupVSWithoutVSC,
			},
			expected: `begin diagnose CSI exposer
Pod velero/fake-backup, phase Pending, node name fake-node, message 
Pod condition Initialized, status True, reason , message fake-pod-message
PVC velero/fake-backup, phase Pending, binding to fake-pv
error getting backup pv fake-pv, err: persistentvolumes "fake-pv" not found
VS velero/fake-backup, bind to , readyToUse false, errMessage 
end diagnose CSI exposer`,
		},
		{
			name:        "pvc with volume name, pv exists",
			ownerBackup: backup,
			kubeClientObj: []runtime.Object{
				&backupPodWithNodeName,
				&backupPVCWithVolumeName,
				&backupPV,
				&nodeAgentPod,
			},
			snapshotClientObj: []runtime.Object{
				&backupVSWithoutVSC,
			},
			expected: `begin diagnose CSI exposer
Pod velero/fake-backup, phase Pending, node name fake-node, message 
Pod condition Initialized, status True, reason , message fake-pod-message
PVC velero/fake-backup, phase Pending, binding to fake-pv
PV fake-pv, phase Pending, reason , message fake-pv-message
VS velero/fake-backup, bind to , readyToUse false, errMessage 
end diagnose CSI exposer`,
		},
		{
			name:        "vs with vsc, vsc doesn't exist",
			ownerBackup: backup,
			kubeClientObj: []runtime.Object{
				&backupPodWithNodeName,
				&backupPVCWithVolumeName,
				&backupPV,
				&nodeAgentPod,
			},
			snapshotClientObj: []runtime.Object{
				&backupVSWithVSC,
			},
			expected: `begin diagnose CSI exposer
Pod velero/fake-backup, phase Pending, node name fake-node, message 
Pod condition Initialized, status True, reason , message fake-pod-message
PVC velero/fake-backup, phase Pending, binding to fake-pv
PV fake-pv, phase Pending, reason , message fake-pv-message
VS velero/fake-backup, bind to fake-vsc, readyToUse false, errMessage fake-vs-message
error getting backup vsc fake-vsc, err: volumesnapshotcontents.snapshot.storage.k8s.io "fake-vsc" not found
end diagnose CSI exposer`,
		},
		{
			name:        "vs with vsc, vsc exists",
			ownerBackup: backup,
			kubeClientObj: []runtime.Object{
				&backupPodWithNodeName,
				&backupPVCWithVolumeName,
				&backupPV,
				&nodeAgentPod,
			},
			snapshotClientObj: []runtime.Object{
				&backupVSWithVSC,
				&backupVSC,
			},
			expected: `begin diagnose CSI exposer
Pod velero/fake-backup, phase Pending, node name fake-node, message 
Pod condition Initialized, status True, reason , message fake-pod-message
PVC velero/fake-backup, phase Pending, binding to fake-pv
PV fake-pv, phase Pending, reason , message fake-pv-message
VS velero/fake-backup, bind to fake-vsc, readyToUse false, errMessage fake-vs-message
VSC fake-vsc, readyToUse false, errMessage fake-vsc-message, handle 
end diagnose CSI exposer`,
		},
		{
			name:        "with events",
			ownerBackup: backup,
			kubeClientObj: []runtime.Object{
				&backupPodWithNodeName,
				&backupPVCWithVolumeName,
				&backupPV,
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
					ObjectMeta:     metav1.ObjectMeta{Namespace: velerov1.DefaultNamespace, Name: "event-4"},
					Type:           corev1api.EventTypeWarning,
					InvolvedObject: corev1api.ObjectReference{UID: "fake-vs-uid"},
					Reason:         "reason-4",
					Message:        "message-4",
				},
				&corev1api.Event{
					ObjectMeta:     metav1.ObjectMeta{Namespace: "other-namespace", Name: "event-5"},
					Type:           corev1api.EventTypeWarning,
					InvolvedObject: corev1api.ObjectReference{UID: "fake-pod-uid"},
					Reason:         "reason-5",
					Message:        "message-5",
				},
				&corev1api.Event{
					ObjectMeta:     metav1.ObjectMeta{Namespace: velerov1.DefaultNamespace, Name: "event-6"},
					Type:           corev1api.EventTypeWarning,
					InvolvedObject: corev1api.ObjectReference{UID: "fake-pod-uid"},
					Reason:         "reason-6",
					Message:        "message-6",
				},
			},
			snapshotClientObj: []runtime.Object{
				&backupVSWithVSC,
				&backupVSC,
			},
			expected: `begin diagnose CSI exposer
Pod velero/fake-backup, phase Pending, node name fake-node, message 
Pod condition Initialized, status True, reason , message fake-pod-message
Pod event reason reason-2, message message-2
Pod event reason reason-6, message message-6
PVC velero/fake-backup, phase Pending, binding to fake-pv
PVC event reason reason-3, message message-3
PV fake-pv, phase Pending, reason , message fake-pv-message
VS velero/fake-backup, bind to fake-vsc, readyToUse false, errMessage fake-vs-message
VS event reason reason-4, message message-4
VSC fake-vsc, readyToUse false, errMessage fake-vsc-message, handle 
end diagnose CSI exposer`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeKubeClient := fake.NewSimpleClientset(tt.kubeClientObj...)
			fakeSnapshotClient := snapshotFake.NewSimpleClientset(tt.snapshotClientObj...)
			e := &csiSnapshotExposer{
				kubeClient:        fakeKubeClient,
				csiSnapshotClient: fakeSnapshotClient.SnapshotV1(),
				log:               velerotest.NewLogger(),
			}
			var ownerObject corev1api.ObjectReference
			if tt.ownerBackup != nil {
				ownerObject = corev1api.ObjectReference{
					Kind:       tt.ownerBackup.Kind,
					Namespace:  tt.ownerBackup.Namespace,
					Name:       tt.ownerBackup.Name,
					UID:        tt.ownerBackup.UID,
					APIVersion: tt.ownerBackup.APIVersion,
				}
			}

			diag := e.DiagnoseExpose(t.Context(), ownerObject)
			assert.Equal(t, tt.expected, diag)
		})
	}
}

func TestGetCBTInfo(t *testing.T) {
	handle := "snapshot-handle-1"

	tests := []struct {
		name          string
		vs            *snapshotv1api.VolumeSnapshot
		vsc           *snapshotv1api.VolumeSnapshotContent
		pv            *corev1api.PersistentVolume
		sourcePVName  string
		want          cbtInfo
		wantErrSubstr string
	}{
		{
			name:          "return error when vs is nil",
			vs:            nil,
			vsc:           &snapshotv1api.VolumeSnapshotContent{},
			sourcePVName:  "pv-1",
			wantErrSubstr: "vs or vsc is nil",
		},
		{
			name: "use annotations when change-id and snapshot annotation exist",
			vs: &snapshotv1api.VolumeSnapshot{
				ObjectMeta: metav1.ObjectMeta{
					Name: "vs-anno",
					Annotations: map[string]string{
						util.VSphereCNSChangeIDAnno: "change-id-1",
						util.VSphereCNSSnapshotAnno: "volume-id-1+snapshot-id-1",
					},
				},
			},
			vsc:          &snapshotv1api.VolumeSnapshotContent{},
			sourcePVName: "pv-ignored",
			want: cbtInfo{
				changeID:   "change-id-1",
				volumeID:   "volume-id-1",
				snapshotID: "vs-anno",
			},
		},
		{
			name: "fallback to pv and vsc snapshot handle",
			vs: &snapshotv1api.VolumeSnapshot{
				ObjectMeta: metav1.ObjectMeta{Name: "vs-fallback"},
			},
			vsc: &snapshotv1api.VolumeSnapshotContent{
				Status: &snapshotv1api.VolumeSnapshotContentStatus{
					SnapshotHandle: &handle,
				},
			},
			pv: &corev1api.PersistentVolume{
				ObjectMeta: metav1.ObjectMeta{Name: "pv-1"},
				Spec: corev1api.PersistentVolumeSpec{
					PersistentVolumeSource: corev1api.PersistentVolumeSource{
						CSI: &corev1api.CSIPersistentVolumeSource{
							VolumeHandle: "csi-volume-handle-1",
						},
					},
				},
			},
			sourcePVName: "pv-1",
			want: cbtInfo{
				changeID:   "snapshot-handle-1",
				volumeID:   "csi-volume-handle-1",
				snapshotID: "vs-fallback",
			},
		},
		{
			name: "return error when pv not found in fallback path",
			vs: &snapshotv1api.VolumeSnapshot{
				ObjectMeta: metav1.ObjectMeta{Name: "vs-no-pv"},
			},
			vsc:           &snapshotv1api.VolumeSnapshotContent{},
			sourcePVName:  "pv-not-found",
			wantErrSubstr: "failed to get pv pv-not-found",
		},
		{
			name: "return error when pv has no csi volume handle",
			vs: &snapshotv1api.VolumeSnapshot{
				ObjectMeta: metav1.ObjectMeta{Name: "vs-no-volume-handle"},
			},
			vsc: &snapshotv1api.VolumeSnapshotContent{},
			pv: &corev1api.PersistentVolume{
				ObjectMeta: metav1.ObjectMeta{Name: "pv-no-handle"},
				Spec:       corev1api.PersistentVolumeSpec{},
			},
			sourcePVName:  "pv-no-handle",
			wantErrSubstr: "volumeID must not be empty for CBT",
		},
		{
			name: "return error when snapshot annotation is invalid",
			vs: &snapshotv1api.VolumeSnapshot{
				ObjectMeta: metav1.ObjectMeta{
					Name: "vs-no-volume-handle",
					Annotations: map[string]string{
						util.VSphereCNSChangeIDAnno: "change-id-1",
						util.VSphereCNSSnapshotAnno: "volume-id-1:snapshot-id-1",
					},
				},
			},
			vsc: &snapshotv1api.VolumeSnapshotContent{},
			pv: &corev1api.PersistentVolume{
				ObjectMeta: metav1.ObjectMeta{Name: "pv-1"},
				Spec: corev1api.PersistentVolumeSpec{
					PersistentVolumeSource: corev1api.PersistentVolumeSource{
						CSI: &corev1api.CSIPersistentVolumeSource{
							VolumeHandle: "csi-volume-handle-1",
						},
					},
				},
			},
			sourcePVName:  "pv-1",
			wantErrSubstr: "volumeID must not be empty for CBT",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var objs []runtime.Object
			if tc.pv != nil {
				objs = append(objs, tc.pv)
			}
			exposer := &csiSnapshotExposer{
				kubeClient: kubefake.NewSimpleClientset(objs...),
				log:        logrus.StandardLogger(),
			}

			got, err := exposer.getCBTInfo(context.Background(), tc.vs, tc.vsc, tc.sourcePVName)

			if tc.wantErrSubstr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErrSubstr)
				}
				if !strings.Contains(err.Error(), tc.wantErrSubstr) {
					t.Fatalf("expected error containing %q, got %q", tc.wantErrSubstr, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.changeID != tc.want.changeID || got.volumeID != tc.want.volumeID || got.snapshotID != tc.want.snapshotID {
				t.Fatalf("unexpected cbtInfo, want %+v, got %+v", tc.want, got)
			}
		})
	}
}
