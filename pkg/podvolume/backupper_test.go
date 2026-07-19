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

package podvolume

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrlcache "sigs.k8s.io/controller-runtime/pkg/cache"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	ctrlfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	clientTesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"

	"github.com/vmware-tanzu/velero/internal/resourcepolicies"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/repository"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
)

type fakeInformerRegistration struct{}

func (fakeInformerRegistration) HasSynced() bool { return true }

func (fakeInformerRegistration) HasSyncedChecker() cache.DoneChecker {
	return fakeDoneChecker{name: "fakeInformerRegistration"}
}

type fakeDoneChecker struct {
	name string
}

func (f fakeDoneChecker) Name() string { return f.name }

func (f fakeDoneChecker) Done() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}

type fakeInformer struct {
	handler cache.ResourceEventHandler
}

func (f *fakeInformer) AddEventHandler(handler cache.ResourceEventHandler) (cache.ResourceEventHandlerRegistration, error) {
	f.handler = handler
	return fakeInformerRegistration{}, nil
}

func (f *fakeInformer) AddEventHandlerWithResyncPeriod(handler cache.ResourceEventHandler, _ time.Duration) (cache.ResourceEventHandlerRegistration, error) {
	return f.AddEventHandler(handler)
}

func (f *fakeInformer) AddEventHandlerWithOptions(handler cache.ResourceEventHandler, _ cache.HandlerOptions) (cache.ResourceEventHandlerRegistration, error) {
	return f.AddEventHandler(handler)
}

func (f *fakeInformer) RemoveEventHandler(_ cache.ResourceEventHandlerRegistration) error {
	return nil
}

func (f *fakeInformer) AddIndexers(_ cache.Indexers) error { return nil }

func (f *fakeInformer) HasSynced() bool { return true }

func (f *fakeInformer) HasSyncedChecker() cache.DoneChecker {
	return fakeDoneChecker{name: "fakeInformer"}
}

func (f *fakeInformer) IsStopped() bool { return false }

var _ ctrlcache.Informer = (*fakeInformer)(nil)

func TestIsHostPathVolume(t *testing.T) {
	// hostPath pod volume
	vol := &corev1api.Volume{
		VolumeSource: corev1api.VolumeSource{
			HostPath: &corev1api.HostPathVolumeSource{},
		},
	}
	isHostPath, err := isHostPathVolume(vol, nil, nil)
	require.NoError(t, err)
	assert.True(t, isHostPath)

	// non-hostPath pod volume
	vol = &corev1api.Volume{
		VolumeSource: corev1api.VolumeSource{
			EmptyDir: &corev1api.EmptyDirVolumeSource{},
		},
	}
	isHostPath, err = isHostPathVolume(vol, nil, nil)
	require.NoError(t, err)
	assert.False(t, isHostPath)

	// PVC that doesn't have a PV
	vol = &corev1api.Volume{
		VolumeSource: corev1api.VolumeSource{
			PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
				ClaimName: "pvc-1",
			},
		},
	}
	pvc := &corev1api.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "ns-1",
			Name:      "pvc-1",
		},
	}
	isHostPath, err = isHostPathVolume(vol, pvc, nil)
	require.NoError(t, err)
	assert.False(t, isHostPath)

	// PVC that claims a non-hostPath PV
	vol = &corev1api.Volume{
		VolumeSource: corev1api.VolumeSource{
			PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
				ClaimName: "pvc-1",
			},
		},
	}
	pvc = &corev1api.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "ns-1",
			Name:      "pvc-1",
		},
		Spec: corev1api.PersistentVolumeClaimSpec{
			VolumeName: "pv-1",
		},
	}
	pv := &corev1api.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name: "pv-1",
		},
		Spec: corev1api.PersistentVolumeSpec{},
	}
	crClient1 := velerotest.NewFakeControllerRuntimeClient(t, pv)
	isHostPath, err = isHostPathVolume(vol, pvc, crClient1)
	require.NoError(t, err)
	assert.False(t, isHostPath)

	// PVC that claims a hostPath PV
	vol = &corev1api.Volume{
		VolumeSource: corev1api.VolumeSource{
			PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
				ClaimName: "pvc-1",
			},
		},
	}
	pvc = &corev1api.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "ns-1",
			Name:      "pvc-1",
		},
		Spec: corev1api.PersistentVolumeClaimSpec{
			VolumeName: "pv-1",
		},
	}
	pv = &corev1api.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name: "pv-1",
		},
		Spec: corev1api.PersistentVolumeSpec{
			PersistentVolumeSource: corev1api.PersistentVolumeSource{
				HostPath: &corev1api.HostPathVolumeSource{},
			},
		},
	}
	crClient2 := velerotest.NewFakeControllerRuntimeClient(t, pv)

	isHostPath, err = isHostPathVolume(vol, pvc, crClient2)
	require.NoError(t, err)
	assert.True(t, isHostPath)
}

func Test_backupper_BackupPodVolumes_log_test(t *testing.T) {
	type args struct {
		backup          *velerov1api.Backup
		pod             *corev1api.Pod
		volumesToBackup []string
		resPolicies     *resourcepolicies.Policies
	}
	tests := []struct {
		name    string
		args    args
		wantLog string
	}{
		{
			name: "backup pod volumes should log volume names",
			args: args{
				backup: &velerov1api.Backup{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "backup-1",
						Namespace: "ns-1",
					},
				},
				pod: &corev1api.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "pod-1",
						Namespace: "ns-1",
					},
					Spec: corev1api.PodSpec{
						Volumes: []corev1api.Volume{
							{
								Name: "vol-1",
							},
							{
								Name: "vol-2",
							},
						},
					},
				},
				volumesToBackup: []string{"vol-1", "vol-2"},
				resPolicies:     nil,
			},
			wantLog: "pod ns-1/pod-1 has volumes to backup: [vol-1 vol-2]",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &backupper{
				ctx: t.Context(),
			}
			logOutput := bytes.Buffer{}
			var log = logrus.New()
			log.SetOutput(&logOutput)
			b.BackupPodVolumes(tt.args.backup, tt.args.pod, tt.args.volumesToBackup, tt.args.resPolicies, log)
			fmt.Println(logOutput.String())
			assert.Contains(t, logOutput.String(), tt.wantLog)
		})
	}
}

type reactor struct {
	verb        string
	resource    string
	reactorFunc clientTesting.ReactionFunc
}

func createBackupRepoObj() *velerov1api.BackupRepository {
	bkRepoObj := repository.NewBackupRepository(velerov1api.DefaultNamespace, repository.BackupRepositoryKey{
		VolumeNamespace: "fake-ns",
		BackupLocation:  "fake-bsl",
		RepositoryType:  "kopia",
	})

	bkRepoObj.Status.Phase = velerov1api.BackupRepositoryPhaseReady

	return bkRepoObj
}

func createPodObj(running bool, withVolume bool, withVolumeMounted bool, volumeNum int) *corev1api.Pod {
	podObj := builder.ForPod("fake-ns", "fake-pod").Result()
	podObj.Spec.NodeName = "fake-node-name"
	if running {
		podObj.Status.Phase = corev1api.PodRunning
	}

	if withVolume {
		for i := 0; i < volumeNum; i++ {
			podObj.Spec.Volumes = append(podObj.Spec.Volumes, corev1api.Volume{
				Name: fmt.Sprintf("fake-volume-%d", i+1),
				VolumeSource: corev1api.VolumeSource{
					PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
						ClaimName: fmt.Sprintf("fake-pvc-%d", i+1),
					},
				},
			})
		}

		if withVolumeMounted {
			volumeMount := []corev1api.VolumeMount{}
			for i := 0; i < volumeNum; i++ {
				volumeMount = append(volumeMount, corev1api.VolumeMount{
					Name: fmt.Sprintf("fake-volume-%d", i+1),
				})
			}
			podObj.Spec.Containers = []corev1api.Container{
				{
					Name:         "fake-container",
					VolumeMounts: volumeMount,
				},
			}
		}
	}

	return podObj
}

func createNodeAgentPodObj(running bool) *corev1api.Pod {
	podObj := builder.ForPod(velerov1api.DefaultNamespace, "fake-node-agent").Result()
	podObj.Labels = map[string]string{"role": "node-agent"}

	if running {
		podObj.Status.Phase = corev1api.PodRunning
		podObj.Spec.NodeName = "fake-node-name"
	}

	return podObj
}

func createPVObj(index int, withHostPath bool) *corev1api.PersistentVolume {
	pvObj := builder.ForPersistentVolume(fmt.Sprintf("fake-pv-%d", index)).Result()
	if withHostPath {
		pvObj.Spec.HostPath = &corev1api.HostPathVolumeSource{Path: "fake-host-path"}
	}

	return pvObj
}

func createPVCObj(index int) *corev1api.PersistentVolumeClaim {
	pvcObj := builder.ForPersistentVolumeClaim("fake-ns", fmt.Sprintf("fake-pvc-%d", index)).VolumeName(fmt.Sprintf("fake-pv-%d", index)).Result()
	return pvcObj
}

func createPVBObj(fail bool, withSnapshot bool, index int, uploaderType string) *velerov1api.PodVolumeBackup {
	pvbObj := builder.ForPodVolumeBackup(velerov1api.DefaultNamespace, fmt.Sprintf("fake-pvb-%d", index)).
		PodName("fake-pod").PodNamespace("fake-ns").Volume(fmt.Sprintf("fake-volume-%d", index)).Result()
	if fail {
		pvbObj.Status.Phase = velerov1api.PodVolumeBackupPhaseFailed
		pvbObj.Status.Message = "fake-message"
	} else {
		pvbObj.Status.Phase = velerov1api.PodVolumeBackupPhaseCompleted
	}

	if withSnapshot {
		pvbObj.Status.SnapshotID = fmt.Sprintf("fake-snapshot-id-%d", index)
	}

	pvbObj.Spec.UploaderType = uploaderType

	return pvbObj
}

func createNodeObj() *corev1api.Node {
	return builder.ForNode("fake-node-name").Labels(map[string]string{"kubernetes.io/os": "linux"}).Result()
}

func TestBackupPodVolumes(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, velerov1api.AddToScheme(scheme))
	require.NoError(t, corev1api.AddToScheme(scheme))
	log := logrus.New()

	tests := []struct {
		name                  string
		bsl                   string
		uploaderType          string
		volumes               []string
		sourcePod             *corev1api.Pod
		kubeClientObj         []runtime.Object
		ctlClientObj          []runtime.Object
		veleroClientObj       []runtime.Object
		veleroReactors        []reactor
		runtimeScheme         *runtime.Scheme
		pvbs                  int
		mockGetRepositoryType bool
		errs                  []string
	}{
		{
			name: "empty volume list",
		},
		{
			name: "wrong uploader type",
			volumes: []string{
				"fake-volume-1",
				"fake-volume-2",
			},
			sourcePod: createPodObj(true, false, false, 2),
			kubeClientObj: []runtime.Object{
				createNodeAgentPodObj(true),
			},
			uploaderType: "fake-uploader-type",
			errs: []string{
				"invalid uploader type 'fake-uploader-type', valid types: 'kopia', 'velero-block'",
			},
		},
		{
			name: "pod is not running",
			volumes: []string{
				"fake-volume-1",
				"fake-volume-2",
			},
			kubeClientObj: []runtime.Object{
				createNodeAgentPodObj(true),
			},
			ctlClientObj: []runtime.Object{
				createBackupRepoObj(),
			},
			runtimeScheme: scheme,
			sourcePod:     createPodObj(false, false, false, 2),
			uploaderType:  "kopia",
			bsl:           "fake-bsl",
		},
		{
			name: "node-agent pod is not running in node",
			volumes: []string{
				"fake-volume-1",
				"fake-volume-2",
			},
			sourcePod: createPodObj(true, false, false, 2),
			kubeClientObj: []runtime.Object{
				createNodeObj(),
			},
			uploaderType: "kopia",
			errs: []string{
				"daemonset pod not found in running state in node fake-node-name",
			},
		},
		{
			name: "wrong repository type",
			volumes: []string{
				"fake-volume-1",
				"fake-volume-2",
			},
			sourcePod: createPodObj(true, false, false, 2),
			kubeClientObj: []runtime.Object{
				createNodeAgentPodObj(true),
				createNodeObj(),
			},
			uploaderType:          "kopia",
			mockGetRepositoryType: true,
			errs: []string{
				"empty repository type, uploader kopia",
			},
		},
		{
			name: "ensure repo fail",
			volumes: []string{
				"fake-volume-1",
				"fake-volume-2",
			},
			sourcePod: createPodObj(true, false, false, 2),
			kubeClientObj: []runtime.Object{
				createNodeAgentPodObj(true),
				createNodeObj(),
			},
			uploaderType: "kopia",
			errs: []string{
				"wrong parameters, namespace \"fake-ns\", backup storage location \"\", repository type \"kopia\"",
			},
		},
		{
			name: "volume not found in pod",
			volumes: []string{
				"fake-volume-1",
				"fake-volume-2",
			},
			sourcePod: createPodObj(true, false, false, 2),
			kubeClientObj: []runtime.Object{
				createNodeAgentPodObj(true),
				createNodeObj(),
			},
			ctlClientObj: []runtime.Object{
				createBackupRepoObj(),
			},
			runtimeScheme: scheme,
			uploaderType:  "kopia",
			bsl:           "fake-bsl",
		},
		{
			name: "PVC not found",
			volumes: []string{
				"fake-volume-1",
				"fake-volume-2",
			},
			sourcePod: createPodObj(true, true, false, 2),
			kubeClientObj: []runtime.Object{
				createNodeAgentPodObj(true),
				createNodeObj(),
			},
			ctlClientObj: []runtime.Object{
				createBackupRepoObj(),
			},
			runtimeScheme: scheme,
			uploaderType:  "kopia",
			bsl:           "fake-bsl",
			errs: []string{
				"error getting persistent volume claim for volume: persistentvolumeclaims \"fake-pvc-1\" not found",
				"error getting persistent volume claim for volume: persistentvolumeclaims \"fake-pvc-2\" not found",
			},
		},
		{
			name: "check host path fail",
			volumes: []string{
				"fake-volume-1",
				"fake-volume-2",
			},
			sourcePod: createPodObj(true, true, false, 2),
			kubeClientObj: []runtime.Object{
				createNodeAgentPodObj(true),
				createNodeObj(),
				createPVCObj(1),
				createPVCObj(2),
			},
			ctlClientObj: []runtime.Object{
				createBackupRepoObj(),
			},
			runtimeScheme: scheme,
			uploaderType:  "kopia",
			bsl:           "fake-bsl",
			errs: []string{
				"error checking if volume is a hostPath volume: persistentvolumes \"fake-pv-1\" not found",
				"error checking if volume is a hostPath volume: persistentvolumes \"fake-pv-2\" not found",
			},
		},
		{
			name: "host path volume should be skipped",
			volumes: []string{
				"fake-volume-1",
				"fake-volume-2",
			},
			sourcePod: createPodObj(true, true, false, 2),
			kubeClientObj: []runtime.Object{
				createNodeAgentPodObj(true),
				createNodeObj(),
				createPVCObj(1),
				createPVCObj(2),
				createPVObj(1, true),
				createPVObj(2, true),
			},
			ctlClientObj: []runtime.Object{
				createBackupRepoObj(),
			},
			runtimeScheme: scheme,
			uploaderType:  "kopia",
			bsl:           "fake-bsl",
			errs:          []string{},
		},
		{
			name: "volume not mounted by pod should be skipped",
			volumes: []string{
				"fake-volume-1",
				"fake-volume-2",
			},
			sourcePod: createPodObj(true, true, false, 2),
			kubeClientObj: []runtime.Object{
				createNodeAgentPodObj(true),
				createNodeObj(),
				createPVCObj(1),
				createPVCObj(2),
				createPVObj(1, false),
				createPVObj(2, false),
			},
			ctlClientObj: []runtime.Object{
				createBackupRepoObj(),
			},
			runtimeScheme: scheme,
			uploaderType:  "kopia",
			bsl:           "fake-bsl",
			errs:          []string{},
		},
		{
			name: "return completed pvbs",
			volumes: []string{
				"fake-volume-1",
			},
			sourcePod: createPodObj(true, true, true, 1),
			kubeClientObj: []runtime.Object{
				createNodeAgentPodObj(true),
				createNodeObj(),
				createPVCObj(1),
				createPVObj(1, false),
			},
			ctlClientObj: []runtime.Object{
				createBackupRepoObj(),
			},
			runtimeScheme: scheme,
			uploaderType:  "kopia",
			bsl:           "fake-bsl",
			pvbs:          1,
			errs:          []string{},
		},
	}
	// TODO add more verification around PVCBackupSummary returned by "BackupPodVolumes"
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := t.Context()

			fakeClientBuilder := ctrlfake.NewClientBuilder()
			if test.runtimeScheme != nil {
				fakeClientBuilder = fakeClientBuilder.WithScheme(test.runtimeScheme)
			}

			objList := append(test.ctlClientObj, test.veleroClientObj...)
			objList = append(objList, test.kubeClientObj...)
			fakeCtrlClient := fakeClientBuilder.WithRuntimeObjects(objList...).Build()

			// This test validates creation-time behavior only, so we don't need
			// informer sync/watch to be running.
			pvbInformer := cache.NewSharedIndexInformer(&cache.ListWatch{}, &velerov1api.PodVolumeBackup{}, 0, cache.Indexers{})

			ensurer := repository.NewEnsurer(fakeCtrlClient, velerotest.NewLogger(), time.Millisecond)

			backupObj := builder.ForBackup(velerov1api.DefaultNamespace, "fake-backup").Result()
			backupObj.Spec.StorageLocation = test.bsl

			bp := newBackupper(ctx, log, repository.NewRepoLocker(), ensurer, pvbInformer, fakeCtrlClient, test.uploaderType, backupObj)

			if test.mockGetRepositoryType {
				funcGetRepositoryType = func() string { return "" }
			} else {
				funcGetRepositoryType = getRepositoryType
			}

			pvbs, _, errs := bp.BackupPodVolumes(backupObj, test.sourcePod, test.volumes, nil, velerotest.NewLogger())

			if test.errs != nil {
				for i := 0; i < len(errs); i++ {
					require.EqualError(t, errs[i], test.errs[i])
				}
			}

			assert.Len(t, pvbs, test.pvbs)
		})
	}
}

func TestGetPodVolumeBackupByPodAndVolume(t *testing.T) {
	backupper := &backupper{
		pvbIndexer: cache.NewIndexer(podVolumeBackupKey, cache.Indexers{
			indexNamePod: podIndexFunc,
		}),
	}

	obj := &velerov1api.PodVolumeBackup{
		Spec: velerov1api.PodVolumeBackupSpec{
			Pod: corev1api.ObjectReference{
				Kind:      "Pod",
				Namespace: "default",
				Name:      "pod",
			},
			Volume: "volume",
		},
	}

	err := backupper.pvbIndexer.Add(obj)
	require.NoError(t, err)

	// incorrect pod namespace
	pvb, err := backupper.GetPodVolumeBackupByPodAndVolume("invalid-namespace", "pod", "volume")
	require.NoError(t, err)
	assert.Nil(t, pvb)

	// incorrect pod name
	pvb, err = backupper.GetPodVolumeBackupByPodAndVolume("default", "invalid-pod", "volume")
	require.NoError(t, err)
	assert.Nil(t, pvb)

	// incorrect volume
	pvb, err = backupper.GetPodVolumeBackupByPodAndVolume("default", "pod", "invalid-volume")
	require.NoError(t, err)
	assert.Nil(t, pvb)

	// correct pod namespace, name and volume
	pvb, err = backupper.GetPodVolumeBackupByPodAndVolume("default", "pod", "volume")
	require.NoError(t, err)
	assert.NotNil(t, pvb)
}

func TestListPodVolumeBackupsByPodp(t *testing.T) {
	backupper := &backupper{
		pvbIndexer: cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{
			indexNamePod: podIndexFunc,
		}),
	}

	obj1 := &velerov1api.PodVolumeBackup{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "velero",
			Name:      "pvb1",
		},
		Spec: velerov1api.PodVolumeBackupSpec{
			Pod: corev1api.ObjectReference{
				Kind:      "Pod",
				Namespace: "default",
				Name:      "pod",
			},
		},
	}
	obj2 := &velerov1api.PodVolumeBackup{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "velero",
			Name:      "pvb2",
		},
		Spec: velerov1api.PodVolumeBackupSpec{
			Pod: corev1api.ObjectReference{
				Kind:      "Pod",
				Namespace: "default",
				Name:      "pod",
			},
		},
	}

	err := backupper.pvbIndexer.Add(obj1)
	require.NoError(t, err)
	err = backupper.pvbIndexer.Add(obj2)
	require.NoError(t, err)

	// not exist PVBs
	pvbs, err := backupper.ListPodVolumeBackupsByPod("invalid-namespace", "invalid-name")
	require.NoError(t, err)
	assert.Empty(t, pvbs)

	// exist PVBs
	pvbs, err = backupper.ListPodVolumeBackupsByPod("default", "pod")
	require.NoError(t, err)
	assert.Len(t, pvbs, 2)
}

type logHook struct {
	entry *logrus.Entry
}

func (l *logHook) Levels() []logrus.Level {
	return []logrus.Level{logrus.ErrorLevel}
}
func (l *logHook) Fire(entry *logrus.Entry) error {
	l.entry = entry
	return nil
}

func TestWaitAllPodVolumesProcessed(t *testing.T) {
	timeoutCtx, cancelFunc := context.WithCancel(t.Context())
	cancelFunc()
	log := logrus.New()
	pvb := builder.ForPodVolumeBackup(velerov1api.DefaultNamespace, "pvb").
		PodNamespace("pod-namespace").PodName("pod-name").Volume("volume").Result()
	cases := []struct {
		name              string
		ctx               context.Context
		pvb               *velerov1api.PodVolumeBackup
		statusToBeUpdated *velerov1api.PodVolumeBackupStatus
		expectedErr       string
		expectedPVBPhase  velerov1api.PodVolumeBackupPhase
		expectedPVBCount  int
	}{
		{
			name: "contains no pvb should report no error",
			ctx:  timeoutCtx,
		},
		{
			name:             "context canceled should still return tracked pvbs",
			ctx:              timeoutCtx,
			pvb:              pvb,
			expectedErr:      "timed out waiting for all PodVolumeBackups to complete",
			expectedPVBCount: 1,
		},
		{
			name: "failed pvbs",
			ctx:  t.Context(),
			pvb:  pvb,
			statusToBeUpdated: &velerov1api.PodVolumeBackupStatus{
				Phase:   velerov1api.PodVolumeBackupPhaseFailed,
				Message: "failed",
			},
			expectedPVBPhase: velerov1api.PodVolumeBackupPhaseFailed,
			expectedErr:      "pod volume backup failed: failed",
		},
		{
			name: "completed pvbs",
			ctx:  t.Context(),
			pvb:  pvb,
			statusToBeUpdated: &velerov1api.PodVolumeBackupStatus{
				Phase:   velerov1api.PodVolumeBackupPhaseCompleted,
				Message: "completed",
			},
			expectedPVBPhase: velerov1api.PodVolumeBackupPhaseCompleted,
		},
	}

	for _, c := range cases {
		var objs []ctrlclient.Object
		if c.pvb != nil {
			objs = append(objs, c.pvb)
		}
		scheme := runtime.NewScheme()
		velerov1api.AddToScheme(scheme)
		client := ctrlfake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()

		informer := &fakeInformer{}

		logger := logrus.New()
		logHook := &logHook{}
		logger.Hooks.Add(logHook)

		backuper := newBackupper(c.ctx, log, nil, nil, informer, nil, "", &velerov1api.Backup{})
		if c.pvb != nil {
			require.NoError(t, backuper.pvbIndexer.Add(c.pvb))
			backuper.wg.Add(1)
		}

		if c.statusToBeUpdated != nil {
			pvb := &velerov1api.PodVolumeBackup{}
			err := client.Get(t.Context(), ctrlclient.ObjectKey{Namespace: c.pvb.Namespace, Name: c.pvb.Name}, pvb)
			require.NoError(t, err)

			oldPVB := pvb.DeepCopy()
			pvb.Status = *c.statusToBeUpdated
			err = client.Update(t.Context(), pvb)
			require.NoError(t, err)

			require.NotNil(t, informer.handler)
			informer.handler.OnUpdate(oldPVB, pvb)
		}

		pvbs := backuper.WaitAllPodVolumesProcessed(logger)

		if c.expectedErr != "" {
			assert.Equal(t, c.expectedErr, logHook.entry.Message)
		} else {
			assert.Nil(t, logHook.entry)
		}

		if c.expectedPVBCount > 0 {
			require.Len(t, pvbs, c.expectedPVBCount)
		}

		if c.expectedPVBPhase != "" {
			require.Len(t, pvbs, 1)
			assert.Equal(t, c.expectedPVBPhase, pvbs[0].Status.Phase)
		}
	}
}

func TestCanceledPodVolumeBackupCompletesWaitOnlyOnce(t *testing.T) {
	const backupUID = "backup-uid"

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	informer := &fakeInformer{}
	backup := builder.ForBackup(velerov1api.DefaultNamespace, "backup").
		ObjectMeta(builder.WithUID(backupUID)).
		Result()
	backupper := newBackupper(ctx, logrus.New(), nil, nil, informer, nil, "", backup)
	pvb := builder.ForPodVolumeBackup(velerov1api.DefaultNamespace, "pvb").
		PodNamespace("pod-namespace").
		PodName("pod-name").
		Volume("volume").
		Labels(map[string]string{velerov1api.BackupUIDLabel: backupUID}).
		Phase(velerov1api.PodVolumeBackupPhaseInProgress).
		Result()
	require.NoError(t, backupper.pvbIndexer.Add(pvb))
	backupper.wg.Add(1)

	waitResult := make(chan []*velerov1api.PodVolumeBackup, 1)
	go func() {
		waitResult <- backupper.WaitAllPodVolumesProcessed(logrus.New())
	}()

	canceledPVB := pvb.DeepCopy()
	canceledPVB.Status.Phase = velerov1api.PodVolumeBackupPhaseCanceled
	require.NotNil(t, informer.handler)
	require.NotPanics(t, func() {
		informer.handler.OnUpdate(pvb, canceledPVB)
	})

	select {
	case pvbs := <-waitResult:
		require.NoError(t, ctx.Err(), "wait returned because its context timed out")
		require.Len(t, pvbs, 1)
		assert.Equal(t, velerov1api.PodVolumeBackupPhaseCanceled, pvbs[0].Status.Phase)
	case <-time.After(time.Second):
		t.Fatal("wait did not complete after the PodVolumeBackup was canceled")
	}

	duplicateCanceledPVB := canceledPVB.DeepCopy()
	require.NotPanics(t, func() {
		informer.handler.OnUpdate(canceledPVB, duplicateCanceledPVB)
	}, "duplicate Canceled updates must not decrement the wait group")

	completedPVB := canceledPVB.DeepCopy()
	completedPVB.Status.Phase = velerov1api.PodVolumeBackupPhaseCompleted
	require.NotPanics(t, func() {
		informer.handler.OnUpdate(canceledPVB, completedPVB)
	}, "cross-final updates must not decrement the wait group")
}

func TestPVCBackupSummary(t *testing.T) {
	pbs := NewPVCBackupSummary()
	pbs.pvcMap["vol-1"] = builder.ForPersistentVolumeClaim("ns-1", "pvc-1").VolumeName("pv-1").Result()
	pbs.pvcMap["vol-2"] = builder.ForPersistentVolumeClaim("ns-2", "pvc-2").VolumeName("pv-2").Result()

	// it won't be added if the volme is not in the pvc map.
	pbs.addSkipped("vol-3", "whatever reason")
	assert.Empty(t, pbs.Skipped)
	pbs.addBackedup("vol-3")
	assert.Empty(t, pbs.Backedup)

	// only can be added as skipped when it's not in backedup set
	pbs.addBackedup("vol-1")
	assert.Len(t, pbs.Backedup, 1)
	assert.Equal(t, "pvc-1", pbs.Backedup["vol-1"].Name)
	pbs.addSkipped("vol-1", "whatever reason")
	assert.Empty(t, pbs.Skipped)
	pbs.addSkipped("vol-2", "vol-2 has to be skipped")
	assert.Len(t, pbs.Skipped, 1)
	assert.Equal(t, "pvc-2", pbs.Skipped["vol-2"].PVC.Name)

	// adding a vol as backedup removes it from skipped set
	pbs.addBackedup("vol-2")
	assert.Empty(t, pbs.Skipped)
	assert.Len(t, pbs.Backedup, 2)
}

func TestGetMatchAction_PendingPVC(t *testing.T) {
	// Create resource policies that skip Pending/Lost PVCs
	resPolicies := &resourcepolicies.ResourcePolicies{
		Version: "v1",
		VolumePolicies: []resourcepolicies.VolumePolicy{
			{
				Conditions: map[string]any{
					"pvcPhase": []string{"Pending", "Lost"},
				},
				Action: resourcepolicies.Action{
					Type: resourcepolicies.Skip,
				},
			},
		},
	}
	policies := &resourcepolicies.Policies{}
	err := policies.BuildPolicy(resPolicies)
	require.NoError(t, err)

	testCases := []struct {
		name           string
		pvc            *corev1api.PersistentVolumeClaim
		volume         *corev1api.Volume
		pv             *corev1api.PersistentVolume
		expectedAction *resourcepolicies.Action
		expectError    bool
	}{
		{
			name: "Pending PVC with pvcPhase skip policy should return skip action",
			pvc: builder.ForPersistentVolumeClaim("ns", "pending-pvc").
				StorageClass("test-sc").
				Phase(corev1api.ClaimPending).
				Result(),
			volume: &corev1api.Volume{
				Name: "test-volume",
				VolumeSource: corev1api.VolumeSource{
					PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
						ClaimName: "pending-pvc",
					},
				},
			},
			pv:             nil,
			expectedAction: &resourcepolicies.Action{Type: resourcepolicies.Skip},
			expectError:    false,
		},
		{
			name: "Lost PVC with pvcPhase skip policy should return skip action",
			pvc: builder.ForPersistentVolumeClaim("ns", "lost-pvc").
				StorageClass("test-sc").
				Phase(corev1api.ClaimLost).
				Result(),
			volume: &corev1api.Volume{
				Name: "test-volume",
				VolumeSource: corev1api.VolumeSource{
					PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
						ClaimName: "lost-pvc",
					},
				},
			},
			pv:             nil,
			expectedAction: &resourcepolicies.Action{Type: resourcepolicies.Skip},
			expectError:    false,
		},
		{
			name: "Bound PVC with matching PV should not match pvcPhase policy",
			pvc: builder.ForPersistentVolumeClaim("ns", "bound-pvc").
				StorageClass("test-sc").
				VolumeName("test-pv").
				Phase(corev1api.ClaimBound).
				Result(),
			volume: &corev1api.Volume{
				Name: "test-volume",
				VolumeSource: corev1api.VolumeSource{
					PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
						ClaimName: "bound-pvc",
					},
				},
			},
			pv:             builder.ForPersistentVolume("test-pv").StorageClass("test-sc").Result(),
			expectedAction: nil,
			expectError:    false,
		},
		{
			name: "Pending PVC with no matching policy should return nil action",
			pvc: builder.ForPersistentVolumeClaim("ns", "pending-pvc-no-match").
				StorageClass("test-sc").
				Phase(corev1api.ClaimPending).
				Result(),
			volume: &corev1api.Volume{
				Name: "test-volume",
				VolumeSource: corev1api.VolumeSource{
					PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
						ClaimName: "pending-pvc-no-match",
					},
				},
			},
			pv:             nil,
			expectedAction: &resourcepolicies.Action{Type: resourcepolicies.Skip}, // Will match the pvcPhase policy
			expectError:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Build fake client with PV if present
			var objs []runtime.Object
			if tc.pv != nil {
				objs = append(objs, tc.pv)
			}
			fakeClient := velerotest.NewFakeControllerRuntimeClient(t, objs...)

			b := &backupper{
				crClient: fakeClient,
			}

			action, err := b.getMatchAction(policies, tc.pvc, tc.volume)
			if tc.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			if tc.expectedAction == nil {
				assert.Nil(t, action)
			} else {
				require.NotNil(t, action)
				assert.Equal(t, tc.expectedAction.Type, action.Type)
			}
		})
	}
}

func TestGetMatchAction_PVCWithoutPVLookupError(t *testing.T) {
	// Test that when a PVC has a VolumeName but the PV doesn't exist,
	// the function ignores the error and tries to match with PVC only
	resPolicies := &resourcepolicies.ResourcePolicies{
		Version: "v1",
		VolumePolicies: []resourcepolicies.VolumePolicy{
			{
				Conditions: map[string]any{
					"pvcPhase": []string{"Pending"},
				},
				Action: resourcepolicies.Action{
					Type: resourcepolicies.Skip,
				},
			},
		},
	}
	policies := &resourcepolicies.Policies{}
	err := policies.BuildPolicy(resPolicies)
	require.NoError(t, err)

	// Pending PVC without a matching PV in the cluster
	pvc := builder.ForPersistentVolumeClaim("ns", "pending-pvc").
		StorageClass("test-sc").
		Phase(corev1api.ClaimPending).
		Result()

	volume := &corev1api.Volume{
		Name: "test-volume",
		VolumeSource: corev1api.VolumeSource{
			PersistentVolumeClaim: &corev1api.PersistentVolumeClaimVolumeSource{
				ClaimName: "pending-pvc",
			},
		},
	}

	// Empty client - no PV exists
	fakeClient := velerotest.NewFakeControllerRuntimeClient(t)

	b := &backupper{
		crClient: fakeClient,
	}

	// Should succeed even though PV lookup would fail
	// because the function ignores PV lookup errors and uses PVC-only matching
	action, err := b.getMatchAction(policies, pvc, volume)
	require.NoError(t, err)
	require.NotNil(t, action)
	assert.Equal(t, resourcepolicies.Skip, action.Type)
}
