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

package csi

import (
	"errors"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	snapshotFake "github.com/kubernetes-csi/external-snapshotter/client/v8/clientset/versioned/fake"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	storagev1api "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientTesting "k8s.io/client-go/testing"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/test"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
	"github.com/vmware-tanzu/velero/pkg/util/boolptr"
	"github.com/vmware-tanzu/velero/pkg/util/logging"
	"github.com/vmware-tanzu/velero/pkg/util/stringptr"
)

type reactor struct {
	verb        string
	resource    string
	reactorFunc clientTesting.ReactionFunc
}

// expected: &v1.VolumeSnapshot{TypeMeta:v1.TypeMeta{Kind:"", APIVersion:""}, ObjectMeta:v1.ObjectMeta{Name:"fake-vs", GenerateName:"", Namespace:"fake-ns", SelfLink:"", UID:"", ResourceVersion:"999", Generation:0, CreationTimestamp:time.Date(1, time.January, 1, 0, 0, 0, 0, time.UTC), DeletionTimestamp:<nil>, DeletionGracePeriodSeconds:(*int64)(nil), Labels:map[string]string(nil), Annotations:map[string]string(nil), OwnerReferences:[]v1.OwnerReference(nil), Finalizers:[]string(nil), ManagedFields:[]v1.ManagedFieldsEntry(nil)}, Spec:v1.VolumeSnapshotSpec{Source:v1.VolumeSnapshotSource{PersistentVolumeClaimName:(*string)(nil), VolumeSnapshotContentName:(*string)(nil)}, VolumeSnapshotClassName:(*string)(nil)}, Status:(*v1.VolumeSnapshotStatus)(0x140000af8c0)}
// actual  : &v1.VolumeSnapshot{TypeMeta:v1.TypeMeta{Kind:"", APIVersion:""}, ObjectMeta:v1.ObjectMeta{Name:"fake-vs", GenerateName:"", Namespace:"fake-ns", SelfLink:"", UID:"", ResourceVersion:"999", Generation:0, CreationTimestamp:time.Date(1, time.January, 1, 0, 0, 0, 0, time.UTC), DeletionTimestamp:<nil>, DeletionGracePeriodSeconds:(*int64)(nil), Labels:map[string]string(nil), Annotations:map[string]string(nil), OwnerReferences:[]v1.OwnerReference(nil), Finalizers:[]string(nil), ManagedFields:[]v1.ManagedFieldsEntry(nil)}, Spec:v1.VolumeSnapshotSpec{Source:v1.VolumeSnapshotSource{PersistentVolumeClaimName:(*string)(nil), VolumeSnapshotContentName:(*string)(nil)}, VolumeSnapshotClassName:(*string)(nil)}, Status:(*v1.VolumeSnapshotStatus)(0x1400024ed20)}

func TestWaitVolumeSnapshotReady(t *testing.T) {
	vscName := "fake-vsc"
	quantity := resource.MustParse("0")
	vsObj := &snapshotv1api.VolumeSnapshot{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "fake-vs",
			Namespace: "fake-ns",
		},
		Status: &snapshotv1api.VolumeSnapshotStatus{
			BoundVolumeSnapshotContentName: &vscName,
			ReadyToUse:                     boolptr.True(),
			RestoreSize:                    &quantity,
		},
	}

	errMessage := "fake-snapshot-creation-error"

	tests := []struct {
		name      string
		clientObj []runtime.Object
		vsName    string
		namespace string
		err       string
		expect    *snapshotv1api.VolumeSnapshot
	}{
		{
			name:      "get vs error",
			vsName:    "fake-vs-1",
			namespace: "fake-ns-1",
			err:       "error to get VolumeSnapshot fake-ns-1/fake-vs-1: volumesnapshots.snapshot.storage.k8s.io \"fake-vs-1\" not found",
		},
		{
			name:      "vs status is nil",
			vsName:    "fake-vs",
			namespace: "fake-ns",
			clientObj: []runtime.Object{
				&snapshotv1api.VolumeSnapshot{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "fake-vs",
						Namespace: "fake-ns",
					},
				},
			},
			err: "volume snapshot is not ready until timeout, errors: []",
		},
		{
			name:      "vsc is nil in status",
			vsName:    "fake-vs",
			namespace: "fake-ns",
			clientObj: []runtime.Object{
				&snapshotv1api.VolumeSnapshot{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "fake-vs",
						Namespace: "fake-ns",
					},
					Status: &snapshotv1api.VolumeSnapshotStatus{},
				},
			},
			err: "volume snapshot is not ready until timeout, errors: []",
		},
		{
			name:      "ready to use is nil in status",
			vsName:    "fake-vs",
			namespace: "fake-ns",
			clientObj: []runtime.Object{
				&snapshotv1api.VolumeSnapshot{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "fake-vs",
						Namespace: "fake-ns",
					},
					Status: &snapshotv1api.VolumeSnapshotStatus{
						BoundVolumeSnapshotContentName: &vscName,
					},
				},
			},
			err: "volume snapshot is not ready until timeout, errors: []",
		},
		{
			name:      "ready to use is false",
			vsName:    "fake-vs",
			namespace: "fake-ns",
			clientObj: []runtime.Object{
				&snapshotv1api.VolumeSnapshot{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "fake-vs",
						Namespace: "fake-ns",
					},
					Status: &snapshotv1api.VolumeSnapshotStatus{
						BoundVolumeSnapshotContentName: &vscName,
						ReadyToUse:                     boolptr.False(),
					},
				},
			},
			err: "volume snapshot is not ready until timeout, errors: []",
		},
		{
			name:      "snapshot creation error with message",
			vsName:    "fake-vs",
			namespace: "fake-ns",
			clientObj: []runtime.Object{
				&snapshotv1api.VolumeSnapshot{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "fake-vs",
						Namespace: "fake-ns",
					},
					Status: &snapshotv1api.VolumeSnapshotStatus{
						Error: &snapshotv1api.VolumeSnapshotError{
							Message: &errMessage,
						},
					},
				},
			},
			err: "volume snapshot is not ready until timeout, errors: [fake-snapshot-creation-error]",
		},
		{
			name:      "snapshot creation error without message",
			vsName:    "fake-vs",
			namespace: "fake-ns",
			clientObj: []runtime.Object{
				&snapshotv1api.VolumeSnapshot{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "fake-vs",
						Namespace: "fake-ns",
					},
					Status: &snapshotv1api.VolumeSnapshotStatus{
						Error: &snapshotv1api.VolumeSnapshotError{},
					},
				},
			},
			err: "volume snapshot is not ready until timeout, errors: [" + stringptr.NilString + "]",
		},
		{
			name:      "success",
			vsName:    "fake-vs",
			namespace: "fake-ns",
			clientObj: []runtime.Object{
				vsObj,
			},
			expect: vsObj,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakeClient := snapshotFake.NewSimpleClientset(test.clientObj...)

			vs, err := WaitVolumeSnapshotReady(t.Context(), fakeClient.SnapshotV1(), test.vsName, test.namespace, time.Millisecond, velerotest.NewLogger())
			if err != nil {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
			}

			assert.Equal(t, test.expect, vs)
		})
	}
}

func TestGetVolumeSnapshotContentForVolumeSnapshot(t *testing.T) {
	vscName := "fake-vsc"
	vsObj := &snapshotv1api.VolumeSnapshot{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "fake-vs",
			Namespace: "fake-ns",
		},
		Status: &snapshotv1api.VolumeSnapshotStatus{
			BoundVolumeSnapshotContentName: &vscName,
			ReadyToUse:                     boolptr.True(),
			RestoreSize:                    &resource.Quantity{},
		},
	}

	vscObj := &snapshotv1api.VolumeSnapshotContent{
		ObjectMeta: metav1.ObjectMeta{
			Name: "fake-vsc",
		},
	}

	tests := []struct {
		name        string
		snapshotObj *snapshotv1api.VolumeSnapshot
		clientObj   []runtime.Object
		vsName      string
		namespace   string
		err         string
		expect      *snapshotv1api.VolumeSnapshotContent
	}{
		{
			name:      "vs status is nil",
			vsName:    "fake-vs",
			namespace: "fake-ns",
			snapshotObj: &snapshotv1api.VolumeSnapshot{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "fake-vs",
					Namespace: "fake-ns",
				},
			},
			err: "invalid snapshot info in volume snapshot fake-vs",
		},
		{
			name:      "vsc is nil in status",
			vsName:    "fake-vs",
			namespace: "fake-ns",
			snapshotObj: &snapshotv1api.VolumeSnapshot{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "fake-vs",
					Namespace: "fake-ns",
				},
			},
			err: "invalid snapshot info in volume snapshot fake-vs",
		},
		{
			name:        "get vsc fail",
			vsName:      "fake-vs",
			namespace:   "fake-ns",
			snapshotObj: vsObj,
			err:         "error getting volume snapshot content from API: volumesnapshotcontents.snapshot.storage.k8s.io \"fake-vsc\" not found",
		},
		{
			name:        "success",
			vsName:      "fake-vs",
			namespace:   "fake-ns",
			snapshotObj: vsObj,
			clientObj:   []runtime.Object{vscObj},
			expect:      vscObj,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakeClient := snapshotFake.NewSimpleClientset(test.clientObj...)

			vs, err := GetVolumeSnapshotContentForVolumeSnapshot(test.snapshotObj, fakeClient.SnapshotV1())
			if err != nil {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
			}

			assert.Equal(t, test.expect, vs)
		})
	}
}

func TestEnsureDeleteVS(t *testing.T) {
	vsObj := &snapshotv1api.VolumeSnapshot{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "fake-vs",
			Namespace: "fake-ns",
		},
	}

	vsObjWithFinalizer := &snapshotv1api.VolumeSnapshot{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "fake-vs",
			Namespace:  "fake-ns",
			Finalizers: []string{"fake-finalizer-1", "fake-finalizer-2"},
		},
	}

	tests := []struct {
		name      string
		clientObj []runtime.Object
		vsName    string
		namespace string
		reactors  []reactor
		err       string
	}{
		{
			name:      "delete fail",
			vsName:    "fake-vs",
			namespace: "fake-ns",
			err:       "error to delete volume snapshot: volumesnapshots.snapshot.storage.k8s.io \"fake-vs\" not found",
		},
		{
			name:      "wait fail",
			vsName:    "fake-vs",
			namespace: "fake-ns",
			clientObj: []runtime.Object{vsObj},
			reactors: []reactor{
				{
					verb:     "get",
					resource: "volumesnapshots",
					reactorFunc: func(action clientTesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, errors.New("fake-get-error")
					},
				},
			},
			err: "error to assure VolumeSnapshot is deleted, fake-vs: error to get VolumeSnapshot fake-vs: fake-get-error",
		},
		{
			name:      "wait timeout",
			vsName:    "fake-vs",
			namespace: "fake-ns",
			clientObj: []runtime.Object{vsObjWithFinalizer},
			reactors: []reactor{
				{
					verb:     "delete",
					resource: "volumesnapshots",
					reactorFunc: func(action clientTesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, nil
					},
				},
			},
			err: "timeout to assure VolumeSnapshot fake-vs is deleted, finalizers in VS [fake-finalizer-1 fake-finalizer-2]",
		},
		{
			name:      "wait timeout, no finalizer",
			vsName:    "fake-vs",
			namespace: "fake-ns",
			clientObj: []runtime.Object{vsObj},
			reactors: []reactor{
				{
					verb:     "delete",
					resource: "volumesnapshots",
					reactorFunc: func(action clientTesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, nil
					},
				},
			},
			err: "timeout to assure VolumeSnapshot fake-vs is deleted, finalizers in VS []",
		},
		{
			name:      "success",
			vsName:    "fake-vs",
			namespace: "fake-ns",
			clientObj: []runtime.Object{vsObj},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakeSnapshotClient := snapshotFake.NewSimpleClientset(test.clientObj...)

			for _, reactor := range test.reactors {
				fakeSnapshotClient.Fake.PrependReactor(reactor.verb, reactor.resource, reactor.reactorFunc)
			}

			err := EnsureDeleteVS(t.Context(), fakeSnapshotClient.SnapshotV1(), test.vsName, test.namespace, time.Millisecond)
			if err != nil {
				assert.EqualError(t, err, test.err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestEnsureDeleteVSC(t *testing.T) {
	vscObj := &snapshotv1api.VolumeSnapshotContent{
		ObjectMeta: metav1.ObjectMeta{
			Name: "fake-vsc",
		},
	}

	vscObjWithFinalizer := &snapshotv1api.VolumeSnapshotContent{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "fake-vsc",
			Finalizers: []string{"fake-finalizer-1", "fake-finalizer-2"},
		},
	}

	tests := []struct {
		name      string
		clientObj []runtime.Object
		reactors  []reactor
		vscName   string
		err       string
	}{
		{
			name:    "delete fail on VSC not found",
			vscName: "fake-vsc",
		},
		{
			name:      "delete fail on others",
			vscName:   "fake-vsc",
			clientObj: []runtime.Object{vscObj},
			reactors: []reactor{
				{
					verb:     "delete",
					resource: "volumesnapshotcontents",
					reactorFunc: func(action clientTesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, errors.New("fake-delete-error")
					},
				},
			},
			err: "error to delete volume snapshot content: fake-delete-error",
		},
		{
			name:      "wait fail",
			vscName:   "fake-vsc",
			clientObj: []runtime.Object{vscObj},
			reactors: []reactor{
				{
					verb:     "get",
					resource: "volumesnapshotcontents",
					reactorFunc: func(action clientTesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, errors.New("fake-get-error")
					},
				},
			},
			err: "error to assure VolumeSnapshotContent is deleted, fake-vsc: error to get VolumeSnapshotContent fake-vsc: fake-get-error",
		},
		{
			name:      "wait timeout",
			vscName:   "fake-vsc",
			clientObj: []runtime.Object{vscObjWithFinalizer},
			reactors: []reactor{
				{
					verb:     "delete",
					resource: "volumesnapshotcontents",
					reactorFunc: func(action clientTesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, nil
					},
				},
			},
			err: "timeout to assure VolumeSnapshotContent fake-vsc is deleted, finalizers in VSC [fake-finalizer-1 fake-finalizer-2]",
		},
		{
			name:      "wait timeout, no finalizer",
			vscName:   "fake-vsc",
			clientObj: []runtime.Object{vscObj},
			reactors: []reactor{
				{
					verb:     "delete",
					resource: "volumesnapshotcontents",
					reactorFunc: func(action clientTesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, nil
					},
				},
			},
			err: "timeout to assure VolumeSnapshotContent fake-vsc is deleted, finalizers in VSC []",
		},
		{
			name:      "success",
			vscName:   "fake-vsc",
			clientObj: []runtime.Object{vscObj},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakeSnapshotClient := snapshotFake.NewSimpleClientset(test.clientObj...)

			for _, reactor := range test.reactors {
				fakeSnapshotClient.Fake.PrependReactor(reactor.verb, reactor.resource, reactor.reactorFunc)
			}

			err := EnsureDeleteVSC(t.Context(), fakeSnapshotClient.SnapshotV1(), test.vscName, time.Millisecond)
			if test.err != "" {
				assert.EqualError(t, err, test.err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDeleteVolumeSnapshotContentIfAny(t *testing.T) {
	tests := []struct {
		name       string
		clientObj  []runtime.Object
		reactors   []reactor
		vscName    string
		logMessage string
		logLevel   string
		logError   string
	}{
		{
			name:       "vsc not exist",
			vscName:    "fake-vsc",
			logMessage: "Abort deleting VSC, it doesn't exist fake-vsc",
			logLevel:   "level=debug",
		},
		{
			name:    "deleete fail",
			vscName: "fake-vsc",
			reactors: []reactor{
				{
					verb:     "delete",
					resource: "volumesnapshotcontents",
					reactorFunc: func(action clientTesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, errors.New("fake-delete-error")
					},
				},
			},
			logMessage: "Failed to delete volume snapshot content fake-vsc",
			logLevel:   "level=error",
			logError:   "error=fake-delete-error",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakeSnapshotClient := snapshotFake.NewSimpleClientset(test.clientObj...)

			for _, reactor := range test.reactors {
				fakeSnapshotClient.Fake.PrependReactor(reactor.verb, reactor.resource, reactor.reactorFunc)
			}

			logMessage := ""

			DeleteVolumeSnapshotContentIfAny(t.Context(), fakeSnapshotClient.SnapshotV1(), test.vscName, velerotest.NewSingleLogger(&logMessage))

			if len(test.logMessage) > 0 {
				assert.Contains(t, logMessage, test.logMessage)
			}

			if len(test.logLevel) > 0 {
				assert.Contains(t, logMessage, test.logLevel)
			}

			if len(test.logError) > 0 {
				assert.Contains(t, logMessage, test.logError)
			}
		})
	}
}

func TestDeleteVolumeSnapshotIfAny(t *testing.T) {
	tests := []struct {
		name        string
		clientObj   []runtime.Object
		reactors    []reactor
		vsName      string
		vsNamespace string
		logMessage  string
		logLevel    string
		logError    string
	}{
		{
			name:        "vs not exist",
			vsName:      "fake-vs",
			vsNamespace: "fake-ns",
			logMessage:  "Abort deleting volume snapshot, it doesn't exist fake-ns/fake-vs",
			logLevel:    "level=debug",
		},
		{
			name:        "delete fail",
			vsName:      "fake-vs",
			vsNamespace: "fake-ns",
			reactors: []reactor{
				{
					verb:     "delete",
					resource: "volumesnapshots",
					reactorFunc: func(action clientTesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, errors.New("fake-delete-error")
					},
				},
			},
			logMessage: "Failed to delete volume snapshot fake-ns/fake-vs",
			logLevel:   "level=error",
			logError:   "error=fake-delete-error",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakeSnapshotClient := snapshotFake.NewSimpleClientset(test.clientObj...)

			for _, reactor := range test.reactors {
				fakeSnapshotClient.Fake.PrependReactor(reactor.verb, reactor.resource, reactor.reactorFunc)
			}

			logMessage := ""

			DeleteVolumeSnapshotIfAny(t.Context(), fakeSnapshotClient.SnapshotV1(), test.vsName, test.vsNamespace, velerotest.NewSingleLogger(&logMessage))

			if len(test.logMessage) > 0 {
				assert.Contains(t, logMessage, test.logMessage)
			}

			if len(test.logLevel) > 0 {
				assert.Contains(t, logMessage, test.logLevel)
			}

			if len(test.logError) > 0 {
				assert.Contains(t, logMessage, test.logError)
			}
		})
	}
}

func TestRetainVSC(t *testing.T) {
	vscObj := &snapshotv1api.VolumeSnapshotContent{
		ObjectMeta: metav1.ObjectMeta{
			Name: "fake-vsc",
		},
	}

	tests := []struct {
		name      string
		clientObj []runtime.Object
		reactors  []reactor
		vsc       *snapshotv1api.VolumeSnapshotContent
		updated   *snapshotv1api.VolumeSnapshotContent
		err       string
	}{
		{
			name: "already retained",
			vsc: &snapshotv1api.VolumeSnapshotContent{
				ObjectMeta: metav1.ObjectMeta{
					Name: "fake-vsc",
				},
				Spec: snapshotv1api.VolumeSnapshotContentSpec{
					DeletionPolicy: snapshotv1api.VolumeSnapshotContentRetain,
				},
			},
			updated: &snapshotv1api.VolumeSnapshotContent{
				ObjectMeta: metav1.ObjectMeta{
					Name: "fake-vsc",
				},
				Spec: snapshotv1api.VolumeSnapshotContentSpec{
					DeletionPolicy: snapshotv1api.VolumeSnapshotContentRetain,
				},
			},
		},
		{
			name: "path vsc fail",
			vsc: &snapshotv1api.VolumeSnapshotContent{
				ObjectMeta: metav1.ObjectMeta{
					Name: "fake-vsc",
				},
				Spec: snapshotv1api.VolumeSnapshotContentSpec{
					DeletionPolicy: snapshotv1api.VolumeSnapshotContentDelete,
				},
			},
			reactors: []reactor{
				{
					verb:     "patch",
					resource: "volumesnapshotcontents",
					reactorFunc: func(action clientTesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, errors.New("fake-patch-error")
					},
				},
			},
			err: "error patching VSC: fake-patch-error",
		},
		{
			name: "success",
			vsc: &snapshotv1api.VolumeSnapshotContent{
				ObjectMeta: metav1.ObjectMeta{
					Name: "fake-vsc",
				},
				Spec: snapshotv1api.VolumeSnapshotContentSpec{
					DeletionPolicy: snapshotv1api.VolumeSnapshotContentDelete,
				},
			},
			clientObj: []runtime.Object{vscObj},
			updated: &snapshotv1api.VolumeSnapshotContent{
				ObjectMeta: metav1.ObjectMeta{
					Name: "fake-vsc",
				},
				Spec: snapshotv1api.VolumeSnapshotContentSpec{
					DeletionPolicy: snapshotv1api.VolumeSnapshotContentRetain,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakeSnapshotClient := snapshotFake.NewSimpleClientset(test.clientObj...)

			for _, reactor := range test.reactors {
				fakeSnapshotClient.Fake.PrependReactor(reactor.verb, reactor.resource, reactor.reactorFunc)
			}

			returned, err := RetainVSC(t.Context(), fakeSnapshotClient.SnapshotV1(), test.vsc)

			if len(test.err) == 0 {
				require.NoError(t, err)
			} else {
				require.EqualError(t, err, test.err)
			}

			if test.updated != nil {
				assert.Equal(t, *test.updated, *returned)
			} else {
				assert.Nil(t, returned)
			}
		})
	}
}

func TestRemoveVSCProtect(t *testing.T) {
	vscObj := &snapshotv1api.VolumeSnapshotContent{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "fake-vsc",
			Finalizers: []string{volumeSnapshotContentProtectFinalizer},
		},
	}

	tests := []struct {
		name      string
		clientObj []runtime.Object
		reactors  []reactor
		vsc       string
		updated   *snapshotv1api.VolumeSnapshotContent
		timeout   time.Duration
		err       string
	}{
		{
			name: "get vsc error",
			vsc:  "fake-vsc",
			err:  "error to get VolumeSnapshotContent fake-vsc: volumesnapshotcontents.snapshot.storage.k8s.io \"fake-vsc\" not found",
		},
		{
			name:      "update vsc fail",
			vsc:       "fake-vsc",
			clientObj: []runtime.Object{vscObj},
			reactors: []reactor{
				{
					verb:     "update",
					resource: "volumesnapshotcontents",
					reactorFunc: func(action clientTesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, errors.New("fake-update-error")
					},
				},
			},
			err: "error to update VolumeSnapshotContent fake-vsc: fake-update-error",
		},
		{
			name:      "update vsc timeout",
			vsc:       "fake-vsc",
			clientObj: []runtime.Object{vscObj},
			reactors: []reactor{
				{
					verb:     "update",
					resource: "volumesnapshotcontents",
					reactorFunc: func(action clientTesting.Action) (handled bool, ret runtime.Object, err error) {
						return true, nil, &apierrors.StatusError{ErrStatus: metav1.Status{
							Reason: metav1.StatusReasonConflict,
						}}
					},
				},
			},
			timeout: time.Second,
			err:     "context deadline exceeded",
		},
		{
			name:      "succeed",
			vsc:       "fake-vsc",
			clientObj: []runtime.Object{vscObj},
			timeout:   time.Second,
			updated: &snapshotv1api.VolumeSnapshotContent{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "fake-vsc",
					Finalizers: []string{},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fakeSnapshotClient := snapshotFake.NewSimpleClientset(test.clientObj...)

			for _, reactor := range test.reactors {
				fakeSnapshotClient.Fake.PrependReactor(reactor.verb, reactor.resource, reactor.reactorFunc)
			}

			err := RemoveVSCProtect(t.Context(), fakeSnapshotClient.SnapshotV1(), test.vsc, test.timeout)

			if len(test.err) == 0 {
				require.NoError(t, err)
			} else {
				require.EqualError(t, err, test.err)
			}

			if test.updated != nil {
				updated, err := fakeSnapshotClient.SnapshotV1().VolumeSnapshotContents().Get(t.Context(), test.vsc, metav1.GetOptions{})
				require.NoError(t, err)

				assert.Equal(t, test.updated.Finalizers, updated.Finalizers)
			}
		})
	}
}

func TestGetVolumeSnapshotClass(t *testing.T) {
	// backups
	backupFoo := &velerov1api.Backup{
		ObjectMeta: metav1.ObjectMeta{
			Name: "foo",
			Annotations: map[string]string{
				"velero.io/csi-volumesnapshot-class_foo.csi.k8s.io": "foowithoutlabel",
			},
		},
		Spec: velerov1api.BackupSpec{
			IncludedNamespaces: []string{"ns1", "ns2"},
		},
	}
	backupFoo2 := &velerov1api.Backup{
		ObjectMeta: metav1.ObjectMeta{
			Name: "foo2",
			Annotations: map[string]string{
				"velero.io/csi-volumesnapshot-class_foo.csi.k8s.io": "foo2",
			},
		},
		Spec: velerov1api.BackupSpec{
			IncludedNamespaces: []string{"ns1", "ns2"},
		},
	}

	backupBar2 := &velerov1api.Backup{
		ObjectMeta: metav1.ObjectMeta{
			Name: "bar",
			Annotations: map[string]string{
				"velero.io/csi-volumesnapshot-class_bar.csi.k8s.io": "bar2",
			},
		},
		Spec: velerov1api.BackupSpec{
			IncludedNamespaces: []string{"ns1", "ns2"},
		},
	}

	backupNone := &velerov1api.Backup{
		ObjectMeta: metav1.ObjectMeta{
			Name: "none",
		},
		Spec: velerov1api.BackupSpec{
			IncludedNamespaces: []string{"ns1", "ns2"},
		},
	}

	// pvcs
	pvcFoo := &corev1api.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name: "foo",
			Annotations: map[string]string{
				"velero.io/csi-volumesnapshot-class": "foowithoutlabel",
			},
		},
		Spec: corev1api.PersistentVolumeClaimSpec{},
	}
	pvcFoo2 := &corev1api.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name: "foo",
			Annotations: map[string]string{
				"velero.io/csi-volumesnapshot-class": "foo2",
			},
		},
		Spec: corev1api.PersistentVolumeClaimSpec{},
	}
	pvcNone := &corev1api.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name: "none",
		},
		Spec: corev1api.PersistentVolumeClaimSpec{},
	}

	// vsclasses
	hostpathClass := &snapshotv1api.VolumeSnapshotClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "hostpath",
			Labels: map[string]string{
				velerov1api.VolumeSnapshotClassSelectorLabel: "foo",
			},
		},
		Driver: "hostpath.csi.k8s.io",
	}

	fooClass := &snapshotv1api.VolumeSnapshotClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "foo",
			Labels: map[string]string{
				velerov1api.VolumeSnapshotClassSelectorLabel: "foo",
			},
		},
		Driver: "foo.csi.k8s.io",
	}
	fooClassWithoutLabel := &snapshotv1api.VolumeSnapshotClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "foowithoutlabel",
		},
		Driver: "foo.csi.k8s.io",
	}

	barClass := &snapshotv1api.VolumeSnapshotClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "bar",
			Labels: map[string]string{
				velerov1api.VolumeSnapshotClassSelectorLabel: "true",
			},
		},
		Driver: "bar.csi.k8s.io",
	}

	barClass2 := &snapshotv1api.VolumeSnapshotClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "bar2",
			Labels: map[string]string{
				velerov1api.VolumeSnapshotClassSelectorLabel: "true",
			},
		},
		Driver: "bar.csi.k8s.io",
	}

	sctestClass := &snapshotv1api.VolumeSnapshotClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "sctest",
		},
		Driver: "foo.csi.k8s.io",
	}

	// storageclasses
	fooStorageClass := &storagev1api.StorageClass{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "foo",
			Labels: map[string]string{},
		},
		Provisioner: "foo.csi.k8s.io",
	}

	fooannotationStorageClass := &storagev1api.StorageClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "foo",
			Annotations: map[string]string{
				"velero.io/csi-volumesnapshot-class": "sctest",
			},
		},
		Provisioner: "foo.csi.k8s.io",
	}

	barStorageClass := &storagev1api.StorageClass{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "bar",
			Labels: map[string]string{},
		},
		Provisioner: "bar.csi.k8s.io",
	}

	hostpathStorageClass := &storagev1api.StorageClass{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "hostpath",
			Labels: map[string]string{},
		},
		Provisioner: "hostpath.csi.k8s.io",
	}

	blahStorageClass := &storagev1api.StorageClass{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "blah",
			Labels: map[string]string{},
		},
		Provisioner: "blah.csi.k8s.io",
	}

	objs := []runtime.Object{hostpathClass, sctestClass, fooClass, barClass, fooClassWithoutLabel, barClass2}
	fakeClient := velerotest.NewFakeControllerRuntimeClient(t, objs...)

	testCases := []struct {
		name         string
		storageClass *storagev1api.StorageClass
		pvc          *corev1api.PersistentVolumeClaim
		backup       *velerov1api.Backup
		expectedVSC  *snapshotv1api.VolumeSnapshotClass
		expectError  bool
	}{
		{
			name:         "no annotations on pvc and backup, should find hostpath volumesnapshotclass using default behavior of labels",
			storageClass: hostpathStorageClass,
			pvc:          pvcNone,
			backup:       backupNone,
			expectedVSC:  hostpathClass,
			expectError:  false,
		},
		{
			name:         "foowithoutlabel VSC annotations on pvc",
			storageClass: fooStorageClass,
			pvc:          pvcFoo,
			backup:       backupNone,
			expectedVSC:  fooClassWithoutLabel,
			expectError:  false,
		},
		{
			name:         "sctest VSC annotations on StorageClass",
			storageClass: fooannotationStorageClass,
			pvc:          pvcNone,
			backup:       backupNone,
			expectedVSC:  sctestClass,
			expectError:  false,
		},
		{
			name:         "foowithoutlabel VSC annotations on pvc, but csi driver does not match, no annotation on backup so fallback to default behavior of labels",
			storageClass: barStorageClass,
			pvc:          pvcFoo,
			backup:       backupNone,
			expectedVSC:  barClass,
			expectError:  false,
		},
		{
			name:         "foowithoutlabel VSC annotations on pvc, but csi driver does not match so fallback to fetch from backupAnnotations ",
			storageClass: barStorageClass,
			pvc:          pvcFoo,
			backup:       backupBar2,
			expectedVSC:  barClass2,
			expectError:  false,
		},
		{
			name:         "foowithoutlabel VSC annotations on backup for foo.csi.k8s.io",
			storageClass: fooStorageClass,
			pvc:          pvcNone,
			backup:       backupFoo,
			expectedVSC:  fooClassWithoutLabel,
			expectError:  false,
		},
		{
			name:         "foowithoutlabel VSC annotations on backup for bar.csi.k8s.io, no annotation corresponding to foo.csi.k8s.io, so fallback to default behavior of labels",
			storageClass: barStorageClass,
			pvc:          pvcNone,
			backup:       backupFoo,
			expectedVSC:  barClass,
			expectError:  false,
		},
		{
			name:         "no snapshotClass for given driver",
			storageClass: blahStorageClass,
			pvc:          pvcNone,
			backup:       backupNone,
			expectedVSC:  nil,
			expectError:  true,
		},
		{
			name:         "foo2 VSC annotations on pvc, but doesn't exist in cluster, fallback to default behavior of labels",
			storageClass: fooStorageClass,
			pvc:          pvcFoo2,
			backup:       backupFoo2,
			expectedVSC:  fooClass,
			expectError:  false,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actualSnapshotClass, actualError := GetVolumeSnapshotClass(
				tc.storageClass, tc.backup, tc.pvc, logrus.New(), fakeClient)
			if tc.expectError {
				require.Error(t, actualError)
				assert.Nil(t, actualSnapshotClass)
				return
			}
			assert.Equal(t, tc.expectedVSC, actualSnapshotClass)
		})
	}
}

func TestGetVolumeSnapshotClassForStorageClass(t *testing.T) {
	hostpathClass := &snapshotv1api.VolumeSnapshotClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "hostpath",
			Labels: map[string]string{
				velerov1api.VolumeSnapshotClassSelectorLabel: "foo",
			},
		},
		Driver: "hostpath.csi.k8s.io",
	}

	fooClass := &snapshotv1api.VolumeSnapshotClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "foo",
			Labels: map[string]string{
				velerov1api.VolumeSnapshotClassSelectorLabel: "foo",
			},
		},
		Driver: "foo.csi.k8s.io",
	}

	barClass := &snapshotv1api.VolumeSnapshotClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "bar",
			Labels: map[string]string{
				velerov1api.VolumeSnapshotClassSelectorLabel: "foo",
			},
		},
		Driver: "bar.csi.k8s.io",
	}

	bazClass := &snapshotv1api.VolumeSnapshotClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "baz",
		},
		Driver: "baz.csi.k8s.io",
	}

	ambClass1 := &snapshotv1api.VolumeSnapshotClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "amb1",
		},
		Driver: "amb.csi.k8s.io",
	}

	ambClass2 := &snapshotv1api.VolumeSnapshotClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "amb2",
		},
		Driver: "amb.csi.k8s.io",
	}

	snapshotClasses := &snapshotv1api.VolumeSnapshotClassList{
		Items: []snapshotv1api.VolumeSnapshotClass{
			*hostpathClass, *fooClass, *barClass, *bazClass, *ambClass1, *ambClass2},
	}

	testCases := []struct {
		name        string
		driverName  string
		expectedVSC *snapshotv1api.VolumeSnapshotClass
		expectError bool
	}{
		{
			name:        "should find hostpath volumesnapshotclass",
			driverName:  "hostpath.csi.k8s.io",
			expectedVSC: hostpathClass,
			expectError: false,
		},
		{
			name:        "should find foo volumesnapshotclass",
			driverName:  "foo.csi.k8s.io",
			expectedVSC: fooClass,
			expectError: false,
		},
		{
			name:        "should find bar volumesnapshotclass",
			driverName:  "bar.csi.k8s.io",
			expectedVSC: barClass,
			expectError: false,
		},
		{
			name:        "should find baz volumesnapshotclass without \"velero.io/csi-volumesnapshot-class\" label, b/c there's only one vsclass matching the driver name",
			driverName:  "baz.csi.k8s.io",
			expectedVSC: bazClass,
			expectError: false,
		},
		{
			name:        "should not find amb volumesnapshotclass without \"velero.io/csi-volumesnapshot-class\" label, b/c there're  more than one vsclass matching the driver name",
			driverName:  "amb.csi.k8s.io",
			expectedVSC: nil,
			expectError: true,
		},
		{
			name:        "should not find does-not-exist volumesnapshotclass",
			driverName:  "not-found.csi.k8s.io",
			expectedVSC: nil,
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actualVSC, actualError := GetVolumeSnapshotClassForStorageClass(tc.driverName, snapshotClasses)

			if tc.expectError {
				require.Error(t, actualError)
				assert.Nil(t, actualVSC)
				return
			}

			assert.Equalf(t, tc.expectedVSC.Name, actualVSC.Name, "unexpected volumesnapshotclass name returned. Want: %s; Got:%s", tc.expectedVSC.Name, actualVSC.Name)
			assert.Equalf(t, tc.expectedVSC.Driver, actualVSC.Driver, "unexpected driver name returned. Want: %s; Got:%s", tc.expectedVSC.Driver, actualVSC.Driver)
		})
	}
}

func TestIsVolumeSnapshotClassHasListerSecret(t *testing.T) {
	testCases := []struct {
		name      string
		snapClass snapshotv1api.VolumeSnapshotClass
		expected  bool
	}{
		{
			name: "should find both annotations",
			snapClass: snapshotv1api.VolumeSnapshotClass{
				ObjectMeta: metav1.ObjectMeta{
					Name: "class-1",
					Annotations: map[string]string{
						velerov1api.PrefixedListSecretNameAnnotation:      "snapListSecret",
						velerov1api.PrefixedListSecretNamespaceAnnotation: "awesome-ns",
					},
				},
			},
			expected: true,
		},
		{
			name: "should not find both annotations name is missing",
			snapClass: snapshotv1api.VolumeSnapshotClass{
				ObjectMeta: metav1.ObjectMeta{
					Name: "class-1",
					Annotations: map[string]string{
						"foo": "snapListSecret",
						velerov1api.PrefixedListSecretNamespaceAnnotation: "awesome-ns",
					},
				},
			},
			expected: false,
		},
		{
			name: "should not find both annotations namespace is missing",
			snapClass: snapshotv1api.VolumeSnapshotClass{
				ObjectMeta: metav1.ObjectMeta{
					Name: "class-1",
					Annotations: map[string]string{
						velerov1api.PrefixedListSecretNameAnnotation: "snapListSecret",
						"foo": "awesome-ns",
					},
				},
			},
			expected: false,
		},
		{
			name: "should not find expected annotation non-empty annotation",
			snapClass: snapshotv1api.VolumeSnapshotClass{
				ObjectMeta: metav1.ObjectMeta{
					Name: "class-2",
					Annotations: map[string]string{
						"foo": "snapListSecret",
						"bar": "awesome-ns",
					},
				},
			},
			expected: false,
		},
		{
			name: "should not find expected annotation nil annotation",
			snapClass: snapshotv1api.VolumeSnapshotClass{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "class-3",
					Annotations: nil,
				},
			},
			expected: false,
		},
		{
			name: "should not find expected annotation empty annotation",
			snapClass: snapshotv1api.VolumeSnapshotClass{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "class-3",
					Annotations: map[string]string{},
				},
			},
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := IsVolumeSnapshotClassHasListerSecret(&tc.snapClass)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestIsVolumeSnapshotContentHasDeleteSecret(t *testing.T) {
	testCases := []struct {
		name     string
		vsc      snapshotv1api.VolumeSnapshotContent
		expected bool
	}{
		{
			name: "should find both annotations",
			vsc: snapshotv1api.VolumeSnapshotContent{
				ObjectMeta: metav1.ObjectMeta{
					Name: "vsc-1",
					Annotations: map[string]string{
						velerov1api.PrefixedSecretNameAnnotation:      "delSnapSecret",
						velerov1api.PrefixedSecretNamespaceAnnotation: "awesome-ns",
					},
				},
			},
			expected: true,
		},
		{
			name: "should not find both annotations name is missing",
			vsc: snapshotv1api.VolumeSnapshotContent{
				ObjectMeta: metav1.ObjectMeta{
					Name: "vsc-2",
					Annotations: map[string]string{
						"foo": "delSnapSecret",
						velerov1api.PrefixedSecretNamespaceAnnotation: "awesome-ns",
					},
				},
			},
			expected: false,
		},
		{
			name: "should not find both annotations namespace is missing",
			vsc: snapshotv1api.VolumeSnapshotContent{
				ObjectMeta: metav1.ObjectMeta{
					Name: "vsc-3",
					Annotations: map[string]string{
						velerov1api.PrefixedSecretNameAnnotation: "delSnapSecret",
						"foo":                                    "awesome-ns",
					},
				},
			},
			expected: false,
		},
		{
			name: "should not find expected annotation non-empty annotation",
			vsc: snapshotv1api.VolumeSnapshotContent{
				ObjectMeta: metav1.ObjectMeta{
					Name: "vsc-4",
					Annotations: map[string]string{
						"foo": "delSnapSecret",
						"bar": "awesome-ns",
					},
				},
			},
			expected: false,
		},
		{
			name: "should not find expected annotation empty annotation",
			vsc: snapshotv1api.VolumeSnapshotContent{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "vsc-5",
					Annotations: map[string]string{},
				},
			},
			expected: false,
		},
		{
			name: "should not find expected annotation nil annotation",
			vsc: snapshotv1api.VolumeSnapshotContent{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "vsc-6",
					Annotations: nil,
				},
			},
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := IsVolumeSnapshotContentHasDeleteSecret(&tc.vsc)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestIsVolumeSnapshotExists(t *testing.T) {
	vsExists := &snapshotv1api.VolumeSnapshot{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "vs-exists",
			Namespace: "default",
		},
	}
	vsNotExists := &snapshotv1api.VolumeSnapshot{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "vs-does-not-exists",
			Namespace: "default",
		},
	}

	objs := []runtime.Object{vsExists}
	fakeClient := velerotest.NewFakeControllerRuntimeClient(t, objs...)
	testCases := []struct {
		name     string
		expected bool
		vs       *snapshotv1api.VolumeSnapshot
	}{
		{
			name:     "should find existing VolumeSnapshot object",
			expected: true,
			vs:       vsExists,
		},
		{
			name:     "should not find non-existing VolumeSnapshot object",
			expected: false,
			vs:       vsNotExists,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := IsVolumeSnapshotExists(tc.vs.Namespace, tc.vs.Name, fakeClient)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestSetVolumeSnapshotContentDeletionPolicy(t *testing.T) {
	testCases := []struct {
		name         string
		inputVSCName string
		policy       snapshotv1api.DeletionPolicy
		objs         []runtime.Object
		expectError  bool
	}{
		{
			name:         "should update DeletionPolicy of a VSC from retain to delete",
			inputVSCName: "retainVSC",
			policy:       snapshotv1api.VolumeSnapshotContentDelete,
			objs: []runtime.Object{
				&snapshotv1api.VolumeSnapshotContent{
					ObjectMeta: metav1.ObjectMeta{
						Name: "retainVSC",
					},
					Spec: snapshotv1api.VolumeSnapshotContentSpec{
						DeletionPolicy: snapshotv1api.VolumeSnapshotContentRetain,
					},
				},
			},
			expectError: false,
		},
		{
			name:         "should be a no-op updating if DeletionPolicy of a VSC is already Delete",
			inputVSCName: "deleteVSC",
			policy:       snapshotv1api.VolumeSnapshotContentDelete,
			objs: []runtime.Object{
				&snapshotv1api.VolumeSnapshotContent{
					ObjectMeta: metav1.ObjectMeta{
						Name: "deleteVSC",
					},
					Spec: snapshotv1api.VolumeSnapshotContentSpec{
						DeletionPolicy: snapshotv1api.VolumeSnapshotContentDelete,
					},
				},
			},
			expectError: false,
		},
		{
			name:         "should update DeletionPolicy of a VSC with no DeletionPolicy",
			inputVSCName: "nothingVSC",
			policy:       snapshotv1api.VolumeSnapshotContentDelete,
			objs: []runtime.Object{
				&snapshotv1api.VolumeSnapshotContent{
					ObjectMeta: metav1.ObjectMeta{
						Name: "nothingVSC",
					},
					Spec: snapshotv1api.VolumeSnapshotContentSpec{},
				},
			},
			expectError: false,
		},
		{
			name:         "should return not found error if supplied VSC does not exist",
			inputVSCName: "does-not-exist",
			objs:         []runtime.Object{},
			expectError:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fakeClient := velerotest.NewFakeControllerRuntimeClient(t, tc.objs...)
			_, err := SetVolumeSnapshotContentDeletionPolicy(tc.inputVSCName, fakeClient, tc.policy)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				actual := new(snapshotv1api.VolumeSnapshotContent)
				err := fakeClient.Get(
					t.Context(),
					crclient.ObjectKey{Name: tc.inputVSCName},
					actual,
				)
				require.NoError(t, err)
				assert.Equal(
					t,
					tc.policy,
					actual.Spec.DeletionPolicy,
				)
			}
		})
	}
}

func TestDeleteVolumeSnapshots(t *testing.T) {
	tests := []struct {
		name         string
		vs           snapshotv1api.VolumeSnapshot
		vsc          snapshotv1api.VolumeSnapshotContent
		keepVSAndVSC bool
	}{
		{
			name: "VS is ReadyToUse, and VS has corresponding VSC. VS should be deleted.",
			vs: *builder.ForVolumeSnapshot("velero", "vs1").
				ObjectMeta(builder.WithLabels("testing-vs", "vs1")).
				Status().BoundVolumeSnapshotContentName("vsc1").Result(),
			vsc: *builder.ForVolumeSnapshotContent("vsc1").
				DeletionPolicy(snapshotv1api.VolumeSnapshotContentDelete).
				Status(&snapshotv1api.VolumeSnapshotContentStatus{}).Result(),
		},
		{
			name: "VS status is nil. VSC should not be modified.",
			vs: *builder.ForVolumeSnapshot("velero", "vs1").
				ObjectMeta(builder.WithLabels("testing-vs", "vs1")).Result(),
			vsc: *builder.ForVolumeSnapshotContent("vsc1").
				DeletionPolicy(snapshotv1api.VolumeSnapshotContentDelete).
				Status(&snapshotv1api.VolumeSnapshotContentStatus{}).Result(),
			keepVSAndVSC: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := velerotest.NewFakeControllerRuntimeClient(
				t,
				[]runtime.Object{&tc.vs, &tc.vsc}...,
			)
			logger := logging.DefaultLogger(logrus.DebugLevel, logging.FormatText)

			DeleteReadyVolumeSnapshot(tc.vs, client, logger)

			vsList := new(snapshotv1api.VolumeSnapshotList)
			err := client.List(
				t.Context(),
				vsList,
				&crclient.ListOptions{
					Namespace: "velero",
				},
			)
			require.NoError(t, err)

			vscList := new(snapshotv1api.VolumeSnapshotContentList)
			err = client.List(
				t.Context(),
				vscList,
			)
			require.NoError(t, err)

			if tc.keepVSAndVSC {
				require.Equal(t, crclient.ObjectKeyFromObject(&tc.vs), crclient.ObjectKeyFromObject(&vsList.Items[0]))
				require.Equal(t, crclient.ObjectKeyFromObject(&tc.vsc), crclient.ObjectKeyFromObject(&vscList.Items[0]))
			} else {
				require.Empty(t, vsList.Items)
				require.Empty(t, vscList.Items)
			}
		})
	}
}

func TestWaitUntilVSCHandleIsReady(t *testing.T) {
	vscName := "snapcontent-7d1bdbd1-d10d-439c-8d8e-e1c2565ddc53"
	snapshotHandle := "snapshot-handle"
	vscObj := &snapshotv1api.VolumeSnapshotContent{
		ObjectMeta: metav1.ObjectMeta{
			Name: vscName,
		},
		Spec: snapshotv1api.VolumeSnapshotContentSpec{
			VolumeSnapshotRef: corev1api.ObjectReference{
				Name:       "vol-snap-1",
				APIVersion: snapshotv1api.SchemeGroupVersion.String(),
			},
		},
		Status: &snapshotv1api.VolumeSnapshotContentStatus{
			SnapshotHandle: &snapshotHandle,
		},
	}
	validVS := &snapshotv1api.VolumeSnapshot{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "vs",
			Namespace: "default",
		},
		Status: &snapshotv1api.VolumeSnapshotStatus{
			BoundVolumeSnapshotContentName: &vscName,
		},
	}

	notFound := "does-not-exist"
	vsWithVSCNotFound := &snapshotv1api.VolumeSnapshot{
		ObjectMeta: metav1.ObjectMeta{
			Name:      notFound,
			Namespace: "default",
		},
		Status: &snapshotv1api.VolumeSnapshotStatus{
			BoundVolumeSnapshotContentName: &notFound,
		},
	}

	vsWithNilStatus := &snapshotv1api.VolumeSnapshot{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nil-status-vs",
			Namespace: "default",
		},
		Status: nil,
	}
	vsWithNilStatusField := &snapshotv1api.VolumeSnapshot{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nil-status-field-vs",
			Namespace: "default",
		},
		Status: &snapshotv1api.VolumeSnapshotStatus{
			BoundVolumeSnapshotContentName: nil,
		},
	}

	nilStatusVsc := "nil-status-vsc"
	vscWithNilStatus := &snapshotv1api.VolumeSnapshotContent{
		ObjectMeta: metav1.ObjectMeta{
			Name: nilStatusVsc,
		},
		Spec: snapshotv1api.VolumeSnapshotContentSpec{
			VolumeSnapshotRef: corev1api.ObjectReference{
				Name:       "vol-snap-1",
				APIVersion: snapshotv1api.SchemeGroupVersion.String(),
			},
		},
		Status: nil,
	}
	vsForNilStatusVsc := &snapshotv1api.VolumeSnapshot{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "vs-for-nil-status-vsc",
			Namespace: "default",
		},
		Status: &snapshotv1api.VolumeSnapshotStatus{
			BoundVolumeSnapshotContentName: &nilStatusVsc,
		},
	}

	nilStatusFieldVsc := "nil-status-field-vsc"
	vscWithNilStatusField := &snapshotv1api.VolumeSnapshotContent{
		ObjectMeta: metav1.ObjectMeta{
			Name: nilStatusFieldVsc,
		},
		Spec: snapshotv1api.VolumeSnapshotContentSpec{
			VolumeSnapshotRef: corev1api.ObjectReference{
				Name:       "vol-snap-1",
				APIVersion: snapshotv1api.SchemeGroupVersion.String(),
			},
		},
		Status: &snapshotv1api.VolumeSnapshotContentStatus{
			SnapshotHandle: nil,
		},
	}
	vsForNilStatusFieldVsc := &snapshotv1api.VolumeSnapshot{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "vs-for-nil-status-field",
			Namespace: "default",
		},
		Status: &snapshotv1api.VolumeSnapshotStatus{
			BoundVolumeSnapshotContentName: &nilStatusFieldVsc,
		},
	}

	objs := []runtime.Object{
		vscObj,
		validVS,
		vsWithVSCNotFound,
		vsWithNilStatus,
		vsWithNilStatusField,
		vscWithNilStatus,
		vsForNilStatusVsc,
		vscWithNilStatusField,
		vsForNilStatusFieldVsc,
	}
	fakeClient := velerotest.NewFakeControllerRuntimeClient(t, objs...)
	testCases := []struct {
		name        string
		volSnap     *snapshotv1api.VolumeSnapshot
		exepctedVSC *snapshotv1api.VolumeSnapshotContent
		expectError bool
	}{
		{
			name:        "waitEnabled should find volumesnapshotcontent for volumesnapshot",
			volSnap:     validVS,
			exepctedVSC: vscObj,
			expectError: false,
		},
		{
			name:        "waitEnabled should not find volumesnapshotcontent for volumesnapshot with non-existing snapshotcontent name in status.BoundVolumeSnapshotContentName",
			volSnap:     vsWithVSCNotFound,
			exepctedVSC: nil,
			expectError: true,
		},
		{
			name:        "waitEnabled should not find volumesnapshotcontent for a non-existent volumesnapshot",
			exepctedVSC: nil,
			expectError: true,
			volSnap: &snapshotv1api.VolumeSnapshot{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "not-found",
					Namespace: "default",
				},
				Status: &snapshotv1api.VolumeSnapshotStatus{
					BoundVolumeSnapshotContentName: &nilStatusVsc,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actualVSC, actualError := WaitUntilVSCHandleIsReady(tc.volSnap, fakeClient, logrus.New().WithField("fake", "test"), 0)
			if tc.expectError && actualError == nil {
				require.Error(t, actualError)
				assert.Nil(t, actualVSC)
				return
			}
			assert.Equal(t, tc.exepctedVSC, actualVSC)
		})
	}
}

func TestDiagnoseVS(t *testing.T) {
	vscName := "fake-vsc"
	readyToUse := true
	message := "fake-message"

	testCases := []struct {
		name     string
		vs       *snapshotv1api.VolumeSnapshot
		events   *corev1api.EventList
		expected string
	}{
		{
			name: "VS with no status",
			vs: &snapshotv1api.VolumeSnapshot{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "fake-vs",
					Namespace: "fake-ns",
				},
			},
			expected: "VS fake-ns/fake-vs, bind to , readyToUse false, errMessage \n",
		},
		{
			name: "VS with empty status",
			vs: &snapshotv1api.VolumeSnapshot{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "fake-vs",
					Namespace: "fake-ns",
				},
				Status: &snapshotv1api.VolumeSnapshotStatus{},
			},
			expected: "VS fake-ns/fake-vs, bind to , readyToUse false, errMessage \n",
		},
		{
			name: "VS with VSC name",
			vs: &snapshotv1api.VolumeSnapshot{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "fake-vs",
					Namespace: "fake-ns",
				},
				Status: &snapshotv1api.VolumeSnapshotStatus{
					BoundVolumeSnapshotContentName: &vscName,
				},
			},
			expected: "VS fake-ns/fake-vs, bind to fake-vsc, readyToUse false, errMessage \n",
		},
		{
			name: "VS with VSC name+ready",
			vs: &snapshotv1api.VolumeSnapshot{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "fake-vs",
					Namespace: "fake-ns",
				},
				Status: &snapshotv1api.VolumeSnapshotStatus{
					BoundVolumeSnapshotContentName: &vscName,
					ReadyToUse:                     &readyToUse,
				},
			},
			expected: "VS fake-ns/fake-vs, bind to fake-vsc, readyToUse true, errMessage \n",
		},
		{
			name: "VS with VSC name+ready+empty error",
			vs: &snapshotv1api.VolumeSnapshot{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "fake-vs",
					Namespace: "fake-ns",
				},
				Status: &snapshotv1api.VolumeSnapshotStatus{
					BoundVolumeSnapshotContentName: &vscName,
					ReadyToUse:                     &readyToUse,
					Error:                          &snapshotv1api.VolumeSnapshotError{},
				},
			},
			expected: "VS fake-ns/fake-vs, bind to fake-vsc, readyToUse true, errMessage \n",
		},
		{
			name: "VS with VSC name+ready+error",
			vs: &snapshotv1api.VolumeSnapshot{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "fake-vs",
					Namespace: "fake-ns",
				},
				Status: &snapshotv1api.VolumeSnapshotStatus{
					BoundVolumeSnapshotContentName: &vscName,
					ReadyToUse:                     &readyToUse,
					Error: &snapshotv1api.VolumeSnapshotError{
						Message: &message,
					},
				},
			},
			expected: "VS fake-ns/fake-vs, bind to fake-vsc, readyToUse true, errMessage fake-message\n",
		},
		{
			name: "VS with VSC and empty event",
			vs: &snapshotv1api.VolumeSnapshot{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "fake-vs",
					Namespace: "fake-ns",
				},
				Status: &snapshotv1api.VolumeSnapshotStatus{
					BoundVolumeSnapshotContentName: &vscName,
					ReadyToUse:                     &readyToUse,
					Error:                          &snapshotv1api.VolumeSnapshotError{},
				},
			},
			events:   &corev1api.EventList{},
			expected: "VS fake-ns/fake-vs, bind to fake-vsc, readyToUse true, errMessage \n",
		},
		{
			name: "VS with VSC and events",
			vs: &snapshotv1api.VolumeSnapshot{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "fake-vs",
					Namespace: "fake-ns",
					UID:       "fake-vs-uid",
				},
				Status: &snapshotv1api.VolumeSnapshotStatus{
					BoundVolumeSnapshotContentName: &vscName,
					ReadyToUse:                     &readyToUse,
					Error:                          &snapshotv1api.VolumeSnapshotError{},
				},
			},
			events: &corev1api.EventList{Items: []corev1api.Event{
				{
					InvolvedObject: corev1api.ObjectReference{UID: "fake-uid-1"},
					Type:           corev1api.EventTypeWarning,
					Reason:         "reason-1",
					Message:        "message-1",
				},
				{
					InvolvedObject: corev1api.ObjectReference{UID: "fake-uid-2"},
					Type:           corev1api.EventTypeWarning,
					Reason:         "reason-2",
					Message:        "message-2",
				},
				{
					InvolvedObject: corev1api.ObjectReference{UID: "fake-vs-uid"},
					Type:           corev1api.EventTypeWarning,
					Reason:         "reason-3",
					Message:        "message-3",
				},
				{
					InvolvedObject: corev1api.ObjectReference{UID: "fake-vs-uid"},
					Type:           corev1api.EventTypeNormal,
					Reason:         "reason-4",
					Message:        "message-4",
				},
				{
					InvolvedObject: corev1api.ObjectReference{UID: "fake-vs-uid"},
					Type:           corev1api.EventTypeNormal,
					Reason:         "reason-5",
					Message:        "message-5",
				},
				{
					InvolvedObject: corev1api.ObjectReference{UID: "fake-vs-uid"},
					Type:           corev1api.EventTypeWarning,
					Reason:         "reason-6",
					Message:        "message-6",
				},
			}},
			expected: "VS fake-ns/fake-vs, bind to fake-vsc, readyToUse true, errMessage \nVS event reason reason-3, message message-3\nVS event reason reason-6, message message-6\n",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			diag := DiagnoseVS(tc.vs, tc.events)
			assert.Equal(t, tc.expected, diag)
		})
	}
}

func TestDiagnoseVSC(t *testing.T) {
	readyToUse := true
	message := "fake-message"
	handle := "fake-handle"

	testCases := []struct {
		name     string
		vsc      *snapshotv1api.VolumeSnapshotContent
		expected string
	}{
		{
			name: "VS with no status",
			vsc: &snapshotv1api.VolumeSnapshotContent{
				ObjectMeta: metav1.ObjectMeta{
					Name: "fake-vsc",
				},
			},
			expected: "VSC fake-vsc, readyToUse false, errMessage , handle \n",
		},
		{
			name: "VSC with empty status",
			vsc: &snapshotv1api.VolumeSnapshotContent{
				ObjectMeta: metav1.ObjectMeta{
					Name: "fake-vsc",
				},
				Status: &snapshotv1api.VolumeSnapshotContentStatus{},
			},
			expected: "VSC fake-vsc, readyToUse false, errMessage , handle \n",
		},
		{
			name: "VSC with ready",
			vsc: &snapshotv1api.VolumeSnapshotContent{
				ObjectMeta: metav1.ObjectMeta{
					Name: "fake-vsc",
				},
				Status: &snapshotv1api.VolumeSnapshotContentStatus{
					ReadyToUse: &readyToUse,
				},
			},
			expected: "VSC fake-vsc, readyToUse true, errMessage , handle \n",
		},
		{
			name: "VSC with ready+handle",
			vsc: &snapshotv1api.VolumeSnapshotContent{
				ObjectMeta: metav1.ObjectMeta{
					Name: "fake-vsc",
				},
				Status: &snapshotv1api.VolumeSnapshotContentStatus{
					ReadyToUse:     &readyToUse,
					SnapshotHandle: &handle,
				},
			},
			expected: "VSC fake-vsc, readyToUse true, errMessage , handle fake-handle\n",
		},
		{
			name: "VSC with ready+handle+empty error",
			vsc: &snapshotv1api.VolumeSnapshotContent{
				ObjectMeta: metav1.ObjectMeta{
					Name: "fake-vsc",
				},
				Status: &snapshotv1api.VolumeSnapshotContentStatus{
					ReadyToUse:     &readyToUse,
					SnapshotHandle: &handle,
					Error:          &snapshotv1api.VolumeSnapshotError{},
				},
			},
			expected: "VSC fake-vsc, readyToUse true, errMessage , handle fake-handle\n",
		},
		{
			name: "VSC with ready+handle+error",
			vsc: &snapshotv1api.VolumeSnapshotContent{
				ObjectMeta: metav1.ObjectMeta{
					Name: "fake-vsc",
				},
				Status: &snapshotv1api.VolumeSnapshotContentStatus{
					ReadyToUse:     &readyToUse,
					SnapshotHandle: &handle,
					Error: &snapshotv1api.VolumeSnapshotError{
						Message: &message,
					},
				},
			},
			expected: "VSC fake-vsc, readyToUse true, errMessage fake-message, handle fake-handle\n",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			diag := DiagnoseVSC(tc.vsc)
			assert.Equal(t, tc.expected, diag)
		})
	}
}

func TestGetVSCForVS(t *testing.T) {
	testCases := []struct {
		name        string
		vs          *snapshotv1api.VolumeSnapshot
		vsc         *snapshotv1api.VolumeSnapshotContent
		expectedErr string
		expectedVSC *snapshotv1api.VolumeSnapshotContent
	}{
		{
			name:        "vs has no status",
			vs:          builder.ForVolumeSnapshot("ns1", "vs1").Result(),
			expectedErr: "invalid snapshot info in volume snapshot vs1",
		},
		{
			name:        "vs has no bound vsc",
			vs:          builder.ForVolumeSnapshot("ns1", "vs1").Status().Result(),
			expectedErr: "invalid snapshot info in volume snapshot vs1",
		},
		{
			name:        "vs bound vsc cannot be found",
			vs:          builder.ForVolumeSnapshot("ns1", "vs1").Status().BoundVolumeSnapshotContentName("vsc1").Result(),
			expectedErr: "error getting volume snapshot content from API: volumesnapshotcontents.snapshot.storage.k8s.io \"vsc1\" not found",
		},
		{
			name:        "normal case",
			vs:          builder.ForVolumeSnapshot("ns1", "vs1").Status().BoundVolumeSnapshotContentName("vsc1").Result(),
			vsc:         builder.ForVolumeSnapshotContent("vsc1").Result(),
			expectedVSC: builder.ForVolumeSnapshotContent("vsc1").Result(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			objs := []runtime.Object{tc.vs}
			if tc.vsc != nil {
				objs = append(objs, tc.vsc)
			}

			client := test.NewFakeControllerRuntimeClient(t, objs...)
			vsc, err := GetVSCForVS(t.Context(), tc.vs, client)

			if tc.expectedErr != "" {
				require.EqualError(t, err, tc.expectedErr)
			} else {
				require.NoError(t, err)
			}

			if tc.expectedVSC != nil {
				require.True(t, cmp.Equal(tc.expectedVSC, vsc, cmpopts.IgnoreFields(snapshotv1api.VolumeSnapshotContent{}, "ResourceVersion")))
			}
		})
	}
}
