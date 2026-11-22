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

package csi

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	snapshotv1api "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	snapshotFake "github.com/kubernetes-csi/external-snapshotter/client/v8/clientset/versioned/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientTesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	velerov2alpha1api "github.com/velero-io/velero/pkg/apis/velero/v2alpha1"
	velerotest "github.com/velero-io/velero/pkg/test"
	"github.com/velero-io/velero/pkg/util/kube"
)

const (
	retainedTestDriver = "rbd.csi.ceph.com"
	retainedTestHandle = "0001-0009-rook-ceph-0000000000000001-snap"
)

func retainedTestRecord() *velerov2alpha1api.RetainedCSIStorageSnapshot {
	return &velerov2alpha1api.RetainedCSIStorageSnapshot{
		CSISnapshotHandle: retainedTestHandle,
		Driver:            retainedTestDriver,
	}
}

// failingReader makes every read through it fail, to prove the reads of the
// retained-snapshot deletion go through the given reader and not the writer.
type failingReader struct {
	err error
}

func (f *failingReader) Get(context.Context, crclient.ObjectKey, crclient.Object, ...crclient.GetOption) error {
	return f.err
}

func (f *failingReader) List(context.Context, crclient.ObjectList, ...crclient.ListOption) error {
	return f.err
}

func TestGetRetainedSnapshotFromVSC(t *testing.T) {
	tests := []struct {
		name string
		vsc  *snapshotv1api.VolumeSnapshotContent
		want *velerov2alpha1api.RetainedCSIStorageSnapshot
	}{
		{
			name: "nil content",
			vsc:  nil,
			want: nil,
		},
		{
			name: "no handle",
			vsc: &snapshotv1api.VolumeSnapshotContent{
				Spec: snapshotv1api.VolumeSnapshotContentSpec{
					Driver: retainedTestDriver,
				},
			},
			want: nil,
		},
		{
			name: "no driver",
			vsc: &snapshotv1api.VolumeSnapshotContent{
				Spec: snapshotv1api.VolumeSnapshotContentSpec{
					Source: snapshotv1api.VolumeSnapshotContentSource{
						SnapshotHandle: ptr.To(retainedTestHandle),
					},
				},
			},
			want: nil,
		},
		{
			name: "handle from spec",
			vsc: &snapshotv1api.VolumeSnapshotContent{
				Spec: snapshotv1api.VolumeSnapshotContentSpec{
					Driver: retainedTestDriver,
					Source: snapshotv1api.VolumeSnapshotContentSource{
						SnapshotHandle: ptr.To(retainedTestHandle),
					},
				},
			},
			want: &velerov2alpha1api.RetainedCSIStorageSnapshot{
				CSISnapshotHandle: retainedTestHandle,
				Driver:            retainedTestDriver,
			},
		},
		{
			name: "empty spec handle falls back to status handle",
			vsc: &snapshotv1api.VolumeSnapshotContent{
				Spec: snapshotv1api.VolumeSnapshotContentSpec{
					Driver: retainedTestDriver,
				},
				Status: &snapshotv1api.VolumeSnapshotContentStatus{
					SnapshotHandle: ptr.To(retainedTestHandle),
				},
			},
			want: &velerov2alpha1api.RetainedCSIStorageSnapshot{
				CSISnapshotHandle: retainedTestHandle,
				Driver:            retainedTestDriver,
			},
		},
		{
			name: "spec handle wins over status handle",
			vsc: &snapshotv1api.VolumeSnapshotContent{
				Spec: snapshotv1api.VolumeSnapshotContentSpec{
					Driver: retainedTestDriver,
					Source: snapshotv1api.VolumeSnapshotContentSource{
						SnapshotHandle: ptr.To("spec-handle"),
					},
				},
				Status: &snapshotv1api.VolumeSnapshotContentStatus{
					SnapshotHandle: ptr.To("status-handle"),
				},
			},
			want: &velerov2alpha1api.RetainedCSIStorageSnapshot{
				CSISnapshotHandle: "spec-handle",
				Driver:            retainedTestDriver,
			},
		},
		{
			name: "labels and secret annotations are carried",
			vsc: &snapshotv1api.VolumeSnapshotContent{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						kube.VolumeSnapshotContentManagedByLabel: "velero",
						"unrelated":                              "label",
					},
					Annotations: map[string]string{
						VSCDeletionSecretNameAnnotation:      "secret-name",
						VSCDeletionSecretNamespaceAnnotation: "secret-ns",
					},
				},
				Spec: snapshotv1api.VolumeSnapshotContentSpec{
					Driver: retainedTestDriver,
					Source: snapshotv1api.VolumeSnapshotContentSource{
						SnapshotHandle: ptr.To(retainedTestHandle),
					},
				},
			},
			want: &velerov2alpha1api.RetainedCSIStorageSnapshot{
				CSISnapshotHandle:   retainedTestHandle,
				Driver:              retainedTestDriver,
				ManagedByLabelValue: "velero",
				DeletionSecretRef: &corev1api.SecretReference{
					Name:      "secret-name",
					Namespace: "secret-ns",
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := GetRetainedSnapshotFromVSC(tc.vsc)
			if tc.want == nil {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, tc.want.CSISnapshotHandle, got.CSISnapshotHandle)
			assert.Equal(t, tc.want.Driver, got.Driver)
			assert.Equal(t, tc.want.ManagedByLabelValue, got.ManagedByLabelValue)
			assert.Equal(t, tc.want.DeletionSecretRef, got.DeletionSecretRef)
		})
	}
}

func TestTempVSCName(t *testing.T) {
	name := TempVSCName(retainedTestDriver, retainedTestHandle)

	// Deterministic: a retry of an interrupted deletion derives the same name
	// and reuses the leftover content.
	assert.Equal(t, name, TempVSCName(retainedTestDriver, retainedTestHandle))
	assert.True(t, strings.HasPrefix(name, "vsc-"))

	// Different driver or handle must produce a different content name.
	assert.NotEqual(t, name, TempVSCName("other.driver", retainedTestHandle))
	assert.NotEqual(t, name, TempVSCName(retainedTestDriver, "other-handle"))
}

func TestBuildTempVSCForRetainedSnapshot(t *testing.T) {
	record := retainedTestRecord()
	record.ManagedByLabelValue = "velero"
	record.DeletionSecretRef = &corev1api.SecretReference{Name: "secret-name", Namespace: "secret-ns"}

	vsc := BuildTempVSCForRetainedSnapshot(record)

	assert.Equal(t, TempVSCName(record.Driver, record.CSISnapshotHandle), vsc.Name)
	assert.Equal(t, []string{VSCBoundProtectionFinalizer}, vsc.Finalizers)
	assert.Equal(t, snapshotv1api.VolumeSnapshotContentDelete, vsc.Spec.DeletionPolicy)
	assert.Equal(t, record.Driver, vsc.Spec.Driver)
	require.NotNil(t, vsc.Spec.Source.SnapshotHandle)
	assert.Equal(t, record.CSISnapshotHandle, *vsc.Spec.Source.SnapshotHandle)
	assert.Nil(t, vsc.Spec.VolumeSnapshotClassName)

	// The synthetic reference must carry an empty uid: that routes the content
	// into the sidecar's unbound pre-provisioned deletion path.
	assert.Empty(t, vsc.Spec.VolumeSnapshotRef.UID)
	assert.Equal(t, snapshotv1api.SchemeGroupVersion.String(), vsc.Spec.VolumeSnapshotRef.APIVersion)
	assert.Equal(t, "VolumeSnapshot", vsc.Spec.VolumeSnapshotRef.Kind)
	assert.NotEmpty(t, vsc.Spec.VolumeSnapshotRef.Namespace)
	assert.NotEmpty(t, vsc.Spec.VolumeSnapshotRef.Name)

	assert.Equal(t, map[string]string{kube.VolumeSnapshotContentManagedByLabel: "velero"}, vsc.Labels)
	assert.Equal(t, map[string]string{
		VSCDeletionSecretNameAnnotation:      "secret-name",
		VSCDeletionSecretNamespaceAnnotation: "secret-ns",
	}, vsc.Annotations)

	// A minimal record carries neither labels nor annotations.
	minimal := BuildTempVSCForRetainedSnapshot(retainedTestRecord())
	assert.Nil(t, minimal.Labels)
	assert.Nil(t, minimal.Annotations)
}

func TestPatchVSCDeletionPolicy(t *testing.T) {
	vscObj := &snapshotv1api.VolumeSnapshotContent{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "fake-vsc",
			ResourceVersion: "999",
		},
		Spec: snapshotv1api.VolumeSnapshotContentSpec{
			DeletionPolicy: snapshotv1api.VolumeSnapshotContentRetain,
			Driver:         retainedTestDriver,
		},
	}

	tests := []struct {
		name            string
		clientObj       []runtime.Object
		vscName         string
		resourceVersion string
		patchErr        func(err error) bool
	}{
		{
			name:            "patch carries the resourceVersion under metadata",
			clientObj:       []runtime.Object{vscObj.DeepCopy()},
			vscName:         "fake-vsc",
			resourceVersion: "999",
		},
		{
			name:      "empty resourceVersion skips the precondition",
			clientObj: []runtime.Object{vscObj.DeepCopy()},
			vscName:   "fake-vsc",
		},
		{
			name:    "vsc not found",
			vscName: "missing-vsc",
			patchErr: func(err error) bool {
				return apierrors.IsNotFound(err)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fakeSnapshotClient := snapshotFake.NewSimpleClientset(tc.clientObj...)

			var patchBytes []byte
			fakeSnapshotClient.Fake.PrependReactor("patch", "volumesnapshotcontents", func(action clientTesting.Action) (bool, runtime.Object, error) {
				patchBytes = action.(clientTesting.PatchAction).GetPatch()
				return false, nil, nil
			})

			patched, err := PatchVSCDeletionPolicy(t.Context(), fakeSnapshotClient.SnapshotV1(), tc.vscName, snapshotv1api.VolumeSnapshotContentDelete, tc.resourceVersion)
			if tc.patchErr != nil {
				require.Error(t, err)
				assert.True(t, tc.patchErr(err), "unexpected error: %v", err)
				return
			}
			require.NoError(t, err)

			// The precondition must sit under metadata.resourceVersion: that is
			// the only placement the API server honors. A top-level
			// resourceVersion key is not part of the object's schema and is
			// silently dropped, which would make the patch unconditional.
			var patch map[string]any
			require.NoError(t, json.Unmarshal(patchBytes, &patch))
			_, topLevel := patch["resourceVersion"]
			assert.False(t, topLevel, "resourceVersion must not be a top-level patch key, patch: %s", patchBytes)
			if tc.resourceVersion != "" {
				metadata, ok := patch["metadata"].(map[string]any)
				require.True(t, ok, "patch must carry metadata.resourceVersion, patch: %s", patchBytes)
				assert.Equal(t, tc.resourceVersion, metadata["resourceVersion"])
			} else {
				assert.NotContains(t, string(patchBytes), "resourceVersion")
			}
			spec := patch["spec"].(map[string]any)
			assert.Equal(t, string(snapshotv1api.VolumeSnapshotContentDelete), spec["deletionPolicy"])

			// The post-write object is handed back with the policy applied, so
			// the caller's next preconditioned operation is built on it.
			require.NotNil(t, patched)
			assert.Equal(t, snapshotv1api.VolumeSnapshotContentDelete, patched.Spec.DeletionPolicy)
			assert.Equal(t, tc.vscName, patched.Name)
		})
	}
}

func TestSeedVSCStatusSnapshotHandle(t *testing.T) {
	vscWithHandle := &snapshotv1api.VolumeSnapshotContent{
		ObjectMeta: metav1.ObjectMeta{Name: "fake-vsc", ResourceVersion: "999"},
		Status: &snapshotv1api.VolumeSnapshotContentStatus{
			SnapshotHandle: ptr.To("existing-handle"),
		},
	}
	vscWithoutStatus := &snapshotv1api.VolumeSnapshotContent{
		ObjectMeta: metav1.ObjectMeta{Name: "fake-vsc", ResourceVersion: "999"},
	}

	tests := []struct {
		name        string
		clientObj   []runtime.Object
		reactors    []reactor
		vsc         *snapshotv1api.VolumeSnapshotContent
		handle      string
		wantHandle  string
		wantSameObj bool
		err         string
	}{
		{
			name:        "empty handle returns the object unchanged",
			vsc:         vscWithoutStatus.DeepCopy(),
			handle:      "",
			wantSameObj: true,
		},
		{
			name:        "handle already set returns the object unchanged",
			clientObj:   []runtime.Object{vscWithHandle.DeepCopy()},
			vsc:         vscWithHandle.DeepCopy(),
			handle:      "new-handle",
			wantSameObj: true,
		},
		{
			name:       "status write seeds the handle",
			clientObj:  []runtime.Object{vscWithoutStatus.DeepCopy()},
			vsc:        vscWithoutStatus.DeepCopy(),
			handle:     "new-handle",
			wantHandle: "new-handle",
		},
		{
			name: "conflict is resolved by the fresh status",
			clientObj: []runtime.Object{
				&snapshotv1api.VolumeSnapshotContent{
					ObjectMeta: metav1.ObjectMeta{Name: "fake-vsc", ResourceVersion: "1001"},
					Status: &snapshotv1api.VolumeSnapshotContentStatus{
						SnapshotHandle: ptr.To("sidecar-handle"),
					},
				},
			},
			reactors: []reactor{
				{
					verb:     "update",
					resource: "volumesnapshotcontents/status",
					reactorFunc: func(action clientTesting.Action) (bool, runtime.Object, error) {
						return true, nil, apierrors.NewConflict(
							snapshotv1api.Resource("volumesnapshotcontents"), "fake-vsc", errors.New("fake-conflict"))
					},
				},
			},
			vsc:        vscWithoutStatus.DeepCopy(),
			handle:     "new-handle",
			wantHandle: "sidecar-handle",
		},
		{
			name: "conflict without a handle in the fresh status fails",
			clientObj: []runtime.Object{
				&snapshotv1api.VolumeSnapshotContent{
					ObjectMeta: metav1.ObjectMeta{Name: "fake-vsc", ResourceVersion: "1001"},
				},
			},
			reactors: []reactor{
				{
					verb:     "update",
					resource: "volumesnapshotcontents/status",
					reactorFunc: func(action clientTesting.Action) (bool, runtime.Object, error) {
						return true, nil, apierrors.NewConflict(
							snapshotv1api.Resource("volumesnapshotcontents"), "fake-vsc", errors.New("fake-conflict"))
					},
				},
			},
			vsc:    vscWithoutStatus.DeepCopy(),
			handle: "new-handle",
			err:    "error writing the status of VolumeSnapshotContent after a conflict: Operation cannot be fulfilled on volumesnapshotcontents.snapshot.storage.k8s.io \"fake-vsc\": fake-conflict",
		},
		{
			name: "conflict and the re-read fails",
			reactors: []reactor{
				{
					verb:     "update",
					resource: "volumesnapshotcontents/status",
					reactorFunc: func(action clientTesting.Action) (bool, runtime.Object, error) {
						return true, nil, apierrors.NewConflict(
							snapshotv1api.Resource("volumesnapshotcontents"), "fake-vsc", errors.New("fake-conflict"))
					},
				},
				{
					verb:     "get",
					resource: "volumesnapshotcontents",
					reactorFunc: func(action clientTesting.Action) (bool, runtime.Object, error) {
						return true, nil, errors.New("fake-get-error")
					},
				},
			},
			vsc:    vscWithoutStatus.DeepCopy(),
			handle: "new-handle",
			err:    "error re-reading the status of the VolumeSnapshotContent after a conflict: fake-get-error",
		},
		{
			name: "content vanished before the write",
			reactors: []reactor{
				{
					verb:     "update",
					resource: "volumesnapshotcontents/status",
					reactorFunc: func(action clientTesting.Action) (bool, runtime.Object, error) {
						return true, nil, apierrors.NewNotFound(
							snapshotv1api.Resource("volumesnapshotcontents"), "fake-vsc")
					},
				},
			},
			vsc:    vscWithoutStatus.DeepCopy(),
			handle: "new-handle",
			err:    "error writing the status of VolumeSnapshotContent fake-vsc: volumesnapshotcontents.snapshot.storage.k8s.io \"fake-vsc\" not found",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fakeSnapshotClient := snapshotFake.NewSimpleClientset(tc.clientObj...)

			for _, reactor := range tc.reactors {
				fakeSnapshotClient.Fake.PrependReactor(reactor.verb, reactor.resource, reactor.reactorFunc)
			}

			result, err := SeedVSCStatusSnapshotHandle(t.Context(), fakeSnapshotClient.SnapshotV1(), tc.vsc, tc.handle)
			if tc.err != "" {
				assert.EqualError(t, err, tc.err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, result)

			if tc.wantSameObj {
				// Early return hands the passed object back unchanged, with no
				// server write at all.
				assert.Same(t, tc.vsc, result)
				assert.Empty(t, fakeSnapshotClient.Fake.Actions())
				return
			}

			require.NotNil(t, result.Status)
			require.NotNil(t, result.Status.SnapshotHandle)
			assert.Equal(t, tc.wantHandle, *result.Status.SnapshotHandle)

			// The server-held object carries the handle too.
			server, serr := fakeSnapshotClient.SnapshotV1().VolumeSnapshotContents().Get(
				t.Context(), "fake-vsc", metav1.GetOptions{})
			if assert.NoError(t, serr) {
				require.NotNil(t, server.Status)
				require.NotNil(t, server.Status.SnapshotHandle)
				assert.Equal(t, tc.wantHandle, *server.Status.SnapshotHandle)
			}
		})
	}
}

func TestDeleteVSWithResourceVersion(t *testing.T) {
	vsObj := &snapshotv1api.VolumeSnapshot{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "fake-vs",
			Namespace:       "fake-ns",
			ResourceVersion: "999",
		},
	}

	tests := []struct {
		name            string
		clientObj       []runtime.Object
		reactors        []reactor
		resourceVersion string
		wantPrecond     bool
		err             string
	}{
		{
			name:            "delete carries the resourceVersion precondition",
			clientObj:       []runtime.Object{vsObj},
			resourceVersion: "999",
			wantPrecond:     true,
		},
		{
			name:        "empty resourceVersion deletes without a precondition",
			clientObj:   []runtime.Object{vsObj},
			wantPrecond: false,
		},
		{
			name: "not found is absorbed",
		},
		{
			name:      "other errors are returned",
			clientObj: []runtime.Object{vsObj},
			reactors: []reactor{
				{
					verb:     "delete",
					resource: "volumesnapshots",
					reactorFunc: func(action clientTesting.Action) (bool, runtime.Object, error) {
						return true, nil, errors.New("fake-delete-error")
					},
				},
			},
			err: "error deleting VolumeSnapshot fake-ns/fake-vs: fake-delete-error",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fakeSnapshotClient := snapshotFake.NewSimpleClientset(tc.clientObj...)

			var deleteOptions metav1.DeleteOptions
			fakeSnapshotClient.Fake.PrependReactor("delete", "volumesnapshots", func(action clientTesting.Action) (bool, runtime.Object, error) {
				deleteOptions = action.(clientTesting.DeleteAction).GetDeleteOptions()
				return false, nil, nil
			})

			for _, reactor := range tc.reactors {
				fakeSnapshotClient.Fake.PrependReactor(reactor.verb, reactor.resource, reactor.reactorFunc)
			}

			err := DeleteVSWithResourceVersion(t.Context(), fakeSnapshotClient.SnapshotV1(), "fake-ns", "fake-vs", tc.resourceVersion)
			if tc.err != "" {
				assert.EqualError(t, err, tc.err)
				return
			}
			require.NoError(t, err)

			if tc.wantPrecond {
				require.NotNil(t, deleteOptions.Preconditions)
				require.NotNil(t, deleteOptions.Preconditions.ResourceVersion)
				assert.Equal(t, tc.resourceVersion, *deleteOptions.Preconditions.ResourceVersion)
			} else {
				assert.Nil(t, deleteOptions.Preconditions)
			}
		})
	}
}

func TestDeleteVSCWithResourceVersion(t *testing.T) {
	vscObj := &snapshotv1api.VolumeSnapshotContent{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "fake-vsc",
			ResourceVersion: "999",
		},
	}

	tests := []struct {
		name            string
		clientObj       []runtime.Object
		reactors        []reactor
		resourceVersion string
		wantPrecond     bool
		err             string
	}{
		{
			name:            "delete carries the resourceVersion precondition",
			clientObj:       []runtime.Object{vscObj},
			resourceVersion: "999",
			wantPrecond:     true,
		},
		{
			name:        "empty resourceVersion deletes without a precondition",
			clientObj:   []runtime.Object{vscObj},
			wantPrecond: false,
		},
		{
			name: "not found is absorbed",
		},
		{
			name:      "other errors are returned",
			clientObj: []runtime.Object{vscObj},
			reactors: []reactor{
				{
					verb:     "delete",
					resource: "volumesnapshotcontents",
					reactorFunc: func(action clientTesting.Action) (bool, runtime.Object, error) {
						return true, nil, errors.New("fake-delete-error")
					},
				},
			},
			err: "error deleting VolumeSnapshotContent fake-vsc: fake-delete-error",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fakeSnapshotClient := snapshotFake.NewSimpleClientset(tc.clientObj...)

			var deleteOptions metav1.DeleteOptions
			fakeSnapshotClient.Fake.PrependReactor("delete", "volumesnapshotcontents", func(action clientTesting.Action) (bool, runtime.Object, error) {
				deleteOptions = action.(clientTesting.DeleteAction).GetDeleteOptions()
				return false, nil, nil
			})

			for _, reactor := range tc.reactors {
				fakeSnapshotClient.Fake.PrependReactor(reactor.verb, reactor.resource, reactor.reactorFunc)
			}

			err := DeleteVSCWithResourceVersion(t.Context(), fakeSnapshotClient.SnapshotV1(), "fake-vsc", tc.resourceVersion)
			if tc.err != "" {
				assert.EqualError(t, err, tc.err)
				return
			}
			require.NoError(t, err)

			if tc.wantPrecond {
				require.NotNil(t, deleteOptions.Preconditions)
				require.NotNil(t, deleteOptions.Preconditions.ResourceVersion)
				assert.Equal(t, tc.resourceVersion, *deleteOptions.Preconditions.ResourceVersion)
			} else {
				assert.Nil(t, deleteOptions.Preconditions)
			}
		})
	}
}

// TestEnsureDeleteVSCTimeoutErrorIsTyped pins the timeout of EnsureDeleteVSC
// to its typed error, on top of the message-based cases of
// TestEnsureDeleteVSC: the DataUpload patch-back branches on the type.
func TestEnsureDeleteVSCTimeoutErrorIsTyped(t *testing.T) {
	vscObj := &snapshotv1api.VolumeSnapshotContent{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "fake-vsc",
			Finalizers: []string{"fake-finalizer"},
		},
	}

	fakeSnapshotClient := snapshotFake.NewSimpleClientset(vscObj)
	// The delete is accepted but the content stays behind its finalizer, as on
	// a live cluster while the snapshotter has not released it yet.
	fakeSnapshotClient.Fake.PrependReactor("delete", "volumesnapshotcontents", func(action clientTesting.Action) (bool, runtime.Object, error) {
		return true, nil, nil
	})

	err := EnsureDeleteVSC(t.Context(), fakeSnapshotClient.SnapshotV1(), "fake-vsc", time.Millisecond)
	require.Error(t, err)

	var timeoutErr *VSCDeletionTimeoutError
	require.ErrorAs(t, err, &timeoutErr)
	assert.Equal(t, "fake-vsc", timeoutErr.VSCName)
	assert.True(t, timeoutErr.FinalizersRead)
	assert.Equal(t, []string{"fake-finalizer"}, timeoutErr.Finalizers)
}

// fakeSnapshotterBackend plays the CSI snapshotter and the storage for the
// temporary VolumeSnapshotContent of a retained snapshot, following
// external-snapshotter v8.6: the sidecar calls DeleteSnapshot only for a
// content being deleted whose policy is Delete and whose status carries the
// handle; it then removes the bound-protection finalizer, which makes the
// content disappear. A snapshot the driver reports as gone still counts as
// deleted, as does one absent from the storage when notFoundIsSuccess is set.
type fakeSnapshotterBackend struct {
	// snapshots maps handle -> exists.
	snapshots map[string]bool
	// notFoundIsSuccess makes a missing snapshot satisfy the sidecar, the way
	// a driver reporting "snapshot not found" does.
	notFoundIsSuccess bool
	// deleteErrorMessage, when set, makes the DeleteSnapshot call fail with a
	// SnapshotDeleteError event carrying this message, as the sidecar does.
	deleteErrorMessage string
	// deleteCallsTo records the handles DeleteSnapshot was called for.
	deleteCallsTo []string
}

func (b *fakeSnapshotterBackend) client(t *testing.T, objs ...runtime.Object) crclient.Client {
	t.Helper()
	// The status subresource must be modeled for the VolumeSnapshotContent:
	// without it the fake client treats a status update as a full-object
	// update and wipes the spec, which a real API server never does.
	fakeClient := velerotest.NewFakeControllerRuntimeClientBuilder(t).
		WithRuntimeObjects(objs...).
		WithStatusSubresource(&snapshotv1api.VolumeSnapshotContent{}).
		Build()
	return interceptor.NewClient(fakeClient.(crclient.WithWatch), interceptor.Funcs{
		Delete: func(ctx context.Context, c crclient.WithWatch, obj crclient.Object, opts ...crclient.DeleteOption) error {
			if err := c.Delete(ctx, obj, opts...); err != nil {
				return err
			}
			vsc, ok := obj.(*snapshotv1api.VolumeSnapshotContent)
			if !ok {
				return nil
			}
			deleting := &snapshotv1api.VolumeSnapshotContent{}
			if err := c.Get(ctx, crclient.ObjectKeyFromObject(vsc), deleting); err != nil {
				return crclient.IgnoreNotFound(err)
			}
			if deleting.Spec.DeletionPolicy == snapshotv1api.VolumeSnapshotContentDelete &&
				deleting.Status != nil && deleting.Status.SnapshotHandle != nil {
				handle := *deleting.Status.SnapshotHandle
				if b.deleteErrorMessage != "" {
					// The sidecar keeps the finalizer and retries, reporting
					// the failure only as an event, never as status.error.
					event := &corev1api.Event{
						ObjectMeta: metav1.ObjectMeta{
							GenerateName: "event-",
							Namespace:    metav1.NamespaceDefault,
						},
						InvolvedObject: corev1api.ObjectReference{
							Kind: "VolumeSnapshotContent",
							Name: deleting.Name,
						},
						Reason:        SnapshotDeleteErrorEventReason,
						Message:       b.deleteErrorMessage,
						LastTimestamp: metav1.Now(),
					}
					if err := c.Create(ctx, event); err != nil {
						return err
					}
					return nil
				}
				if b.snapshots[handle] || b.notFoundIsSuccess {
					b.deleteCallsTo = append(b.deleteCallsTo, handle)
					b.snapshots[handle] = false
				} else {
					// The sidecar cannot delete the snapshot and reports
					// nothing: the content stays behind its finalizer.
					return nil
				}
			}
			// The finalizer is removed once the sidecar is done with the
			// content, which makes it disappear.
			deleting.Finalizers = nil
			return c.Update(ctx, deleting)
		},
	})
}

// shortenRetainedSnapshotDeletionTimeout bounds the deletion wait of the
// retained-snapshot tests, so a stuck content times out in milliseconds.
func shortenRetainedSnapshotDeletionTimeout(t *testing.T) {
	t.Helper()
	orig := RetainedSnapshotDeletionTimeout
	RetainedSnapshotDeletionTimeout = 100 * time.Millisecond
	t.Cleanup(func() {
		RetainedSnapshotDeletionTimeout = orig
	})
}

func TestDeleteRetainedSnapshotSuccess(t *testing.T) {
	record := retainedTestRecord()

	t.Run("snapshot exists and is deleted", func(t *testing.T) {
		backend := &fakeSnapshotterBackend{snapshots: map[string]bool{retainedTestHandle: true}}
		c := backend.client(t)

		require.NoError(t, DeleteRetainedSnapshot(t.Context(), c, c, record, velerotest.NewLogger()))

		// The driver was called exactly once, through the seeded status.
		assert.Equal(t, []string{retainedTestHandle}, backend.deleteCallsTo)
		// The temp content is gone.
		err := c.Get(t.Context(), crclient.ObjectKey{Name: TempVSCName(record.Driver, record.CSISnapshotHandle)}, &snapshotv1api.VolumeSnapshotContent{})
		assert.True(t, apierrors.IsNotFound(err))
	})

	t.Run("driver reports the snapshot gone", func(t *testing.T) {
		backend := &fakeSnapshotterBackend{
			snapshots:         map[string]bool{retainedTestHandle: false},
			notFoundIsSuccess: true,
		}
		c := backend.client(t)

		require.NoError(t, DeleteRetainedSnapshot(t.Context(), c, c, record, velerotest.NewLogger()))
		assert.Equal(t, []string{retainedTestHandle}, backend.deleteCallsTo)
	})

	t.Run("nil reader falls back to the writing client", func(t *testing.T) {
		backend := &fakeSnapshotterBackend{snapshots: map[string]bool{retainedTestHandle: true}}
		c := backend.client(t)

		require.NoError(t, DeleteRetainedSnapshot(t.Context(), c, nil, record, velerotest.NewLogger()))
		assert.Equal(t, []string{retainedTestHandle}, backend.deleteCallsTo)
	})

	t.Run("an interrupted deletion reuses the leftover content", func(t *testing.T) {
		backend := &fakeSnapshotterBackend{snapshots: map[string]bool{retainedTestHandle: true}}
		record := retainedTestRecord()
		leftover := BuildTempVSCForRetainedSnapshot(record)
		c := backend.client(t, leftover)

		require.NoError(t, DeleteRetainedSnapshot(t.Context(), c, c, record, velerotest.NewLogger()))

		// The leftover content was reused, not duplicated: exactly one
		// DeleteSnapshot call and no second content exists under any name.
		assert.Equal(t, []string{retainedTestHandle}, backend.deleteCallsTo)
		contents := &snapshotv1api.VolumeSnapshotContentList{}
		require.NoError(t, c.List(t.Context(), contents))
		assert.Empty(t, contents.Items)
	})
}

func TestDeleteRetainedSnapshotInvalidRecord(t *testing.T) {
	c := (&fakeSnapshotterBackend{snapshots: map[string]bool{}}).client(t)

	for _, record := range []*velerov2alpha1api.RetainedCSIStorageSnapshot{
		nil,
		{Driver: retainedTestDriver},
		{CSISnapshotHandle: retainedTestHandle},
	} {
		err := DeleteRetainedSnapshot(t.Context(), c, c, record, velerotest.NewLogger())
		assert.EqualError(t, err, "invalid retained snapshot record, handle and driver are required")
	}
}

func TestDeleteRetainedSnapshotReadsGoThroughTheReader(t *testing.T) {
	backend := &fakeSnapshotterBackend{snapshots: map[string]bool{retainedTestHandle: true}}
	writer := backend.client(t)
	reader := &failingReader{err: errors.New("fake-reader-error")}

	err := DeleteRetainedSnapshot(t.Context(), writer, reader, retainedTestRecord(), velerotest.NewLogger())
	require.EqualError(t, err, "error getting temp VolumeSnapshotContent "+TempVSCName(retainedTestDriver, retainedTestHandle)+": fake-reader-error")
	// Nothing was written through the writer either.
	assert.Empty(t, backend.deleteCallsTo)
}

func TestDeleteRetainedSnapshotStatusWriteFailure(t *testing.T) {
	record := retainedTestRecord()
	fakeClient := velerotest.NewFakeControllerRuntimeClientBuilder(t).
		WithStatusSubresource(&snapshotv1api.VolumeSnapshotContent{}).
		Build()
	c := interceptor.NewClient(fakeClient.(crclient.WithWatch), interceptor.Funcs{
		SubResourceUpdate: func(ctx context.Context, c crclient.Client, subResourceName string, obj crclient.Object, opts ...crclient.SubResourceUpdateOption) error {
			return errors.New("fake-status-update-error")
		},
	})

	err := DeleteRetainedSnapshot(t.Context(), c, c, record, velerotest.NewLogger())
	assert.ErrorContains(t, err, "error writing the status of temp VolumeSnapshotContent "+TempVSCName(record.Driver, record.CSISnapshotHandle))
}

// TestDeleteRetainedSnapshotReadbackVerification proves the deletion is not
// issued before the status write is confirmed: a read-back without the handle
// fails the whole deletion instead of deleting the content unhandled.
func TestDeleteRetainedSnapshotReadbackVerification(t *testing.T) {
	record := retainedTestRecord()
	tempName := TempVSCName(record.Driver, record.CSISnapshotHandle)

	// The reader always reports the content without a status, as an
	// informer-lagged cache would: the read-back must not pass.
	leftover := BuildTempVSCForRetainedSnapshot(record)
	fakeClient := velerotest.NewFakeControllerRuntimeClientBuilder(t).
		WithRuntimeObjects(leftover).
		WithStatusSubresource(&snapshotv1api.VolumeSnapshotContent{}).
		Build()
	reader := interceptor.NewClient(fakeClient.(crclient.WithWatch), interceptor.Funcs{
		Get: func(ctx context.Context, c crclient.WithWatch, key crclient.ObjectKey, obj crclient.Object, opts ...crclient.GetOption) error {
			if err := c.Get(ctx, key, obj, opts...); err != nil {
				return err
			}
			if vsc, ok := obj.(*snapshotv1api.VolumeSnapshotContent); ok && vsc.Name == tempName {
				vsc.Status = nil
			}
			return nil
		},
	})

	err := DeleteRetainedSnapshot(t.Context(), fakeClient, reader, record, velerotest.NewLogger())
	require.ErrorContains(t, err, "the status of temp VolumeSnapshotContent "+tempName+" does not carry the snapshot handle")

	// The content was not deleted on the unconfirmed status.
	still := &snapshotv1api.VolumeSnapshotContent{}
	require.NoError(t, fakeClient.Get(t.Context(), crclient.ObjectKey{Name: tempName}, still))
}

func TestDeleteRetainedSnapshotFailureClassification(t *testing.T) {
	shortenRetainedSnapshotDeletionTimeout(t)
	record := retainedTestRecord()
	tempName := TempVSCName(record.Driver, record.CSISnapshotHandle)

	t.Run("delete call failure is a SnapshotDeleteCallError", func(t *testing.T) {
		backend := &fakeSnapshotterBackend{
			snapshots:          map[string]bool{retainedTestHandle: true},
			deleteErrorMessage: "Failed to delete snapshot " + retainedTestHandle + ": fake-driver-error",
		}
		c := backend.client(t)

		err := DeleteRetainedSnapshot(t.Context(), c, c, record, velerotest.NewLogger())
		require.Error(t, err)

		var callErr *SnapshotDeleteCallError
		require.ErrorAs(t, err, &callErr)
		assert.Contains(t, callErr.Message, "fake-driver-error")
		assert.Contains(t, callErr.Error(), "CSI snapshotter failed to delete the snapshot: ")
	})

	t.Run("credential failure stays retryable, not classified as a call failure", func(t *testing.T) {
		backend := &fakeSnapshotterBackend{
			snapshots:          map[string]bool{retainedTestHandle: true},
			deleteErrorMessage: "Failed to get snapshot credentials for snapshot " + retainedTestHandle,
		}
		c := backend.client(t)

		err := DeleteRetainedSnapshot(t.Context(), c, c, record, velerotest.NewLogger())
		require.Error(t, err)

		var callErr *SnapshotDeleteCallError
		assert.NotErrorAs(t, err, &callErr)
		assert.ErrorContains(t, err, "CSI snapshotter failed on temp VolumeSnapshotContent "+tempName)
	})

	t.Run("unknown event message stays retryable", func(t *testing.T) {
		backend := &fakeSnapshotterBackend{
			snapshots:          map[string]bool{retainedTestHandle: true},
			deleteErrorMessage: "Failed to update the status of snapshot " + retainedTestHandle,
		}
		c := backend.client(t)

		err := DeleteRetainedSnapshot(t.Context(), c, c, record, velerotest.NewLogger())
		require.Error(t, err)

		var callErr *SnapshotDeleteCallError
		assert.NotErrorAs(t, err, &callErr)
	})

	t.Run("stuck deletion without events reports the timeout", func(t *testing.T) {
		// The snapshot never becomes deletable and the sidecar reports
		// nothing: the plain timeout must name the bound and the content.
		backend := &fakeSnapshotterBackend{snapshots: map[string]bool{retainedTestHandle: false}}
		c := backend.client(t)

		err := DeleteRetainedSnapshot(t.Context(), c, c, record, velerotest.NewLogger())
		require.Error(t, err)

		var callErr *SnapshotDeleteCallError
		assert.NotErrorAs(t, err, &callErr)
		require.ErrorContains(t, err, "is not deleted within")
		assert.ErrorContains(t, err, tempName)
	})
}

func TestLatestSnapshotDeleteErrorMessage(t *testing.T) {
	newEvent := func(eventName, vscName, message, reason string, timestamp metav1.Time) *corev1api.Event {
		return &corev1api.Event{
			ObjectMeta: metav1.ObjectMeta{
				Name:      eventName,
				Namespace: metav1.NamespaceDefault,
			},
			InvolvedObject: corev1api.ObjectReference{
				Kind: "VolumeSnapshotContent",
				Name: vscName,
			},
			Reason:        reason,
			Message:       message,
			LastTimestamp: timestamp,
		}
	}

	tests := []struct {
		name        string
		clientObj   []runtime.Object
		vscName     string
		wantMessage string
		wantKind    string
	}{
		{
			name:    "no events",
			vscName: "fake-vsc",
		},
		{
			name: "ignores other kinds, names and reasons",
			clientObj: func() []runtime.Object {
				otherKind := newEvent("event-3", "fake-vsc", "Failed to delete snapshot x", SnapshotDeleteErrorEventReason, metav1.Now())
				otherKind.InvolvedObject.Kind = "SomethingElse"
				return []runtime.Object{
					newEvent("event-1", "other-vsc", "Failed to delete snapshot x", SnapshotDeleteErrorEventReason, metav1.Now()),
					newEvent("event-2", "fake-vsc", "Failed to delete snapshot x", "OtherReason", metav1.Now()),
					otherKind,
				}
			}(),
			vscName: "fake-vsc",
		},
		{
			name: "latest event wins",
			clientObj: []runtime.Object{
				newEvent("event-old", "fake-vsc", "older message", SnapshotDeleteErrorEventReason, metav1.NewTime(time.Now().Add(-time.Hour))),
				newEvent("event-new", "fake-vsc", "Failed to delete snapshot newer", SnapshotDeleteErrorEventReason, metav1.Now()),
			},
			vscName:     "fake-vsc",
			wantMessage: "Failed to delete snapshot newer",
			wantKind:    snapshotDeleteCallFailureMessage,
		},
		{
			name: "credential message is not a call failure",
			clientObj: []runtime.Object{
				newEvent("event-cred", "fake-vsc", "Failed to get snapshot credentials", SnapshotDeleteErrorEventReason, metav1.Now()),
			},
			vscName:     "fake-vsc",
			wantMessage: "Failed to get snapshot credentials",
			wantKind:    "other",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := velerotest.NewFakeControllerRuntimeClient(t, tc.clientObj...)

			message, kind := latestSnapshotDeleteErrorMessage(t.Context(), c, tc.vscName, velerotest.NewLogger())
			assert.Equal(t, tc.wantMessage, message)
			assert.Equal(t, tc.wantKind, kind)
		})
	}

	t.Run("list failure only drops the detail", func(t *testing.T) {
		reader := &failingReader{err: errors.New("fake-list-error")}

		message, kind := latestSnapshotDeleteErrorMessage(t.Context(), reader, "fake-vsc", velerotest.NewLogger())
		assert.Empty(t, message)
		assert.Empty(t, kind)
	})
}
