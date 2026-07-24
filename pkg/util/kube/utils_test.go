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

package kube

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	storagev1api "k8s.io/api/storage/v1"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/vmware-tanzu/velero/pkg/builder"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
	"github.com/vmware-tanzu/velero/pkg/uploader"
)

func TestNamespaceAndName(t *testing.T) {
	//TODO
}

func TestEnsureNamespaceExistsAndIsReady(t *testing.T) {
	tests := []struct {
		name                          string
		expectNSFound                 bool
		nsPhase                       corev1api.NamespacePhase
		nsDeleting                    bool
		expectCreate                  bool
		alreadyExists                 bool
		expectedResult                bool
		expectedCreatedResult         bool
		nsAlreadyInTerminationTracker bool
		ResourceDeletionStatusTracker ResourceDeletionStatusTracker
	}{
		{
			name:                  "namespace found, not deleting",
			expectNSFound:         true,
			expectedResult:        true,
			expectedCreatedResult: false,
		},
		{
			name:                  "namespace found, terminating phase",
			expectNSFound:         true,
			nsPhase:               corev1api.NamespaceTerminating,
			expectedResult:        false,
			expectedCreatedResult: false,
		},
		{
			name:                  "namespace found, deletiontimestamp set",
			expectNSFound:         true,
			nsDeleting:            true,
			expectedResult:        false,
			expectedCreatedResult: false,
		},
		{
			name:                  "namespace not found, successfully created",
			expectCreate:          true,
			expectedResult:        true,
			expectedCreatedResult: true,
		},
		{
			name:                  "namespace not found initially, create returns already exists error, returned namespace is ready",
			alreadyExists:         true,
			expectedResult:        true,
			expectedCreatedResult: false,
		},
		{
			name:                  "namespace not found initially, create returns already exists error, returned namespace is terminating",
			alreadyExists:         true,
			nsPhase:               corev1api.NamespaceTerminating,
			expectedResult:        false,
			expectedCreatedResult: false,
		},
		{
			name:                          "same namespace found earlier, terminating phase already tracked",
			expectNSFound:                 true,
			nsPhase:                       corev1api.NamespaceTerminating,
			expectedResult:                false,
			expectedCreatedResult:         false,
			nsAlreadyInTerminationTracker: true,
		},
	}

	resourceDeletionStatusTracker := NewResourceDeletionStatusTracker()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			namespace := &corev1api.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test",
				},
			}

			if test.nsPhase != "" {
				namespace.Status.Phase = test.nsPhase
			}

			if test.nsDeleting {
				namespace.SetDeletionTimestamp(&metav1.Time{Time: time.Now()})
			}

			timeout := time.Millisecond

			nsClient := &velerotest.FakeNamespaceClient{}
			defer nsClient.AssertExpectations(t)

			if test.expectNSFound {
				nsClient.On("Get", "test", metav1.GetOptions{}).Return(namespace, nil)
			} else {
				nsClient.On("Get", "test", metav1.GetOptions{}).Return(&corev1api.Namespace{}, apierrors.NewNotFound(schema.GroupResource{Resource: "namespaces"}, "test"))
			}

			if test.alreadyExists {
				nsClient.On("Create", namespace).Return(namespace, apierrors.NewAlreadyExists(schema.GroupResource{Resource: "namespaces"}, "test"))
			}

			if test.expectCreate {
				nsClient.On("Create", namespace).Return(namespace, nil)
			}

			if test.nsAlreadyInTerminationTracker {
				resourceDeletionStatusTracker.Add(namespace.Kind, "test", "test")
			}

			result, nsCreated, _ := EnsureNamespaceExistsAndIsReady(namespace, nsClient, timeout, resourceDeletionStatusTracker)

			assert.Equal(t, test.expectedResult, result)
			assert.Equal(t, test.expectedCreatedResult, nsCreated)
		})
	}
}

// TestEnsureNamespaceExistsAndIsReadyTerminatingTrackerKindMismatch verifies the
// tracker skip-path fires when Add and Contains see different Kind values, as they
// do in production: getNamespace() sets Kind="Namespace" but client.Get() strips it.
func TestEnsureNamespaceExistsAndIsReadyTerminatingTrackerKindMismatch(t *testing.T) {
	// Passed-in namespace mirrors getNamespace(): Kind is set.
	namespace := &corev1api.Namespace{
		TypeMeta:   metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
	}

	// clusterNS mirrors client.Get(): Kind stripped, phase Terminating.
	clusterNS := &corev1api.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Status:     corev1api.NamespaceStatus{Phase: corev1api.NamespaceTerminating},
	}

	nsClient := &velerotest.FakeNamespaceClient{}
	defer nsClient.AssertExpectations(t)
	nsClient.On("Get", "test", metav1.GetOptions{}).Return(clusterNS, nil)

	// Seed the tracker as production Add() does.
	tracker := NewResourceDeletionStatusTracker()
	tracker.Add(namespace.Kind, namespace.Name, namespace.Name)

	result, nsCreated, err := EnsureNamespaceExistsAndIsReady(namespace, nsClient, time.Millisecond, tracker)

	assert.False(t, result)
	assert.False(t, nsCreated)
	// Skip-path must fire, not the full terminating-resource-timeout wait.
	require.ErrorContains(t, err, "skipping polling for terminating namespace")
	assert.NotContains(t, err.Error(), "timed out waiting for terminating namespace")
}

// TestGetVolumeDirectorySuccess tests that the GetVolumeDirectory function
// returns a volume's name or a volume's name plus '/mount' when a PVC is present.
func TestGetVolumeDirectorySuccess(t *testing.T) {
	tests := []struct {
		name string
		pod  *corev1api.Pod
		pvc  *corev1api.PersistentVolumeClaim
		pv   *corev1api.PersistentVolume
		want string
	}{
		{
			name: "Non-CSI volume with a PVC/PV returns the volume's name",
			pod:  builder.ForPod("ns-1", "my-pod").Volumes(builder.ForVolume("my-vol").PersistentVolumeClaimSource("my-pvc").Result()).Result(),
			pvc:  builder.ForPersistentVolumeClaim("ns-1", "my-pvc").VolumeName("a-pv").Result(),
			pv:   builder.ForPersistentVolume("a-pv").Result(),
			want: "a-pv",
		},
		{
			name: "CSI volume with a PVC/PV appends '/mount' to the volume name",
			pod:  builder.ForPod("ns-1", "my-pod").Volumes(builder.ForVolume("my-vol").PersistentVolumeClaimSource("my-pvc").Result()).Result(),
			pvc:  builder.ForPersistentVolumeClaim("ns-1", "my-pvc").VolumeName("a-pv").Result(),
			pv:   builder.ForPersistentVolume("a-pv").CSI("csi.test.com", "provider-volume-id").Result(),
			want: "a-pv/mount",
		},
		{
			name: "Block CSI volume with a PVC/PV does not append '/mount' to the volume name",
			pod:  builder.ForPod("ns-1", "my-pod").Volumes(builder.ForVolume("my-vol").PersistentVolumeClaimSource("my-pvc").Result()).Result(),
			pvc:  builder.ForPersistentVolumeClaim("ns-1", "my-pvc").VolumeName("a-pv").Result(),
			pv:   builder.ForPersistentVolume("a-pv").CSI("csi.test.com", "provider-volume-id").VolumeMode(corev1api.PersistentVolumeBlock).Result(),
			want: "a-pv",
		},
		{
			name: "CSI volume mounted without a PVC appends '/mount' to the volume name",
			pod:  builder.ForPod("ns-1", "my-pod").Volumes(builder.ForVolume("my-vol").CSISource("csi.test.com").Result()).Result(),
			want: "my-vol/mount",
		},
		{
			name: "Non-CSI volume without a PVC returns the volume name",
			pod:  builder.ForPod("ns-1", "my-pod").Volumes(builder.ForVolume("my-vol").Result()).Result(),
			want: "my-vol",
		},
		{
			name: "Volume with CSI annotation appends '/mount' to the volume name",
			pod:  builder.ForPod("ns-1", "my-pod").Volumes(builder.ForVolume("my-vol").PersistentVolumeClaimSource("my-pvc").Result()).Result(),
			pvc:  builder.ForPersistentVolumeClaim("ns-1", "my-pvc").VolumeName("a-pv").Result(),
			pv:   builder.ForPersistentVolume("a-pv").ObjectMeta(builder.WithAnnotations(KubeAnnDynamicallyProvisioned, "csi.test.com")).Result(),
			want: "a-pv/mount",
		},
		{
			name: "Volume with CSI annotation 'pv.kubernetes.io/migrated-to' appends '/mount' to the volume name",
			pod:  builder.ForPod("ns-1", "my-pod").Volumes(builder.ForVolume("my-vol").PersistentVolumeClaimSource("my-pvc").Result()).Result(),
			pvc:  builder.ForPersistentVolumeClaim("ns-1", "my-pvc").VolumeName("a-pv").Result(),
			pv:   builder.ForPersistentVolume("a-pv").ObjectMeta(builder.WithAnnotations(KubeAnnMigratedTo, "csi.test.com")).Result(),
			want: "a-pv/mount",
		},
	}

	csiDriver := storagev1api.CSIDriver{
		ObjectMeta: metav1.ObjectMeta{Name: "csi.test.com"},
	}
	for _, tc := range tests {
		objs := []runtime.Object{&csiDriver}
		if tc.pvc != nil {
			objs = append(objs, tc.pvc)
		}
		if tc.pv != nil {
			objs = append(objs, tc.pv)
		}

		fakeKubeClient := fake.NewSimpleClientset(objs...)

		// Function under test
		dir, err := GetVolumeDirectory(t.Context(), logrus.StandardLogger(), tc.pod, tc.pod.Spec.Volumes[0].Name, fakeKubeClient)

		require.NoError(t, err)
		assert.Equal(t, tc.want, dir)
	}
}

// TestGetVolumeModeSuccess tests the GetVolumeMode function
func TestGetVolumeModeSuccess(t *testing.T) {
	tests := []struct {
		name string
		pod  *corev1api.Pod
		pvc  *corev1api.PersistentVolumeClaim
		pv   *corev1api.PersistentVolume
		want uploader.PersistentVolumeMode
	}{
		{
			name: "Filesystem PVC volume",
			pod:  builder.ForPod("ns-1", "my-pod").Volumes(builder.ForVolume("my-vol").PersistentVolumeClaimSource("my-pvc").Result()).Result(),
			pvc:  builder.ForPersistentVolumeClaim("ns-1", "my-pvc").VolumeName("a-pv").Result(),
			pv:   builder.ForPersistentVolume("a-pv").VolumeMode(corev1api.PersistentVolumeFilesystem).Result(),
			want: uploader.PersistentVolumeFilesystem,
		},
		{
			name: "Block PVC volume",
			pod:  builder.ForPod("ns-1", "my-pod").Volumes(builder.ForVolume("my-vol").PersistentVolumeClaimSource("my-pvc").Result()).Result(),
			pvc:  builder.ForPersistentVolumeClaim("ns-1", "my-pvc").VolumeName("a-pv").Result(),
			pv:   builder.ForPersistentVolume("a-pv").VolumeMode(corev1api.PersistentVolumeBlock).Result(),
			want: uploader.PersistentVolumeBlock,
		},
		{
			name: "Pod volume without a PVC",
			pod:  builder.ForPod("ns-1", "my-pod").Volumes(builder.ForVolume("my-vol").Result()).Result(),
			want: uploader.PersistentVolumeFilesystem,
		},
	}

	for _, tc := range tests {
		objs := []runtime.Object{}
		if tc.pvc != nil {
			objs = append(objs, tc.pvc)
		}
		if tc.pv != nil {
			objs = append(objs, tc.pv)
		}

		fakeKubeClient := fake.NewSimpleClientset(objs...)

		// Function under test
		mode, err := GetVolumeMode(t.Context(), logrus.StandardLogger(), tc.pod, tc.pod.Spec.Volumes[0].Name, fakeKubeClient)

		require.NoError(t, err)
		assert.Equal(t, tc.want, mode)
	}
}

func TestIsV1Beta1CRDReady(t *testing.T) {
	tests := []struct {
		name string
		crd  *apiextv1beta1.CustomResourceDefinition
		want bool
	}{
		{
			name: "CRD is not established & not accepting names - not ready",
			crd:  builder.ForCustomResourceDefinitionV1Beta1("MyCRD").Result(),
			want: false,
		},
		{
			name: "CRD is established & not accepting names - not ready",
			crd: builder.ForCustomResourceDefinitionV1Beta1("MyCRD").
				Condition(builder.ForCustomResourceDefinitionV1Beta1Condition().Type(apiextv1beta1.Established).Status(apiextv1beta1.ConditionTrue).Result()).Result(),
			want: false,
		},
		{
			name: "CRD is not established & accepting names - not ready",
			crd: builder.ForCustomResourceDefinitionV1Beta1("MyCRD").
				Condition(builder.ForCustomResourceDefinitionV1Beta1Condition().Type(apiextv1beta1.NamesAccepted).Status(apiextv1beta1.ConditionTrue).Result()).Result(),
			want: false,
		},
		{
			name: "CRD is established & accepting names - ready",
			crd: builder.ForCustomResourceDefinitionV1Beta1("MyCRD").
				Condition(builder.ForCustomResourceDefinitionV1Beta1Condition().Type(apiextv1beta1.Established).Status(apiextv1beta1.ConditionTrue).Result()).
				Condition(builder.ForCustomResourceDefinitionV1Beta1Condition().Type(apiextv1beta1.NamesAccepted).Status(apiextv1beta1.ConditionTrue).Result()).
				Result(),
			want: true,
		},
	}

	for _, tc := range tests {
		result := IsV1Beta1CRDReady(tc.crd)
		assert.Equal(t, tc.want, result)
	}
}

func TestIsV1CRDReady(t *testing.T) {
	tests := []struct {
		name string
		crd  *apiextv1.CustomResourceDefinition
		want bool
	}{
		{
			name: "CRD is not established & not accepting names - not ready",
			crd:  builder.ForV1CustomResourceDefinition("MyCRD").Result(),
			want: false,
		},
		{
			name: "CRD is established & not accepting names - not ready",
			crd: builder.ForV1CustomResourceDefinition("MyCRD").
				Condition(builder.ForV1CustomResourceDefinitionCondition().Type(apiextv1.Established).Status(apiextv1.ConditionTrue).Result()).Result(),
			want: false,
		},
		{
			name: "CRD is not established & accepting names - not ready",
			crd: builder.ForV1CustomResourceDefinition("MyCRD").
				Condition(builder.ForV1CustomResourceDefinitionCondition().Type(apiextv1.NamesAccepted).Status(apiextv1.ConditionTrue).Result()).Result(),
			want: false,
		},
		{
			name: "CRD is established & accepting names - ready",
			crd: builder.ForV1CustomResourceDefinition("MyCRD").
				Condition(builder.ForV1CustomResourceDefinitionCondition().Type(apiextv1.Established).Status(apiextv1.ConditionTrue).Result()).
				Condition(builder.ForV1CustomResourceDefinitionCondition().Type(apiextv1.NamesAccepted).Status(apiextv1.ConditionTrue).Result()).
				Result(),
			want: true,
		},
	}

	for _, tc := range tests {
		result := IsV1CRDReady(tc.crd)
		assert.Equal(t, tc.want, result)
	}
}

func TestIsCRDReady(t *testing.T) {
	v1beta1tests := []struct {
		name string
		crd  *apiextv1beta1.CustomResourceDefinition
		want bool
	}{
		{
			name: "v1beta1CRD is not established & not accepting names - not ready",
			crd:  builder.ForCustomResourceDefinitionV1Beta1("MyCRD").Result(),
			want: false,
		},
		{
			name: "v1beta1CRD is established & not accepting names - not ready",
			crd: builder.ForCustomResourceDefinitionV1Beta1("MyCRD").
				Condition(builder.ForCustomResourceDefinitionV1Beta1Condition().Type(apiextv1beta1.Established).Status(apiextv1beta1.ConditionTrue).Result()).Result(),
			want: false,
		},
		{
			name: "v1beta1CRD is not established & accepting names - not ready",
			crd: builder.ForCustomResourceDefinitionV1Beta1("MyCRD").
				Condition(builder.ForCustomResourceDefinitionV1Beta1Condition().Type(apiextv1beta1.NamesAccepted).Status(apiextv1beta1.ConditionTrue).Result()).Result(),
			want: false,
		},
		{
			name: "v1beta1CRD is established & accepting names - ready",
			crd: builder.ForCustomResourceDefinitionV1Beta1("MyCRD").
				Condition(builder.ForCustomResourceDefinitionV1Beta1Condition().Type(apiextv1beta1.Established).Status(apiextv1beta1.ConditionTrue).Result()).
				Condition(builder.ForCustomResourceDefinitionV1Beta1Condition().Type(apiextv1beta1.NamesAccepted).Status(apiextv1beta1.ConditionTrue).Result()).
				Result(),
			want: true,
		},
	}

	for _, tc := range v1beta1tests {
		m, err := runtime.DefaultUnstructuredConverter.ToUnstructured(tc.crd)
		require.NoError(t, err)
		result, err := IsCRDReady(&unstructured.Unstructured{Object: m})
		require.NoError(t, err)
		assert.Equal(t, tc.want, result)
	}

	v1tests := []struct {
		name string
		crd  *apiextv1.CustomResourceDefinition
		want bool
	}{
		{
			name: "v1CRD is not established & not accepting names - not ready",
			crd:  builder.ForV1CustomResourceDefinition("MyCRD").Result(),
			want: false,
		},
		{
			name: "v1CRD is established & not accepting names - not ready",
			crd: builder.ForV1CustomResourceDefinition("MyCRD").
				Condition(builder.ForV1CustomResourceDefinitionCondition().Type(apiextv1.Established).Status(apiextv1.ConditionTrue).Result()).Result(),
			want: false,
		},
		{
			name: "v1CRD is not established & accepting names - not ready",
			crd: builder.ForV1CustomResourceDefinition("MyCRD").
				Condition(builder.ForV1CustomResourceDefinitionCondition().Type(apiextv1.NamesAccepted).Status(apiextv1.ConditionTrue).Result()).Result(),
			want: false,
		},
		{
			name: "v1CRD is established & accepting names - ready",
			crd: builder.ForV1CustomResourceDefinition("MyCRD").
				Condition(builder.ForV1CustomResourceDefinitionCondition().Type(apiextv1.Established).Status(apiextv1.ConditionTrue).Result()).
				Condition(builder.ForV1CustomResourceDefinitionCondition().Type(apiextv1.NamesAccepted).Status(apiextv1.ConditionTrue).Result()).
				Result(),
			want: true,
		},
	}

	for _, tc := range v1tests {
		m, err := runtime.DefaultUnstructuredConverter.ToUnstructured(tc.crd)
		require.NoError(t, err)
		result, err := IsCRDReady(&unstructured.Unstructured{Object: m})
		require.NoError(t, err)
		assert.Equal(t, tc.want, result)
	}

	// input param is unrecognized
	resBytes := []byte(`
{
	"apiVersion": "apiextensions.k8s.io/v9",
	"kind": "CustomResourceDefinition",
	"metadata": {
		"name": "foos.example.foo.com"
	},
	"spec": {
		"group": "example.foo.com",
		"version": "v1alpha1",
		"scope": "Namespaced",
		"names": {
			"plural": "foos",
			"singular": "foo",
			"kind": "Foo"
		},
		"validation": {
			"openAPIV3Schema": {
				"required": [
					"spec"
				],
				"properties": {
					"spec": {
						"required": [
							"bar"
						],
						"properties": {
							"bar": {
								"type": "integer",
								"minimum": 1
							}
						}
					}
				}
			}
		}
	}
}
`)
	obj := &unstructured.Unstructured{}
	err := json.Unmarshal(resBytes, obj)
	require.NoError(t, err)
	_, err = IsCRDReady(obj)
	assert.Error(t, err)
}

func TestSinglePathMatch(t *testing.T) {
	fakeFS := velerotest.NewFakeFileSystem()
	fakeFS.MkdirAll("testDir1/subpath", 0755)
	fakeFS.MkdirAll("testDir2/subpath", 0755)

	_, err := SinglePathMatch("./*/subpath", fakeFS, logrus.StandardLogger())
	require.ErrorContains(t, err, "expected one matching path")
}

func TestAddAnnotations(t *testing.T) {
	annotationValues := map[string]string{
		"k1": "v1",
		"k2": "v2",
		"k3": "v3",
		"k4": "v4",
		"k5": "v5",
	}
	testCases := []struct {
		name  string
		o     metav1.ObjectMeta
		toAdd map[string]string
	}{
		{
			name: "should create a new annotation map when annotation is nil",
			o: metav1.ObjectMeta{
				Annotations: nil,
			},
			toAdd: annotationValues,
		},
		{
			name: "should add all supplied annotations into empty annotation",
			o: metav1.ObjectMeta{
				Annotations: map[string]string{},
			},
			toAdd: annotationValues,
		},
		{
			name: "should add all supplied annotations to existing annotation",
			o: metav1.ObjectMeta{
				Annotations: map[string]string{
					"k100": "v100",
					"k200": "v200",
					"k300": "v300",
				},
			},
			toAdd: annotationValues,
		},
		{
			name: "should overwrite some existing annotations",
			o: metav1.ObjectMeta{
				Annotations: map[string]string{
					"k100": "v100",
					"k2":   "v200",
					"k300": "v300",
				},
			},
			toAdd: annotationValues,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			AddAnnotations(&tc.o, tc.toAdd)
			for k, v := range tc.toAdd {
				actual, exists := tc.o.Annotations[k]
				assert.True(t, exists)
				assert.Equal(t, v, actual)
			}
		})
	}
}

func TestAddLabels(t *testing.T) {
	labelValues := map[string]string{
		"l1": "v1",
		"l2": "v2",
		"l3": "v3",
		"l4": "v4",
		"l5": "v5",
	}
	testCases := []struct {
		name  string
		o     metav1.ObjectMeta
		toAdd map[string]string
	}{
		{
			name: "should create a new labels map when labels is nil",
			o: metav1.ObjectMeta{
				Labels: nil,
			},
			toAdd: labelValues,
		},
		{
			name: "should add all supplied labels into empty labels",
			o: metav1.ObjectMeta{
				Labels: map[string]string{},
			},
			toAdd: labelValues,
		},
		{
			name: "should add all supplied labels to existing labels",
			o: metav1.ObjectMeta{
				Labels: map[string]string{
					"l100": "v100",
					"l200": "v200",
					"l300": "v300",
				},
			},
			toAdd: labelValues,
		},
		{
			name: "should overwrite some existing labels",
			o: metav1.ObjectMeta{
				Labels: map[string]string{
					"l100": "v100",
					"l2":   "v200",
					"l300": "v300",
				},
			},
			toAdd: labelValues,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			AddLabels(&tc.o, tc.toAdd)
			for k, v := range tc.toAdd {
				actual, exists := tc.o.Labels[k]
				assert.True(t, exists)
				assert.Equal(t, v, actual)
			}
		})
	}
}

func TestHasBackupLabel(t *testing.T) {
	testCases := []struct {
		name       string
		o          metav1.ObjectMeta
		backupName string
		expected   bool
	}{
		{
			name:     "object has no labels",
			o:        metav1.ObjectMeta{},
			expected: false,
		},
		{
			name:       "object has no velero backup label",
			backupName: "csi-b1",
			o: metav1.ObjectMeta{
				Labels: map[string]string{
					"l100": "v100",
					"l2":   "v200",
					"l300": "v300",
				},
			},
			expected: false,
		},
		{
			name:       "object has velero backup label but value not equal to backup name",
			backupName: "csi-b1",
			o: metav1.ObjectMeta{
				Labels: map[string]string{
					"velero.io/backup-name": "does-not-match",
					"l100":                  "v100",
					"l2":                    "v200",
					"l300":                  "v300",
				},
			},
			expected: false,
		},
		{
			name:       "object has backup label with matching backup name value",
			backupName: "does-match",
			o: metav1.ObjectMeta{
				Labels: map[string]string{
					"velero.io/backup-name": "does-match",
					"l100":                  "v100",
					"l2":                    "v200",
					"l300":                  "v300",
				},
			},
			expected: true,
		},
	}

	for _, tc := range testCases {
		actual := HasBackupLabel(&tc.o, tc.backupName)
		assert.Equal(t, tc.expected, actual)
	}
}

func TestVerifyJsonConfigs(t *testing.T) {
	testCases := []struct {
		name          string
		configMapName string
		configMap     *corev1api.ConfigMap
		configType    any
		expectedErr   string
	}{
		{
			name:          "ConfigMap not exist",
			configMapName: "non-exist",
			expectedErr:   "fail to find ConfigMap non-exist: configmaps \"non-exist\" not found",
		},
		{
			name:          "ConfigMap doesn't have data",
			configMapName: "no-data",
			expectedErr:   "data is not available in ConfigMap no-data",
			configMap:     builder.ForConfigMap("velero", "no-data").Result(),
		},
		{
			name:          "ConfigMap data is invalid",
			configMapName: "invalid",
			expectedErr:   "error to unmarshall data from ConfigMap invalid: unexpected end of JSON input",
			configMap:     builder.ForConfigMap("velero", "invalid").Data("global", "{\"podResources\": {\"cpuRequest\": \"100m\", \"cpuLimit\": \"200m\", \"memoryRequest\": \"100Mi\", \"memoryLimit\": \"200Mi\"}, \"keepLatestMaintenanceJobs\": 1}", "other", "{\"podResources\": {\"cpuRequest\": \"100m\", \"cpuLimit\": \"200m\", \"memoryRequest\": \"100Mi\", \"memoryLimit\": \"200Mi\"}, \"keepLatestMaintenanceJobs: 1}").Result(),
		},
		{
			name:          "Normal case",
			configMapName: "normal",
			configMap:     builder.ForConfigMap("velero", "normal").Data("global", "{\"podResources\": {\"cpuRequest\": \"100m\", \"cpuLimit\": \"200m\", \"memoryRequest\": \"100Mi\", \"memoryLimit\": \"200Mi\"}, \"keepLatestMaintenanceJobs\": 1}", "other", "{\"podResources\": {\"cpuRequest\": \"100m\", \"cpuLimit\": \"200m\", \"memoryRequest\": \"100Mi\", \"memoryLimit\": \"200Mi\"}, \"keepLatestMaintenanceJobs\": 1}").Result(),
			configType:    make(map[string]any),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			objects := make([]runtime.Object, 0)
			if tc.configMap != nil {
				objects = append(objects, tc.configMap)
			}
			fakeClient := velerotest.NewFakeControllerRuntimeClient(t, objects...)
			err := VerifyJSONConfigs(t.Context(), "velero", fakeClient, tc.configMapName, tc.configMap)
			if len(tc.expectedErr) > 0 {
				require.EqualError(t, err, tc.expectedErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestGetVolumeModeByPVC(t *testing.T) {
	modeFilesystem := corev1api.PersistentVolumeFilesystem
	modeBlock := corev1api.PersistentVolumeBlock

	tests := []struct {
		name     string
		pvc      *corev1api.PersistentVolumeClaim
		expected corev1api.PersistentVolumeMode
	}{
		{
			name: "nil VolumeMode returns Filesystem",
			pvc: &corev1api.PersistentVolumeClaim{
				Spec: corev1api.PersistentVolumeClaimSpec{
					VolumeMode: nil,
				},
			},
			expected: corev1api.PersistentVolumeFilesystem,
		},
		{
			name: "Filesystem VolumeMode returns Filesystem",
			pvc: &corev1api.PersistentVolumeClaim{
				Spec: corev1api.PersistentVolumeClaimSpec{
					VolumeMode: &modeFilesystem,
				},
			},
			expected: corev1api.PersistentVolumeFilesystem,
		},
		{
			name: "Block VolumeMode returns Block",
			pvc: &corev1api.PersistentVolumeClaim{
				Spec: corev1api.PersistentVolumeClaimSpec{
					VolumeMode: &modeBlock,
				},
			},
			expected: corev1api.PersistentVolumeBlock,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := GetVolumeModeByPVC(test.pvc)
			assert.Equal(t, test.expected, actual)
		})
	}
}

func TestGetVolumeModeByPV(t *testing.T) {
	modeFilesystem := corev1api.PersistentVolumeFilesystem
	modeBlock := corev1api.PersistentVolumeBlock

	tests := []struct {
		name     string
		pv       *corev1api.PersistentVolume
		expected corev1api.PersistentVolumeMode
	}{
		{
			name: "nil VolumeMode returns Filesystem",
			pv: &corev1api.PersistentVolume{
				Spec: corev1api.PersistentVolumeSpec{
					VolumeMode: nil,
				},
			},
			expected: corev1api.PersistentVolumeFilesystem,
		},
		{
			name: "Filesystem VolumeMode returns Filesystem",
			pv: &corev1api.PersistentVolume{
				Spec: corev1api.PersistentVolumeSpec{
					VolumeMode: &modeFilesystem,
				},
			},
			expected: corev1api.PersistentVolumeFilesystem,
		},
		{
			name: "Block VolumeMode returns Block",
			pv: &corev1api.PersistentVolume{
				Spec: corev1api.PersistentVolumeSpec{
					VolumeMode: &modeBlock,
				},
			},
			expected: corev1api.PersistentVolumeBlock,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := GetVolumeModeByPV(test.pv)
			assert.Equal(t, test.expected, actual)
		})
	}
}
