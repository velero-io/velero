/*
Copyright 2019 the Velero contributors.

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

package backup

import (
	"bytes"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrlfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/vmware-tanzu/velero/internal/resourcepolicies"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/kuberesource"
	"github.com/vmware-tanzu/velero/pkg/util/collections"
)

func Test_resourceKey(t *testing.T) {
	tests := []struct {
		resource metav1.Object
		want     string
	}{
		{resource: builder.ForPod("default", "test").Result(), want: "v1/Pod"},
		{resource: builder.ForDeployment("default", "test").Result(), want: "apps/v1/Deployment"},
		{resource: builder.ForPersistentVolume("test").Result(), want: "v1/PersistentVolume"},
		{resource: builder.ForRole("default", "test").Result(), want: "rbac.authorization.k8s.io/v1/Role"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			content, _ := runtime.DefaultUnstructuredConverter.ToUnstructured(tt.resource)
			unstructured := &unstructured.Unstructured{Object: content}
			assert.Equal(t, tt.want, resourceKey(unstructured))
		})
	}
}

func Test_zoneFromPVNodeAffinity(t *testing.T) {
	keys := []string{
		awsEbsCsiZoneKey,
		azureCsiZoneKey,
		gkeCsiZoneKey,
		zoneLabel,
		zoneLabelDeprecated,
	}
	tests := []struct {
		name      string
		pv        *corev1api.PersistentVolume
		wantKey   string
		wantValue string
	}{
		{
			name: "AWS CSI Volume",
			pv: builder.ForPersistentVolume("awscsi").NodeAffinityRequired(
				builder.ForNodeSelector(
					*builder.NewNodeSelectorTermBuilder().WithMatchExpression("topology.ebs.csi.aws.com/zone",
						"In", "us-east-2c").Result(),
				).Result(),
			).Result(),
			wantKey:   "topology.ebs.csi.aws.com/zone",
			wantValue: "us-east-2c",
		},
		{
			name: "Azure CSI Volume",
			pv: builder.ForPersistentVolume("azurecsi").NodeAffinityRequired(
				builder.ForNodeSelector(
					*builder.NewNodeSelectorTermBuilder().WithMatchExpression("topology.disk.csi.azure.com/zone",
						"In", "us-central").Result(),
				).Result(),
			).Result(),
			wantKey:   "topology.disk.csi.azure.com/zone",
			wantValue: "us-central",
		},
		{
			name: "GCP CSI Volume",
			pv: builder.ForPersistentVolume("gcpcsi").NodeAffinityRequired(
				builder.ForNodeSelector(
					*builder.NewNodeSelectorTermBuilder().WithMatchExpression("topology.gke.io/zone",
						"In", "us-west1-a").Result(),
				).Result(),
			).Result(),
			wantKey:   "topology.gke.io/zone",
			wantValue: "us-west1-a",
		},
		{
			name: "AWS CSI Volume with multiple zone value, returns the first",
			pv: builder.ForPersistentVolume("awscsi").NodeAffinityRequired(
				builder.ForNodeSelector(
					*builder.NewNodeSelectorTermBuilder().WithMatchExpression("topology.ebs.csi.aws.com/zone",
						"In", "us-east-2c", "us-west").Result(),
				).Result(),
			).Result(),
			wantKey:   "topology.ebs.csi.aws.com/zone",
			wantValue: "us-east-2c",
		},
		{
			name: "Volume with no matching key",
			pv: builder.ForPersistentVolume("no-matching-pv").NodeAffinityRequired(
				builder.ForNodeSelector(
					*builder.NewNodeSelectorTermBuilder().WithMatchExpression("some-key",
						"In", "us-west").Result(),
				).Result(),
			).Result(),
			wantKey:   "",
			wantValue: "",
		},
		{
			name: "Volume with multiple valid keys, returns the first match", // it should never happen
			pv: builder.ForPersistentVolume("multi-matching-pv").NodeAffinityRequired(
				builder.ForNodeSelector(
					*builder.NewNodeSelectorTermBuilder().WithMatchExpression("topology.disk.csi.azure.com/zone",
						"In", "us-central").Result(),
					*builder.NewNodeSelectorTermBuilder().WithMatchExpression("topology.ebs.csi.aws.com/zone",
						"In", "us-east-2c", "us-west").Result(),
					*builder.NewNodeSelectorTermBuilder().WithMatchExpression("topology.ebs.csi.aws.com/zone",
						"In", "unknown").Result(),
				).Result(),
			).Result(),
			wantKey:   "topology.disk.csi.azure.com/zone",
			wantValue: "us-central",
		},
		{
			/* an valid example of node affinity in a GKE's regional PV
			nodeAffinity:
			  required:
			    nodeSelectorTerms:
			    - matchExpressions:
			      - key: topology.gke.io/zone
			        operator: In
			        values:
			        - us-central1-a
			    - matchExpressions:
			      - key: topology.gke.io/zone
			        operator: In
			        values:
			        - us-central1-c
			*/
			name: "Volume with multiple valid keys, and provider is gke, returns all valid entries's first zone value",
			pv: builder.ForPersistentVolume("multi-matching-pv").NodeAffinityRequired(
				builder.ForNodeSelector(
					*builder.NewNodeSelectorTermBuilder().WithMatchExpression("topology.gke.io/zone",
						"In", "us-central1-c").Result(),
					*builder.NewNodeSelectorTermBuilder().WithMatchExpression("topology.gke.io/zone",
						"In", "us-east-2c", "us-east-2b").Result(),
					*builder.NewNodeSelectorTermBuilder().WithMatchExpression("topology.gke.io/zone",
						"In", "europe-north1-a").Result(),
				).Result(),
			).Result(),
			wantKey:   "topology.gke.io/zone",
			wantValue: "us-central1-c__us-east-2c__europe-north1-a",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k, v := zoneFromPVNodeAffinity(tt.pv, keys...)
			assert.Equal(t, tt.wantKey, k)
			assert.Equal(t, tt.wantValue, v)
		})
	}
}

func TestGetPVName(t *testing.T) {
	testcases := []struct {
		name          string
		obj           metav1.Object
		groupResource schema.GroupResource
		pvName        string
		hasErr        bool
	}{
		{
			name:          "pv should return pv name",
			obj:           builder.ForPersistentVolume("test-pv").Result(),
			groupResource: kuberesource.PersistentVolumes,
			pvName:        "test-pv",
			hasErr:        false,
		},
		{
			name:          "pvc without volumeName should return error",
			obj:           builder.ForPersistentVolumeClaim("ns", "pvc-1").Result(),
			groupResource: kuberesource.PersistentVolumeClaims,
			pvName:        "",
			hasErr:        true,
		},
		{
			name:          "pvc with volumeName should return pv name",
			obj:           builder.ForPersistentVolumeClaim("ns", "pvc-1").VolumeName("test-pv-2").Result(),
			groupResource: kuberesource.PersistentVolumeClaims,
			pvName:        "test-pv-2",
			hasErr:        false,
		},
		{
			name:          "unsupported group resource should return empty pv name",
			obj:           builder.ForPod("ns", "pod1").Result(),
			groupResource: kuberesource.Pods,
			pvName:        "",
			hasErr:        false,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			o := &unstructured.Unstructured{Object: nil}
			if tc.obj != nil {
				data, err := runtime.DefaultUnstructuredConverter.ToUnstructured(tc.obj)
				o = &unstructured.Unstructured{Object: data}
				require.NoError(t, err)
			}
			name, err2 := getPVName(o, tc.groupResource)
			assert.Equal(t, tc.pvName, name)
			assert.Equal(t, tc.hasErr, err2 != nil)
		})
	}
}

func TestRandom(t *testing.T) {
	pv := new(corev1api.PersistentVolume)
	pvc := new(corev1api.PersistentVolumeClaim)
	obj := builder.ForPod("ns1", "pod1").ServiceAccount("sa").Result()
	o, _ := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	err1 := runtime.DefaultUnstructuredConverter.FromUnstructured(o, pv)
	err2 := runtime.DefaultUnstructuredConverter.FromUnstructured(o, pvc)
	t.Logf("err1: %v, err2: %v", err1, err2)
}

func TestAddVolumeInfo(t *testing.T) {
	tests := []struct {
		name string
		pv   *corev1api.PersistentVolume
	}{
		{
			name: "PV has ClaimRef",
			pv:   builder.ForPersistentVolume("testPV").ClaimRef("testNS", "testPVC").Result(),
		},
		{
			name: "PV has no ClaimRef",
			pv:   builder.ForPersistentVolume("testPV").Result(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ib := itemBackupper{}
			ib.backupRequest = new(Request)
			ib.backupRequest.VolumesInformation.Init()

			pvObj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(tc.pv)
			require.NoError(t, err)
			logger := logrus.StandardLogger()

			err = ib.addVolumeInfo(&unstructured.Unstructured{Object: pvObj}, logger)
			require.NoError(t, err)
		})
	}
}

func TestGetMatchAction_PendingLostPVC(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1api.AddToScheme(scheme))

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
		pv             *corev1api.PersistentVolume
		expectedAction *resourcepolicies.Action
		expectError    bool
	}{
		{
			name: "Pending PVC with no VolumeName should match pvcPhase policy",
			pvc: builder.ForPersistentVolumeClaim("ns", "pending-pvc").
				StorageClass("test-sc").
				Phase(corev1api.ClaimPending).
				Result(),
			pv:             nil,
			expectedAction: &resourcepolicies.Action{Type: resourcepolicies.Skip},
			expectError:    false,
		},
		{
			name: "Lost PVC with no VolumeName should match pvcPhase policy",
			pvc: builder.ForPersistentVolumeClaim("ns", "lost-pvc").
				StorageClass("test-sc").
				Phase(corev1api.ClaimLost).
				Result(),
			pv:             nil,
			expectedAction: &resourcepolicies.Action{Type: resourcepolicies.Skip},
			expectError:    false,
		},
		{
			name: "Bound PVC with VolumeName and matching PV should not match pvcPhase policy",
			pvc: builder.ForPersistentVolumeClaim("ns", "bound-pvc").
				StorageClass("test-sc").
				VolumeName("test-pv").
				Phase(corev1api.ClaimBound).
				Result(),
			pv:             builder.ForPersistentVolume("test-pv").StorageClass("test-sc").Result(),
			expectedAction: nil,
			expectError:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Build fake client with PV if present
			clientBuilder := ctrlfake.NewClientBuilder().WithScheme(scheme)
			if tc.pv != nil {
				clientBuilder = clientBuilder.WithObjects(tc.pv)
			}
			fakeClient := clientBuilder.Build()

			ib := &itemBackupper{
				kbClient: fakeClient,
				backupRequest: &Request{
					ResPolicies: policies,
				},
			}

			// Convert PVC to unstructured
			pvcData, err := runtime.DefaultUnstructuredConverter.ToUnstructured(tc.pvc)
			require.NoError(t, err)
			obj := &unstructured.Unstructured{Object: pvcData}

			action, err := ib.getMatchAction(obj, kuberesource.PersistentVolumeClaims, csiBIAPluginName)
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

func TestTrackSkippedPV_PendingLostPVC(t *testing.T) {
	testCases := []struct {
		name string
		pvc  *corev1api.PersistentVolumeClaim
	}{
		{
			name: "Pending PVC should log at info level",
			pvc: builder.ForPersistentVolumeClaim("ns", "pending-pvc").
				Phase(corev1api.ClaimPending).
				Result(),
		},
		{
			name: "Lost PVC should log at info level",
			pvc: builder.ForPersistentVolumeClaim("ns", "lost-pvc").
				Phase(corev1api.ClaimLost).
				Result(),
		},
		{
			name: "Bound PVC without VolumeName should log at info level",
			pvc: builder.ForPersistentVolumeClaim("ns", "bound-pvc").
				Phase(corev1api.ClaimBound).
				Result(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ib := &itemBackupper{
				backupRequest: &Request{
					SkippedPVTracker: NewSkipPVTracker(),
				},
			}

			// Set up log capture
			logOutput := &bytes.Buffer{}
			logger := logrus.New()
			logger.SetOutput(logOutput)
			logger.SetLevel(logrus.DebugLevel)

			// Convert PVC to unstructured
			pvcData, err := runtime.DefaultUnstructuredConverter.ToUnstructured(tc.pvc)
			require.NoError(t, err)
			obj := &unstructured.Unstructured{Object: pvcData}

			ib.trackSkippedPV(obj, kuberesource.PersistentVolumeClaims, "", "test reason", logger)

			logStr := logOutput.String()
			assert.Contains(t, logStr, "level=info")
			assert.Contains(t, logStr, "unable to get PV name, skip tracking.")
		})
	}
}

func TestUnTrackSkippedPV_PendingLostPVC(t *testing.T) {
	testCases := []struct {
		name               string
		pvc                *corev1api.PersistentVolumeClaim
		expectWarningLog   bool
		expectDebugMessage string
	}{
		{
			name: "Pending PVC should log at debug level, not warning",
			pvc: builder.ForPersistentVolumeClaim("ns", "pending-pvc").
				Phase(corev1api.ClaimPending).
				Result(),
			expectWarningLog:   false,
			expectDebugMessage: "unable to get PV name for Pending PVC, skip untracking.",
		},
		{
			name: "Lost PVC should log at debug level, not warning",
			pvc: builder.ForPersistentVolumeClaim("ns", "lost-pvc").
				Phase(corev1api.ClaimLost).
				Result(),
			expectWarningLog:   false,
			expectDebugMessage: "unable to get PV name for Lost PVC, skip untracking.",
		},
		{
			name: "Bound PVC without VolumeName should log warning",
			pvc: builder.ForPersistentVolumeClaim("ns", "bound-pvc").
				Phase(corev1api.ClaimBound).
				Result(),
			expectWarningLog:   true,
			expectDebugMessage: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ib := &itemBackupper{
				backupRequest: &Request{
					SkippedPVTracker: NewSkipPVTracker(),
				},
			}

			// Set up log capture
			logOutput := &bytes.Buffer{}
			logger := logrus.New()
			logger.SetOutput(logOutput)
			logger.SetLevel(logrus.DebugLevel)

			// Convert PVC to unstructured
			pvcData, err := runtime.DefaultUnstructuredConverter.ToUnstructured(tc.pvc)
			require.NoError(t, err)
			obj := &unstructured.Unstructured{Object: pvcData}

			ib.unTrackSkippedPV(obj, kuberesource.PersistentVolumeClaims, logger)

			logStr := logOutput.String()
			if tc.expectWarningLog {
				assert.Contains(t, logStr, "level=warning")
				assert.Contains(t, logStr, "unable to get PV name, skip untracking.")
			} else {
				assert.NotContains(t, logStr, "level=warning")
				if tc.expectDebugMessage != "" {
					assert.Contains(t, logStr, "level=debug")
					assert.Contains(t, logStr, tc.expectDebugMessage)
				}
			}
		})
	}
}

// includeAllIE is a minimal IncludesExcludesInterface that includes everything —
// used in tests where the global resource include/exclude logic is not under test.
type includeAllIE struct{}

func (includeAllIE) ShouldInclude(string) bool { return true }
func (includeAllIE) ShouldExclude(string) bool { return false }

// makeTestUnstructured creates an unstructured object with the given namespace, name, and labels.
func makeTestUnstructured(namespace, name string, labels map[string]string) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{}
	obj.SetNamespace(namespace)
	obj.SetName(name)
	if labels != nil {
		obj.SetLabels(labels)
	}
	return obj
}

// makeNameIE creates an IncludesExcludes that includes only the given glob patterns.
func makeNameIE(include ...string) *collections.IncludesExcludes {
	ie := collections.NewIncludesExcludes()
	ie.Includes(include...)
	return ie
}

// newTestItemBackupper builds a minimal itemBackupper suitable for itemInclusionChecks tests.
func newTestItemBackupper(req *Request) *itemBackupper {
	return &itemBackupper{
		backupRequest: req,
	}
}

// baseRequest returns a Request with NamespaceIncludesExcludes and ResourceIncludesExcludes
// configured to include everything, so only the filter-map logic under test is exercised.
func baseRequest() *Request {
	return &Request{
		Backup:                    builder.ForBackup("velero", "test-backup").Result(),
		NamespaceIncludesExcludes: collections.NewNamespaceIncludesExcludes().Includes("*"),
		ResourceIncludesExcludes:  includeAllIE{},
		SkippedPVTracker:          NewSkipPVTracker(),
	}
}

var configMapsGR = schema.GroupResource{Group: "", Resource: "configmaps"}
var clusterRolesGR = schema.GroupResource{Group: "rbac.authorization.k8s.io", Resource: "clusterroles"}

// TestItemInclusionChecks_ExcludeLabel_OverridesNamespaceFilter verifies that
// velero.io/exclude-from-backup=true takes precedence over a namespacedFilterPolicies
// entry that would otherwise include the resource.
func TestItemInclusionChecks_ExcludeLabel_OverridesNamespaceFilter(t *testing.T) {
	req := baseRequest()
	req.NamespacedFilterMap = map[string]*ResolvedNamespaceFilter{
		"ns-a": {
			ResourceFilterMap: map[string]*ResolvedResourceFilter{
				configMapsGR.String(): {}, // include all ConfigMaps in ns-a
			},
		},
	}
	req.NamespacedFilterPatterns = []NamespacedFilterPattern{}

	ib := newTestItemBackupper(req)
	log := logrus.New()

	obj := makeTestUnstructured("ns-a", "my-config", map[string]string{
		velerov1api.ExcludeFromBackupLabel: "true",
	})

	result := ib.itemInclusionChecks(log, false, obj, obj, configMapsGR)
	assert.False(t, result, "resource with exclude-from-backup=true must be excluded even when matched by namespacedFilterPolicies")
}

// TestItemInclusionChecks_ExcludeLabel_OverridesCatchAll verifies that
// velero.io/exclude-from-backup=true takes precedence over the catch-all filter.
func TestItemInclusionChecks_ExcludeLabel_OverridesCatchAll(t *testing.T) {
	catchAllFilter := &ResolvedResourceFilter{} // include everything via catch-all
	req := baseRequest()
	req.NamespacedFilterMap = map[string]*ResolvedNamespaceFilter{
		"ns-a": {
			ResourceFilterMap: map[string]*ResolvedResourceFilter{},
			CatchAllFilter:    catchAllFilter,
		},
	}
	req.NamespacedFilterPatterns = []NamespacedFilterPattern{}

	ib := newTestItemBackupper(req)
	log := logrus.New()

	obj := makeTestUnstructured("ns-a", "my-config", map[string]string{
		velerov1api.ExcludeFromBackupLabel: "true",
	})

	result := ib.itemInclusionChecks(log, false, obj, obj, configMapsGR)
	assert.False(t, result, "resource with exclude-from-backup=true must be excluded even when matched by catch-all filter")
}

// TestItemInclusionChecks_ExcludeLabel_OverridesClusterScopedFilter verifies that
// velero.io/exclude-from-backup=true takes precedence over clusterScopedFilterPolicy.
func TestItemInclusionChecks_ExcludeLabel_OverridesClusterScopedFilter(t *testing.T) {
	req := baseRequest()
	req.ClusterScopedFilterMap = map[string]*ResolvedResourceFilter{
		clusterRolesGR.String(): {}, // include all ClusterRoles
	}

	ib := newTestItemBackupper(req)
	log := logrus.New()

	// Cluster-scoped object: no namespace
	obj := makeTestUnstructured("", "my-role", map[string]string{
		velerov1api.ExcludeFromBackupLabel: "true",
	})

	result := ib.itemInclusionChecks(log, false, obj, obj, clusterRolesGR)
	assert.False(t, result, "cluster-scoped resource with exclude-from-backup=true must be excluded even when in clusterScopedFilterPolicy")
}

// TestItemInclusionChecks_ClusterScoped_NotInFilterMap_PassesThrough verifies that
// a dynamically injected cluster-scoped resource NOT listed in ClusterScopedFilterMap
// passes through itemInclusionChecks (permissive passthrough at Stage 2).
func TestItemInclusionChecks_ClusterScoped_NotInFilterMap_PassesThrough(t *testing.T) {
	req := baseRequest()
	req.ClusterScopedFilterMap = map[string]*ResolvedResourceFilter{
		clusterRolesGR.String(): {}, // only ClusterRoles are listed
	}

	ib := newTestItemBackupper(req)
	log := logrus.New()

	// VolumeSnapshotClass is NOT in the filter map
	volumeSnapshotClassGR := schema.GroupResource{Group: "snapshot.storage.k8s.io", Resource: "volumesnapshotclasses"}
	obj := makeTestUnstructured("", "standard", nil)

	result := ib.itemInclusionChecks(log, false, obj, obj, volumeSnapshotClassGR)
	assert.True(t, result, "cluster-scoped resource not in ClusterScopedFilterMap must pass through (permissive Stage 2 for unlisted kinds)")
}

// TestItemInclusionChecks_ClusterScoped_NameIE_Matching verifies that a cluster-scoped
// resource listed in ClusterScopedFilterMap with a NameIE filter is included/excluded
// based on its name.
func TestItemInclusionChecks_ClusterScoped_NameIE_Matching(t *testing.T) {
	req := baseRequest()
	req.ClusterScopedFilterMap = map[string]*ResolvedResourceFilter{
		clusterRolesGR.String(): {
			NameIE: makeNameIE("my-app-*"),
		},
	}

	ib := newTestItemBackupper(req)
	log := logrus.New()

	// Matching name
	matching := makeTestUnstructured("", "my-app-reader", nil)
	assert.True(t, ib.itemInclusionChecks(log, false, matching, matching, clusterRolesGR),
		"ClusterRole matching name pattern must be included")

	// Non-matching name
	nonMatching := makeTestUnstructured("", "other-role", nil)
	assert.False(t, ib.itemInclusionChecks(log, false, nonMatching, nonMatching, clusterRolesGR),
		"ClusterRole not matching name pattern must be excluded")
}

// TestItemInclusionChecks_GlobalExclusion_OverridesNamespaceFilter verifies that
// a resource kind globally excluded by includeExcludePolicy is rejected at Stage 2
// even when a namespacedFilterPolicies entry lists that kind. The global
// ResourceIncludesExcludes.ShouldInclude check fires before the per-namespace filter.
func TestItemInclusionChecks_GlobalExclusion_OverridesNamespaceFilter(t *testing.T) {
	// excludeSecretsIE excludes "secrets" globally, includes everything else.
	excludeSecretsIE := &excludeResourceIE{excluded: "secrets"}

	req := &Request{
		Backup:                    builder.ForBackup("velero", "test-backup").Result(),
		NamespaceIncludesExcludes: collections.NewNamespaceIncludesExcludes().Includes("*"),
		ResourceIncludesExcludes:  excludeSecretsIE,
		SkippedPVTracker:          NewSkipPVTracker(),
		// namespacedFilterPolicies says to back up Secrets in ns-a
		NamespacedFilterMap: map[string]*ResolvedNamespaceFilter{
			"ns-a": {
				ResourceFilterMap: map[string]*ResolvedResourceFilter{
					"secrets.": {}, // Secret listed in per-namespace filter
				},
			},
		},
		NamespacedFilterPatterns: []NamespacedFilterPattern{},
	}

	ib := newTestItemBackupper(req)
	log := logrus.New()

	secretsGR := schema.GroupResource{Group: "", Resource: "secrets"}
	obj := makeTestUnstructured("ns-a", "my-secret", nil)

	result := ib.itemInclusionChecks(log, false, obj, obj, secretsGR)
	assert.False(t, result,
		"Secret must be excluded because it is globally excluded by ResourceIncludesExcludes, "+
			"even though namespacedFilterPolicies lists it")
}

// TestItemInclusionChecks_PluginItem_UnlistedKind_NoCatchAll_PassesThrough verifies the
// intentional permissive passthrough at Stage 2 for plugin-injected additional items.
// When a namespace has a namespacedFilterPolicies entry but the item's kind is not listed
// in that policy and there is no catch-all entry, itemInclusionChecks must still allow
// the item through.
//
// Rationale: plugin-injected additional items (returned by BackupItemAction) must be able
// to reach the archive even when their kind was not explicitly listed in the filter policy,
// because rejecting them here would break backup completeness. For example, a CSI plugin
// may inject a VolumeSnapshotContent that is required for a correct restore.
// Kind-level exclusion for the primary collection pass is enforced at Stage 1 in
// item_collector.go, not at Stage 2 here.
func TestItemInclusionChecks_PluginItem_UnlistedKind_NoCatchAll_PassesThrough(t *testing.T) {
	req := baseRequest()
	// Namespace filter only lists ConfigMaps; Secrets are not listed and there is no catch-all.
	req.NamespacedFilterMap = map[string]*ResolvedNamespaceFilter{
		"ns-a": {
			ResourceFilterMap: map[string]*ResolvedResourceFilter{
				configMapsGR.String(): {},
			},
			CatchAllFilter: nil,
		},
	}
	req.NamespacedFilterPatterns = []NamespacedFilterPattern{}

	ib := newTestItemBackupper(req)
	log := logrus.New()

	secretsGR := schema.GroupResource{Group: "", Resource: "secrets"}
	obj := makeTestUnstructured("ns-a", "plugin-injected-secret", nil)

	result := ib.itemInclusionChecks(log, false, obj, obj, secretsGR)
	assert.True(t, result,
		"plugin-injected additional item of an unlisted kind must pass through Stage 2 "+
			"even when its namespace has a namespacedFilterPolicies entry with no catch-all; "+
			"kind exclusion is enforced at Stage 1 (item_collector.go), not here")
}

// TestItemInclusionChecks_PluginItem_UnlistedKind_WithCatchAll_PassesThrough verifies that
// a plugin-injected additional item of a kind not listed in the namespace filter also passes
// through Stage 2 when a catch-all entry is present. The catch-all is validated to never
// carry a NameIE (names/excludedNames are prohibited on catch-all entries), so the name
// check is always a no-op for catch-all-matched items and the item is included.
func TestItemInclusionChecks_PluginItem_UnlistedKind_WithCatchAll_PassesThrough(t *testing.T) {
	req := baseRequest()
	// Namespace filter lists ConfigMaps explicitly; a catch-all covers everything else.
	// The catch-all has no NameIE — this is enforced by validation.
	req.NamespacedFilterMap = map[string]*ResolvedNamespaceFilter{
		"ns-a": {
			ResourceFilterMap: map[string]*ResolvedResourceFilter{
				configMapsGR.String(): {},
			},
			CatchAllFilter: &ResolvedResourceFilter{
				// NameIE intentionally nil: validation forbids names/excludedNames on catch-all
				NameIE: nil,
			},
		},
	}
	req.NamespacedFilterPatterns = []NamespacedFilterPattern{}

	ib := newTestItemBackupper(req)
	log := logrus.New()

	secretsGR := schema.GroupResource{Group: "", Resource: "secrets"}
	obj := makeTestUnstructured("ns-a", "plugin-injected-secret", nil)

	result := ib.itemInclusionChecks(log, false, obj, obj, secretsGR)
	assert.True(t, result,
		"plugin-injected additional item matched by catch-all must pass through Stage 2; "+
			"the catch-all has no NameIE so the name check is a no-op")
}

// excludeResourceIE is an IncludesExcludesInterface that excludes a single resource
// type and includes everything else. Used to simulate includeExcludePolicy global exclusions.
type excludeResourceIE struct {
	excluded string
}

func (e *excludeResourceIE) ShouldInclude(typeName string) bool {
	return typeName != e.excluded
}
func (e *excludeResourceIE) ShouldExclude(typeName string) bool {
	return typeName == e.excluded
}
