package restore

import (
	"io"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/vmware-tanzu/velero/internal/resourcepolicies"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/test"
)

func TestRestoreResourcePoliciesFiltering(t *testing.T) {
	customKindRes := &test.APIResource{Group: "mygroup.io", Version: "v1", Name: "mycustomkinds", Kind: "MyCustomKind", Namespaced: true}
	clusterCustomKindRes := &test.APIResource{Group: "mygroup.io", Version: "v1", Name: "myclustercustomkinds", Kind: "MyClusterCustomKind", Namespaced: false}

	tests := []struct {
		name         string
		restore      *velerov1api.Restore
		backup       *velerov1api.Backup
		policyYAML   string
		apiResources []*test.APIResource
		tarball      io.Reader
		want         map[*test.APIResource][]string
	}{
		{
			name:    "namespaced filter policy with exact namespace match",
			restore: defaultRestore().Result(),
			backup:  defaultBackup().Result(),
			policyYAML: `version: v1
namespacedFilterPolicies:
  - namespaces:
      - ns-1
    resourceFilters:
      - kinds:
          - pods
        names:
          - pod-1
`,
			tarball: test.NewTarWriter(t).
				AddItems("pods",
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-1", "pod-2").Result(),
					builder.ForPod("ns-2", "pod-1").Result(),
				).
				Done(),
			apiResources: []*test.APIResource{
				test.Pods(),
			},
			want: map[*test.APIResource][]string{
				test.Pods(): {"ns-1/pod-1", "ns-2/pod-1"}, // ns-2 is not filtered, ns-1 only includes pod-1
			},
		},
		{
			name:    "namespaced filter policy with exact match priority over glob",
			restore: defaultRestore().Result(),
			backup:  defaultBackup().Result(),
			policyYAML: `version: v1
namespacedFilterPolicies:
  - namespaces:
      - ns-*
    resourceFilters:
      - kinds:
          - pods
        names:
          - pod-1
  - namespaces:
      - ns-1
    resourceFilters:
      - kinds:
          - pods
        names:
          - pod-2
`,
			tarball: test.NewTarWriter(t).
				AddItems("pods",
					builder.ForPod("ns-1", "pod-1").Result(),
					builder.ForPod("ns-1", "pod-2").Result(),
					builder.ForPod("ns-2", "pod-1").Result(),
					builder.ForPod("ns-2", "pod-2").Result(),
				).
				Done(),
			apiResources: []*test.APIResource{
				test.Pods(),
			},
			want: map[*test.APIResource][]string{
				test.Pods(): {"ns-1/pod-2", "ns-2/pod-1"},
			},
		},
		{
			name:    "cluster scoped filter policy",
			restore: defaultRestore().Result(),
			backup:  defaultBackup().Result(),
			policyYAML: `version: v1
clusterScopedFilterPolicy:
  resourceFilters:
    - kinds:
        - persistentvolumes
      names:
        - pv-1
`,
			tarball: test.NewTarWriter(t).
				AddItems("persistentvolumes",
					builder.ForPersistentVolume("pv-1").Result(),
					builder.ForPersistentVolume("pv-2").Result(),
				).
				Done(),
			apiResources: []*test.APIResource{
				test.PVs(),
			},
			want: map[*test.APIResource][]string{
				test.PVs(): {"/pv-1"},
			},
		},
		{
			name:    "catch-all filter",
			restore: defaultRestore().Result(),
			backup:  defaultBackup().Result(),
			policyYAML: `version: v1
namespacedFilterPolicies:
  - namespaces:
      - ns-1
    resourceFilters:
      - kinds:
          - '*'
        labelSelector:
          app: test
`,
			tarball: test.NewTarWriter(t).
				AddItems("pods",
					builder.ForPod("ns-1", "pod-1").ObjectMeta(builder.WithLabels("app", "test")).Result(),
					builder.ForPod("ns-1", "pod-2").Result(),
				).
				AddItems("deployments.apps",
					builder.ForDeployment("ns-1", "deploy-1").ObjectMeta(builder.WithLabels("app", "test")).Result(),
					builder.ForDeployment("ns-1", "deploy-2").Result(),
				).
				Done(),
			apiResources: []*test.APIResource{
				test.Pods(),
				test.Deployments(),
			},
			want: map[*test.APIResource][]string{
				test.Pods():        {"ns-1/pod-1"},
				test.Deployments(): {"ns-1/deploy-1"},
			},
		},
		{
			name:    "unresolved kind in namespaced filter policy is still restored via peek-and-map",
			restore: defaultRestore().Result(),
			backup:  defaultBackup().Result(),
			policyYAML: `version: v1
namespacedFilterPolicies:
  - namespaces: ["ns-1"]
    resourceFilters:
      - kinds: ["MyCustomKind"]
`,
			tarball: test.NewTarWriter(t).AddItems("mycustomkinds.mygroup.io",
				&unstructured.Unstructured{Object: map[string]any{"apiVersion": "mygroup.io/v1", "kind": "MyCustomKind", "metadata": map[string]any{"namespace": "ns-1", "name": "my-cr"}}},
			).Done(),
			apiResources: []*test.APIResource{
				customKindRes,
			},
			want: map[*test.APIResource][]string{
				customKindRes: {"ns-1/my-cr"},
			},
		},
		{
			name:    "unresolved kind in cluster-scoped filter policy is still restored via peek-and-map",
			restore: defaultRestore().Result(),
			backup:  defaultBackup().Result(),
			policyYAML: `version: v1
clusterScopedFilterPolicy:
  resourceFilters:
    - kinds: ["MyClusterCustomKind"]
`,
			tarball: test.NewTarWriter(t).AddItems("myclustercustomkinds.mygroup.io",
				&unstructured.Unstructured{Object: map[string]any{"apiVersion": "mygroup.io/v1", "kind": "MyClusterCustomKind", "metadata": map[string]any{"name": "my-cluster-cr"}}},
			).Done(),
			apiResources: []*test.APIResource{
				clusterCustomKindRes,
			},
			want: map[*test.APIResource][]string{
				clusterCustomKindRes: {"/my-cluster-cr"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)

			for _, r := range tc.apiResources {
				h.DiscoveryClient.WithAPIResource(r)
			}
			require.NoError(t, h.restorer.discoveryHelper.Refresh())

			var resPolicies *resourcepolicies.Policies
			if tc.policyYAML != "" {
				cm := &corev1api.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-policies",
						Namespace: "velero",
					},
					Data: map[string]string{
						"policy.yaml": tc.policyYAML,
					},
				}
				client := fake.NewClientBuilder().WithScheme(scheme.Scheme).WithObjects(cm).Build()
				restore := tc.restore.DeepCopy()
				restore.Namespace = "velero"
				restore.Spec.ResourcePolicy = &corev1api.TypedLocalObjectReference{
					Kind: "configmap",
					Name: "test-policies",
				}
				var err error
				resPolicies, err = resourcepolicies.GetResourcePoliciesFromRestore(t.Context(), restore, client, logrus.New())
				require.NoError(t, err)
			}

			data := &Request{
				Log:              h.log,
				Restore:          tc.restore,
				Backup:           tc.backup,
				PodVolumeBackups: nil,
				VolumeSnapshots:  nil,
				BackupReader:     tc.tarball,
				ResPolicies:      resPolicies,
			}
			warnings, errs := h.restorer.Restore(
				data,
				nil, // restoreItemActions
				nil, // volume snapshotter getter
			)

			assertEmptyResults(t, warnings, errs)
			assertAPIContents(t, h, tc.want)
		})
	}
}

func TestResolveRestoreNamespacedFilterPolicies_Validation(t *testing.T) {
	log := logrus.New()
	helper := test.NewFakeDiscoveryHelper(true, nil)

	policies := []resourcepolicies.NamespacedFilterPolicy{
		{
			Namespaces: []string{"ns-1"},
			ResourceFilters: []resourcepolicies.ResourceFilter{
				{
					Kinds: []string{"MyKind", "mykind"},
				},
			},
		},
	}

	_, _, err := resolveRestoreNamespacedFilterPolicies(policies, nil, helper, log)
	require.Error(t, err)
	require.Contains(t, err.Error(), "ambiguous policy: duplicate kind")
}

func TestResolveRestoreClusterScopedFilterPolicy_Validation(t *testing.T) {
	log := logrus.New()
	helper := test.NewFakeDiscoveryHelper(true, nil)

	policy := &resourcepolicies.ClusterScopedFilterPolicy{
		ResourceFilters: []resourcepolicies.ResourceFilter{
			{
				Kinds: []string{"MyKind", "mykind"},
			},
		},
	}

	_, err := resolveRestoreClusterScopedFilterPolicy(policy, helper, log)
	require.Error(t, err)
	require.Contains(t, err.Error(), "ambiguous policy: duplicate kind")
}

func TestResolveRestoreNamespacedFilterPolicies_GlobalExcludesWarning(t *testing.T) {
	log, hook := logrustest.NewNullLogger()
	helper := test.NewFakeDiscoveryHelper(true, nil)

	policies := []resourcepolicies.NamespacedFilterPolicy{
		{
			Namespaces: []string{"ns-1"},
			ResourceFilters: []resourcepolicies.ResourceFilter{
				{
					Kinds: []string{"ConfigMaps"},
				},
			},
		},
	}

	excludedResources := []string{"ConfigMaps"} // Same case
	_, _, err := resolveRestoreNamespacedFilterPolicies(policies, excludedResources, helper, log)
	require.NoError(t, err)

	// Check if a warning was emitted
	found := false
	for _, entry := range hook.Entries {
		if entry.Level == logrus.WarnLevel && strings.Contains(entry.Message, "namespacedFilterPolicies entry lists a kind that is globally excluded") {
			found = true
			break
		}
	}
	require.True(t, found, "expected warning about globally excluded resource")

	hook.Reset()

	excludedResourcesDiffCase := []string{"configmaps"} // Different case
	_, _, err = resolveRestoreNamespacedFilterPolicies(policies, excludedResourcesDiffCase, helper, log)
	require.NoError(t, err)

	found = false
	for _, entry := range hook.Entries {
		if entry.Level == logrus.WarnLevel && strings.Contains(entry.Message, "namespacedFilterPolicies entry lists a kind that is globally excluded") {
			found = true
			break
		}
	}
	require.True(t, found, "expected warning about globally excluded resource even if case differs")
}
