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

package restore

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/velero-io/velero/pkg/builder"
	"github.com/velero-io/velero/pkg/test"
)

func TestK8sPrioritySort(t *testing.T) {
	tests := []struct {
		name string
		orig []metav1.GroupVersionForDiscovery
		want []metav1.GroupVersionForDiscovery
	}{
		{
			name: "sorts Kubernetes API group versions per k8s priority",
			orig: []metav1.GroupVersionForDiscovery{
				{Version: "v2"},
				{Version: "v11alpha2"},
				{Version: "foo10"},
				{Version: "v10"},
				{Version: "v12alpha1"},
				{Version: "v3beta1"},
				{Version: "foo1"},
				{Version: "v1"},
				{Version: "v10beta3"},
				{Version: "v11beta2"},
			},
			want: []metav1.GroupVersionForDiscovery{
				{Version: "v10"},
				{Version: "v2"},
				{Version: "v1"},
				{Version: "v11beta2"},
				{Version: "v10beta3"},
				{Version: "v3beta1"},
				{Version: "v12alpha1"},
				{Version: "v11alpha2"},
				{Version: "foo1"},
				{Version: "foo10"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			k8sPrioritySort(tc.orig)

			assert.Equal(t, tc.want, tc.orig)
		})
	}
}

func TestUserResourceGroupVersionPriorities(t *testing.T) {
	tests := []struct {
		name       string
		cm         *corev1api.ConfigMap
		want       map[string]metav1.APIGroup
		wantErrMsg string
	}{
		{
			name: "retrieve version priority data from config map",
			cm: builder.
				ForConfigMap("velero", "enableapigroupversions").
				Data(
					"restoreResourcesVersionPriority",
					`rockbands.music.example.io=v2beta1,v2beta2
orchestras.music.example.io=v2,v3alpha1
subscriptions.operators.coreos.com=v2,v1`,
				).
				Result(),
			want: map[string]metav1.APIGroup{
				"rockbands.music.example.io": {Versions: []metav1.GroupVersionForDiscovery{
					{Version: "v2beta1"},
					{Version: "v2beta2"},
				}},
				"orchestras.music.example.io": {Versions: []metav1.GroupVersionForDiscovery{
					{Version: "v2"},
					{Version: "v3alpha1"},
				}},
				"subscriptions.operators.coreos.com": {Versions: []metav1.GroupVersionForDiscovery{
					{Version: "v2"},
					{Version: "v1"},
				}},
			},
		},
		{
			name: "incorrect data format returns an error",
			cm: builder.
				ForConfigMap("velero", "enableapigroupversions").
				Data(
					"restoreResourcesVersionPriority",
					`rockbands.music.example.io=v2beta1,v2beta2\n orchestras.music.example.io=v2,v3alpha1`,
				).
				Result(),
			want:       nil,
			wantErrMsg: "parsing user priorities: validating user priority: line must have one and only one equal sign",
		},
		{
			name: "spaces and empty lines are removed before storing user version priorities",
			cm: builder.
				ForConfigMap("velero", "enableapigroupversions").
				Data(
					"restoreResourcesVersionPriority",
					`     pods=v2,v1beta2
horizontalpodautoscalers.autoscaling = v2beta2
jobs.batch=v3    
  `,
				).
				Result(),
			want: map[string]metav1.APIGroup{
				"pods": {Versions: []metav1.GroupVersionForDiscovery{
					{Version: "v2"},
					{Version: "v1beta2"},
				}},
				"horizontalpodautoscalers.autoscaling": {Versions: []metav1.GroupVersionForDiscovery{
					{Version: "v2beta2"},
				}},
				"jobs.batch": {Versions: []metav1.GroupVersionForDiscovery{
					{Version: "v3"},
				}},
			},
		},
	}

	fakeCtx := &restoreContext{
		log: test.NewLogger(),
	}

	for _, tc := range tests {
		t.Log(tc.name)
		priorities := userResourceGroupVersionPriorities(fakeCtx, tc.cm)

		assert.Equal(t, tc.want, priorities)
	}
}

func TestFindAPIGroup(t *testing.T) {
	tests := []struct {
		name       string
		targetGrps []metav1.APIGroup
		grpName    string
		want       metav1.APIGroup
	}{
		{
			name: "return the API Group in target list matching group string",
			targetGrps: []metav1.APIGroup{
				{
					Name: "rbac.authorization.k8s.io",
					Versions: []metav1.GroupVersionForDiscovery{
						{Version: "v2"},
					},
					PreferredVersion: metav1.GroupVersionForDiscovery{Version: "v2"},
				},
				{
					Name: "",
					Versions: []metav1.GroupVersionForDiscovery{
						{Version: "v1"},
					},
					PreferredVersion: metav1.GroupVersionForDiscovery{Version: "v1"},
				},
				{
					Name: "velero.io",
					Versions: []metav1.GroupVersionForDiscovery{
						{Version: "v2beta1"},
						{Version: "v2beta2"},
						{Version: "v2"},
					},
					PreferredVersion: metav1.GroupVersionForDiscovery{Version: "v2"},
				},
			},
			grpName: "velero.io",
			want: metav1.APIGroup{
				Name: "velero.io",
				Versions: []metav1.GroupVersionForDiscovery{
					{Version: "v2beta1"},
					{Version: "v2beta2"},
					{Version: "v2"},
				},
				PreferredVersion: metav1.GroupVersionForDiscovery{Version: "v2"},
			},
		},
		{
			name: "return empty API Group if no match in target list",
			targetGrps: []metav1.APIGroup{
				{
					Name: "rbac.authorization.k8s.io",
					Versions: []metav1.GroupVersionForDiscovery{
						{Version: "v2"},
					},
					PreferredVersion: metav1.GroupVersionForDiscovery{Version: "v2"},
				},
				{
					Name: "",
					Versions: []metav1.GroupVersionForDiscovery{
						{Version: "v1"},
					},
					PreferredVersion: metav1.GroupVersionForDiscovery{Version: "v1"},
				},
				{
					Name: "velero.io",
					Versions: []metav1.GroupVersionForDiscovery{
						{Version: "v2beta1"},
						{Version: "v2beta2"},
						{Version: "v2"},
					},
					PreferredVersion: metav1.GroupVersionForDiscovery{Version: "v2"},
				},
			},
			grpName: "autoscaling",
			want:    metav1.APIGroup{},
		},
	}

	for _, tc := range tests {
		grp := findAPIGroup(tc.targetGrps, tc.grpName)

		assert.Equal(t, tc.want, grp)
	}
}

func TestFindSupportedUserVersion(t *testing.T) {
	tests := []struct {
		name      string
		userGVs   []metav1.GroupVersionForDiscovery
		targetGVs []metav1.GroupVersionForDiscovery
		sourceGVs []metav1.GroupVersionForDiscovery
		want      string
	}{
		{
			name: "return the single user group version that has a match in both source and target clusters",
			userGVs: []metav1.GroupVersionForDiscovery{
				{Version: "foo"},
				{Version: "v10alpha2"},
				{Version: "v3"},
			},
			targetGVs: []metav1.GroupVersionForDiscovery{
				{Version: "v9"},
				{Version: "v10beta1"},
				{Version: "v10alpha2"},
				{Version: "v10alpha3"},
			},
			sourceGVs: []metav1.GroupVersionForDiscovery{
				{Version: "v10alpha2"},
				{Version: "v9beta1"},
			},
			want: "v10alpha2",
		},
		{
			name: "return the first user group version that has a match in both source and target clusters",
			userGVs: []metav1.GroupVersionForDiscovery{
				{Version: "v2beta1"},
				{Version: "v2beta2"},
			},
			targetGVs: []metav1.GroupVersionForDiscovery{
				{Version: "v2beta2"},
				{Version: "v2beta1"},
			},
			sourceGVs: []metav1.GroupVersionForDiscovery{
				{Version: "v1"},
				{Version: "v2beta2"},
				{Version: "v2beta1"},
			},
			want: "v2beta1",
		},
		{
			name: "return empty string if there's only matches in the source cluster, but not target",
			userGVs: []metav1.GroupVersionForDiscovery{
				{Version: "v1"},
			},
			targetGVs: []metav1.GroupVersionForDiscovery{
				{Version: "v2"},
			},
			sourceGVs: []metav1.GroupVersionForDiscovery{
				{Version: "v1"},
			},
			want: "",
		},
		{
			name: "return empty string if there's only matches in the target cluster, but not source",
			userGVs: []metav1.GroupVersionForDiscovery{
				{Version: "v3"},
				{Version: "v1"},
			},
			targetGVs: []metav1.GroupVersionForDiscovery{
				{Version: "v3"},
				{Version: "v3beta2"},
			},
			sourceGVs: []metav1.GroupVersionForDiscovery{
				{Version: "v2"},
				{Version: "v2beta1"},
			},
			want: "",
		},
		{
			name: "return empty string if there is no match with either target and source clusters",
			userGVs: []metav1.GroupVersionForDiscovery{
				{Version: "v2beta2"},
				{Version: "v2beta1"},
				{Version: "v2beta3"},
			},
			targetGVs: []metav1.GroupVersionForDiscovery{
				{Version: "v2"},
				{Version: "v1"},
				{Version: "v2alpha1"},
			},
			sourceGVs: []metav1.GroupVersionForDiscovery{
				{Version: "v1"},
				{Version: "v2alpha1"},
			},
			want: "",
		},
	}

	for _, tc := range tests {
		uv := findSupportedUserVersion(tc.userGVs, tc.targetGVs, tc.sourceGVs)

		assert.Equal(t, tc.want, uv)
	}
}

func TestVersionsContain(t *testing.T) {
	tests := []struct {
		name string
		GVs  []metav1.GroupVersionForDiscovery
		ver  string
		want bool
	}{
		{
			name: "version is not in list",
			GVs: []metav1.GroupVersionForDiscovery{
				{Version: "v1"},
				{Version: "v2alpha1"},
				{Version: "v2beta1"},
			},
			ver:  "v2",
			want: false,
		},
		{
			name: "version is in list",
			GVs: []metav1.GroupVersionForDiscovery{
				{Version: "v2"},
				{Version: "v2alpha1"},
				{Version: "v2beta1"},
			},
			ver:  "v2",
			want: true,
		},
	}

	for _, tc := range tests {
		assert.Equal(t, tc.want, versionsContain(tc.GVs, tc.ver))
	}
}
