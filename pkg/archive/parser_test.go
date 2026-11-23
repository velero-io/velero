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

package archive

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/velero-io/velero/pkg/test"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name       string
		files      []string
		dir        string
		wantErrMsg error
		want       map[string]*ResourceItems
	}{
		{
			name:       "when there is no top-level resources directory, an error is returned",
			dir:        "root-dir",
			wantErrMsg: ErrNotExist,
		},
		{
			name:  "when there are no directories under the resources directory, an empty map is returned",
			dir:   "root-dir",
			files: []string{"root-dir/resources/"},
			want:  map[string]*ResourceItems{},
		},
		{
			name: "a mix of cluster-scoped and namespaced items across multiple resources are correctly returned",
			dir:  "root-dir",
			files: []string{
				"root-dir/resources/widgets.foo/cluster/item-1.json",
				"root-dir/resources/widgets.foo/cluster/item-2.json",
				"root-dir/resources/widgets.foo/namespaces/ns-1/item-1.json",
				"root-dir/resources/widgets.foo/namespaces/ns-1/item-2.json",
				"root-dir/resources/widgets.foo/namespaces/ns-2/item-1.json",
				"root-dir/resources/widgets.foo/namespaces/ns-2/item-2.json",

				"root-dir/resources/dongles.foo/cluster/item-3.json",
				"root-dir/resources/dongles.foo/cluster/item-4.json",

				"root-dir/resources/dongles.bar/namespaces/ns-3/item-3.json",
				"root-dir/resources/dongles.bar/namespaces/ns-3/item-4.json",
				"root-dir/resources/dongles.bar/namespaces/ns-4/item-5.json",
				"root-dir/resources/dongles.bar/namespaces/ns-4/item-6.json",
			},
			want: map[string]*ResourceItems{
				"widgets.foo": {
					GroupResource: "widgets.foo",
					ItemsByNamespace: map[string][]string{
						"":     {"item-1", "item-2"},
						"ns-1": {"item-1", "item-2"},
						"ns-2": {"item-1", "item-2"},
					},
				},
				"dongles.foo": {
					GroupResource: "dongles.foo",
					ItemsByNamespace: map[string][]string{
						"": {"item-3", "item-4"},
					},
				},
				"dongles.bar": {
					GroupResource: "dongles.bar",
					ItemsByNamespace: map[string][]string{
						"ns-3": {"item-3", "item-4"},
						"ns-4": {"item-5", "item-6"},
					},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &Parser{
				log: test.NewLogger(),
				fs:  test.NewFakeFileSystem(),
			}

			for _, file := range tc.files {
				require.NoError(t, p.fs.MkdirAll(file, 0755))

				if !strings.HasSuffix(file, "/") {
					res, err := p.fs.Create(file)
					require.NoError(t, err)
					require.NoError(t, res.Close())
				}
			}

			res, err := p.Parse(tc.dir)
			if tc.wantErrMsg != nil {
				assert.ErrorIs(t, err, tc.wantErrMsg, "Error should be: %v, got: %v", tc.wantErrMsg, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.want, res)
			}
		})
	}
}

func TestParseGroupVersions(t *testing.T) {
	tests := []struct {
		name       string
		files      []string
		backupDir  string
		wantErrMsg error
		want       map[string]metav1.APIGroup
	}{
		{
			name:       "when there is no top-level resources directory, an error is returned",
			backupDir:  "/var/folders",
			wantErrMsg: ErrNotExist,
		},
		{
			name:      "when there are no directories under the resources directory, an empty map is returned",
			backupDir: "/var/folders",
			files:     []string{"/var/folders/resources/"},
			want:      map[string]metav1.APIGroup{},
		},
		{
			name:      "when there is a mix of cluster-scoped and namespaced items for resources with preferred or multiple API groups, all group versions are correctly returned",
			backupDir: "/var/folders",
			files: []string{
				"/var/folders/resources/clusterroles.rbac.authorization.k8s.io/v1-preferredversion/cluster/system/controller/attachdetach-controller.json",
				"/var/folders/resources/clusterroles.rbac.authorization.k8s.io/cluster/system/controller/attachdetach-controller.json",

				"/var/folders/resources/horizontalpodautoscalers.autoscaling/namespaces/myexample/php-apache-autoscaler.json",
				"/var/folders/resources/horizontalpodautoscalers.autoscaling/v1-preferredversion/namespaces/myexample/php-apache-autoscaler.json",
				"/var/folders/resources/horizontalpodautoscalers.autoscaling/v2beta1/namespaces/myexample/php-apache-autoscaler.json",
				"/var/folders/resources/horizontalpodautoscalers.autoscaling/v2beta2/namespaces/myexample/php-apache-autoscaler.json",

				"/var/folders/resources/pods/namespaces/nginx-example/nginx-deployment-57d5dcb68-wrqsc.json",
				"/var/folders/resources/pods/v1-preferredversion/namespaces/nginx-example/nginx-deployment-57d5dcb68-wrqsc.json",
			},
			want: map[string]metav1.APIGroup{
				"clusterroles.rbac.authorization.k8s.io": {
					Name: "rbac.authorization.k8s.io",
					Versions: []metav1.GroupVersionForDiscovery{
						{
							GroupVersion: "rbac.authorization.k8s.io/v1",
							Version:      "v1",
						},
					},
					PreferredVersion: metav1.GroupVersionForDiscovery{
						GroupVersion: "rbac.authorization.k8s.io/v1",
						Version:      "v1",
					},
				},
				"horizontalpodautoscalers.autoscaling": {
					Name: "autoscaling",
					Versions: []metav1.GroupVersionForDiscovery{
						{
							GroupVersion: "autoscaling/v1",
							Version:      "v1",
						},
						{
							GroupVersion: "autoscaling/v2beta1",
							Version:      "v2beta1",
						},
						{
							GroupVersion: "autoscaling/v2beta2",
							Version:      "v2beta2",
						},
					},
					PreferredVersion: metav1.GroupVersionForDiscovery{
						GroupVersion: "autoscaling/v1",
						Version:      "v1",
					},
				},
				"pods": {
					Name: "",
					Versions: []metav1.GroupVersionForDiscovery{
						{
							GroupVersion: "v1",
							Version:      "v1",
						},
					},
					PreferredVersion: metav1.GroupVersionForDiscovery{
						GroupVersion: "v1",
						Version:      "v1",
					},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &Parser{
				log: test.NewLogger(),
				fs:  test.NewFakeFileSystem(),
			}

			for _, file := range tc.files {
				require.NoError(t, p.fs.MkdirAll(file, 0755))

				if !strings.HasSuffix(file, "/") {
					res, err := p.fs.Create(file)
					require.NoError(t, err)
					require.NoError(t, res.Close())
				}
			}

			res, err := p.ParseGroupVersions(tc.backupDir)
			if tc.wantErrMsg != nil {
				assert.ErrorIs(t, err, tc.wantErrMsg, "Error should be: %v, got: %v", tc.wantErrMsg, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.want, res)
			}
		})
	}
}

func TestExtractGroupName(t *testing.T) {
	tests := []struct {
		name  string
		rgDir string
		want  string
	}{
		{
			name:  "Directory has no dots (only a group name)",
			rgDir: "pods",
			want:  "",
		},
		{
			name:  "Directory has one concatenation dot (has both resource and group name which have 0 dots",
			rgDir: "cronjobs.batch",
			want:  "batch",
		},
		{
			name:  "Directory has 3 dots in name (group has 2 dot)",
			rgDir: "leases.coordination.k8s.io",
			want:  "coordination.k8s.io",
		},
		{
			name:  "Directory has 4 dots in name (group has 3 dots)",
			rgDir: "roles.rbac.authorization.k8s.io",
			want:  "rbac.authorization.k8s.io",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			grp := extractGroupName(tc.rgDir)

			assert.Equal(t, tc.want, grp)
		})
	}
}
