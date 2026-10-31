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
package resourcemodifiers

import (
	"reflect"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer/yaml"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
)

func TestGetResourceModifiersFromConfig(t *testing.T) {
	cm1 := &corev1api.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-configmap",
			Namespace: "test-namespace",
		},
		Data: map[string]string{
			"sub.yml": "version: v1\nresourceModifierRules:\n- conditions:\n    groupResource: persistentvolumeclaims\n    resourceNameRegex: \".*\"\n    namespaces:\n    - bar\n    - foo\n  patches:\n  - operation: replace\n    path: \"/spec/storageClassName\"\n    value: \"premium\"\n  - operation: remove\n    path: \"/metadata/labels/test\"\n\n\n",
		},
	}

	rules1 := &ResourceModifiers{
		Version: "v1",
		ResourceModifierRules: []ResourceModifierRule{
			{
				Conditions: Conditions{
					GroupResource:     "persistentvolumeclaims",
					ResourceNameRegex: ".*",
					Namespaces:        []string{"bar", "foo"},
				},
				Patches: []JSONPatch{
					{
						Operation: "replace",
						Path:      "/spec/storageClassName",
						Value:     "premium",
					},
					{
						Operation: "remove",
						Path:      "/metadata/labels/test",
					},
				},
			},
		},
	}
	cm2 := &corev1api.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-configmap",
			Namespace: "test-namespace",
		},
		Data: map[string]string{
			"sub.yml": "version: v1\nresourceModifierRules:\n- conditions:\n    groupResource: deployments.apps\n    resourceNameRegex: \"^test-.*$\"\n    namespaces:\n    - bar\n    - foo\n  patches:\n  - operation: add\n    path: \"/spec/template/spec/containers/0\"\n    value: \"{\\\"name\\\": \\\"nginx\\\", \\\"image\\\": \\\"nginx:1.14.2\\\", \\\"ports\\\": [{\\\"containerPort\\\": 80}]}\"\n  - operation: copy\n    from: \"/spec/template/spec/containers/0\"\n    path: \"/spec/template/spec/containers/1\"\n\n\n",
		},
	}

	rules2 := &ResourceModifiers{
		Version: "v1",
		ResourceModifierRules: []ResourceModifierRule{
			{
				Conditions: Conditions{
					GroupResource:     "deployments.apps",
					ResourceNameRegex: "^test-.*$",
					Namespaces:        []string{"bar", "foo"},
				},
				Patches: []JSONPatch{
					{
						Operation: "add",
						Path:      "/spec/template/spec/containers/0",
						Value:     `{"name": "nginx", "image": "nginx:1.14.2", "ports": [{"containerPort": 80}]}`,
					},
					{
						Operation: "copy",
						From:      "/spec/template/spec/containers/0",
						Path:      "/spec/template/spec/containers/1",
					},
				},
			},
		},
	}

	cm3 := &corev1api.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-configmap",
			Namespace: "test-namespace",
		},
		Data: map[string]string{
			"sub.yml": "version1: v1\nresourceModifierRules:\n- conditions:\n    groupResource: deployments.apps\n    resourceNameRegex: \"^test-.*$\"\n    namespaces:\n    - bar\n    - foo\n  patches:\n  - operation: add\n    path: \"/spec/template/spec/containers/0\"\n    value: \"{\\\"name\\\": \\\"nginx\\\", \\\"image\\\": \\\"nginx:1.14.2\\\", \\\"ports\\\": [{\\\"containerPort\\\": 80}]}\"\n  - operation: copy\n    from: \"/spec/template/spec/containers/0\"\n    path: \"/spec/template/spec/containers/1\"\n\n\n",
		},
	}

	cm4 := &corev1api.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-configmap",
			Namespace: "test-namespace",
		},
		Data: map[string]string{
			"sub.yml": "version: v1\nresourceModifierRules:\n- conditions:\n    groupResource: deployments.apps\n    labelSelector:\n      matchLabels:\n        a: b\n",
		},
	}

	rules4 := &ResourceModifiers{
		Version: "v1",
		ResourceModifierRules: []ResourceModifierRule{
			{
				Conditions: Conditions{
					GroupResource: "deployments.apps",
					LabelSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"a": "b",
						},
					},
				},
			},
		},
	}

	cm5 := &corev1api.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-configmap",
			Namespace: "test-namespace",
		},
		Data: map[string]string{
			"sub.yml": "version: v1\nresourceModifierRules:\n- conditions:\n    groupResource: pods\n    namespaces:\n    - ns1\n    matches:\n    - path: /metadata/annotations/foo\n      value: bar\n  mergePatches:\n  - patchData: |\n      metadata:\n        annotations:\n          foo: null",
		},
	}

	rules5 := &ResourceModifiers{
		Version: "v1",
		ResourceModifierRules: []ResourceModifierRule{
			{
				Conditions: Conditions{
					GroupResource: "pods",
					Namespaces: []string{
						"ns1",
					},
					Matches: []MatchRule{
						{
							Path:  "/metadata/annotations/foo",
							Value: "bar",
						},
					},
				},
				MergePatches: []JSONMergePatch{
					{
						PatchData: "metadata:\n  annotations:\n    foo: null",
					},
				},
			},
		},
	}

	cm6 := &corev1api.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-configmap",
			Namespace: "test-namespace",
		},
		Data: map[string]string{
			"sub.yml": "version: v1\nresourceModifierRules:\n- conditions:\n    groupResource: pods\n    namespaces:\n    - ns1\n  strategicPatches:\n  - patchData: |\n      spec:\n        containers:\n        - name: nginx\n          image: repo2/nginx",
		},
	}

	rules6 := &ResourceModifiers{
		Version: "v1",
		ResourceModifierRules: []ResourceModifierRule{
			{
				Conditions: Conditions{
					GroupResource: "pods",
					Namespaces: []string{
						"ns1",
					},
				},
				StrategicPatches: []StrategicMergePatch{
					{
						PatchData: "spec:\n  containers:\n  - name: nginx\n    image: repo2/nginx",
					},
				},
			},
		},
	}

	cm7 := &corev1api.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-configmap",
			Namespace: "test-namespace",
		},
		Data: map[string]string{
			"sub.yml": "version: v1\nresourceModifierRules:\n- conditions:\n    groupResource: pods\n    namespaces:\n    - ns1\n  mergePatches:\n  - patchData: |\n      {\"metadata\":{\"annotations\":{\"foo\":null}}}",
		},
	}

	rules7 := &ResourceModifiers{
		Version: "v1",
		ResourceModifierRules: []ResourceModifierRule{
			{
				Conditions: Conditions{
					GroupResource: "pods",
					Namespaces: []string{
						"ns1",
					},
				},
				MergePatches: []JSONMergePatch{
					{
						PatchData: `{"metadata":{"annotations":{"foo":null}}}`,
					},
				},
			},
		},
	}

	cm8 := &corev1api.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-configmap",
			Namespace: "test-namespace",
		},
		Data: map[string]string{
			"sub.yml": "version: v1\nresourceModifierRules:\n- conditions:\n    groupResource: pods\n    namespaces:\n    - ns1\n  strategicPatches:\n  - patchData: |\n      {\"spec\":{\"containers\":[{\"name\": \"nginx\",\"image\": \"repo2/nginx\"}]}}",
		},
	}

	rules8 := &ResourceModifiers{
		Version: "v1",
		ResourceModifierRules: []ResourceModifierRule{
			{
				Conditions: Conditions{
					GroupResource: "pods",
					Namespaces: []string{
						"ns1",
					},
				},
				StrategicPatches: []StrategicMergePatch{
					{
						PatchData: `{"spec":{"containers":[{"name": "nginx","image": "repo2/nginx"}]}}`,
					},
				},
			},
		},
	}
	cm9 := &corev1api.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-configmap",
			Namespace: "test-namespace",
		},
		Data: map[string]string{
			"sub.yml": "version: v1\nresourceModifierRules:\n- conditions:\n    groupResource: deployments.apps\n    resourceNameRegex: \"^test-.*$\"\n    namespaces:\n    - bar\n    - foo\n  patches:\n  - operation: replace\n    path: \"/value/bool\"\n    value: \"\\\"true\\\"\"\n\n\n",
		},
	}

	rules9 := &ResourceModifiers{
		Version: "v1",
		ResourceModifierRules: []ResourceModifierRule{
			{
				Conditions: Conditions{
					GroupResource:     "deployments.apps",
					ResourceNameRegex: "^test-.*$",
					Namespaces:        []string{"bar", "foo"},
				},
				Patches: []JSONPatch{
					{
						Operation: "replace",
						Path:      "/value/bool",
						Value:     `"true"`,
					},
				},
			},
		},
	}
	cm10 := &corev1api.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-configmap",
			Namespace: "test-namespace",
		},
		Data: map[string]string{
			"sub.yml": "version: v1\nresourceModifierRules:\n- conditions:\n    groupResource: deployments.apps\n    resourceNameRegex: \"^test-.*$\"\n    namespaces:\n    - bar\n    - foo\n  patches:\n  - operation: replace\n    path: \"/value/bool\"\n    value: \"true\"\n\n\n",
		},
	}

	rules10 := &ResourceModifiers{
		Version: "v1",
		ResourceModifierRules: []ResourceModifierRule{
			{
				Conditions: Conditions{
					GroupResource:     "deployments.apps",
					ResourceNameRegex: "^test-.*$",
					Namespaces:        []string{"bar", "foo"},
				},
				Patches: []JSONPatch{
					{
						Operation: "replace",
						Path:      "/value/bool",
						Value:     "true",
					},
				},
			},
		},
	}

	type args struct {
		cm *corev1api.ConfigMap
	}
	tests := []struct {
		name    string
		args    args
		want    *ResourceModifiers
		wantErr bool
	}{
		{
			name: "test 1",
			args: args{
				cm: cm1,
			},
			want:    rules1,
			wantErr: false,
		},
		{
			name: "complex payload in add and copy operator",
			args: args{
				cm: cm2,
			},
			want:    rules2,
			wantErr: false,
		},
		{
			name: "invalid payload version1",
			args: args{
				cm: cm3,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "match labels",
			args: args{
				cm: cm4,
			},
			want:    rules4,
			wantErr: false,
		},
		{
			name: "nil configmap",
			args: args{
				cm: nil,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "complex yaml data with json merge patch",
			args: args{
				cm: cm5,
			},
			want:    rules5,
			wantErr: false,
		},
		{
			name: "complex yaml data with strategic merge patch",
			args: args{
				cm: cm6,
			},
			want:    rules6,
			wantErr: false,
		},
		{
			name: "complex json data with json merge patch",
			args: args{
				cm: cm7,
			},
			want:    rules7,
			wantErr: false,
		},
		{
			name: "complex json data with strategic merge patch",
			args: args{
				cm: cm8,
			},
			want:    rules8,
			wantErr: false,
		},
		{
			name: "bool value as string",
			args: args{
				cm: cm9,
			},
			want:    rules9,
			wantErr: false,
		},
		{
			name: "bool value as bool",
			args: args{
				cm: cm10,
			},
			want:    rules10,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetResourceModifiersFromConfig(tt.args.cm)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetResourceModifiersFromConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetResourceModifiersFromConfig() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestResourceModifiers_ApplyResourceModifierRules(t *testing.T) {
	pvcStandardSc := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "v1",
			"kind":       "PersistentVolumeClaim",
			"metadata": map[string]any{
				"name":      "test-pvc",
				"namespace": "foo",
			},
			"spec": map[string]any{
				"storageClassName": "standard",
			},
		},
	}

	pvcPremiumSc := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "v1",
			"kind":       "PersistentVolumeClaim",
			"metadata": map[string]any{
				"name":      "test-pvc",
				"namespace": "foo",
			},
			"spec": map[string]any{
				"storageClassName": "premium",
			},
		},
	}

	pvcGoldSc := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "v1",
			"kind":       "PersistentVolumeClaim",
			"metadata": map[string]any{
				"name":      "test-pvc",
				"namespace": "foo",
			},
			"spec": map[string]any{
				"storageClassName": "gold",
			},
		},
	}

	deployNginxOneReplica := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]any{
				"name":      "test-deployment",
				"namespace": "foo",
				"labels": map[string]any{
					"app": "nginx",
				},
			},
			"spec": map[string]any{
				"replicas": int64(1),
				"template": map[string]any{
					"metadata": map[string]any{
						"labels": map[string]any{
							"app": "nginx",
						},
					},
					"spec": map[string]any{
						"containers": []any{
							map[string]any{
								"name":  "nginx",
								"image": "nginx:latest",
							},
						},
					},
				},
			},
		},
	}
	deployNginxTwoReplica := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]any{
				"name":      "test-deployment",
				"namespace": "foo",
				"labels": map[string]any{
					"app": "nginx",
				},
			},
			"spec": map[string]any{
				"replicas": int64(2),
				"template": map[string]any{
					"metadata": map[string]any{
						"labels": map[string]any{
							"app": "nginx",
						},
					},
					"spec": map[string]any{
						"containers": []any{
							map[string]any{
								"name":  "nginx",
								"image": "nginx:latest",
							},
						},
					},
				},
			},
		},
	}
	deployNginxMysql := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": map[string]any{
				"name":      "test-deployment",
				"namespace": "foo",
				"labels": map[string]any{
					"app": "nginx",
				},
			},
			"spec": map[string]any{
				"replicas": int64(1),
				"template": map[string]any{
					"metadata": map[string]any{
						"labels": map[string]any{
							"app": "nginx",
						},
					},
					"spec": map[string]any{
						"containers": []any{
							map[string]any{
								"name":  "nginx",
								"image": "nginx:latest",
							},
							map[string]any{
								"name":  "mysql",
								"image": "mysql:latest",
							},
						},
					},
				},
			},
		},
	}
	cmTrue := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"data": map[string]any{
				"test": "true",
			},
		},
	}
	cmFalse := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"data": map[string]any{
				"test": "false",
			},
		},
	}
	type fields struct {
		Version               string
		ResourceModifierRules []ResourceModifierRule
	}
	type args struct {
		obj           *unstructured.Unstructured
		groupResource string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
		wantObj *unstructured.Unstructured
	}{
		{
			name: "configmap true false string",
			fields: fields{
				Version: "v1",
				ResourceModifierRules: []ResourceModifierRule{
					{
						Conditions: Conditions{
							GroupResource:     "configmaps",
							ResourceNameRegex: ".*",
						},
						Patches: []JSONPatch{
							{
								Operation: "replace",
								Path:      "/data/test",
								Value:     `"false"`,
							},
						},
					},
				},
			},
			args: args{
				obj:           cmTrue.DeepCopy(),
				groupResource: "configmaps",
			},
			wantErr: false,
			wantObj: cmFalse.DeepCopy(),
		},
		{
			name: "Invalid Regex throws error",
			fields: fields{
				Version: "v1",
				ResourceModifierRules: []ResourceModifierRule{
					{
						Conditions: Conditions{
							GroupResource:     "persistentvolumeclaims",
							ResourceNameRegex: "[a-z",
							Namespaces:        []string{"foo"},
						},
						Patches: []JSONPatch{
							{
								Operation: "test",
								Path:      "/spec/storageClassName",
								Value:     "standard",
							},
							{
								Operation: "replace",
								Path:      "/spec/storageClassName",
								Value:     "premium",
							},
						},
					},
				},
			},
			args: args{
				obj:           pvcStandardSc.DeepCopy(),
				groupResource: "persistentvolumeclaims",
			},
			wantErr: true,
			wantObj: pvcStandardSc.DeepCopy(),
		},
		{
			name: "pvc with standard storage class should be patched to premium",
			fields: fields{
				Version: "v1",
				ResourceModifierRules: []ResourceModifierRule{
					{
						Conditions: Conditions{
							GroupResource:     "persistentvolumeclaims",
							ResourceNameRegex: ".*",
							Namespaces:        []string{"foo"},
						},
						Patches: []JSONPatch{
							{
								Operation: "test",
								Path:      "/spec/storageClassName",
								Value:     "standard",
							},
							{
								Operation: "replace",
								Path:      "/spec/storageClassName",
								Value:     "premium",
							},
						},
					},
				},
			},
			args: args{
				obj:           pvcStandardSc.DeepCopy(),
				groupResource: "persistentvolumeclaims",
			},
			wantErr: false,
			wantObj: pvcPremiumSc.DeepCopy(),
		},
		{
			name: "pvc with standard storage class should be patched to premium, even when rules are [standard => premium, premium => gold]",
			fields: fields{
				Version: "v1",
				ResourceModifierRules: []ResourceModifierRule{
					{
						Conditions: Conditions{
							GroupResource:     "persistentvolumeclaims",
							ResourceNameRegex: ".*",
							Matches: []MatchRule{
								{
									Path:  "/spec/storageClassName",
									Value: "standard",
								},
							},
						},
						Patches: []JSONPatch{
							{
								Operation: "replace",
								Path:      "/spec/storageClassName",
								Value:     "premium",
							},
						},
					},
					{
						Conditions: Conditions{
							GroupResource:     "persistentvolumeclaims",
							ResourceNameRegex: ".*",
							Matches: []MatchRule{
								{
									Path:  "/spec/storageClassName",
									Value: "premium",
								},
							},
						},
						Patches: []JSONPatch{
							{
								Operation: "replace",
								Path:      "/spec/storageClassName",
								Value:     "gold",
							},
						},
					},
				},
			},
			args: args{
				obj:           pvcStandardSc.DeepCopy(),
				groupResource: "persistentvolumeclaims",
			},
			wantErr: false,
			wantObj: pvcPremiumSc.DeepCopy(),
		},
		{
			name: "pvc with standard storage class should be patched to gold, even when rules are [standard => premium, standard => gold]",
			fields: fields{
				Version: "v1",
				ResourceModifierRules: []ResourceModifierRule{
					{
						Conditions: Conditions{
							GroupResource:     "persistentvolumeclaims",
							ResourceNameRegex: ".*",
							Matches: []MatchRule{
								{
									Path:  "/spec/storageClassName",
									Value: "standard",
								},
							},
						},
						Patches: []JSONPatch{
							{
								Operation: "replace",
								Path:      "/spec/storageClassName",
								Value:     "premium",
							},
						},
					},
					{
						Conditions: Conditions{
							GroupResource:     "persistentvolumeclaims",
							ResourceNameRegex: ".*",
							Matches: []MatchRule{
								{
									Path:  "/spec/storageClassName",
									Value: "standard",
								},
							},
						},
						Patches: []JSONPatch{
							{
								Operation: "replace",
								Path:      "/spec/storageClassName",
								Value:     "gold",
							},
						},
					},
				},
			},
			args: args{
				obj:           pvcStandardSc.DeepCopy(),
				groupResource: "persistentvolumeclaims",
			},
			wantErr: false,
			wantObj: pvcGoldSc.DeepCopy(),
		},
		{
			name: "nginx deployment: 1 -> 2 replicas",
			fields: fields{
				Version: "v1",
				ResourceModifierRules: []ResourceModifierRule{
					{
						Conditions: Conditions{
							GroupResource:     "deployments.apps",
							ResourceNameRegex: "^test-.*$",
							Namespaces:        []string{"foo"},
						},
						Patches: []JSONPatch{
							{
								Operation: "test",
								Path:      "/spec/replicas",
								Value:     "1",
							},
							{
								Operation: "replace",
								Path:      "/spec/replicas",
								Value:     "2",
							},
						},
					},
				},
			},
			args: args{
				obj:           deployNginxOneReplica.DeepCopy(),
				groupResource: "deployments.apps",
			},
			wantErr: false,
			wantObj: deployNginxTwoReplica.DeepCopy(),
		},
		{
			name: "nginx deployment: test operator fails, skips substitution, no error",
			fields: fields{
				Version: "v1",
				ResourceModifierRules: []ResourceModifierRule{
					{
						Conditions: Conditions{
							GroupResource:     "deployments.apps",
							ResourceNameRegex: "^test-.*$",
							Namespaces:        []string{"foo"},
						},
						Patches: []JSONPatch{
							{
								Operation: "test",
								Path:      "/spec/replicas",
								Value:     "5",
							},
							{
								Operation: "replace",
								Path:      "/spec/replicas",
								Value:     "2",
							},
						},
					},
				},
			},
			args: args{
				obj:           deployNginxOneReplica.DeepCopy(),
				groupResource: "deployments.apps",
			},
			wantErr: false,
			wantObj: deployNginxOneReplica.DeepCopy(),
		},
		{
			name: "nginx deployment: Empty Resource Regex",
			fields: fields{
				Version: "v1",
				ResourceModifierRules: []ResourceModifierRule{
					{
						Conditions: Conditions{
							GroupResource: "deployments.apps",
							Namespaces:    []string{"foo"},
						},
						Patches: []JSONPatch{
							{
								Operation: "test",
								Path:      "/spec/replicas",
								Value:     "1",
							},
							{
								Operation: "replace",
								Path:      "/spec/replicas",
								Value:     "2",
							},
						},
					},
				},
			},
			args: args{
				obj:           deployNginxOneReplica.DeepCopy(),
				groupResource: "deployments.apps",
			},
			wantErr: false,
			wantObj: deployNginxTwoReplica.DeepCopy(),
		},
		{
			name: "nginx deployment: Empty Resource Regex",
			fields: fields{
				Version: "v1",
				ResourceModifierRules: []ResourceModifierRule{
					{
						Conditions: Conditions{
							GroupResource: "deployments.apps",
							Namespaces:    []string{"foo"},
						},
						Patches: []JSONPatch{
							{
								Operation: "test",
								Path:      "/spec/replicas",
								Value:     "1",
							},
							{
								Operation: "replace",
								Path:      "/spec/replicas",
								Value:     "2",
							},
						},
					},
				},
			},
			args: args{
				obj:           deployNginxOneReplica.DeepCopy(),
				groupResource: "deployments.apps",
			},
			wantErr: false,
			wantObj: deployNginxTwoReplica.DeepCopy(),
		},
		{
			name: "nginx deployment: Empty Resource Regex  and namespaces list",
			fields: fields{
				Version: "v1",
				ResourceModifierRules: []ResourceModifierRule{
					{
						Conditions: Conditions{
							GroupResource: "deployments.apps",
						},
						Patches: []JSONPatch{
							{
								Operation: "test",
								Path:      "/spec/replicas",
								Value:     "1",
							},
							{
								Operation: "replace",
								Path:      "/spec/replicas",
								Value:     "2",
							},
						},
					},
				},
			},
			args: args{
				obj:           deployNginxOneReplica.DeepCopy(),
				groupResource: "deployments.apps",
			},
			wantErr: false,
			wantObj: deployNginxTwoReplica.DeepCopy(),
		},
		{
			name: "nginx deployment: namespace doesn't match",
			fields: fields{
				Version: "v1",
				ResourceModifierRules: []ResourceModifierRule{
					{
						Conditions: Conditions{
							GroupResource:     "deployments.apps",
							ResourceNameRegex: ".*",
							Namespaces:        []string{"bar"},
						},
						Patches: []JSONPatch{
							{
								Operation: "test",
								Path:      "/spec/replicas",
								Value:     "1",
							},
							{
								Operation: "replace",
								Path:      "/spec/replicas",
								Value:     "2",
							},
						},
					},
				},
			},
			args: args{
				obj:           deployNginxOneReplica.DeepCopy(),
				groupResource: "deployments.apps",
			},
			wantErr: false,
			wantObj: deployNginxOneReplica.DeepCopy(),
		},
		{
			name: "add container mysql to deployment",
			fields: fields{
				Version: "v1",
				ResourceModifierRules: []ResourceModifierRule{
					{
						Conditions: Conditions{
							GroupResource:     "deployments.apps",
							ResourceNameRegex: "^test-.*$",
							Namespaces:        []string{"foo"},
						},
						Patches: []JSONPatch{
							{
								Operation: "add",
								Path:      "/spec/template/spec/containers/1",
								Value:     `{"name": "mysql", "image": "mysql:latest"}`,
							},
						},
					},
				},
			},
			args: args{
				obj:           deployNginxOneReplica,
				groupResource: "deployments.apps",
			},
			wantErr: false,
			wantObj: deployNginxMysql,
		},
		{
			name: "Copy container 0 to container 1 and then modify container 1",
			fields: fields{
				Version: "v1",
				ResourceModifierRules: []ResourceModifierRule{
					{
						Conditions: Conditions{
							GroupResource:     "deployments.apps",
							ResourceNameRegex: "^test-.*$",
							Namespaces:        []string{"foo"},
						},
						Patches: []JSONPatch{
							{
								Operation: "copy",
								From:      "/spec/template/spec/containers/0",
								Path:      "/spec/template/spec/containers/1",
							},
							{
								Operation: "test",
								Path:      "/spec/template/spec/containers/1/image",
								Value:     "nginx:latest",
							},
							{
								Operation: "replace",
								Path:      "/spec/template/spec/containers/1/name",
								Value:     "mysql",
							},
							{
								Operation: "replace",
								Path:      "/spec/template/spec/containers/1/image",
								Value:     "mysql:latest",
							},
						},
					},
				},
			},
			args: args{
				obj:           deployNginxOneReplica.DeepCopy(),
				groupResource: "deployments.apps",
			},
			wantErr: false,
			wantObj: deployNginxMysql.DeepCopy(),
		},
		{
			name: "nginx deployment: match label selector",
			fields: fields{
				Version: "v1",
				ResourceModifierRules: []ResourceModifierRule{
					{
						Conditions: Conditions{
							GroupResource: "deployments.apps",
							Namespaces:    []string{"foo"},
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"app": "nginx",
								},
							},
						},
						Patches: []JSONPatch{
							{
								Operation: "test",
								Path:      "/spec/replicas",
								Value:     "1",
							},
							{
								Operation: "replace",
								Path:      "/spec/replicas",
								Value:     "2",
							},
						},
					},
				},
			},
			args: args{
				obj:           deployNginxOneReplica.DeepCopy(),
				groupResource: "deployments.apps",
			},
			wantErr: false,
			wantObj: deployNginxTwoReplica.DeepCopy(),
		},
		{
			name: "nginx deployment: mismatch label selector",
			fields: fields{
				Version: "v1",
				ResourceModifierRules: []ResourceModifierRule{
					{
						Conditions: Conditions{
							GroupResource: "deployments.apps",
							Namespaces:    []string{"foo"},
							LabelSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"app": "nginx-mismatch",
								},
							},
						},
						Patches: []JSONPatch{
							{
								Operation: "test",
								Path:      "/spec/replicas",
								Value:     "1",
							},
							{
								Operation: "replace",
								Path:      "/spec/replicas",
								Value:     "2",
							},
						},
					},
				},
			},
			args: args{
				obj:           deployNginxOneReplica.DeepCopy(),
				groupResource: "deployments.apps",
			},
			wantErr: false,
			wantObj: deployNginxOneReplica.DeepCopy(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &ResourceModifiers{
				Version:               tt.fields.Version,
				ResourceModifierRules: tt.fields.ResourceModifierRules,
			}
			got := p.ApplyResourceModifierRules(tt.args.obj, tt.args.groupResource, nil, logrus.New())

			assert.Equal(t, tt.wantErr, len(got) > 0)
			assert.Equal(t, *tt.wantObj, *tt.args.obj)
		})
	}
}

var podYAMLWithNginxImage = `
apiVersion: v1
kind: Pod
metadata:
  name: pod1
  namespace: fake
spec:
  containers:
  - image: nginx
    name: nginx
`

var podYAMLWithNginx1Image = `
apiVersion: v1
kind: Pod
metadata:
  name: pod1
  namespace: fake
spec:
  containers:
  - image: nginx1
    name: nginx
`

var podYAMLWithNFSVolume = `
apiVersion: v1
kind: Pod
metadata:
  name: pod1
  namespace: fake
spec:
  containers:
  - image: fake
    name: fake
    volumeMounts:
    - mountPath: /fake1
      name: vol1
    - mountPath: /fake2
      name: vol2
  volumes:
  - name: vol1
    nfs:
      path: /fake2
  - name: vol2
    emptyDir: {}
`

var podYAMLWithPVCVolume = `
apiVersion: v1
kind: Pod
metadata:
  name: pod1
  namespace: fake
spec:
  containers:
  - image: fake
    name: fake
    volumeMounts:
    - mountPath: /fake1
      name: vol1
    - mountPath: /fake2
      name: vol2
  volumes:
  - name: vol1
    persistentVolumeClaim:
      claimName: pvc1
  - name: vol2
    emptyDir: {}
`

var svcYAMLWithPort8000 = `
apiVersion: v1
kind: Service
metadata:
  name: svc1
  namespace: fake
spec:
  ports:
  - name: fake1
    port: 8001
    protocol: TCP
    targetPort: 8001
  - name: fake
    port: 8000
    protocol: TCP
    targetPort: 8000
  - name: fake2
    port: 8002
    protocol: TCP
    targetPort: 8002
`

var svcYAMLWithPort9000 = `
apiVersion: v1
kind: Service
metadata:
  name: svc1
  namespace: fake
spec:
  ports:
  - name: fake1
    port: 8001
    protocol: TCP
    targetPort: 8001
  - name: fake
    port: 9000
    protocol: TCP
    targetPort: 9000
  - name: fake2
    port: 8002
    protocol: TCP
    targetPort: 8002
`

var cmYAMLWithLabelAToB = `
apiVersion: v1
kind: ConfigMap
metadata:
  name: cm1
  namespace: fake
  labels:
    a: b
    c: d
`

var cmYAMLWithLabelAToC = `
apiVersion: v1
kind: ConfigMap
metadata:
  name: cm1
  namespace: fake
  labels:
    a: c
    c: d
`

var cmYAMLWithoutLabelA = `
apiVersion: v1
kind: ConfigMap
metadata:
  name: cm1
  namespace: fake
  labels:
    c: d
`

func TestResourceModifiers_ApplyResourceModifierRules_StrategicMergePatch(t *testing.T) {
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	unstructuredSerializer := yaml.NewDecodingSerializer(unstructured.UnstructuredJSONScheme)
	o1, _, err := unstructuredSerializer.Decode([]byte(podYAMLWithNFSVolume), nil, nil)
	require.NoError(t, err)
	podWithNFSVolume := o1.(*unstructured.Unstructured)

	o2, _, err := unstructuredSerializer.Decode([]byte(podYAMLWithPVCVolume), nil, nil)
	require.NoError(t, err)
	podWithPVCVolume := o2.(*unstructured.Unstructured)

	o3, _, err := unstructuredSerializer.Decode([]byte(svcYAMLWithPort8000), nil, nil)
	require.NoError(t, err)
	svcWithPort8000 := o3.(*unstructured.Unstructured)

	o4, _, err := unstructuredSerializer.Decode([]byte(svcYAMLWithPort9000), nil, nil)
	require.NoError(t, err)
	svcWithPort9000 := o4.(*unstructured.Unstructured)

	o5, _, err := unstructuredSerializer.Decode([]byte(podYAMLWithNginxImage), nil, nil)
	require.NoError(t, err)
	podWithNginxImage := o5.(*unstructured.Unstructured)

	o6, _, err := unstructuredSerializer.Decode([]byte(podYAMLWithNginx1Image), nil, nil)
	require.NoError(t, err)
	podWithNginx1Image := o6.(*unstructured.Unstructured)

	tests := []struct {
		name          string
		rm            *ResourceModifiers
		obj           *unstructured.Unstructured
		groupResource string
		wantErr       bool
		wantObj       *unstructured.Unstructured
	}{
		{
			name: "update image",
			rm: &ResourceModifiers{
				Version: "v1",
				ResourceModifierRules: []ResourceModifierRule{
					{
						Conditions: Conditions{
							GroupResource: "pods",
							Namespaces:    []string{"fake"},
						},
						StrategicPatches: []StrategicMergePatch{
							{
								PatchData: `{"spec":{"containers":[{"name":"nginx","image":"nginx1"}]}}`,
							},
						},
					},
				},
			},
			obj:           podWithNginxImage.DeepCopy(),
			groupResource: "pods",
			wantErr:       false,
			wantObj:       podWithNginx1Image.DeepCopy(),
		},
		{
			name: "update image with yaml format",
			rm: &ResourceModifiers{
				Version: "v1",
				ResourceModifierRules: []ResourceModifierRule{
					{
						Conditions: Conditions{
							GroupResource: "pods",
							Namespaces:    []string{"fake"},
						},
						StrategicPatches: []StrategicMergePatch{
							{
								PatchData: `spec:
  containers:
  - name: nginx
    image: nginx1`,
							},
						},
					},
				},
			},
			obj:           podWithNginxImage.DeepCopy(),
			groupResource: "pods",
			wantErr:       false,
			wantObj:       podWithNginx1Image.DeepCopy(),
		},
		{
			name: "replace nfs with pvc in volume",
			rm: &ResourceModifiers{
				Version: "v1",
				ResourceModifierRules: []ResourceModifierRule{
					{
						Conditions: Conditions{
							GroupResource: "pods",
							Namespaces:    []string{"fake"},
						},
						StrategicPatches: []StrategicMergePatch{
							{
								PatchData: `{"spec":{"volumes":[{"nfs":null,"name":"vol1","persistentVolumeClaim":{"claimName":"pvc1"}}]}}`,
							},
						},
					},
				},
			},
			obj:           podWithNFSVolume.DeepCopy(),
			groupResource: "pods",
			wantErr:       false,
			wantObj:       podWithPVCVolume.DeepCopy(),
		},
		{
			name: "replace any other volume source with pvc in volume",
			rm: &ResourceModifiers{
				Version: "v1",
				ResourceModifierRules: []ResourceModifierRule{
					{
						Conditions: Conditions{
							GroupResource: "pods",
							Namespaces:    []string{"fake"},
						},
						StrategicPatches: []StrategicMergePatch{
							{
								PatchData: `{"spec":{"volumes":[{"$retainKeys":["name","persistentVolumeClaim"],"name":"vol1","persistentVolumeClaim":{"claimName":"pvc1"}}]}}`,
							},
						},
					},
				},
			},
			obj:           podWithNFSVolume.DeepCopy(),
			groupResource: "pods",
			wantErr:       false,
			wantObj:       podWithPVCVolume.DeepCopy(),
		},
		{
			name: "update a service port",
			rm: &ResourceModifiers{
				Version: "v1",
				ResourceModifierRules: []ResourceModifierRule{
					{
						Conditions: Conditions{
							GroupResource: "services",
							Namespaces:    []string{"fake"},
						},
						StrategicPatches: []StrategicMergePatch{
							{
								PatchData: `{"spec":{"$setElementOrder/ports":[{"port":8001},{"port":9000},{"port":8002}],"ports":[{"name":"fake","port":9000,"protocol":"TCP","targetPort":9000},{"$patch":"delete","port":8000}]}}`,
							},
						},
					},
				},
			},
			obj:           svcWithPort8000.DeepCopy(),
			groupResource: "services",
			wantErr:       false,
			wantObj:       svcWithPort9000.DeepCopy(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.rm.ApplyResourceModifierRules(tt.obj, tt.groupResource, scheme, logrus.New())

			assert.Equal(t, tt.wantErr, len(got) > 0)
			assert.Equal(t, *tt.wantObj, *tt.obj)
		})
	}
}

func TestResourceModifiers_ApplyResourceModifierRules_JSONMergePatch(t *testing.T) {
	unstructuredSerializer := yaml.NewDecodingSerializer(unstructured.UnstructuredJSONScheme)
	o1, _, err := unstructuredSerializer.Decode([]byte(cmYAMLWithLabelAToB), nil, nil)
	require.NoError(t, err)
	cmWithLabelAToB := o1.(*unstructured.Unstructured)

	o2, _, err := unstructuredSerializer.Decode([]byte(cmYAMLWithLabelAToC), nil, nil)
	require.NoError(t, err)
	cmWithLabelAToC := o2.(*unstructured.Unstructured)

	o3, _, err := unstructuredSerializer.Decode([]byte(cmYAMLWithoutLabelA), nil, nil)
	require.NoError(t, err)
	cmWithoutLabelA := o3.(*unstructured.Unstructured)

	tests := []struct {
		name          string
		rm            *ResourceModifiers
		obj           *unstructured.Unstructured
		groupResource string
		wantErr       bool
		wantObj       *unstructured.Unstructured
	}{
		{
			name: "update labels",
			rm: &ResourceModifiers{
				Version: "v1",
				ResourceModifierRules: []ResourceModifierRule{
					{
						Conditions: Conditions{
							GroupResource: "configmaps",
							Namespaces:    []string{"fake"},
						},
						MergePatches: []JSONMergePatch{
							{
								PatchData: `{"metadata":{"labels":{"a":"c"}}}`,
							},
						},
					},
				},
			},
			obj:           cmWithLabelAToB.DeepCopy(),
			groupResource: "configmaps",
			wantErr:       false,
			wantObj:       cmWithLabelAToC.DeepCopy(),
		},
		{
			name: "update labels in yaml format",
			rm: &ResourceModifiers{
				Version: "v1",
				ResourceModifierRules: []ResourceModifierRule{
					{
						Conditions: Conditions{
							GroupResource: "configmaps",
							Namespaces:    []string{"fake"},
						},
						MergePatches: []JSONMergePatch{
							{
								PatchData: `metadata:
  labels:
    a: c`,
							},
						},
					},
				},
			},
			obj:           cmWithLabelAToB.DeepCopy(),
			groupResource: "configmaps",
			wantErr:       false,
			wantObj:       cmWithLabelAToC.DeepCopy(),
		},
		{
			name: "delete labels",
			rm: &ResourceModifiers{
				Version: "v1",
				ResourceModifierRules: []ResourceModifierRule{
					{
						Conditions: Conditions{
							GroupResource: "configmaps",
							Namespaces:    []string{"fake"},
						},
						MergePatches: []JSONMergePatch{
							{
								PatchData: `{"metadata":{"labels":{"a":null}}}`,
							},
						},
					},
				},
			},
			obj:           cmWithLabelAToB.DeepCopy(),
			groupResource: "configmaps",
			wantErr:       false,
			wantObj:       cmWithoutLabelA.DeepCopy(),
		},
		{
			name: "add labels",
			rm: &ResourceModifiers{
				Version: "v1",
				ResourceModifierRules: []ResourceModifierRule{
					{
						Conditions: Conditions{
							GroupResource: "configmaps",
							Namespaces:    []string{"fake"},
						},
						MergePatches: []JSONMergePatch{
							{
								PatchData: `{"metadata":{"labels":{"a":"b"}}}`,
							},
						},
					},
				},
			},
			obj:           cmWithoutLabelA.DeepCopy(),
			groupResource: "configmaps",
			wantErr:       false,
			wantObj:       cmWithLabelAToB.DeepCopy(),
		},
		{
			name: "delete non-existing labels",
			rm: &ResourceModifiers{
				Version: "v1",
				ResourceModifierRules: []ResourceModifierRule{
					{
						Conditions: Conditions{
							GroupResource: "configmaps",
							Namespaces:    []string{"fake"},
						},
						MergePatches: []JSONMergePatch{
							{
								PatchData: `{"metadata":{"labels":{"a":null}}}`,
							},
						},
					},
				},
			},
			obj:           cmWithoutLabelA.DeepCopy(),
			groupResource: "configmaps",
			wantErr:       false,
			wantObj:       cmWithoutLabelA.DeepCopy(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.rm.ApplyResourceModifierRules(tt.obj, tt.groupResource, nil, logrus.New())

			assert.Equal(t, tt.wantErr, len(got) > 0)
			assert.Equal(t, *tt.wantObj, *tt.obj)
		})
	}
}

func TestResourceModifiers_wildcard_in_GroupResource(t *testing.T) {
	unstructuredSerializer := yaml.NewDecodingSerializer(unstructured.UnstructuredJSONScheme)
	o1, _, err := unstructuredSerializer.Decode([]byte(cmYAMLWithLabelAToB), nil, nil)
	require.NoError(t, err)
	cmWithLabelAToB := o1.(*unstructured.Unstructured)

	o2, _, err := unstructuredSerializer.Decode([]byte(cmYAMLWithLabelAToC), nil, nil)
	require.NoError(t, err)
	cmWithLabelAToC := o2.(*unstructured.Unstructured)

	tests := []struct {
		name          string
		rm            *ResourceModifiers
		obj           *unstructured.Unstructured
		groupResource string
		wantErr       bool
		wantObj       *unstructured.Unstructured
	}{
		{
			name: "match all groups and resources",
			rm: &ResourceModifiers{
				Version: "v1",
				ResourceModifierRules: []ResourceModifierRule{
					{
						Conditions: Conditions{
							GroupResource: "*",
							Namespaces:    []string{"fake"},
						},
						MergePatches: []JSONMergePatch{
							{
								PatchData: `{"metadata":{"labels":{"a":"c"}}}`,
							},
						},
					},
				},
			},
			obj:           cmWithLabelAToB.DeepCopy(),
			groupResource: "configmaps",
			wantErr:       false,
			wantObj:       cmWithLabelAToC.DeepCopy(),
		},
		{
			name: "match all resources in group apps",
			rm: &ResourceModifiers{
				Version: "v1",
				ResourceModifierRules: []ResourceModifierRule{
					{
						Conditions: Conditions{
							GroupResource: "*.apps",
							Namespaces:    []string{"fake"},
						},
						MergePatches: []JSONMergePatch{
							{
								PatchData: `{"metadata":{"labels":{"a":"c"}}}`,
							},
						},
					},
				},
			},
			obj:           cmWithLabelAToB.DeepCopy(),
			groupResource: "fake.apps",
			wantErr:       false,
			wantObj:       cmWithLabelAToC.DeepCopy(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.rm.ApplyResourceModifierRules(tt.obj, tt.groupResource, nil, logrus.New())

			assert.Equal(t, tt.wantErr, len(got) > 0)
			assert.Equal(t, *tt.wantObj, *tt.obj)
		})
	}
}

func TestResourceModifiers_conditional_patches(t *testing.T) {
	unstructuredSerializer := yaml.NewDecodingSerializer(unstructured.UnstructuredJSONScheme)
	o1, _, err := unstructuredSerializer.Decode([]byte(cmYAMLWithLabelAToB), nil, nil)
	require.NoError(t, err)
	cmWithLabelAToB := o1.(*unstructured.Unstructured)

	o2, _, err := unstructuredSerializer.Decode([]byte(cmYAMLWithLabelAToC), nil, nil)
	require.NoError(t, err)
	cmWithLabelAToC := o2.(*unstructured.Unstructured)

	tests := []struct {
		name          string
		rm            *ResourceModifiers
		obj           *unstructured.Unstructured
		groupResource string
		wantErr       bool
		wantObj       *unstructured.Unstructured
	}{
		{
			name: "match conditions and apply patches",
			rm: &ResourceModifiers{
				Version: "v1",
				ResourceModifierRules: []ResourceModifierRule{
					{
						Conditions: Conditions{
							GroupResource: "*",
							Namespaces:    []string{"fake"},
							Matches: []MatchRule{
								{
									Path:  "/metadata/labels/a",
									Value: "b",
								},
							},
						},
						MergePatches: []JSONMergePatch{
							{
								PatchData: `{"metadata":{"labels":{"a":"c"}}}`,
							},
						},
					},
				},
			},
			obj:           cmWithLabelAToB.DeepCopy(),
			groupResource: "configmaps",
			wantErr:       false,
			wantObj:       cmWithLabelAToC.DeepCopy(),
		},
		{
			name: "mismatch conditions and skip patches",
			rm: &ResourceModifiers{
				Version: "v1",
				ResourceModifierRules: []ResourceModifierRule{
					{
						Conditions: Conditions{
							GroupResource: "*",
							Namespaces:    []string{"fake"},
							Matches: []MatchRule{
								{
									Path:  "/metadata/labels/a",
									Value: "c",
								},
							},
						},
						MergePatches: []JSONMergePatch{
							{
								PatchData: `{"metadata":{"labels":{"a":"c"}}}`,
							},
						},
					},
				},
			},
			obj:           cmWithLabelAToB.DeepCopy(),
			groupResource: "configmaps",
			wantErr:       false,
			wantObj:       cmWithLabelAToB.DeepCopy(),
		},
		{
			name: "missing condition path and skip patches",
			rm: &ResourceModifiers{
				Version: "v1",
				ResourceModifierRules: []ResourceModifierRule{
					{
						Conditions: Conditions{
							GroupResource: "*",
							Namespaces:    []string{"fake"},
							Matches: []MatchRule{
								{
									Path:  "/metadata/labels/a/b",
									Value: "c",
								},
							},
						},
						MergePatches: []JSONMergePatch{
							{
								PatchData: `{"metadata":{"labels":{"a":"c"}}}`,
							},
						},
					},
				},
			},
			obj:           cmWithLabelAToB.DeepCopy(),
			groupResource: "configmaps",
			wantErr:       false,
			wantObj:       cmWithLabelAToB.DeepCopy(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.rm.ApplyResourceModifierRules(tt.obj, tt.groupResource, nil, logrus.New())

			assert.Equal(t, tt.wantErr, len(got) > 0)
			assert.Equal(t, *tt.wantObj, *tt.obj)
		})
	}
}

func TestJSONPatch_ToString(t *testing.T) {
	type fields struct {
		Operation string
		From      string
		Path      string
		Value     string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "test",
			fields: fields{
				Operation: "test",
				Path:      "/spec/replicas",
				Value:     "1",
			},
			want: `{"op": "test", "from": "", "path": "/spec/replicas", "value": 1}`,
		},
		{
			name: "replace integer",
			fields: fields{
				Operation: "replace",
				Path:      "/spec/replicas",
				Value:     "2",
			},
			want: `{"op": "replace", "from": "", "path": "/spec/replicas", "value": 2}`,
		},
		{
			name: "replace array",
			fields: fields{
				Operation: "replace",
				Path:      "/spec/template/spec/containers/0/ports",
				Value:     `[{"containerPort": 80}]`,
			},
			want: `{"op": "replace", "from": "", "path": "/spec/template/spec/containers/0/ports", "value": [{"containerPort": 80}]}`,
		},
		{
			name: "replace with null",
			fields: fields{
				Operation: "replace",
				Path:      "/spec/template/spec/containers/0/ports",
				Value:     `null`,
			},
			want: `{"op": "replace", "from": "", "path": "/spec/template/spec/containers/0/ports", "value": null}`,
		},
		{
			name: "add json object",
			fields: fields{
				Operation: "add",
				Path:      "/spec/template/spec/containers/0",
				Value:     `{"name": "nginx", "image": "nginx:1.14.2", "ports": [{"containerPort": 80}]}`,
			},
			want: `{"op": "add", "from": "", "path": "/spec/template/spec/containers/0", "value": {"name": "nginx", "image": "nginx:1.14.2", "ports": [{"containerPort": 80}]}}`,
		},
		{
			name: "remove",
			fields: fields{
				Operation: "remove",
				Path:      "/spec/template/spec/containers/0",
			},
			want: `{"op": "remove", "from": "", "path": "/spec/template/spec/containers/0", "value": ""}`,
		},
		{
			name: "move",
			fields: fields{
				Operation: "move",
				From:      "/spec/template/spec/containers/0",
				Path:      "/spec/template/spec/containers/1",
			},
			want: `{"op": "move", "from": "/spec/template/spec/containers/0", "path": "/spec/template/spec/containers/1", "value": ""}`,
		},
		{
			name: "copy",
			fields: fields{
				Operation: "copy",
				From:      "/spec/template/spec/containers/0",
				Path:      "/spec/template/spec/containers/1",
			},
			want: `{"op": "copy", "from": "/spec/template/spec/containers/0", "path": "/spec/template/spec/containers/1", "value": ""}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &JSONPatch{
				Operation: tt.fields.Operation,
				From:      tt.fields.From,
				Path:      tt.fields.Path,
				Value:     tt.fields.Value,
			}
			if got := p.ToString(); got != tt.want {
				t.Errorf("JSONPatch.ToString() = %v, want %v", got, tt.want)
			}
		})
	}
}
