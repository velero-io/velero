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

package common

import (
	"reflect"
	"testing"

	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	velerov1 "github.com/velero-io/velero/pkg/apis/velero/v1"
)

func TestGetPluginConfig(t *testing.T) {
	type args struct {
		kind    PluginKind
		name    string
		objects []runtime.Object
	}
	pluginLabelsMap := map[string]string{"velero.io/plugin-config": "", "foo": "RestoreItemAction"}
	testConfigMap := &corev1api.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			Kind: "ConfigMap",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo-config",
			Namespace: velerov1.DefaultNamespace,
			Labels:    pluginLabelsMap,
		},
	}
	tests := []struct {
		name    string
		args    args
		want    *corev1api.ConfigMap
		wantErr bool
	}{
		{
			name: "should return nil if no config map found",
			args: args{
				kind:    PluginKindRestoreItemAction,
				name:    "foo",
				objects: []runtime.Object{},
			},
			want:    nil,
			wantErr: false,
		},
		{
			name: "should return error if more than one config map found",
			args: args{
				kind: PluginKindRestoreItemAction,
				name: "foo",
				objects: []runtime.Object{
					&corev1api.ConfigMap{
						TypeMeta: metav1.TypeMeta{
							Kind: "ConfigMap",
						},
						ObjectMeta: metav1.ObjectMeta{
							Name:      "foo-config",
							Namespace: velerov1.DefaultNamespace,
							Labels:    pluginLabelsMap,
						},
					},
					&corev1api.ConfigMap{
						TypeMeta: metav1.TypeMeta{
							Kind: "ConfigMap",
						},
						ObjectMeta: metav1.ObjectMeta{
							Name:      "foo-config-duplicate",
							Namespace: velerov1.DefaultNamespace,
							Labels:    pluginLabelsMap,
						},
					},
				},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "should return pointer to configmap if only one config map with label found",
			args: args{
				kind: PluginKindRestoreItemAction,
				name: "foo",
				objects: []runtime.Object{
					testConfigMap,
				},
			},
			want:    testConfigMap,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := fake.NewSimpleClientset(tt.args.objects...)
			got, err := GetPluginConfig(tt.args.kind, tt.args.name, fakeClient.CoreV1().ConfigMaps(velerov1.DefaultNamespace))
			if (err != nil) != tt.wantErr {
				t.Errorf("GetPluginConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetPluginConfig() = %v, want %v", got, tt.want)
			}
		})
	}
}
