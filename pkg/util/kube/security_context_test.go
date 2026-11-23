/*
Copyright 2020 the Velero contributors.

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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"

	"github.com/velero-io/velero/pkg/util/boolptr"
)

func TestParseSecurityContext(t *testing.T) {
	type args struct {
		runAsUser                string
		runAsGroup               string
		allowPrivilegeEscalation string
		secCtx                   string
	}
	tests := []struct {
		name     string
		args     args
		wantErr  bool
		expected *corev1api.SecurityContext
	}{
		{
			"valid security context",
			args{"1001", "999", "true", ``},
			false,
			&corev1api.SecurityContext{
				RunAsUser:                pointInt64(1001),
				RunAsGroup:               pointInt64(999),
				AllowPrivilegeEscalation: boolptr.True(),
			},
		},
		{
			"valid security context with override runAsUser",
			args{"1001", "999", "true", `runAsUser: 2000`},
			false,
			&corev1api.SecurityContext{
				RunAsUser:                pointInt64(2000),
				RunAsGroup:               pointInt64(999),
				AllowPrivilegeEscalation: boolptr.True(),
			},
		},
		{
			"valid securityContext with comments only secCtx key",
			args{"", "", "", `
capabilities:
    drop:
    - ALL
    add:
    - cap1
    - cap2
seLinuxOptions:
    user: userLabel
    role: roleLabel
    type: typeLabel
    level: levelLabel
# user www-data
runAsUser: 3333
# group www-data
runAsGroup: 3333
runAsNonRoot: true
readOnlyRootFilesystem: true
allowPrivilegeEscalation: false`},
			false,
			&corev1api.SecurityContext{
				RunAsUser:  pointInt64(3333),
				RunAsGroup: pointInt64(3333),
				Capabilities: &corev1api.Capabilities{
					Drop: []corev1api.Capability{"ALL"},
					Add:  []corev1api.Capability{"cap1", "cap2"},
				},
				SELinuxOptions: &corev1api.SELinuxOptions{
					User:  "userLabel",
					Role:  "roleLabel",
					Type:  "typeLabel",
					Level: "levelLabel",
				},
				RunAsNonRoot:             boolptr.True(),
				ReadOnlyRootFilesystem:   boolptr.True(),
				AllowPrivilegeEscalation: boolptr.False(),
			},
		},
		{
			"valid securityContext with comments only secCtx key check seLinuxOptions is correctly parsed",
			args{"", "", "", `
capabilities:
    drop:
    - ALL
    add:
    - cap1
    - cap2
seLinuxOptions:
    user: userLabelFail
    role: roleLabel
    type: typeLabel
    level: levelLabel
# user www-data
runAsUser: 3333
# group www-data
runAsGroup: 3333
runAsNonRoot: true
readOnlyRootFilesystem: true
allowPrivilegeEscalation: false`},
			true,
			&corev1api.SecurityContext{
				RunAsUser:  pointInt64(3333),
				RunAsGroup: pointInt64(3333),
				Capabilities: &corev1api.Capabilities{
					Drop: []corev1api.Capability{"ALL"},
					Add:  []corev1api.Capability{"cap1", "cap2"},
				},
				SELinuxOptions: &corev1api.SELinuxOptions{
					User:  "userLabel",
					Role:  "roleLabel",
					Type:  "typeLabel",
					Level: "levelLabel",
				},
				RunAsNonRoot:             boolptr.True(),
				ReadOnlyRootFilesystem:   boolptr.True(),
				AllowPrivilegeEscalation: boolptr.False(),
			},
		},
		{
			"valid securityContext with secCtx key override runAsUser runAsGroup and allowPrivilegeEscalation",
			args{"1001", "999", "true", `
capabilities:
    drop:
    - ALL
    add:
    - cap1
    - cap2
seLinuxOptions:
    user: userLabel
    role: roleLabel
    type: typeLabel
    level: levelLabel
# user www-data
runAsUser: 3333
# group www-data
runAsGroup: 3333
runAsNonRoot: true
readOnlyRootFilesystem: true
allowPrivilegeEscalation: false`},
			false,
			&corev1api.SecurityContext{
				RunAsUser:  pointInt64(3333),
				RunAsGroup: pointInt64(3333),
				Capabilities: &corev1api.Capabilities{
					Drop: []corev1api.Capability{"ALL"},
					Add:  []corev1api.Capability{"cap1", "cap2"},
				},
				SELinuxOptions: &corev1api.SELinuxOptions{
					User:  "userLabel",
					Role:  "roleLabel",
					Type:  "typeLabel",
					Level: "levelLabel",
				},
				RunAsNonRoot:             boolptr.True(),
				ReadOnlyRootFilesystem:   boolptr.True(),
				AllowPrivilegeEscalation: boolptr.False(),
			},
		},
		{
			"another valid security context",
			args{"1001", "999", "false", ""},
			false,
			&corev1api.SecurityContext{
				RunAsUser:                pointInt64(1001),
				RunAsGroup:               pointInt64(999),
				AllowPrivilegeEscalation: boolptr.False(),
			},
		},
		{"security context without runAsGroup", args{"1001", "", "", ""}, false, &corev1api.SecurityContext{
			RunAsUser: pointInt64(1001),
		}},
		{"security context without runAsUser", args{"", "999", "", ""}, false, &corev1api.SecurityContext{
			RunAsGroup: pointInt64(999),
		}},
		{"empty context without runAsUser", args{"", "", "", ""}, false, &corev1api.SecurityContext{}},
		{
			"invalid securityContext secCtx unknown key",
			args{"", "", "", `
capabilitiesUnknownkey:
    drop:
    - ALL
    add:
    - cap1
    - cap2
# user www-data
runAsUser: 3333
# group www-data
runAsGroup: 3333
runAsNonRoot: true
readOnlyRootFilesystem: true
allowPrivilegeEscalation: false`},
			true, nil,
		},
		{
			"invalid securityContext secCtx wrong value type string instead of bool",
			args{"", "", "", `
capabilitiesUnknownkey:
    drop:
    - ALL
    add:
    - cap1
    - cap2
# user www-data
runAsUser: 3333
# group www-data
runAsGroup: 3333
runAsNonRoot: plop
readOnlyRootFilesystem: true
allowPrivilegeEscalation: false`},
			true, nil,
		},
		{
			"invalid securityContext secCtx wrong value type string instead of int",
			args{"", "", "", `
capabilitiesUnknownkey:
    drop:
    - ALL
    add:
    - cap1
    - cap2
# user www-data
runAsUser: plop
# group www-data
runAsGroup: 3333
runAsNonRoot: true
readOnlyRootFilesystem: true
allowPrivilegeEscalation: false`},
			true, nil,
		},
		{"invalid security context runAsUser", args{"not a number", "", "", ""}, true, nil},
		{"invalid security context runAsGroup", args{"", "not a number", "", ""}, true, nil},
		{"invalid security context allowPrivilegeEscalation", args{"", "", "not a bool", ""}, true, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSecurityContext(tt.args.runAsUser, tt.args.runAsGroup, tt.args.allowPrivilegeEscalation, tt.args.secCtx)
			if err != nil && tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)

			if tt.expected == nil {
				tt.expected = &corev1api.SecurityContext{}
			}

			if tt.wantErr {
				assert.NotEqual(t, *tt.expected, got)
				return
			}
			assert.Equal(t, *tt.expected, got)
		})
	}
}

func pointInt64(i int64) *int64 {
	return &i
}
