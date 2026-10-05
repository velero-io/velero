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

package datamover

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsBuiltInDataMover(t *testing.T) {
	testcases := []struct {
		name      string
		dataMover string
		want      bool
	}{
		{
			name:      "empty dataMover is builtin",
			dataMover: "",
			want:      true,
		},
		{
			name:      "velero dataMover is builtin",
			dataMover: "velero",
			want:      true,
		},
		{
			name:      "velero-fs dataMover is builtin",
			dataMover: "velero-fs",
			want:      true,
		},
		{
			name:      "velero-block dataMover is builtin",
			dataMover: "velero-block",
			want:      true,
		},
		{
			name:      "kopia dataMover is not builtin",
			dataMover: "kopia",
			want:      false,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(tt *testing.T) {
			assert.Equal(tt, tc.want, IsBuiltInDataMover(tc.dataMover))
		})
	}
}

func TestGetDefaultBuiltInDataMover(t *testing.T) {
	assert.Equal(t, DataMoverTypeVeleroFs, GetDefaultBuiltInDataMover())
}

func TestIsFSDataMover(t *testing.T) {
	testcases := []struct {
		name      string
		dataMover string
		want      bool
	}{
		{
			name:      "empty dataMover is fs",
			dataMover: "",
			want:      true,
		},
		{
			name:      "velero dataMover is fs",
			dataMover: "velero",
			want:      true,
		},
		{
			name:      "velero-fs dataMover is fs",
			dataMover: "velero-fs",
			want:      true,
		},
		{
			name:      "velero-block dataMover is not fs",
			dataMover: "velero-block",
			want:      false,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(tt *testing.T) {
			assert.Equal(tt, tc.want, IsVeleroFSDataMover(tc.dataMover))
		})
	}
}

func TestIsBlockDataMover(t *testing.T) {
	testcases := []struct {
		name      string
		dataMover string
		want      bool
	}{
		{
			name:      "velero-block dataMover is block",
			dataMover: "velero-block",
			want:      true,
		},
		{
			name:      "velero-fs dataMover is not block",
			dataMover: "velero-fs",
			want:      false,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(tt *testing.T) {
			assert.Equal(tt, tc.want, IsVeleroBlockDataMover(tc.dataMover))
		})
	}
}
