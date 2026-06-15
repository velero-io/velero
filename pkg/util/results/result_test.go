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

package results

import (
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/stretchr/testify/assert"
)

func TestMerge(t *testing.T) {
	tests := []struct {
		name   string
		result *Result
		other  *Result
		want   *Result
	}{
		{
			name: "when an empty result is merged into a non-empty result, the result does not change",
			result: &Result{
				Cluster: []string{"foo"},
				Namespaces: map[string][]string{
					"ns-1": {"bar"},
					"ns-2": {"baz"},
				},
			},
			other: &Result{},
			want: &Result{
				Cluster: []string{"foo"},
				Namespaces: map[string][]string{
					"ns-1": {"bar"},
					"ns-2": {"baz"},
				},
			},
		},
		{
			name:   "when a non-empty result is merged into an result, the result looks like the non-empty result",
			result: &Result{},
			other: &Result{
				Cluster: []string{"foo"},
				Namespaces: map[string][]string{
					"ns-1": {"bar"},
					"ns-2": {"baz"},
				},
			},
			want: &Result{
				Cluster: []string{"foo"},
				Namespaces: map[string][]string{
					"ns-1": {"bar"},
					"ns-2": {"baz"},
				},
			},
		},
		{
			name: "when two non-empty results are merged, the result is the union of the two",
			result: &Result{
				Cluster: []string{"cluster-err-1"},
				Namespaces: map[string][]string{
					"ns-1": {"ns-1-err-1"},
					"ns-2": {"ns-2-err-1"},
					"ns-3": {"ns-3-err-1"},
				},
			},
			other: &Result{
				Cluster: []string{"cluster-err-2"},
				Namespaces: map[string][]string{
					"ns-1": {"ns-1-err-2"},
					"ns-2": {"ns-2-err-2"},
					"ns-4": {"ns-4-err-1"},
				},
			},
			want: &Result{
				Cluster: []string{"cluster-err-1", "cluster-err-2"},
				Namespaces: map[string][]string{
					"ns-1": {"ns-1-err-1", "ns-1-err-2"},
					"ns-2": {"ns-2-err-1", "ns-2-err-2"},
					"ns-3": {"ns-3-err-1"},
					"ns-4": {"ns-4-err-1"},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.result.Merge(tc.other)
			assert.Equal(t, tc.want, tc.result)
		})
	}
}

func TestAddVeleroError(t *testing.T) {
	tests := []struct {
		name   string
		result *Result
		err    error
		want   *Result
	}{
		{
			name:   "when AddVeleroError is called for a result with no velero errors, the result has the new error added properly",
			result: &Result{},
			err:    errors.New("foo"),
			want:   &Result{Velero: []string{"foo"}},
		},

		{
			name:   "when AddVeleroError is called for a result with existing velero errors, the result has the new error appended properly",
			result: &Result{Velero: []string{"bar"}},
			err:    errors.New("foo"),
			want:   &Result{Velero: []string{"bar", "foo"}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.result.AddVeleroError(tc.err)
			assert.Equal(t, tc.want, tc.result)
		})
	}
}

func TestAdd(t *testing.T) {
	tests := []struct {
		name   string
		result *Result
		ns     string
		err    error
		want   *Result
	}{
		{
			name:   "when Add is called for a result with no existing errors and an empty namespace, the error is added to the cluster-scoped list",
			result: &Result{},
			ns:     "",
			err:    errors.New("foo"),
			want:   &Result{Cluster: []string{"foo"}},
		},
		{
			name:   "when Add is called for a result with some existing errors and an empty namespace, the error is added to the cluster-scoped list",
			result: &Result{Cluster: []string{"bar"}},
			ns:     "",
			err:    errors.New("foo"),
			want:   &Result{Cluster: []string{"bar", "foo"}},
		},

		{
			name:   "when Add is called for a result with no existing errors and a non-empty namespace, the error is added to the namespace list",
			result: &Result{},
			ns:     "ns-1",
			err:    errors.New("foo"),
			want: &Result{
				Namespaces: map[string][]string{
					"ns-1": {"foo"},
				},
			},
		},
		{
			name: "when Add is called for a result with some existing errors and a non-empty namespace, the error is added to the namespace list",
			result: &Result{
				Namespaces: map[string][]string{
					"ns-1": {"bar"},
					"ns-2": {"baz"},
				},
			},
			ns:  "ns-1",
			err: errors.New("foo"),
			want: &Result{
				Namespaces: map[string][]string{
					"ns-1": {"bar", "foo"},
					"ns-2": {"baz"},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.result.Add(tc.ns, tc.err)
			assert.Equal(t, tc.want, tc.result)
		})
	}
}

func TestIsEmpty(t *testing.T) {
	result := &Result{
		Velero:     nil,
		Cluster:    nil,
		Namespaces: nil,
	}
	assert.True(t, result.IsEmpty())

	result = &Result{
		Velero:     []string{"error"},
		Cluster:    nil,
		Namespaces: nil,
	}
	assert.False(t, result.IsEmpty())
}
