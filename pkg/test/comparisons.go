/*
Copyright 2018 the Velero contributors.

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

package test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/util/diff"
	core "k8s.io/client-go/testing"
)

// CompareActions checks slices of actual and expected Actions
// for equality (ignoring order). It checks that the lengths of
// the slices are the same, that each actual Action has a
// corresponding expected Action, and that each expected Action
// has a corresponding actual Action.
func CompareActions(t *testing.T, expected, actual []core.Action) {
	t.Helper()
	assert.Len(t, actual, len(expected))

	for _, e := range expected {
		found := false
		for _, a := range actual {
			if reflect.DeepEqual(e, a) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing expected action %#v", e)
		}
	}

	for _, a := range actual {
		found := false
		for _, e := range expected {
			if reflect.DeepEqual(e, a) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("unexpected action %#v", a)
		}
	}
}

// ValidatePatch tests the validity of an action. It checks
// that the action is a PatchAction, that the patch decodes from JSON
// with the provided decode func and has no extraneous fields, and that
// the decoded patch matches the expected.
func ValidatePatch(t *testing.T, action core.Action, expected any, decodeFunc func(*json.Decoder) (any, error)) {
	t.Helper()
	patchAction, ok := action.(core.PatchAction)
	require.True(t, ok, "action is not a PatchAction")

	decoder := json.NewDecoder(bytes.NewReader(patchAction.GetPatch()))
	decoder.DisallowUnknownFields()

	actual, err := decodeFunc(decoder)
	require.NoError(t, err)

	AssertDeepEqual(t, expected, actual)
}

// TimesAreEqual compares two times for equality.
// This function is used by equality.Semantic.DeepEqual to compare two time objects
// without having to call a method.
func TimesAreEqual(t1, t2 time.Time) bool {
	return t1.Equal(t2)
}

// AssertDeepEqual asserts the semantic equality of objects.
// This function exists in order to make sure time.Time and metav1.Time objects
// can be compared correctly. See https://github.com/stretchr/testify/issues/502.
func AssertDeepEqual(t *testing.T, expected, actual any) bool {
	t.Helper()
	// By default, the equality.Semantic object doesn't have a function for comparing time.Times
	err := equality.Semantic.AddFunc(TimesAreEqual)
	if err != nil {
		// Programmer error, the test should die.
		t.Fatalf("Could not register equality function: %s", err)
	}

	if !equality.Semantic.DeepEqual(expected, actual) {
		s := diff.Diff(expected, actual)
		return assert.Fail(t, fmt.Sprintf("Objects not equal:\n\n%s", s))
	}

	return true
}

// AssertErrorMatches asserts that if expected is the empty string, actual
// is nil, otherwise, that actual's error string matches expected.
func AssertErrorMatches(t *testing.T, expected string, actual error) bool {
	t.Helper()
	if expected != "" {
		return assert.EqualError(t, actual, expected)
	}

	return assert.NoError(t, actual)
}

func CompareSlice(x, y []string) bool {
	less := func(a, b string) bool { return a < b }
	return cmp.Diff(x, y, cmpopts.SortSlices(less)) == ""
}
