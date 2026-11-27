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

package itemoutcome

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An owner or reporter edge is recorded before the item is fetched or backed
// up, so the row it mints must not claim a success nothing has established.
func TestEdgeAloneMintsNamed(t *testing.T) {
	r := NewRecorder()
	reporter := pod("ns1", "pod1")
	r.SetReportedBy(pvc("ns1", "data-disk"), reporter)

	result := r.Result()
	require.Len(t, result.Items, 1)
	item := result.Items[0]
	assert.Equal(t, OutcomeNamed, item.Outcome)
	require.Len(t, item.ReportedBy, 1)
	assert.Equal(t, *newItemRef(reporter), item.ReportedBy[0])
}

func TestReportedByRecordsEveryDistinctReporter(t *testing.T) {
	r := NewRecorder()
	child := pvc("ns1", "pvc1")
	first := pod("ns1", "pod1")
	second := pod("ns1", "pod2")

	r.SetReportedBy(child, first)
	r.SetReportedBy(child, second)

	result := r.Result()
	require.Len(t, result.Items, 1)
	require.Len(t, result.Items[0].ReportedBy, 2)
	assert.Equal(t, *newItemRef(first), result.Items[0].ReportedBy[0])
	assert.Equal(t, *newItemRef(second), result.Items[0].ReportedBy[1])
}

// The same identity can be both the controller owner and an additional-item
// reporter. They are separate relationships and both facts must survive.
func TestOwnerAndReportedBySameIdentityAreBothPreserved(t *testing.T) {
	r := NewRecorder()
	child := pvc("ns1", "pvc1")
	owner := pod("ns1", "pod1")

	r.SetOwner(child, owner)
	r.SetReportedBy(child, owner)

	result := r.Result()
	require.Len(t, result.Items, 1)
	require.NotNil(t, result.Items[0].Owner)
	assert.Equal(t, *newItemRef(owner), *result.Items[0].Owner)
	require.Len(t, result.Items[0].ReportedBy, 1)
	assert.Equal(t, *newItemRef(owner), result.Items[0].ReportedBy[0])
}

func TestOwnerIsSeparateFromReportedBy(t *testing.T) {
	r := NewRecorder()
	child := pvc("ns1", "pvc1")
	owner := pod("ns1", "owner")
	reporter := pod("ns1", "reporter")

	r.SetOwner(child, owner)
	r.SetReportedBy(child, reporter)

	result := r.Result()
	require.Len(t, result.Items, 1)
	require.NotNil(t, result.Items[0].Owner)
	assert.Equal(t, *newItemRef(owner), *result.Items[0].Owner)
	require.Len(t, result.Items[0].ReportedBy, 1)
	assert.Equal(t, *newItemRef(reporter), result.Items[0].ReportedBy[0])
}

// The controller owner is single and immutable; the first owner wins.
func TestOwnerKeepsFirstClaim(t *testing.T) {
	r := NewRecorder()
	child := pvc("ns1", "pvc1")
	first := pod("ns1", "first")
	second := pod("ns1", "second")

	r.SetOwner(child, first)
	r.SetOwner(child, second)

	result := r.Result()
	require.Len(t, result.Items, 1)
	require.NotNil(t, result.Items[0].Owner)
	assert.Equal(t, *newItemRef(first), *result.Items[0].Owner)
}

func TestDuplicateReporterClaimsCollapseToOne(t *testing.T) {
	r := NewRecorder()
	child := pvc("ns1", "pvc1")
	reporter := pod("ns1", "pod1")

	r.SetReportedBy(child, reporter)
	r.SetReportedBy(child, reporter)

	result := r.Result()
	require.Len(t, result.Items, 1)
	require.Len(t, result.Items[0].ReportedBy, 1)
	assert.Equal(t, *newItemRef(reporter), result.Items[0].ReportedBy[0])
}

func TestEqualStrengthDistinctReportersAreBothRecorded(t *testing.T) {
	r := NewRecorder()
	child := pvc("ns1", "pvc1")
	first := pod("ns1", "pod1")
	second := pod("ns1", "pod2")

	r.SetReportedBy(child, first)
	r.SetReportedBy(child, second)

	result := r.Result()
	require.Len(t, result.Items, 1)
	require.Len(t, result.Items[0].ReportedBy, 2)
	assert.Equal(t, "pod1", result.Items[0].ReportedBy[0].Name)
	assert.Equal(t, "pod2", result.Items[0].ReportedBy[1].Name)
}

func TestOwnerAndReportedByEmptyWithoutRelationships(t *testing.T) {
	r := NewRecorder()
	r.Observe(pod("ns1", "pod1"))

	result := r.Result()
	require.Len(t, result.Items, 1)
	assert.Nil(t, result.Items[0].Owner)
	assert.Empty(t, result.Items[0].ReportedBy)
}

func TestOwnerAndReportedByAreIndependentOfOutcome(t *testing.T) {
	r := NewRecorder()
	child := pvc("ns1", "pvc1")
	owner := pod("ns1", "owner")
	reporter := pod("ns1", "reporter")

	r.SetOwner(child, owner)
	r.SetReportedBy(child, reporter)
	r.Fail(child, "boom")

	result := r.Result()
	require.Len(t, result.Items, 1)
	assert.Equal(t, OutcomeFailed, result.Items[0].Outcome)
	require.NotNil(t, result.Items[0].Owner)
	assert.Equal(t, *newItemRef(owner), *result.Items[0].Owner)
	require.Len(t, result.Items[0].ReportedBy, 1)
	assert.Equal(t, *newItemRef(reporter), result.Items[0].ReportedBy[0])
}

func TestObservePromotesNamedToBackedUp(t *testing.T) {
	r := NewRecorder()
	child := pvc("ns1", "pvc1")
	reporter := pod("ns1", "pod1")

	r.SetReportedBy(child, reporter)
	r.Observe(child)

	result := r.Result()
	require.Len(t, result.Items, 1)
	assert.Equal(t, OutcomeSucceeded, result.Items[0].Outcome)
	require.Len(t, result.Items[0].ReportedBy, 1)
}

func TestVerdictSurvivesEdgeArrivingLater(t *testing.T) {
	r := NewRecorder()
	child := pvc("ns1", "pvc1")
	reporter := pod("ns1", "pod1")

	r.Fail(child, "boom")
	r.SetReportedBy(child, reporter)

	result := r.Result()
	require.Len(t, result.Items, 1)
	assert.Equal(t, OutcomeFailed, result.Items[0].Outcome)
	assert.Contains(t, result.Items[0].Messages, "boom")
	require.Len(t, result.Items[0].ReportedBy, 1)
}

func TestSetReportedByRefusesSelfEdge(t *testing.T) {
	r := NewRecorder()
	id := pod("ns", "pod")

	r.SetReportedBy(id, id)

	assert.Empty(t, r.Result().Items)
}

func TestSetOwnerRefusesSelfEdge(t *testing.T) {
	r := NewRecorder()
	id := pod("ns", "pod")

	r.SetOwner(id, id)

	assert.Empty(t, r.Result().Items)
}

func TestRekeyReportedByFollowsReporterRename(t *testing.T) {
	r := NewRecorder()
	reporter := pod("ns", "reporter")
	renamedReporter := pod("ns", "reporter-renamed")
	child := pvc("ns", "disk")

	r.SetReportedBy(child, reporter)
	r.Observe(child)
	r.Observe(reporter)
	r.For(reporter).Rekey(renamedReporter)
	r.Observe(renamedReporter)

	result := r.Result()
	byName := map[string]ItemOutcome{}
	for _, item := range result.Items {
		byName[item.Name] = item
	}

	require.Contains(t, byName, "disk")
	require.Len(t, byName["disk"].ReportedBy, 1)
	assert.Equal(t, "reporter-renamed", byName["disk"].ReportedBy[0].Name)
	assert.NotContains(t, byName, "reporter")
}

func TestRekeyResolvesChildRenameForReportedBy(t *testing.T) {
	r := NewRecorder()
	reporter := pod("ns", "reporter")
	child := pvc("ns", "disk")
	renamedChild := pvc("ns", "disk-generated")

	r.SetReportedBy(child, reporter)
	r.Observe(child)
	r.For(child).Rekey(renamedChild)

	// A later edge still names the pre-rename child identity.
	r.SetReportedBy(child, reporter)
	r.Observe(renamedChild)

	result := r.Result()
	byName := map[string]ItemOutcome{}
	for _, item := range result.Items {
		byName[item.Name] = item
	}

	require.Contains(t, byName, "disk-generated")
	require.NotContains(t, byName, "disk")
	require.Len(t, byName["disk-generated"].ReportedBy, 1)
	assert.Equal(t, "reporter", byName["disk-generated"].ReportedBy[0].Name)
}

func TestRekeyBeforeReportedByKeepsEdgeOnFinalRow(t *testing.T) {
	r := NewRecorder()
	reporter := pod("ns", "reporter")
	child := pvc("ns", "disk")
	renamedChild := pvc("ns", "disk-generated")

	// The rename is known before the edge is written.
	r.For(child).Rekey(renamedChild)
	r.SetReportedBy(child, reporter)
	r.Observe(renamedChild)

	result := r.Result()
	byName := map[string]ItemOutcome{}
	for _, item := range result.Items {
		byName[item.Name] = item
	}

	require.Contains(t, byName, "disk-generated")
	require.NotContains(t, byName, "disk")
	require.Len(t, byName["disk-generated"].ReportedBy, 1)
	assert.Equal(t, "reporter", byName["disk-generated"].ReportedBy[0].Name)
}

// A rekey that merges a child into its reporter's identity must not leave the
// merged row pointing at itself.
func TestRekeyDropsSelfEdgeAfterMerge(t *testing.T) {
	t.Run("destination row exists", func(t *testing.T) {
		r := NewRecorder()
		child := pvc("ns", "child")
		reporter := pod("ns", "reporter")

		r.SetReportedBy(child, reporter)
		r.Observe(reporter)
		r.For(child).Rekey(reporter)

		result := r.Result()
		require.Len(t, result.Items, 1)
		assert.Equal(t, "reporter", result.Items[0].Name)
		assert.Empty(t, result.Items[0].ReportedBy)
	})

	t.Run("destination row is created by the move", func(t *testing.T) {
		r := NewRecorder()
		child := pvc("ns", "child")
		reporter := pod("ns", "reporter")

		r.SetReportedBy(child, reporter)
		r.For(child).Rekey(reporter)

		result := r.Result()
		require.Len(t, result.Items, 1)
		assert.Equal(t, "reporter", result.Items[0].Name)
		assert.Equal(t, OutcomeNamed, result.Items[0].Outcome)
		assert.Empty(t, result.Items[0].ReportedBy)
	})
}

func TestRekeyDropsOwnerSelfEdge(t *testing.T) {
	r := NewRecorder()
	child := pvc("ns", "child")
	owner := pod("ns", "owner")

	r.SetOwner(child, owner)
	r.For(child).Rekey(owner)

	result := r.Result()
	require.Len(t, result.Items, 1)
	assert.Equal(t, "owner", result.Items[0].Name)
	assert.Nil(t, result.Items[0].Owner)
}

func TestRekeyOwnerFollowsOwnerRename(t *testing.T) {
	r := NewRecorder()
	child := pvc("ns", "child")
	owner := pod("ns", "owner")
	renamedOwner := pod("ns", "owner-renamed")

	r.SetOwner(child, owner)
	r.For(owner).Rekey(renamedOwner)

	result := r.Result()
	byName := map[string]ItemOutcome{}
	for _, item := range result.Items {
		byName[item.Name] = item
	}
	require.Contains(t, byName, "child")
	require.NotNil(t, byName["child"].Owner)
	assert.Equal(t, "owner-renamed", byName["child"].Owner.Name)
}
