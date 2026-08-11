package flag

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

func TestStringOfLabelSelector(t *testing.T) {
	ls, err := parseToLabelSelector("k1=v1,k2=v2")
	require.NoError(t, err)
	selector := &LabelSelector{
		LabelSelector: ls,
	}
	assert.Equal(t, "k1=v1,k2=v2", selector.String())
}

func TestSetOfLabelSelector(t *testing.T) {
	selector := &LabelSelector{}
	require.NoError(t, selector.Set("k1=v1,k2=v2"))
	str := selector.String()
	assert.True(t, str == "k1=v1,k2=v2" || str == "k2=v2,k1=v1")
}

func TestTypeOfLabelSelector(t *testing.T) {
	selector := &LabelSelector{}
	assert.Equal(t, "labelSelector", selector.Type())
}

func TestSetOfLabelSelectorNotEquals(t *testing.T) {
	// Reproduces https://github.com/velero-io/velero/issues/4724:
	// metav1.ParseToLabelSelector rejects "!=", but kubectl / labels.Parse accept it.
	selector := &LabelSelector{}
	require.NoError(t, selector.Set("for!=1"))
	require.NotNil(t, selector.LabelSelector)
	require.Len(t, selector.LabelSelector.MatchExpressions, 1)
	expr := selector.LabelSelector.MatchExpressions[0]
	assert.Equal(t, "for", expr.Key)
	assert.Equal(t, metav1.LabelSelectorOpNotIn, expr.Operator)
	assert.Equal(t, []string{"1"}, expr.Values)

	as, err := metav1.LabelSelectorAsSelector(selector.LabelSelector)
	require.NoError(t, err)
	assert.False(t, as.Matches(labels.Set{"for": "1"}))
	assert.True(t, as.Matches(labels.Set{"for": "2"}))
	assert.True(t, as.Matches(labels.Set{}))
}

func TestSetOfOrLabelSelectorNotEquals(t *testing.T) {
	selector := &OrLabelSelector{}
	require.NoError(t, selector.Set("env!=prod or tier=frontend"))
	require.Len(t, selector.OrLabelSelectors, 2)

	as0, err := metav1.LabelSelectorAsSelector(selector.OrLabelSelectors[0])
	require.NoError(t, err)
	assert.False(t, as0.Matches(labels.Set{"env": "prod"}))
	assert.True(t, as0.Matches(labels.Set{"env": "dev"}))

	as1, err := metav1.LabelSelectorAsSelector(selector.OrLabelSelectors[1])
	require.NoError(t, err)
	assert.True(t, as1.Matches(labels.Set{"tier": "frontend"}))
	assert.False(t, as1.Matches(labels.Set{"tier": "backend"}))
}

func TestParseToLabelSelectorSupportsCommonOperators(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "equals", input: "a=b"},
		{name: "double equals", input: "a==b"},
		{name: "not equals", input: "a!=b"},
		{name: "in", input: "a in (b,c)"},
		{name: "notin", input: "a notin (b,c)"},
		{name: "exists", input: "a"},
		{name: "does not exist", input: "!a"},
		{name: "mixed with not equals", input: "a!=b,c=d"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ls, err := parseToLabelSelector(tc.input)
			require.NoError(t, err)
			_, err = metav1.LabelSelectorAsSelector(ls)
			require.NoError(t, err)
		})
	}
}
