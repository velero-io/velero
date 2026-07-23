package flag

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestStringOfLabelSelector(t *testing.T) {
	ls, err := metav1.ParseToLabelSelector("k1=v1,k2=v2")
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
	assert.True(t, str == "k1=v1,k2=v2" || str == "k2=v2,k2=v2")
}

func TestSetOfSetBasedLabelSelector(t *testing.T) {
	selector := &LabelSelector{}
	require.NoError(t, selector.Set("pr-label notin (1)"))
	require.NotNil(t, selector.LabelSelector)
	require.Len(t, selector.LabelSelector.MatchExpressions, 1)
	req := selector.LabelSelector.MatchExpressions[0]
	assert.Equal(t, "pr-label", req.Key)
	assert.Equal(t, metav1.LabelSelectorOpNotIn, req.Operator)
	assert.Equal(t, []string{"1"}, req.Values)
}

func TestSetOfDoesNotExistLabelSelector(t *testing.T) {
	selector := &LabelSelector{}
	require.NoError(t, selector.Set("!pr-label"))
	require.NotNil(t, selector.LabelSelector)
	require.Len(t, selector.LabelSelector.MatchExpressions, 1)
	req := selector.LabelSelector.MatchExpressions[0]
	assert.Equal(t, "pr-label", req.Key)
	assert.Equal(t, metav1.LabelSelectorOpDoesNotExist, req.Operator)
	assert.Empty(t, req.Values)
}

func TestTypeOfLabelSelector(t *testing.T) {
	selector := &LabelSelector{}
	assert.Equal(t, "labelSelector", selector.Type())
}
