package boolptr

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsSetToTrue(t *testing.T) {
	assert.False(t, IsSetToTrue(nil))

	f := false
	assert.False(t, IsSetToTrue(&f))

	tr := true
	assert.True(t, IsSetToTrue(&tr))
}

func TestIsSetToFalse(t *testing.T) {
	assert.False(t, IsSetToFalse(nil))

	tr := true
	assert.False(t, IsSetToFalse(&tr))

	f := false
	assert.True(t, IsSetToFalse(&f))
}

func TestTrue(t *testing.T) {
	val := True()
	assert.NotNil(t, val)
	assert.True(t, *val)
}

func TestFalse(t *testing.T) {
	val := False()
	assert.NotNil(t, val)
	assert.False(t, *val)
}
