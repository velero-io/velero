package stringptr

import (
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestGetString(t *testing.T) {
	assert.Equal(t, NilString, GetString(nil))
	
	val := "hello"
	assert.Equal(t, "hello", GetString(&val))
	
	empty := ""
	assert.Equal(t, "", GetString(&empty))
}
