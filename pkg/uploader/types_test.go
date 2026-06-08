package uploader

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateUploaderType(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr string
		wantMsg string
	}{
		{
			"'   kopia  ' is a valid type (space will be trimmed)",
			"   kopia  ",
			"",
			"",
		},
		{
			"'anything_else' is invalid",
			"anything_else",
			"invalid uploader type 'anything_else', valid types: 'kopia', 'velero-block'",
			"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, err := ValidateUploaderType(tt.input)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}

			assert.Equal(t, tt.wantMsg, msg)
		})
	}
}
