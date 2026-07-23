package datamover

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetUploaderType(t *testing.T) {
	testcases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "empty dataMover is kopia",
			input: "",
			want:  "kopia",
		},
		{
			name:  "velero dataMover is kopia",
			input: "velero",
			want:  "kopia",
		},
		{
			name:  "velero-fs dataMover is kopia",
			input: "velero-fs",
			want:  "kopia",
		},
		{
			name:  "velero-block dataMover is velero-block",
			input: "velero-block",
			want:  "velero-block",
		},
		{
			name:  "kopia dataMover is kopia",
			input: "kopia",
			want:  "kopia",
		},
		{
			name:  "restic dataMover is restic",
			input: "restic",
			want:  "restic",
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(tt *testing.T) {
			assert.Equal(tt, tc.want, GetUploaderType(tc.input))
		})
	}
}
