package datamover

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsBuiltInUploader(t *testing.T) {
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
