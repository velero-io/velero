package resourcemodifiers

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
)

func TestJsonMergePatchFailure(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{
			name: "patch with bad yaml",
			data: "a: b:",
		},
		{
			name: "patch with bad json",
			data: `{"a"::1}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			err := clientgoscheme.AddToScheme(scheme)
			require.NoError(t, err)
			pt := &JSONMergePatcher{
				patches: []JSONMergePatch{{PatchData: tt.data}},
			}

			u := &unstructured.Unstructured{}
			_, err = pt.Patch(u, logrus.New())
			assert.Error(t, err)
		})
	}
}
