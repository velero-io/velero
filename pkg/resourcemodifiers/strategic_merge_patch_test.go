package resourcemodifiers

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
)

func TestStrategicMergePatchFailure(t *testing.T) {
	tests := []struct {
		name string
		data string
		kind string
	}{
		{
			name: "patch with unknown kind",
			data: "{}",
			kind: "BadKind",
		},
		{
			name: "patch with bad yaml",
			data: "a: b:",
			kind: "Pod",
		},
		{
			name: "patch with bad json",
			data: `{"a"::1}`,
			kind: "Pod",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			err := clientgoscheme.AddToScheme(scheme)
			require.NoError(t, err)
			pt := &StrategicMergePatcher{
				patches: []StrategicMergePatch{{PatchData: tt.data}},
				scheme:  scheme,
			}

			u := &unstructured.Unstructured{}
			u.SetGroupVersionKind(schema.GroupVersionKind{Version: "v1", Kind: tt.kind})
			_, err = pt.Patch(u, logrus.New())
			assert.Error(t, err)
		})
	}
}
