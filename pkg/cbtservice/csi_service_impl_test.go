/*
Copyright The Velero Contributors.

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

package cbtservice

import (
	"context"
	"errors"
	"testing"

	"github.com/kubernetes-csi/external-snapshot-metadata/pkg/api"
	"github.com/kubernetes-csi/external-snapshot-metadata/pkg/iterator"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/rest"
)

func TestEmitterImplSnapshotMetadataIteratorRecord(t *testing.T) {
	t.Run("records block metadata as ranges", func(t *testing.T) {
		var got [][]Range
		emitter := &emitterImpl{
			logger: logrus.New(),
			recordCallBack: func(ranges []Range) error {
				got = append(got, ranges)
				return nil
			},
		}

		err := emitter.SnapshotMetadataIteratorRecord(7, iterator.IteratorMetadata{
			BlockMetadata: []*api.BlockMetadata{
				{ByteOffset: 10, SizeBytes: 20},
				{ByteOffset: 40, SizeBytes: 50},
			},
		})

		require.NoError(t, err)
		assert.Equal(t, [][]Range{
			{{Offset: 10, Length: 20}},
			{{Offset: 40, Length: 50}},
		}, got)
	})

	t.Run("rejects negative block metadata", func(t *testing.T) {
		callbackCalled := false
		emitter := &emitterImpl{
			logger: logrus.New(),
			recordCallBack: func(ranges []Range) error {
				callbackCalled = true
				return nil
			},
		}

		err := emitter.SnapshotMetadataIteratorRecord(3, iterator.IteratorMetadata{
			BlockMetadata: []*api.BlockMetadata{{ByteOffset: -1, SizeBytes: 20}},
		})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid CBT metadata")
		assert.False(t, callbackCalled)
	})

	t.Run("returns callback error", func(t *testing.T) {
		wantErr := errors.New("record failed")
		emitter := &emitterImpl{
			logger: logrus.New(),
			recordCallBack: func(ranges []Range) error {
				return wantErr
			},
		}

		err := emitter.SnapshotMetadataIteratorRecord(5, iterator.IteratorMetadata{
			BlockMetadata: []*api.BlockMetadata{{ByteOffset: 1, SizeBytes: 2}},
		})

		require.ErrorIs(t, err, wantErr)
	})
}

func TestEmitterImplSnapshotMetadataIteratorDone(t *testing.T) {
	emitter := &emitterImpl{logger: logrus.New()}
	assert.NoError(t, emitter.SnapshotMetadataIteratorDone(4))
}

func TestNewServiceInitializesFields(t *testing.T) {
	logger := logrus.New()
	cfg := &rest.Config{Host: "https://example.com"}

	svc := NewService(logger, "velero-ns", "velero-sa", cfg)

	impl, ok := svc.(*ServiceImpl)
	require.True(t, ok)
	assert.Same(t, logger, impl.logger)
	assert.Equal(t, "velero-ns", impl.vsNamespace)
	assert.Equal(t, "velero-sa", impl.SAName)
	assert.Same(t, cfg, impl.clientConfig)
}

func TestNewServiceForwardsSANameToArgs(t *testing.T) {
	originalBuildClients := buildClients
	originalGetSnapshotMetadata := getSnapshotMetadata
	t.Cleanup(func() {
		buildClients = originalBuildClients
		getSnapshotMetadata = originalGetSnapshotMetadata
	})

	buildClients = func(config *rest.Config) (iterator.Clients, error) {
		return iterator.Clients{}, nil
	}

	var capturedArgs iterator.Args
	getSnapshotMetadata = func(ctx context.Context, args iterator.Args) error {
		capturedArgs = args
		return nil
	}

	svc := NewService(logrus.New(), "velero-ns", "velero-sa", &rest.Config{Host: "https://example.com"})

	err := svc.GetAllocatedBlocks(t.Context(), "snap-1", func([]Range) error { return nil })
	require.NoError(t, err)
	assert.Equal(t, "velero-ns", capturedArgs.Namespace)
	assert.Equal(t, "velero-ns", capturedArgs.SANamespace)
	assert.Equal(t, "velero-sa", capturedArgs.SAName)
}

func TestServiceImplGetAllocatedBlocks(t *testing.T) {
	originalBuildClients := buildClients
	originalGetSnapshotMetadata := getSnapshotMetadata
	t.Cleanup(func() {
		buildClients = originalBuildClients
		getSnapshotMetadata = originalGetSnapshotMetadata
	})

	t.Run("build clients error is returned", func(t *testing.T) {
		wantErr := errors.New("build clients failed")
		getSnapshotCalled := false
		buildClients = func(config *rest.Config) (iterator.Clients, error) {
			return iterator.Clients{}, wantErr
		}
		getSnapshotMetadata = func(ctx context.Context, args iterator.Args) error {
			getSnapshotCalled = true
			return nil
		}

		service := &ServiceImpl{logger: logrus.New(), clientConfig: &rest.Config{Host: "https://example.com"}}

		err := service.GetAllocatedBlocks(t.Context(), "snap-1", func([]Range) error { return nil })

		require.ErrorIs(t, err, wantErr)
		assert.False(t, getSnapshotCalled)
	})

	t.Run("forwards args and callback", func(t *testing.T) {
		cfg := &rest.Config{Host: "https://example.com"}
		fakeClients := iterator.Clients{}
		var capturedArgs iterator.Args
		var recorded [][]Range
		buildClients = func(config *rest.Config) (iterator.Clients, error) {
			assert.Same(t, cfg, config)
			return fakeClients, nil
		}
		getSnapshotMetadata = func(ctx context.Context, args iterator.Args) error {
			capturedArgs = args
			return args.Emitter.SnapshotMetadataIteratorRecord(1, iterator.IteratorMetadata{
				BlockMetadata: []*api.BlockMetadata{{ByteOffset: 11, SizeBytes: 22}},
			})
		}

		service := &ServiceImpl{
			logger:       logrus.New(),
			vsNamespace:  "velero-ns",
			SAName:       "sa-name",
			clientConfig: cfg,
		}

		err := service.GetAllocatedBlocks(t.Context(), "snap-1", func(ranges []Range) error {
			recorded = append(recorded, ranges)
			return nil
		})

		require.NoError(t, err)
		assert.Equal(t, fakeClients, capturedArgs.Clients)
		assert.Equal(t, "snap-1", capturedArgs.SnapshotName)
		assert.Empty(t, capturedArgs.PrevSnapshotName)
		assert.Equal(t, "velero-ns", capturedArgs.Namespace)
		assert.Equal(t, "velero-ns", capturedArgs.SANamespace)
		assert.Equal(t, "sa-name", capturedArgs.SAName)
		assert.Equal(t, iterator.DefaultTokenExpirySeconds, capturedArgs.TokenExpirySecs)
		assert.Zero(t, capturedArgs.MaxResults)
		assert.Equal(t, [][]Range{{{Offset: 11, Length: 22}}}, recorded)
	})
}

func TestServiceImplGetChangedBlocks(t *testing.T) {
	originalBuildClients := buildClients
	originalGetSnapshotMetadata := getSnapshotMetadata
	t.Cleanup(func() {
		buildClients = originalBuildClients
		getSnapshotMetadata = originalGetSnapshotMetadata
	})

	buildClients = func(config *rest.Config) (iterator.Clients, error) {
		return iterator.Clients{}, nil
	}

	t.Run("sets previous snapshot name", func(t *testing.T) {
		var capturedArgs iterator.Args
		getSnapshotMetadata = func(ctx context.Context, args iterator.Args) error {
			capturedArgs = args
			return nil
		}

		service := &ServiceImpl{
			logger:       logrus.New(),
			vsNamespace:  "velero-ns",
			SAName:       "sa-name",
			clientConfig: &rest.Config{Host: "https://example.com"},
		}

		err := service.GetChangedBlocks(t.Context(), "snap-2", "snap-1", func([]Range) error { return nil })

		require.NoError(t, err)
		assert.Equal(t, "snap-2", capturedArgs.SnapshotName)
		assert.Equal(t, "snap-1", capturedArgs.PrevSnapshotName)
		assert.Equal(t, "velero-ns", capturedArgs.Namespace)
		assert.Equal(t, iterator.DefaultTokenExpirySeconds, capturedArgs.TokenExpirySecs)
		assert.Zero(t, capturedArgs.MaxResults)
	})

	t.Run("returns snapshot metadata error", func(t *testing.T) {
		wantErr := errors.New("metadata failed")
		getSnapshotMetadata = func(ctx context.Context, args iterator.Args) error {
			return wantErr
		}

		service := &ServiceImpl{
			logger:       logrus.New(),
			clientConfig: &rest.Config{Host: "https://example.com"},
		}

		err := service.GetChangedBlocks(t.Context(), "snap-2", "snap-1", func([]Range) error { return nil })

		require.ErrorIs(t, err, wantErr)
	})
}
