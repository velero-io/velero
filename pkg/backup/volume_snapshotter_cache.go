package backup

import (
	"sync"

	velerov1api "github.com/velero-io/velero/pkg/apis/velero/v1"
	vsv1 "github.com/velero-io/velero/pkg/plugin/velero/volumesnapshotter/v1"
)

type VolumeSnapshotterCache struct {
	cache  map[string]vsv1.VolumeSnapshotter
	mutex  sync.Mutex
	getter VolumeSnapshotterGetter
}

func NewVolumeSnapshotterCache(getter VolumeSnapshotterGetter) *VolumeSnapshotterCache {
	return &VolumeSnapshotterCache{
		cache:  make(map[string]vsv1.VolumeSnapshotter),
		getter: getter,
	}
}

func (c *VolumeSnapshotterCache) SetNX(location *velerov1api.VolumeSnapshotLocation) (vsv1.VolumeSnapshotter, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if snapshotter, exists := c.cache[location.Name]; exists {
		return snapshotter, nil
	}

	snapshotter, err := c.getter.GetVolumeSnapshotter(location.Spec.Provider)
	if err != nil {
		return nil, err
	}

	if err := snapshotter.Init(location.Spec.Config); err != nil {
		return nil, err
	}

	c.cache[location.Name] = snapshotter
	return snapshotter, nil
}
