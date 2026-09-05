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

package output

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/cmd"
)

func TestPrintVolumeSnapshotLocationDefaultColumn(t *testing.T) {
	t.Parallel()

	location := builder.ForVolumeSnapshotLocation("velero", "aws-default").
		Provider("aws").
		Result()

	defaultLocations := map[string]string{
		"aws": "aws-default",
		"gcp": "gcp-default",
	}

	rows := printVolumeSnapshotLocation(location, defaultLocations)
	require.Len(t, rows, 1)
	require.Len(t, rows[0].Cells, len(volumeSnapshotLocationColumns))

	assert.Equal(t, "aws-default", rows[0].Cells[0])
	assert.Equal(t, "aws", rows[0].Cells[1])
	assert.Equal(t, cmd.TRUE, rows[0].Cells[2])
}

func TestPrintVolumeSnapshotLocationDefaultColumnNotDefault(t *testing.T) {
	t.Parallel()

	location := builder.ForVolumeSnapshotLocation("velero", "aws-secondary").
		Provider("aws").
		Result()

	defaultLocations := map[string]string{
		"aws": "aws-default",
	}

	rows := printVolumeSnapshotLocation(location, defaultLocations)
	require.Len(t, rows, 1)

	assert.Empty(t, rows[0].Cells[2])
}

func TestPrintVolumeSnapshotLocationDefaultColumnUnknownProvider(t *testing.T) {
	t.Parallel()

	location := builder.ForVolumeSnapshotLocation("velero", "portworx-default").
		Provider("portworx").
		Result()

	rows := printVolumeSnapshotLocation(location, map[string]string{"aws": "aws-default"})
	require.Len(t, rows, 1)

	assert.Empty(t, rows[0].Cells[2])
}

func TestPrintVolumeSnapshotLocationListWithNilDefaults(t *testing.T) {
	t.Parallel()

	list := &velerov1api.VolumeSnapshotLocationList{
		Items: []velerov1api.VolumeSnapshotLocation{
			*builder.ForVolumeSnapshotLocation("velero", "default").Provider("aws").Result(),
		},
	}

	rows := printVolumeSnapshotLocationList(list, nil)
	require.Len(t, rows, 1)
	assert.Empty(t, rows[0].Cells[2])
}
