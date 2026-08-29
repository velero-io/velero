package restore

import (
	"testing"

	"github.com/stretchr/testify/require"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
)

func TestIsResourcePolicyValid(t *testing.T) {
	require.True(t, IsResourcePolicyValid(string(velerov1api.ResourcePolicyTypeNone)))
	require.True(t, IsResourcePolicyValid(string(velerov1api.ResourcePolicyTypeUpdate)))
	require.True(t, IsResourcePolicyValid(""))
	require.False(t, IsResourcePolicyValid("invalid"))
}

func TestIsVolumeDataPolicyValid(t *testing.T) {
	require.True(t, IsVolumeDataPolicyValid(string(velerov1api.VolumeDataPolicyTypeNone)))
	require.True(t, IsVolumeDataPolicyValid(string(velerov1api.VolumeDataPolicyTypeFull)))
	require.True(t, IsVolumeDataPolicyValid(string(velerov1api.VolumeDataPolicyTypeIncremental)))
	require.True(t, IsVolumeDataPolicyValid(""))
	require.False(t, IsVolumeDataPolicyValid("invalid"))
}
