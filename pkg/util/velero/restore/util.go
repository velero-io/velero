package restore

import (
	api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
)

func IsResourcePolicyValid(resourcePolicy string) bool {
	return resourcePolicy == "" ||
		resourcePolicy == string(api.ResourcePolicyTypeNone) ||
		resourcePolicy == string(api.ResourcePolicyTypeUpdate)
}

func IsVolumeDataPolicyValid(volumeDataPolicy string) bool {
	return volumeDataPolicy == "" ||
		volumeDataPolicy == string(api.VolumeDataPolicyTypeNone) ||
		volumeDataPolicy == string(api.VolumeDataPolicyTypeFull) ||
		volumeDataPolicy == string(api.VolumeDataPolicyTypeIncremental)
}
