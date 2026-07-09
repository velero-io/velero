/*
Copyright the Velero contributors.

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

package resourcepolicies

import (
	corev1api "k8s.io/api/core/v1"
)

type volumeTypeCondition struct {
	volumeTypes []SupportedVolume
}

type SupportedVolume string

const (
	AWSAzureDisk         SupportedVolume = "awsAzureDisk"
	AWSElasticBlockStore SupportedVolume = "awsElasticBlockStore"
	AzureDisk            SupportedVolume = "azureDisk"
	AzureFile            SupportedVolume = "azureFile"
	Cinder               SupportedVolume = "cinder"
	CephFS               SupportedVolume = "cephfs"
	ConfigMap            SupportedVolume = "configMap"
	CSI                  SupportedVolume = "csi"
	DownwardAPI          SupportedVolume = "downwardAPI"
	EmptyDir             SupportedVolume = "emptyDir"
	Ephemeral            SupportedVolume = "ephemeral"
	FC                   SupportedVolume = "fc"
	Flocker              SupportedVolume = "flocker"
	FlexVolume           SupportedVolume = "flexVolume"
	GitRepo              SupportedVolume = "gitRepo"
	Glusterfs            SupportedVolume = "glusterfs"
	GCEPersistentDisk    SupportedVolume = "gcePersistentDisk"
	HostPath             SupportedVolume = "hostPath"
	Image                SupportedVolume = "image"
	ISCSI                SupportedVolume = "iscsi"
	Local                SupportedVolume = "local"
	NFS                  SupportedVolume = "nfs"
	PhotonPersistentDisk SupportedVolume = "photonPersistentDisk"
	PortworxVolume       SupportedVolume = "portworxVolume"
	Projected            SupportedVolume = "projected"
	Quobyte              SupportedVolume = "quobyte"
	RBD                  SupportedVolume = "rbd"
	ScaleIO              SupportedVolume = "scaleIO"
	Secret               SupportedVolume = "secret"
	StorageOS            SupportedVolume = "storageOS"
	VsphereVolume        SupportedVolume = "vsphereVolume"
)

func (v *volumeTypeCondition) match(s *structuredVolume) bool {
	if len(v.volumeTypes) == 0 {
		return true
	}

	for _, vt := range v.volumeTypes {
		if vt == s.volumeType {
			return true
		}
	}
	return false
}

func (v *volumeTypeCondition) validate() error {
	// validate by yamlv3
	return nil
}

func getVolumeTypeFromPV(pv *corev1api.PersistentVolume) SupportedVolume {
	if pv == nil {
		return ""
	}

	if pv.Spec.AWSElasticBlockStore != nil {
		return AWSElasticBlockStore
	}
	if pv.Spec.AzureDisk != nil {
		return AzureDisk
	}
	if pv.Spec.AzureFile != nil {
		return AzureFile
	}
	if pv.Spec.CephFS != nil {
		return CephFS
	}
	if pv.Spec.Cinder != nil {
		return Cinder
	}
	if pv.Spec.CSI != nil {
		return CSI
	}
	if pv.Spec.FC != nil {
		return FC
	}
	if pv.Spec.Flocker != nil {
		return Flocker
	}
	if pv.Spec.FlexVolume != nil {
		return FlexVolume
	}
	if pv.Spec.GCEPersistentDisk != nil {
		return GCEPersistentDisk
	}
	if pv.Spec.Glusterfs != nil {
		return Glusterfs
	}
	if pv.Spec.HostPath != nil {
		return HostPath
	}
	if pv.Spec.ISCSI != nil {
		return ISCSI
	}
	if pv.Spec.Local != nil {
		return Local
	}
	if pv.Spec.NFS != nil {
		return NFS
	}
	if pv.Spec.PhotonPersistentDisk != nil {
		return PhotonPersistentDisk
	}
	if pv.Spec.PortworxVolume != nil {
		return PortworxVolume
	}
	if pv.Spec.Quobyte != nil {
		return Quobyte
	}
	if pv.Spec.RBD != nil {
		return RBD
	}
	if pv.Spec.ScaleIO != nil {
		return ScaleIO
	}
	if pv.Spec.StorageOS != nil {
		return StorageOS
	}
	if pv.Spec.VsphereVolume != nil {
		return VsphereVolume
	}
	return ""
}

func getVolumeTypeFromVolume(vol *corev1api.Volume) SupportedVolume {
	if vol == nil {
		return ""
	}

	if vol.AWSElasticBlockStore != nil {
		return AWSElasticBlockStore
	}
	if vol.AzureDisk != nil {
		return AzureDisk
	}
	if vol.AzureFile != nil {
		return AzureFile
	}
	if vol.CephFS != nil {
		return CephFS
	}
	if vol.Cinder != nil {
		return Cinder
	}
	if vol.CSI != nil {
		return CSI
	}
	if vol.FC != nil {
		return FC
	}
	if vol.Flocker != nil {
		return Flocker
	}
	if vol.FlexVolume != nil {
		return FlexVolume
	}
	if vol.GCEPersistentDisk != nil {
		return GCEPersistentDisk
	}
	if vol.GitRepo != nil {
		return GitRepo
	}
	if vol.Glusterfs != nil {
		return Glusterfs
	}
	if vol.ISCSI != nil {
		return ISCSI
	}
	if vol.NFS != nil {
		return NFS
	}
	if vol.Secret != nil {
		return Secret
	}
	if vol.RBD != nil {
		return RBD
	}
	if vol.DownwardAPI != nil {
		return DownwardAPI
	}
	if vol.ConfigMap != nil {
		return ConfigMap
	}
	if vol.Projected != nil {
		return Projected
	}
	if vol.Ephemeral != nil {
		return Ephemeral
	}
	if vol.FC != nil {
		return FC
	}
	if vol.PhotonPersistentDisk != nil {
		return PhotonPersistentDisk
	}
	if vol.PortworxVolume != nil {
		return PortworxVolume
	}
	if vol.Quobyte != nil {
		return Quobyte
	}
	if vol.ScaleIO != nil {
		return ScaleIO
	}
	if vol.StorageOS != nil {
		return StorageOS
	}
	if vol.VsphereVolume != nil {
		return VsphereVolume
	}
	if vol.HostPath != nil {
		return HostPath
	}
	if vol.EmptyDir != nil {
		return EmptyDir
	}
	if vol.Image != nil {
		return Image
	}
	return ""
}
