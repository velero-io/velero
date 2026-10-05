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
	"testing"

	corev1api "k8s.io/api/core/v1"
)

func TestGetVolumeTypeFromPV(t *testing.T) {
	testCases := []struct {
		name     string
		inputPV  *corev1api.PersistentVolume
		expected SupportedVolume
	}{
		{
			name:     "nil PersistentVolume",
			inputPV:  nil,
			expected: "",
		},
		{
			name: "Test GCEPersistentDisk",
			inputPV: &corev1api.PersistentVolume{
				Spec: corev1api.PersistentVolumeSpec{
					PersistentVolumeSource: corev1api.PersistentVolumeSource{
						GCEPersistentDisk: &corev1api.GCEPersistentDiskVolumeSource{},
					},
				},
			},
			expected: GCEPersistentDisk,
		},
		{
			name: "Test AWSElasticBlockStore",
			inputPV: &corev1api.PersistentVolume{
				Spec: corev1api.PersistentVolumeSpec{
					PersistentVolumeSource: corev1api.PersistentVolumeSource{
						AWSElasticBlockStore: &corev1api.AWSElasticBlockStoreVolumeSource{},
					},
				},
			},
			expected: AWSElasticBlockStore,
		},
		{
			name: "Test HostPath",
			inputPV: &corev1api.PersistentVolume{
				Spec: corev1api.PersistentVolumeSpec{
					PersistentVolumeSource: corev1api.PersistentVolumeSource{
						HostPath: &corev1api.HostPathVolumeSource{},
					},
				},
			},
			expected: HostPath,
		},
		{
			name: "Test Glusterfs",
			inputPV: &corev1api.PersistentVolume{
				Spec: corev1api.PersistentVolumeSpec{
					PersistentVolumeSource: corev1api.PersistentVolumeSource{
						Glusterfs: &corev1api.GlusterfsPersistentVolumeSource{},
					},
				},
			},
			expected: Glusterfs,
		},
		{
			name: "Test NFS",
			inputPV: &corev1api.PersistentVolume{
				Spec: corev1api.PersistentVolumeSpec{
					PersistentVolumeSource: corev1api.PersistentVolumeSource{
						NFS: &corev1api.NFSVolumeSource{},
					},
				},
			},
			expected: NFS,
		},
		{
			name: "Test RBD",
			inputPV: &corev1api.PersistentVolume{
				Spec: corev1api.PersistentVolumeSpec{
					PersistentVolumeSource: corev1api.PersistentVolumeSource{
						RBD: &corev1api.RBDPersistentVolumeSource{},
					},
				},
			},
			expected: RBD,
		},
		{
			name: "Test ISCSI",
			inputPV: &corev1api.PersistentVolume{
				Spec: corev1api.PersistentVolumeSpec{
					PersistentVolumeSource: corev1api.PersistentVolumeSource{
						ISCSI: &corev1api.ISCSIPersistentVolumeSource{},
					},
				},
			},
			expected: ISCSI,
		},
		{
			name: "Test Cinder",
			inputPV: &corev1api.PersistentVolume{
				Spec: corev1api.PersistentVolumeSpec{
					PersistentVolumeSource: corev1api.PersistentVolumeSource{
						Cinder: &corev1api.CinderPersistentVolumeSource{},
					},
				},
			},
			expected: Cinder,
		},
		{
			name: "Test CephFS",
			inputPV: &corev1api.PersistentVolume{
				Spec: corev1api.PersistentVolumeSpec{
					PersistentVolumeSource: corev1api.PersistentVolumeSource{
						CephFS: &corev1api.CephFSPersistentVolumeSource{},
					},
				},
			},
			expected: CephFS,
		},
		{
			name: "Test FC",
			inputPV: &corev1api.PersistentVolume{
				Spec: corev1api.PersistentVolumeSpec{
					PersistentVolumeSource: corev1api.PersistentVolumeSource{
						FC: &corev1api.FCVolumeSource{},
					},
				},
			},
			expected: FC,
		},
		{
			name: "Test Flocker",
			inputPV: &corev1api.PersistentVolume{
				Spec: corev1api.PersistentVolumeSpec{
					PersistentVolumeSource: corev1api.PersistentVolumeSource{
						Flocker: &corev1api.FlockerVolumeSource{},
					},
				},
			},
			expected: Flocker,
		},
		{
			name: "Test FlexVolume",
			inputPV: &corev1api.PersistentVolume{
				Spec: corev1api.PersistentVolumeSpec{
					PersistentVolumeSource: corev1api.PersistentVolumeSource{
						FlexVolume: &corev1api.FlexPersistentVolumeSource{},
					},
				},
			},
			expected: FlexVolume,
		},
		{
			name: "Test AzureFile",
			inputPV: &corev1api.PersistentVolume{
				Spec: corev1api.PersistentVolumeSpec{
					PersistentVolumeSource: corev1api.PersistentVolumeSource{
						AzureFile: &corev1api.AzureFilePersistentVolumeSource{},
					},
				},
			},
			expected: AzureFile,
		},
		{
			name: "Test VsphereVolume",
			inputPV: &corev1api.PersistentVolume{
				Spec: corev1api.PersistentVolumeSpec{
					PersistentVolumeSource: corev1api.PersistentVolumeSource{
						VsphereVolume: &corev1api.VsphereVirtualDiskVolumeSource{},
					},
				},
			},
			expected: VsphereVolume,
		},
		{
			name: "Test Quobyte",
			inputPV: &corev1api.PersistentVolume{
				Spec: corev1api.PersistentVolumeSpec{
					PersistentVolumeSource: corev1api.PersistentVolumeSource{
						Quobyte: &corev1api.QuobyteVolumeSource{},
					},
				},
			},
			expected: Quobyte,
		},
		{
			name: "Test AzureDisk",
			inputPV: &corev1api.PersistentVolume{
				Spec: corev1api.PersistentVolumeSpec{
					PersistentVolumeSource: corev1api.PersistentVolumeSource{
						AzureDisk: &corev1api.AzureDiskVolumeSource{},
					},
				},
			},
			expected: AzureDisk,
		},
		{
			name: "Test PhotonPersistentDisk",
			inputPV: &corev1api.PersistentVolume{
				Spec: corev1api.PersistentVolumeSpec{
					PersistentVolumeSource: corev1api.PersistentVolumeSource{
						PhotonPersistentDisk: &corev1api.PhotonPersistentDiskVolumeSource{},
					},
				},
			},
			expected: PhotonPersistentDisk,
		},
		{
			name: "Test PortworxVolume",
			inputPV: &corev1api.PersistentVolume{
				Spec: corev1api.PersistentVolumeSpec{
					PersistentVolumeSource: corev1api.PersistentVolumeSource{
						PortworxVolume: &corev1api.PortworxVolumeSource{},
					},
				},
			},
			expected: PortworxVolume,
		},
		{
			name: "Test ScaleIO",
			inputPV: &corev1api.PersistentVolume{
				Spec: corev1api.PersistentVolumeSpec{
					PersistentVolumeSource: corev1api.PersistentVolumeSource{
						ScaleIO: &corev1api.ScaleIOPersistentVolumeSource{},
					},
				},
			},
			expected: ScaleIO,
		},
		{
			name: "Test Local",
			inputPV: &corev1api.PersistentVolume{
				Spec: corev1api.PersistentVolumeSpec{
					PersistentVolumeSource: corev1api.PersistentVolumeSource{
						Local: &corev1api.LocalVolumeSource{},
					},
				},
			},
			expected: Local,
		},
		{
			name: "Test StorageOS",
			inputPV: &corev1api.PersistentVolume{
				Spec: corev1api.PersistentVolumeSpec{
					PersistentVolumeSource: corev1api.PersistentVolumeSource{
						StorageOS: &corev1api.StorageOSPersistentVolumeSource{},
					},
				},
			},
			expected: StorageOS,
		},
		{
			name: "Test CSI",
			inputPV: &corev1api.PersistentVolume{
				Spec: corev1api.PersistentVolumeSpec{
					PersistentVolumeSource: corev1api.PersistentVolumeSource{
						CSI: &corev1api.CSIPersistentVolumeSource{},
					},
				},
			},
			expected: CSI,
		},
		{
			name: "Test Unknown Source",
			inputPV: &corev1api.PersistentVolume{
				Spec: corev1api.PersistentVolumeSpec{},
			},
			expected: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := getVolumeTypeFromPV(tc.inputPV)
			if result != tc.expected {
				t.Errorf("Expected %s, but got %s", tc.expected, result)
			}
		})
	}
}

func TestGetVolumeTypeFromVolume(t *testing.T) {
	testCases := []struct {
		name     string
		inputVol *corev1api.Volume
		expected SupportedVolume
	}{
		{
			name:     "nil Volume",
			inputVol: nil,
			expected: "",
		},
		{
			name: "Test Unknown Source",
			inputVol: &corev1api.Volume{
				VolumeSource: corev1api.VolumeSource{},
			},
			expected: "",
		},
		{
			name: "Test HostPath",
			inputVol: &corev1api.Volume{
				VolumeSource: corev1api.VolumeSource{
					HostPath: &corev1api.HostPathVolumeSource{},
				},
			},
			expected: HostPath,
		},
		{
			name: "Test EmptyDir",
			inputVol: &corev1api.Volume{
				VolumeSource: corev1api.VolumeSource{
					EmptyDir: &corev1api.EmptyDirVolumeSource{},
				},
			},
			expected: EmptyDir,
		},
		{
			name: "Test GCEPersistentDisk",
			inputVol: &corev1api.Volume{
				VolumeSource: corev1api.VolumeSource{
					GCEPersistentDisk: &corev1api.GCEPersistentDiskVolumeSource{},
				},
			},
			expected: GCEPersistentDisk,
		},
		{
			name: "Test AWSElasticBlockStore",
			inputVol: &corev1api.Volume{
				VolumeSource: corev1api.VolumeSource{
					AWSElasticBlockStore: &corev1api.AWSElasticBlockStoreVolumeSource{},
				},
			},
			expected: AWSElasticBlockStore,
		},
		{
			name: "Test GitRepo",
			inputVol: &corev1api.Volume{
				VolumeSource: corev1api.VolumeSource{
					GitRepo: &corev1api.GitRepoVolumeSource{},
				},
			},
			expected: GitRepo,
		},
		{
			name: "Test Secret",
			inputVol: &corev1api.Volume{
				VolumeSource: corev1api.VolumeSource{
					Secret: &corev1api.SecretVolumeSource{},
				},
			},
			expected: Secret,
		},
		{
			name: "Test NFS",
			inputVol: &corev1api.Volume{
				VolumeSource: corev1api.VolumeSource{
					NFS: &corev1api.NFSVolumeSource{},
				},
			},
			expected: NFS,
		},
		{
			name: "Test ISCSI",
			inputVol: &corev1api.Volume{
				VolumeSource: corev1api.VolumeSource{
					ISCSI: &corev1api.ISCSIVolumeSource{},
				},
			},
			expected: ISCSI,
		},
		{
			name: "Test Glusterfs",
			inputVol: &corev1api.Volume{
				VolumeSource: corev1api.VolumeSource{
					Glusterfs: &corev1api.GlusterfsVolumeSource{},
				},
			},
			expected: Glusterfs,
		},
		{
			name: "Test RBD",
			inputVol: &corev1api.Volume{
				VolumeSource: corev1api.VolumeSource{
					RBD: &corev1api.RBDVolumeSource{},
				},
			},
			expected: RBD,
		},
		{
			name: "Test FlexVolume",
			inputVol: &corev1api.Volume{
				VolumeSource: corev1api.VolumeSource{
					FlexVolume: &corev1api.FlexVolumeSource{},
				},
			},
			expected: FlexVolume,
		},
		{
			name: "Test Cinder",
			inputVol: &corev1api.Volume{
				VolumeSource: corev1api.VolumeSource{
					Cinder: &corev1api.CinderVolumeSource{},
				},
			},
			expected: Cinder,
		},
		{
			name: "Test CephFS",
			inputVol: &corev1api.Volume{
				VolumeSource: corev1api.VolumeSource{
					CephFS: &corev1api.CephFSVolumeSource{},
				},
			},
			expected: CephFS,
		},
		{
			name: "Test Flocker",
			inputVol: &corev1api.Volume{
				VolumeSource: corev1api.VolumeSource{
					Flocker: &corev1api.FlockerVolumeSource{},
				},
			},
			expected: Flocker,
		},
		{
			name: "Test DownwardAPI",
			inputVol: &corev1api.Volume{
				VolumeSource: corev1api.VolumeSource{
					DownwardAPI: &corev1api.DownwardAPIVolumeSource{},
				},
			},
			expected: DownwardAPI,
		},
		{
			name: "Test FC",
			inputVol: &corev1api.Volume{
				VolumeSource: corev1api.VolumeSource{
					FC: &corev1api.FCVolumeSource{},
				},
			},
			expected: FC,
		},
		{
			name: "Test AzureFile",
			inputVol: &corev1api.Volume{
				VolumeSource: corev1api.VolumeSource{
					AzureFile: &corev1api.AzureFileVolumeSource{},
				},
			},
			expected: AzureFile,
		},
		{
			name: "Test ConfigMap",
			inputVol: &corev1api.Volume{
				VolumeSource: corev1api.VolumeSource{
					ConfigMap: &corev1api.ConfigMapVolumeSource{},
				},
			},
			expected: ConfigMap,
		},
		{
			name: "Test VsphereVolume",
			inputVol: &corev1api.Volume{
				VolumeSource: corev1api.VolumeSource{
					VsphereVolume: &corev1api.VsphereVirtualDiskVolumeSource{},
				},
			},
			expected: VsphereVolume,
		},
		{
			name: "Test Quobyte",
			inputVol: &corev1api.Volume{
				VolumeSource: corev1api.VolumeSource{
					Quobyte: &corev1api.QuobyteVolumeSource{},
				},
			},
			expected: Quobyte,
		},
		{
			name: "Test AzureDisk",
			inputVol: &corev1api.Volume{
				VolumeSource: corev1api.VolumeSource{
					AzureDisk: &corev1api.AzureDiskVolumeSource{},
				},
			},
			expected: AzureDisk,
		},
		{
			name: "Test PhotonPersistentDisk",
			inputVol: &corev1api.Volume{
				VolumeSource: corev1api.VolumeSource{
					PhotonPersistentDisk: &corev1api.PhotonPersistentDiskVolumeSource{},
				},
			},
			expected: PhotonPersistentDisk,
		},
		{
			name: "Test Projected",
			inputVol: &corev1api.Volume{
				VolumeSource: corev1api.VolumeSource{
					Projected: &corev1api.ProjectedVolumeSource{},
				},
			},
			expected: Projected,
		},
		{
			name: "Test PortworxVolume",
			inputVol: &corev1api.Volume{
				VolumeSource: corev1api.VolumeSource{
					PortworxVolume: &corev1api.PortworxVolumeSource{},
				},
			},
			expected: PortworxVolume,
		},
		{
			name: "Test ScaleIO",
			inputVol: &corev1api.Volume{
				VolumeSource: corev1api.VolumeSource{
					ScaleIO: &corev1api.ScaleIOVolumeSource{},
				},
			},
			expected: ScaleIO,
		},
		{
			name: "Test StorageOS",
			inputVol: &corev1api.Volume{
				VolumeSource: corev1api.VolumeSource{
					StorageOS: &corev1api.StorageOSVolumeSource{},
				},
			},
			expected: StorageOS,
		},
		{
			name: "Test CSI",
			inputVol: &corev1api.Volume{
				VolumeSource: corev1api.VolumeSource{
					CSI: &corev1api.CSIVolumeSource{},
				},
			},
			expected: CSI,
		},
		{
			name: "Test Ephemeral",
			inputVol: &corev1api.Volume{
				VolumeSource: corev1api.VolumeSource{
					Ephemeral: &corev1api.EphemeralVolumeSource{},
				},
			},
			expected: Ephemeral,
		},
		{
			name: "Test Image",
			inputVol: &corev1api.Volume{
				VolumeSource: corev1api.VolumeSource{
					Image: &corev1api.ImageVolumeSource{},
				},
			},
			expected: Image,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := getVolumeTypeFromVolume(tc.inputVol)
			if result != tc.expected {
				t.Errorf("Expected %s, but got %s", tc.expected, result)
			}
		})
	}
}
