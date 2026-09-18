/*
Copyright 2017, 2019 the Velero contributors.

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

package plugin

import (
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/vmware-tanzu/velero/pkg/constant"
	"github.com/vmware-tanzu/velero/pkg/datamover"

	dia "github.com/vmware-tanzu/velero/internal/delete/actions/csi"
	bia "github.com/vmware-tanzu/velero/pkg/backup/actions"
	csibia "github.com/vmware-tanzu/velero/pkg/backup/actions/csi"
	"github.com/vmware-tanzu/velero/pkg/client"
	velerodiscovery "github.com/vmware-tanzu/velero/pkg/discovery"
	iba "github.com/vmware-tanzu/velero/pkg/itemblock/actions"
	veleroplugin "github.com/vmware-tanzu/velero/pkg/plugin/framework"
	plugincommon "github.com/vmware-tanzu/velero/pkg/plugin/framework/common"
	ria "github.com/vmware-tanzu/velero/pkg/restore/actions"
	csiria "github.com/vmware-tanzu/velero/pkg/restore/actions/csi"
	"github.com/vmware-tanzu/velero/pkg/util/actionhelpers"
)

func NewCommand(f client.Factory) *cobra.Command {
	pluginServer := veleroplugin.NewServer()
	c := &cobra.Command{
		Use:    "run-plugins",
		Hidden: true,
		Short:  "INTERNAL COMMAND ONLY - not intended to be run directly by users",
		Run: func(c *cobra.Command, args []string) {
			config := pluginServer.GetConfig()
			f.SetClientQPS(config.ClientQPS)
			f.SetClientBurst(config.ClientBurst)
			pluginServer = pluginServer.
				RegisterBackupItemAction(
					"velero.io/pv",
					newPVBackupItemAction,
				).
				RegisterBackupItemAction(
					"velero.io/pod",
					newPodBackupItemAction,
				).
				RegisterBackupItemAction(
					"velero.io/service-account",
					newServiceAccountBackupItemAction(f),
				).
				RegisterRestoreItemAction(
					"velero.io/job",
					newJobRestoreItemAction,
				).
				RegisterRestoreItemAction(
					"velero.io/pod",
					newPodRestoreItemAction,
				).
				RegisterRestoreItemAction(
					"velero.io/pod-volume-restore",
					newPodVolumeRestoreItemAction(f),
				).
				RegisterRestoreItemAction(
					"velero.io/init-restore-hook",
					newInitRestoreHookPodAction,
				).
				RegisterRestoreItemAction(
					"velero.io/service",
					newServiceRestoreItemAction,
				).
				RegisterRestoreItemAction(
					"velero.io/service-account",
					newServiceAccountRestoreItemAction,
				).
				RegisterRestoreItemAction(
					"velero.io/add-pvc-from-pod",
					newAddPVCFromPodRestoreItemAction,
				).
				RegisterRestoreItemAction(
					"velero.io/change-storage-class",
					newChangeStorageClassRestoreItemAction(f),
				).
				RegisterRestoreItemAction(
					"velero.io/change-image-name",
					newChangeImageNameRestoreItemAction(f),
				).
				RegisterRestoreItemAction(
					"velero.io/role-bindings",
					newRoleBindingItemAction,
				).
				RegisterRestoreItemAction(
					"velero.io/cluster-role-bindings",
					newClusterRoleBindingItemAction,
				).
				RegisterRestoreItemAction(
					"velero.io/crd-preserve-fields",
					newCRDV1PreserveUnknownFieldsItemAction,
				).
				RegisterRestoreItemAction(
					"velero.io/pvc",
					newPVCRestoreItemAction(f),
				).
				RegisterRestoreItemAction(
					"velero.io/apiservice",
					newAPIServiceRestoreItemAction,
				).
				RegisterRestoreItemAction(
					"velero.io/admission-webhook-configuration",
					newAdmissionWebhookConfigurationAction,
				).
				RegisterRestoreItemAction(
					"velero.io/secret",
					newSecretRestoreItemAction(f),
				).
				RegisterRestoreItemAction(
					"velero.io/dataupload",
					newDataUploadRetrieveAction(f),
				).
				RegisterDeleteItemAction(
					"velero.io/dataupload-delete",
					newDateUploadDeleteItemAction(f),
				).
				RegisterDeleteItemAction(
					"velero.io/csi-volumesnapshotcontent-delete",
					newVolumeSnapshotContentDeleteItemAction(f),
				).
				RegisterBackupItemActionV2(
					"velero.io/csi-pvc-backupper",
					newPvcBackupItemAction(f),
				).
				RegisterBackupItemActionV2(
					"velero.io/csi-volumesnapshot-backupper",
					newVolumeSnapshotBackupItemAction(f),
				).
				RegisterBackupItemActionV2(
					"velero.io/csi-volumesnapshotcontent-backupper",
					newVolumeSnapshotContentBackupItemAction,
				).
				RegisterBackupItemActionV2(
					"velero.io/csi-volumesnapshotclass-backupper",
					newVolumeSnapshotClassBackupItemAction,
				).
				RegisterRestoreItemActionV2(
					constant.PluginCSIPVCRestoreRIA,
					newPvcRestoreItemAction(f),
				).
				RegisterRestoreItemActionV2(
					constant.PluginCsiVolumeSnapshotRestoreRIA,
					newVolumeSnapshotRestoreItemAction(f),
				).
				RegisterRestoreItemActionV2(
					"velero.io/csi-volumesnapshotcontent-restorer",
					newVolumeSnapshotContentRestoreItemAction(f),
				).
				RegisterRestoreItemActionV2(
					"velero.io/csi-volumesnapshotclass-restorer",
					newVolumeSnapshotClassRestoreItemAction,
				).
				RegisterItemBlockAction(
					"velero.io/pvc",
					newPVCItemBlockAction(f),
				).
				RegisterItemBlockAction(
					"velero.io/pod",
					newPodItemBlockAction,
				).
				RegisterItemBlockAction(
					"velero.io/service-account",
					newServiceAccountItemBlockAction(f),
				)

			pluginServer.Serve()
		},
		FParseErrWhitelist: cobra.FParseErrWhitelist{ // Velero.io word list : ignore
			UnknownFlags: true,
		},
	}
	pluginServer.BindFlags(c.Flags())
	return c
}

func newPVBackupItemAction(logger logrus.FieldLogger) (any, error) {
	return bia.NewPVCAction(logger), nil
}

func newPodBackupItemAction(logger logrus.FieldLogger) (any, error) {
	return bia.NewPodAction(logger), nil
}

func newServiceAccountBackupItemAction(f client.Factory) plugincommon.HandlerInitializer {
	return func(logger logrus.FieldLogger) (any, error) {
		// TODO(ncdc): consider a k8s style WantsKubernetesClientSet initialization approach
		clientset, err := f.KubeClient()
		if err != nil {
			return nil, err
		}

		discoveryClient, err := f.DiscoveryClient()
		if err != nil {
			return nil, err
		}

		discoveryHelper, err := velerodiscovery.NewHelper(discoveryClient, logger)
		if err != nil {
			return nil, err
		}

		action, err := bia.NewServiceAccountAction(
			logger,
			actionhelpers.NewClusterRoleBindingListerMap(clientset),
			discoveryHelper)
		if err != nil {
			return nil, err
		}

		return action, nil
	}
}

func newJobRestoreItemAction(logger logrus.FieldLogger) (any, error) {
	return ria.NewJobAction(logger), nil
}

func newPodRestoreItemAction(logger logrus.FieldLogger) (any, error) {
	return ria.NewPodAction(logger), nil
}

func newInitRestoreHookPodAction(logger logrus.FieldLogger) (any, error) {
	return ria.NewInitRestoreHookPodAction(logger), nil
}

func newPodVolumeRestoreItemAction(f client.Factory) plugincommon.HandlerInitializer {
	return func(logger logrus.FieldLogger) (any, error) {
		client, err := f.KubeClient()
		if err != nil {
			return nil, err
		}

		crClient, err := f.KubebuilderClient()
		if err != nil {
			return nil, err
		}

		return ria.NewPodVolumeRestoreAction(logger, client.CoreV1().ConfigMaps(f.Namespace()), crClient, f.Namespace())
	}
}

func newServiceRestoreItemAction(logger logrus.FieldLogger) (any, error) {
	return ria.NewServiceAction(logger), nil
}

func newServiceAccountRestoreItemAction(logger logrus.FieldLogger) (any, error) {
	return ria.NewServiceAccountAction(logger), nil
}

func newAddPVCFromPodRestoreItemAction(logger logrus.FieldLogger) (any, error) {
	return ria.NewAddPVCFromPodAction(logger), nil
}

func newCRDV1PreserveUnknownFieldsItemAction(logger logrus.FieldLogger) (any, error) {
	return ria.NewCRDV1PreserveUnknownFieldsAction(logger), nil
}

func newChangeStorageClassRestoreItemAction(f client.Factory) plugincommon.HandlerInitializer {
	return func(logger logrus.FieldLogger) (any, error) {
		client, err := f.KubeClient()
		if err != nil {
			return nil, err
		}

		return ria.NewChangeStorageClassAction(
			logger,
			client.CoreV1().ConfigMaps(f.Namespace()),
			client.StorageV1().StorageClasses(),
		), nil
	}
}

func newChangeImageNameRestoreItemAction(f client.Factory) plugincommon.HandlerInitializer {
	return func(logger logrus.FieldLogger) (any, error) {
		client, err := f.KubeClient()
		if err != nil {
			return nil, err
		}

		return ria.NewChangeImageNameAction(
			logger,
			client.CoreV1().ConfigMaps(f.Namespace()),
		), nil
	}
}
func newRoleBindingItemAction(logger logrus.FieldLogger) (any, error) {
	return ria.NewRoleBindingAction(logger), nil
}

func newClusterRoleBindingItemAction(logger logrus.FieldLogger) (any, error) {
	return ria.NewClusterRoleBindingAction(logger), nil
}

func newPVCRestoreItemAction(f client.Factory) plugincommon.HandlerInitializer {
	return func(logger logrus.FieldLogger) (any, error) {
		client, err := f.KubeClient()
		if err != nil {
			return nil, err
		}

		return ria.NewPVCAction(
			logger,
			client.CoreV1().ConfigMaps(f.Namespace()),
			client.CoreV1().Nodes(),
		), nil
	}
}

func newAPIServiceRestoreItemAction(logger logrus.FieldLogger) (any, error) {
	return ria.NewAPIServiceAction(logger), nil
}

func newAdmissionWebhookConfigurationAction(logger logrus.FieldLogger) (any, error) {
	return ria.NewAdmissionWebhookConfigurationAction(logger), nil
}

func newSecretRestoreItemAction(f client.Factory) plugincommon.HandlerInitializer {
	return func(logger logrus.FieldLogger) (any, error) {
		client, err := f.KubebuilderClient()
		if err != nil {
			return nil, err
		}
		return ria.NewSecretAction(logger, client), nil
	}
}

func newDataUploadRetrieveAction(f client.Factory) plugincommon.HandlerInitializer {
	return func(logger logrus.FieldLogger) (any, error) {
		client, err := f.KubebuilderClient()
		if err != nil {
			return nil, err
		}

		return ria.NewDataUploadRetrieveAction(logger, client), nil
	}
}

func newDateUploadDeleteItemAction(f client.Factory) plugincommon.HandlerInitializer {
	return func(logger logrus.FieldLogger) (any, error) {
		client, err := f.KubebuilderClient()
		if err != nil {
			return nil, err
		}
		return datamover.NewDataUploadDeleteAction(logger, client), nil
	}
}

// CSI plugin init functions.

// BackupItemAction plugins

func newPvcBackupItemAction(f client.Factory) plugincommon.HandlerInitializer {
	return csibia.NewPvcBackupItemAction(f)
}

func newVolumeSnapshotBackupItemAction(f client.Factory) plugincommon.HandlerInitializer {
	return csibia.NewVolumeSnapshotBackupItemAction(f)
}

func newVolumeSnapshotContentBackupItemAction(logger logrus.FieldLogger) (any, error) {
	return csibia.NewVolumeSnapshotContentBackupItemAction(logger)
}

func newVolumeSnapshotClassBackupItemAction(logger logrus.FieldLogger) (any, error) {
	return csibia.NewVolumeSnapshotClassBackupItemAction(logger)
}

// DeleteItemAction plugins

func newVolumeSnapshotContentDeleteItemAction(f client.Factory) plugincommon.HandlerInitializer {
	return dia.NewVolumeSnapshotContentDeleteItemAction(f)
}

// RestoreItemAction plugins

func newPvcRestoreItemAction(f client.Factory) plugincommon.HandlerInitializer {
	return csiria.NewPvcRestoreItemAction(f)
}

func newVolumeSnapshotRestoreItemAction(f client.Factory) plugincommon.HandlerInitializer {
	return csiria.NewVolumeSnapshotRestoreItemAction(f)
}

func newVolumeSnapshotContentRestoreItemAction(f client.Factory) plugincommon.HandlerInitializer {
	return csiria.NewVolumeSnapshotContentRestoreItemAction(f)
}

func newVolumeSnapshotClassRestoreItemAction(logger logrus.FieldLogger) (any, error) {
	return csiria.NewVolumeSnapshotClassRestoreItemAction(logger)
}

// ItemBlockAction plugins

func newPVCItemBlockAction(f client.Factory) plugincommon.HandlerInitializer {
	return iba.NewPVCAction(f)
}

func newPodItemBlockAction(logger logrus.FieldLogger) (any, error) {
	return iba.NewPodAction(logger), nil
}

func newServiceAccountItemBlockAction(f client.Factory) plugincommon.HandlerInitializer {
	return func(logger logrus.FieldLogger) (any, error) {
		// TODO(ncdc): consider a k8s style WantsKubernetesClientSet initialization approach
		clientset, err := f.KubeClient()
		if err != nil {
			return nil, err
		}

		discoveryClient, err := f.DiscoveryClient()
		if err != nil {
			return nil, err
		}

		discoveryHelper, err := velerodiscovery.NewHelper(discoveryClient, logger)
		if err != nil {
			return nil, err
		}

		action, err := iba.NewServiceAccountAction(
			logger,
			actionhelpers.NewClusterRoleBindingListerMap(clientset),
			discoveryHelper)
		if err != nil {
			return nil, err
		}

		return action, nil
	}
}
