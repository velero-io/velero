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

package velero

import (
	"bytes"
	"context"
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"golang.org/x/mod/semver"
	schedulingv1api "k8s.io/api/scheduling/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	ver "k8s.io/apimachinery/pkg/util/version"
	"k8s.io/apimachinery/pkg/util/wait"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/vmware-tanzu/velero/internal/volume"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	cliinstall "github.com/vmware-tanzu/velero/pkg/cmd/cli/install"
	"github.com/vmware-tanzu/velero/pkg/cmd/util/flag"
	veleroexec "github.com/vmware-tanzu/velero/pkg/util/exec"
	"github.com/vmware-tanzu/velero/test"
	. "github.com/vmware-tanzu/velero/test"
	common "github.com/vmware-tanzu/velero/test/util/common"
	. "github.com/vmware-tanzu/velero/test/util/k8s"
)

const BackupObjectsPrefix = "backups"
const RestoreObjectsPrefix = "restores"
const PluginsObjectsPrefix = "plugins"

var ImagesMatrix = map[string]map[string][]string{
	"v1.13": {
		"aws":                   {"velero/velero-plugin-for-aws:v1.9.2"},
		"azure":                 {"velero/velero-plugin-for-microsoft-azure:v1.9.2"},
		"vsphere":               {"vsphereveleroplugin/velero-plugin-for-vsphere:v1.5.2"},
		"gcp":                   {"velero/velero-plugin-for-gcp:v1.9.2"},
		"csi":                   {"velero/velero-plugin-for-csi:v0.7.1"},
		"datamover":             {"velero/velero-plugin-for-aws:v1.9.2"},
		"velero":                {"velero/velero:v1.13.2"},
		"velero-restore-helper": {"velero/velero-restore-helper:v1.13.2"},
	},
	"v1.14": {
		"aws":                   {"velero/velero-plugin-for-aws:v1.10.1"},
		"azure":                 {"velero/velero-plugin-for-microsoft-azure:v1.10.1"},
		"vsphere":               {"vsphereveleroplugin/velero-plugin-for-vsphere:v1.5.2"},
		"gcp":                   {"velero/velero-plugin-for-gcp:v1.10.1"},
		"datamover":             {"velero/velero-plugin-for-aws:v1.10.1"},
		"velero":                {"velero/velero:v1.14.1"},
		"velero-restore-helper": {"velero/velero-restore-helper:v1.14.1"},
	},
	"v1.15": {
		"aws":                   {"velero/velero-plugin-for-aws:v1.11.0"},
		"azure":                 {"velero/velero-plugin-for-microsoft-azure:v1.11.0"},
		"vsphere":               {"vsphereveleroplugin/velero-plugin-for-vsphere:v1.5.2"},
		"gcp":                   {"velero/velero-plugin-for-gcp:v1.11.0"},
		"datamover":             {"velero/velero-plugin-for-aws:v1.11.0"},
		"velero":                {"velero/velero:v1.15.2"},
		"velero-restore-helper": {"velero/velero-restore-helper:v1.15.2"},
	},
	"v1.16": {
		"aws":                   {"velero/velero-plugin-for-aws:v1.12.2"},
		"azure":                 {"velero/velero-plugin-for-microsoft-azure:v1.12.2"},
		"vsphere":               {"vsphereveleroplugin/velero-plugin-for-vsphere:v1.5.2"},
		"gcp":                   {"velero/velero-plugin-for-gcp:v1.12.2"},
		"datamover":             {"velero/velero-plugin-for-aws:v1.12.2"},
		"velero":                {"velero/velero:v1.16.2"},
		"velero-restore-helper": {"velero/velero:v1.16.2"},
	},
	"v1.17": {
		"aws":                   {"velero/velero-plugin-for-aws:v1.13.2"},
		"azure":                 {"velero/velero-plugin-for-microsoft-azure:v1.13.2"},
		"vsphere":               {"vsphereveleroplugin/velero-plugin-for-vsphere:v1.5.2"},
		"gcp":                   {"velero/velero-plugin-for-gcp:v1.13.2"},
		"datamover":             {"velero/velero-plugin-for-aws:v1.13.2"},
		"velero":                {"velero/velero:v1.17.2"},
		"velero-restore-helper": {"velero/velero:v1.17.2"},
	},
	"main": {
		"aws":                   {"velero/velero-plugin-for-aws:main"},
		"azure":                 {"velero/velero-plugin-for-microsoft-azure:main"},
		"vsphere":               {"vsphereveleroplugin/velero-plugin-for-vsphere:v1.5.2"},
		"gcp":                   {"velero/velero-plugin-for-gcp:main"},
		"datamover":             {"velero/velero-plugin-for-aws:main"},
		"velero":                {"velero/velero:main"},
		"velero-restore-helper": {"velero/velero-restore-helper:main"},
	},
}

// UpdateImagesMatrixByProxy is used to append the proxy to the image lists.
func UpdateImagesMatrixByProxy(imageRegistryProxy string) {
	if imageRegistryProxy != "" {
		for i := range ImagesMatrix {
			for j := range ImagesMatrix[i] {
				ImagesMatrix[i][j][0] = path.Join(imageRegistryProxy, ImagesMatrix[i][j][0])
			}
		}
	}
}

func SetImagesToDefaultValues(config VeleroConfig, version string) (VeleroConfig, error) {
	fmt.Printf("Get the images for version %s\n", version)

	ret := config

	ret.Plugins = ""

	versionWithoutPatch := getVersionWithoutPatch(version)

	// Read migration case needs images from the PluginsMatrix map.
	images, ok := ImagesMatrix[versionWithoutPatch]
	if !ok {
		fmt.Printf("Cannot read the images for version %s from the ImagesMatrix. Use the original values.\n", versionWithoutPatch)
		return config, nil
	}

	ret.VeleroImage = images[Velero][0]
	ret.RestoreHelperImage = images[VeleroRestoreHelper][0]

	if ret.CloudProvider == Azure {
		ret.Plugins = images[Azure][0]
	}
	if ret.CloudProvider == AWS {
		ret.Plugins = images[AWS][0]
	}
	// If HasVspherePlugin is false, only install the AWS plugin.
	// If do nothing here, the default behavior is
	// installing both AWS and vSphere plugins.
	if ret.CloudProvider == Vsphere &&
		!ret.HasVspherePlugin {
		ret.Plugins = images[AWS][0]
	}

	if ret.SnapshotMoveData && ret.CloudProvider == Azure {
		ret.Plugins = ret.Plugins + "," + images[AWS][0]
	}

	return ret, nil
}

func getVersionWithoutPatch(version string) string {
	versionWithoutPatch := ""

	mainRe := regexp.MustCompile(`^main$`)
	releaseRe := regexp.MustCompile(`^release-(\d+)\.(\d+)(-dev)?$`)

	switch {
	case mainRe.MatchString(version):
		versionWithoutPatch = "main"
	case releaseRe.MatchString(version):
		matches := releaseRe.FindStringSubmatch(version)
		versionWithoutPatch = fmt.Sprintf("v%s.%s", matches[1], matches[2])
	default:
		versionWithoutPatch = semver.MajorMinor(version)
	}

	fmt.Println("The version is ", versionWithoutPatch)

	return versionWithoutPatch
}

func getPluginsByVersion(version string, cloudProvider string, needDataMoverPlugin bool) ([]string, error) {
	var cloudMap map[string][]string
	arr := strings.Split(version, ".")
	if len(arr) >= 3 {
		cloudMap = ImagesMatrix[arr[0]+"."+arr[1]]
	}
	if len(cloudMap) == 0 {
		cloudMap = ImagesMatrix["main"]
		if len(cloudMap) == 0 {
			return nil, errors.Errorf("fail to get plugins by version: main")
		}
	}
	var plugins []string
	var ok bool

	if slices.Contains(LocalCloudProviders, cloudProvider) {
		plugins, ok = cloudMap[AWS]
		if !ok {
			return nil, errors.Errorf("fail to get plugins by version: %s and provider %s", version, cloudProvider)
		}
	} else {
		plugins, ok = cloudMap[cloudProvider]
		if !ok {
			return nil, errors.Errorf("fail to get plugins by version: %s and provider %s", version, cloudProvider)
		}
	}

	if needDataMoverPlugin {
		pluginsForDatamover, ok := cloudMap["datamover"]
		if !ok {
			return nil, errors.Errorf("fail to get plugins by for datamover")
		}
		for _, p := range pluginsForDatamover {
			if !slices.Contains(plugins, p) {
				plugins = append(plugins, p)
			}
		}
	}
	return plugins, nil
}

// getProviderVeleroInstallOptions returns Velero InstallOptions for the provider.
func getProviderVeleroInstallOptions(veleroCfg *VeleroConfig,
	plugins []string) (*cliinstall.Options, error) {
	if veleroCfg.CloudCredentialsFile == "" && veleroCfg.ServiceAccountNameToInstall == "" {
		return nil, errors.Errorf("No credentials were supplied to use for E2E tests")
	}

	io := cliinstall.NewInstallOptions()
	// always wait for velero and restic pods to be running.
	io.Wait = true
	io.ProviderName = veleroCfg.ObjectStoreProvider

	if veleroCfg.CloudCredentialsFile != "" {
		// Expand home directory if it is specified. https://stackoverflow.com/a/17617721
		if strings.HasPrefix(veleroCfg.CloudCredentialsFile, "~/") {
			usr, _ := user.Current()
			dir := usr.HomeDir
			// Use strings.HasPrefix so we don't match paths like
			// "/something/~/something/"
			veleroCfg.CloudCredentialsFile = filepath.Join(dir, veleroCfg.CloudCredentialsFile[2:])
		}
		realPath, err := filepath.Abs(veleroCfg.CloudCredentialsFile)
		if err != nil {
			return nil, err
		}
		io.SecretFile = realPath
	}

	if veleroCfg.ServiceAccountNameToInstall != "" {
		io.ServiceAccountName = veleroCfg.ServiceAccountNameToInstall
		io.NoSecret = true
	}

	io.BucketName = veleroCfg.BSLBucket
	io.Prefix = veleroCfg.BSLPrefix
	io.BackupStorageConfig = flag.NewMap()
	io.BackupStorageConfig.Set(veleroCfg.BSLConfig)

	io.VolumeSnapshotConfig = flag.NewMap()
	io.VolumeSnapshotConfig.Set(veleroCfg.VSLConfig)

	io.PodLabels = flag.NewMap()
	io.PodLabels.Set(veleroCfg.PodLabels)

	io.ServiceAccountAnnotations = flag.NewMap()
	io.ServiceAccountAnnotations.Set(veleroCfg.ServiceAccountAnnotations)

	io.Plugins = flag.NewStringArray(plugins...)
	io.Features = veleroCfg.Features
	io.DefaultVolumesToFsBackup = veleroCfg.DefaultVolumesToFsBackup
	io.UseVolumeSnapshots = veleroCfg.UseVolumeSnapshots

	io.UseNodeAgent = veleroCfg.UseNodeAgent
	io.Image = veleroCfg.VeleroImage
	io.Namespace = veleroCfg.VeleroNamespace
	io.UploaderType = veleroCfg.UploaderType
	GCFrequency, _ := time.ParseDuration(veleroCfg.GCFrequency)
	io.GarbageCollectionFrequency = GCFrequency
	io.PodVolumeOperationTimeout = veleroCfg.PodVolumeOperationTimeout
	io.NodeAgentPodCPULimit = veleroCfg.NodeAgentPodCPULimit
	io.NodeAgentPodCPURequest = veleroCfg.NodeAgentPodCPURequest
	io.NodeAgentPodMemLimit = veleroCfg.NodeAgentPodMemLimit
	io.NodeAgentPodMemRequest = veleroCfg.NodeAgentPodMemRequest
	io.VeleroPodCPULimit = veleroCfg.VeleroPodCPULimit
	io.VeleroPodCPURequest = veleroCfg.VeleroPodCPURequest
	io.VeleroPodMemLimit = veleroCfg.VeleroPodMemLimit
	io.VeleroPodMemRequest = veleroCfg.VeleroPodMemRequest
	io.DisableInformerCache = veleroCfg.DisableInformerCache
	io.ItemBlockWorkerCount = veleroCfg.ItemBlockWorkerCount
	io.ServerPriorityClassName = veleroCfg.ServerPriorityClassName
	io.NodeAgentPriorityClassName = veleroCfg.NodeAgentPriorityClassName
	io.RepoMaintenanceJobConfigMap = veleroCfg.RepoMaintenanceJobConfigMap
	io.BackupRepoConfigMap = veleroCfg.BackupRepoConfigMap
	io.NodeAgentConfigMap = veleroCfg.NodeAgentConfigMap

	return io, nil
}

// checkBackupPhase uses VeleroCLI to inspect the phase of a Velero backup.
func checkBackupPhase(ctx context.Context, veleroCLI string, veleroNamespace string, backupName string,
	expectedPhase velerov1api.BackupPhase) error {
	checkCMD := exec.CommandContext(ctx, veleroCLI, "--namespace", veleroNamespace, "backup", "get", "-o", "json",
		backupName)

	fmt.Printf("get backup cmd =%v\n", checkCMD)
	jsonBuf, err := common.CMDExecWithOutput(checkCMD)
	if err != nil {
		return err
	}
	backup := velerov1api.Backup{}
	err = json.Unmarshal(*jsonBuf, &backup)
	if err != nil {
		return err
	}
	if backup.Status.Phase != expectedPhase {
		if VeleroCfg.DebugVeleroPodRestart {
			pods, err := GetVeleroPodName(ctx)
			fmt.Println(err)
			CollectClusterEvents(backupName, pods)
		}
		return errors.Errorf("Unexpected backup phase got %s, expecting %s", backup.Status.Phase, expectedPhase)
	}

	return nil
}

// checkRestorePhase uses VeleroCLI to inspect the phase of a Velero restore.
func checkRestorePhase(ctx context.Context, veleroCLI string, veleroNamespace string, restoreName string,
	expectedPhase velerov1api.RestorePhase) error {
	checkCMD := exec.CommandContext(ctx, veleroCLI, "--namespace", veleroNamespace, "restore", "get", "-o", "json",
		restoreName)

	fmt.Printf("get restore cmd =%v\n", checkCMD)
	jsonBuf, err := common.CMDExecWithOutput(checkCMD)
	if err != nil {
		return err
	}
	restore := velerov1api.Restore{}
	err = json.Unmarshal(*jsonBuf, &restore)
	if err != nil {
		return err
	}
	if restore.Status.Phase != expectedPhase {
		if VeleroCfg.DebugVeleroPodRestart {
			pods, err := GetVeleroPodName(ctx)
			fmt.Println(err)
			CollectClusterEvents(restoreName, pods)
		}
		return errors.Errorf("Unexpected restore phase got %s, expecting %s", restore.Status.Phase, expectedPhase)
	}
	return nil
}

func checkSchedulePhase(ctx context.Context, veleroCLI, veleroNamespace, scheduleName string) error {
	return wait.PollImmediate(time.Second*5, time.Minute*2, func() (bool, error) {
		checkCMD := exec.CommandContext(ctx, veleroCLI, "--namespace", veleroNamespace, "schedule", "get", scheduleName, "-o", "json")
		jsonBuf, err := common.CMDExecWithOutput(checkCMD)
		if err != nil {
			return false, err
		}
		schedule := velerov1api.Schedule{}
		err = json.Unmarshal(*jsonBuf, &schedule)
		if err != nil {
			return false, err
		}

		if schedule.Status.Phase != velerov1api.SchedulePhaseEnabled {
			fmt.Printf("Unexpected schedule phase got %s, expecting %s, still waiting...", schedule.Status.Phase, velerov1api.SchedulePhaseEnabled)
			return false, nil
		}
		return true, nil
	})
}

func checkSchedulePause(ctx context.Context, veleroCLI, veleroNamespace, scheduleName string, pause bool) error {
	checkCMD := exec.CommandContext(ctx, veleroCLI, "--namespace", veleroNamespace, "schedule", "get", scheduleName, "-o", "json")
	jsonBuf, err := common.CMDExecWithOutput(checkCMD)
	if err != nil {
		return err
	}
	schedule := velerov1api.Schedule{}
	err = json.Unmarshal(*jsonBuf, &schedule)
	if err != nil {
		return err
	}

	if schedule.Spec.Paused != pause {
		fmt.Printf("Unexpected schedule phase got %s, expecting %s, still waiting...", schedule.Status.Phase, velerov1api.SchedulePhaseEnabled)
		return nil
	}
	return nil
}
func CheckScheduleWithResourceOrder(ctx context.Context, veleroCLI, veleroNamespace, scheduleName string, order map[string]string) error {
	checkCMD := exec.CommandContext(ctx, veleroCLI, "--namespace", veleroNamespace, "schedule", "get", scheduleName, "-o", "json")
	jsonBuf, err := common.CMDExecWithOutput(checkCMD)
	if err != nil {
		return err
	}
	schedule := velerov1api.Schedule{}
	err = json.Unmarshal(*jsonBuf, &schedule)
	if err != nil {
		return err
	}

	if schedule.Status.Phase != velerov1api.SchedulePhaseEnabled {
		return errors.Errorf("Unexpected restore phase got %s, expecting %s", schedule.Status.Phase, velerov1api.SchedulePhaseEnabled)
	}
	if reflect.DeepEqual(schedule.Spec.Template.OrderedResources, order) {
		return nil
	} else {
		return fmt.Errorf("resource order %v set in schedule command is not equal with order %v stored in schedule cr", order, schedule.Spec.Template.OrderedResources)
	}
}

func CheckBackupWithResourceOrder(ctx context.Context, veleroCLI, veleroNamespace, backupName string, orderResources map[string]string) error {
	checkCMD := exec.CommandContext(ctx, veleroCLI, "--namespace", veleroNamespace, "get", "backup", backupName, "-o", "json")
	jsonBuf, err := common.CMDExecWithOutput(checkCMD)
	if err != nil {
		return err
	}
	backup := velerov1api.Backup{}
	err = json.Unmarshal(*jsonBuf, &backup)
	if err != nil {
		return err
	}
	if backup.Status.Phase != velerov1api.BackupPhaseCompleted {
		return errors.Errorf("Unexpected restore phase got %s, expecting %s", backup.Status.Phase, velerov1api.BackupPhaseCompleted)
	}
	if reflect.DeepEqual(backup.Spec.OrderedResources, orderResources) {
		return nil
	} else {
		return fmt.Errorf("resource order %v set in backup command is not equal with order %v stored in backup cr", orderResources, backup.Spec.OrderedResources)
	}
}

// VeleroBackupNamespace uses the veleroCLI to backup a namespace.
func VeleroBackupNamespace(ctx context.Context, veleroCLI, veleroNamespace string, backupCfg BackupConfig) error {
	args := []string{
		"--namespace", veleroNamespace,
		"create", "backup", backupCfg.BackupName,
		"--wait",
	}
	if backupCfg.Namespace != "" {
		args = append(args, "--include-namespaces", backupCfg.Namespace)
	}
	if backupCfg.Selector != "" {
		args = append(args, "--selector", backupCfg.Selector)
	}

	if backupCfg.SnapshotMoveData {
		args = append(args, "--snapshot-move-data")
	}

	if backupCfg.UseVolumeSnapshots {
		if backupCfg.ProvideSnapshotsVolumeParam {
			args = append(args, "--snapshot-volumes")
		}
	}
	if backupCfg.DefaultVolumesToFsBackup {
		if backupCfg.UseResticIfFSBackup {
			args = append(args, "--default-volumes-to-restic")
		} else {
			args = append(args, "--default-volumes-to-fs-backup")
		}

		// To workaround https://github.com/vmware-tanzu/velero-plugin-for-vsphere/issues/347 for vsphere plugin v1.1.1
		// if the "--snapshot-volumes=false" isn't specified explicitly, the vSphere plugin will always take snapshots
		// for the volumes even though the "--default-volumes-to-fs-backup" is specified
		// TODO This can be removed if the logic of vSphere plugin bump up to 1.3
		if backupCfg.ProvideSnapshotsVolumeParam && !backupCfg.UseVolumeSnapshots {
			args = append(args, "--snapshot-volumes=false")
		} // if "--snapshot-volumes" is not provide, snapshot should be taken as default behavior.
	} else { // DefaultVolumesToFsBackup is false
		// Although DefaultVolumesToFsBackup is false, but probably DefaultVolumesToFsBackup
		// was set to true in installation CLI in snapshot volume test, so set DefaultVolumesToFsBackup
		// to false specifically to make sure volume snapshot was taken
		if backupCfg.UseVolumeSnapshots {
			if backupCfg.UseResticIfFSBackup {
				args = append(args, "--default-volumes-to-restic=false")
			} else {
				args = append(args, "--default-volumes-to-fs-backup=false")
			}
		}
		// Although DefaultVolumesToFsBackup is false, but probably DefaultVolumesToFsBackup
		// was set to true in installation CLI in FS volume backup test, so do nothing here, no DefaultVolumesToFsBackup
		// appear in backup CLI
	}
	if backupCfg.BackupLocation != "" {
		args = append(args, "--storage-location", backupCfg.BackupLocation)
	}
	if backupCfg.TTL != 0 {
		args = append(args, "--ttl", backupCfg.TTL.String())
	}

	if backupCfg.IncludeResources != "" {
		args = append(args, "--include-resources", backupCfg.IncludeResources)
	}

	if backupCfg.ExcludeResources != "" {
		args = append(args, "--exclude-resources", backupCfg.ExcludeResources)
	}

	if backupCfg.IncludeClusterResources {
		args = append(args, "--include-cluster-resources")
	}

	if backupCfg.OrderedResources != "" {
		args = append(args, "--ordered-resources", backupCfg.OrderedResources)
	}

	return VeleroBackupExec(ctx, veleroCLI, veleroNamespace, backupCfg.BackupName, args)
}

// VeleroBackupExcludeNamespaces uses the veleroCLI to backup a namespace.
func VeleroBackupExcludeNamespaces(ctx context.Context, veleroCLI string, veleroNamespace string, backupName string, excludeNamespaces []string) error {
	namespaces := strings.Join(excludeNamespaces, ",")
	args := []string{
		"--namespace", veleroNamespace, "create", "backup", backupName,
		"--exclude-namespaces", namespaces,
		"--default-volumes-to-fs-backup", "--wait",
	}
	return VeleroBackupExec(ctx, veleroCLI, veleroNamespace, backupName, args)
}

// VeleroBackupIncludeNamespaces uses the veleroCLI to backup a namespace.
func VeleroBackupIncludeNamespaces(ctx context.Context, veleroCLI string, veleroNamespace string, backupName string, includeNamespaces []string) error {
	namespaces := strings.Join(includeNamespaces, ",")
	args := []string{
		"--namespace", veleroNamespace, "create", "backup", backupName,
		"--include-namespaces", namespaces,
		"--default-volumes-to-fs-backup", "--wait",
	}
	return VeleroBackupExec(ctx, veleroCLI, veleroNamespace, backupName, args)
}

// VeleroRestore uses the VeleroCLI to restore from a Velero backup.
func VeleroRestore(ctx context.Context, veleroCLI, veleroNamespace, restoreName, backupName, includeResources string) error {
	args := []string{
		"--namespace", veleroNamespace, "create", "restore", restoreName,
		"--from-backup", backupName, "--wait",
	}
	if includeResources != "" {
		args = append(args, "--include-resources", includeResources)
	}
	return VeleroRestoreExec(ctx, veleroCLI, veleroNamespace, restoreName, args, velerov1api.RestorePhaseCompleted)
}

func VeleroRestoreExec(ctx context.Context, veleroCLI, veleroNamespace, restoreName string, args []string, phaseExpect velerov1api.RestorePhase) error {
	if err := VeleroCmdExec(ctx, veleroCLI, args); err != nil {
		return err
	}
	return checkRestorePhase(ctx, veleroCLI, veleroNamespace, restoreName, phaseExpect)
}

func VeleroBackupExec(ctx context.Context, veleroCLI string, veleroNamespace string, backupName string, args []string) error {
	if err := VeleroCmdExec(ctx, veleroCLI, args); err != nil {
		return err
	}
	return checkBackupPhase(ctx, veleroCLI, veleroNamespace, backupName, velerov1api.BackupPhaseCompleted)
}

func VeleroBackupDelete(ctx context.Context, veleroCLI string, veleroNamespace string, backupName string) error {
	args := []string{"--namespace", veleroNamespace, "delete", "backup", backupName, "--confirm"}
	return VeleroCmdExec(ctx, veleroCLI, args)
}

func VeleroRestoreDelete(ctx context.Context, veleroCLI string, veleroNamespace string, restoreName string) error {
	args := []string{"--namespace", veleroNamespace, "delete", "restore", restoreName, "--confirm"}
	return VeleroCmdExec(ctx, veleroCLI, args)
}

func VeleroScheduleDelete(ctx context.Context, veleroCLI string, veleroNamespace string, scheduleName string) error {
	args := []string{"--namespace", veleroNamespace, "delete", "schedule", scheduleName, "--confirm"}
	return VeleroCmdExec(ctx, veleroCLI, args)
}

func VeleroScheduleCreate(ctx context.Context, veleroCLI string, veleroNamespace string, scheduleName string, args []string) error {
	args = append([]string{
		"--namespace", veleroNamespace, "create", "schedule", scheduleName,
	}, args...)
	if err := VeleroCmdExec(ctx, veleroCLI, args); err != nil {
		return err
	}
	return checkSchedulePhase(ctx, veleroCLI, veleroNamespace, scheduleName)
}

func VeleroSchedulePause(ctx context.Context, veleroCLI string, veleroNamespace string, scheduleName string) error {
	args := []string{
		"--namespace", veleroNamespace, "schedule", "pause", scheduleName,
	}
	if err := VeleroCmdExec(ctx, veleroCLI, args); err != nil {
		return err
	}
	return checkSchedulePause(ctx, veleroCLI, veleroNamespace, scheduleName, true)
}

func VeleroScheduleUnpause(ctx context.Context, veleroCLI string, veleroNamespace string, scheduleName string) error {
	args := []string{
		"--namespace", veleroNamespace, "schedule", "unpause", scheduleName,
	}
	if err := VeleroCmdExec(ctx, veleroCLI, args); err != nil {
		return err
	}
	return checkSchedulePause(ctx, veleroCLI, veleroNamespace, scheduleName, false)
}

func VeleroCmdExec(ctx context.Context, veleroCLI string, args []string) error {
	cmd := exec.CommandContext(ctx, veleroCLI, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	fmt.Printf("velero cmd =%v\n", cmd)
	err := cmd.Run()
	if strings.Contains(fmt.Sprint(cmd.Stdout), "Failed") {
		return errors.New(fmt.Sprintf("velero cmd =%v return with failure\n", cmd))
	}
	return err
}

func VeleroBackupLogs(ctx context.Context, veleroCLI string, veleroNamespace string, backupName string) error {
	args := []string{
		"--namespace", veleroNamespace, "backup", "describe", backupName,
	}
	if err := VeleroCmdExec(ctx, veleroCLI, args); err != nil {
		return err
	}
	args = []string{
		"--namespace", veleroNamespace, "backup", "logs", backupName,
	}
	return VeleroCmdExec(ctx, veleroCLI, args)
}

func RunDebug(ctx context.Context, veleroCLI, veleroNamespace, backup, restore string) {
	output := fmt.Sprintf("debug-bundle-%d.tar.gz", time.Now().UnixNano())
	args := []string{"debug", "--namespace", veleroNamespace, "--output", output, "--verbose"}
	if len(backup) > 0 {
		args = append(args, "--backup", backup)
	}

	fmt.Printf("Generating the debug tarball at %s\n", output)
	if err := VeleroCmdExec(ctx, veleroCLI, args); err != nil {
		fmt.Println(errors.Wrapf(err, "failed to run the debug command"))
	}
}

func VeleroCreateBackupLocation(ctx context.Context,
	veleroCLI,
	veleroNamespace,
	name,
	objectStoreProvider,
	bucket,
	prefix,
	config,
	secretName,
	secretKey string,
) error {
	args := []string{
		"--namespace", veleroNamespace,
		"create", "backup-location", name,
		"--provider", objectStoreProvider,
		"--bucket", bucket,
	}

	if prefix != "" {
		args = append(args, "--prefix", prefix)
	}

	if config != "" {
		args = append(args, "--config", config)
	}

	if secretName != "" && secretKey != "" {
		args = append(args, "--credential", fmt.Sprintf("%s=%s", secretName, secretKey))
	}

	if err := VeleroCmdExec(ctx, veleroCLI, args); err != nil {
		return err
	}

	return CheckBSL(ctx, veleroNamespace, name)
}

func VeleroVersion(ctx context.Context, veleroCLI, veleroNamespace string) error {
	args := []string{
		"version", "--namespace", veleroNamespace,
	}
	if err := VeleroCmdExec(ctx, veleroCLI, args); err != nil {
		return err
	}
	return nil
}

// GetPlugins will collect all kinds plugins for VeleroInstall, such as provider
// plugins(cloud provider/object store provider, if object store provider is not
// provided, it should be set to value as cloud provider's), feature plugins (CSI/Datamover)
func GetPlugins(ctx context.Context, veleroCfg VeleroConfig, defaultBSL bool) ([]string, error) {
	veleroCLI := veleroCfg.VeleroCLI
	cloudProvider := veleroCfg.CloudProvider
	objectStoreProvider := veleroCfg.ObjectStoreProvider
	providerPlugins := veleroCfg.Plugins
	needDataMoverPlugin := false
	var plugins []string

	version, err := GetVeleroVersion(ctx, veleroCLI, true)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to get velero version")
	}

	// Read the plugins for the additional BSL here.
	if defaultBSL == false {
		fmt.Printf("Additional BSL provider = %s\n", veleroCfg.AdditionalBSLProvider)
		fmt.Printf("Additional BSL plugins = %v\n", veleroCfg.AddBSLPlugins)

		if veleroCfg.AddBSLPlugins == "" {
			if veleroCfg.AdditionalBSLProvider == "" {
				return []string{}, errors.New("AdditionalBSLProvider should be provided.")
			}

			plugins, err = getPluginsByVersion(version, veleroCfg.AdditionalBSLProvider, false)
			if err != nil {
				return nil, errors.WithMessagef(err, "Fail to get plugin by provider %s and version %s", veleroCfg.AdditionalBSLProvider, version)
			}
		} else {
			plugins = append(plugins, veleroCfg.AddBSLPlugins)
		}

		return plugins, nil
	}

	// Fetch the plugins for the provider before checking for the object store provider below.
	if len(providerPlugins) > 0 {
		plugins = strings.Split(providerPlugins, ",")
	} else {
		if cloudProvider == "" {
			return []string{}, errors.New("CloudProvider should be provided")
		}
		if objectStoreProvider == "" {
			objectStoreProvider = cloudProvider
		}

		if veleroCfg.VeleroVersion != "" {
			version = veleroCfg.VeleroVersion
		}

		if veleroCfg.SnapshotMoveData && veleroCfg.DataMoverPlugin == "" && !veleroCfg.IsUpgradeTest {
			needDataMoverPlugin = true
		}

		plugins, err = getPluginsByVersion(version, cloudProvider, needDataMoverPlugin)
		if err != nil {
			return nil, errors.WithMessagef(err, "Fail to get plugin by provider %s and version %s", objectStoreProvider, version)
		}
	}

	return plugins, nil
}

// AddPlugins installs them in the current Velero installation, skipping over those that are already installed.
func AddPlugins(plugins []string, veleroCfg VeleroConfig) error {
	for _, plugin := range plugins {
		stdoutBuf := new(bytes.Buffer)
		stderrBuf := new(bytes.Buffer)

		installPluginCmd := exec.CommandContext(context.TODO(), veleroCfg.VeleroCLI, "--namespace", veleroCfg.VeleroNamespace, "plugin", "add", plugin, "--confirm")
		fmt.Printf("installPluginCmd cmd =%v\n", installPluginCmd)
		installPluginCmd.Stdout = stdoutBuf
		installPluginCmd.Stderr = stderrBuf

		err := installPluginCmd.Run()

		fmt.Fprint(os.Stdout, stdoutBuf)
		fmt.Fprint(os.Stderr, stderrBuf)

		if err != nil {
			// If the plugin failed to install as it was already installed, ignore the error and continue
			// TODO: Check which plugins are already installed by inspecting `velero plugin get`
			if !strings.Contains(stderrBuf.String(), "Duplicate value") {
				return errors.WithMessagef(err, "error installing plugin %s", plugin)
			}
		}
	}

	return nil
}

// WaitForVSphereUploadCompletion waits for uploads started by the Velero Plugin for vSphere to complete
// TODO - remove after upload progress monitoring is implemented
func WaitForVSphereUploadCompletion(ctx context.Context, timeout time.Duration, namespace string, expectCount int) error {
	err := wait.PollImmediate(time.Second*5, timeout, func() (bool, error) {
		checkSnapshotCmd := exec.CommandContext(ctx, "kubectl",
			"get", "-n", namespace, "snapshots.backupdriver.cnsdp.vmware.com", "-o=jsonpath='{range .items[*]}{.spec.resourceHandle.name}{\"=\"}{.status.phase}{\"\\n\"}{end}'")
		fmt.Printf("checkSnapshotCmd cmd =%v\n", checkSnapshotCmd)
		stdout, stderr, err := veleroexec.RunCommand(checkSnapshotCmd)
		if err != nil {
			fmt.Print(stdout)
			fmt.Print(stderr)
			return false, errors.Wrap(err, "failed to wait for vSphere upload completion")
		}
		lines := strings.Split(stdout, "\n")
		complete := true
		actualCount := 0

		for _, curLine := range lines {
			fmt.Printf("%s %s\n", curLine, time.Now().Format("2006-01-02 15:04:05"))
			comps := strings.Split(curLine, "=")
			// SnapshotPhase represents the lifecycle phase of a Snapshot:
			// * New: No work yet, next phase is InProgress
			// * InProgress:     snapshot being taken
			// * Snapshotted:    local snapshot complete, next phase is Protecting or SnapshotFailed
			// * SnapshotFailed: end state, snapshot was not able to be taken
			// * Uploading:      snapshot is being moved to durable storage
			// * Uploaded:       end state, snapshot has been protected
			// * UploadFailed:   end state, unable to move to durable storage
			// * Canceling:      when the SanpshotCancel flag is set, if the Snapshot has not already moved into a terminal state, the
			//                   status will move to Canceling.  The snapshot ID will be removed from the status if the status has been filled in
			//                   and the snapshot ID will not longer be valid for a Clone operation
			// * Canceled:       the operation was canceled, the snapshot ID is not valid
			if len(comps) == 2 {
				phase := comps[1]
				actualCount++
				switch phase {
				case "Uploaded":
				case "New", "InProgress", "Snapshotted", "Uploading":
					complete = false
				default:
					return false, fmt.Errorf("unexpected snapshot phase: %s", phase)
				}
			}
		}

		if expectCount != actualCount {
			fmt.Printf("Snapshot expect count and actual count: %d-%d", expectCount, actualCount)
			complete = false
			if expectCount == 0 {
				return true, nil
			}
		}
		return complete, nil
	})

	return err
}

func GetVsphereSnapshotIDs(ctx context.Context, timeout time.Duration, namespace string, pvcNameList []string) ([]string, error) {
	checkSnapshotCmd := exec.CommandContext(ctx, "kubectl",
		"get", "-n", namespace, "snapshots.backupdriver.cnsdp.vmware.com", "-o=jsonpath='{range .items[*]}{.spec.resourceHandle.name}{\"=\"}{.status.snapshotID}{\"\\n\"}{end}'")
	fmt.Printf("checkSnapshotCmd cmd =%v\n", checkSnapshotCmd)
	stdout, stderr, err := veleroexec.RunCommand(checkSnapshotCmd)
	if err != nil {
		fmt.Print(stdout)
		fmt.Print(stderr)
		return nil, errors.Wrap(err, "Failed to get vSphere snapshot ID list from snapshots.backupdriver.cnsdp.vmware.com")
	}
	stdout = strings.Replace(stdout, "'", "", -1)
	lines := strings.Split(stdout, "\n")
	var result []string
	for _, curLine := range lines {
		fmt.Println("curLine:" + curLine)
		curLine = strings.Replace(curLine, "\n", "", -1)
		if len(curLine) == 0 {
			continue
		}
		var Exist bool
		for _, pvcName := range pvcNameList {
			if pvcName != "" && strings.Contains(curLine, pvcName) {
				Exist = true
				break
			}
		}
		if !Exist {
			continue
		}
		snapshotID := curLine[strings.LastIndex(curLine, ":")+1:]
		fmt.Println("snapshotID:" + snapshotID)
		snapshotIDDec, _ := b64.StdEncoding.DecodeString(snapshotID)
		fmt.Println("snapshotIDDec:" + string(snapshotIDDec))
		result = append(result, string(snapshotIDDec))
		fmt.Println(result)
	}
	fmt.Println(result)
	return result, nil
}

func GetVeleroVersion(ctx context.Context, veleroCLI string, clientOnly bool) (string, error) {
	args := []string{"version", "--timeout", "60s"}
	if clientOnly {
		args = append(args, "--client-only")
	}
	cmd := exec.CommandContext(ctx, veleroCLI, args...)
	fmt.Println("Get Version Command:" + cmd.String())
	stdout, stderr, err := veleroexec.RunCommand(cmd)
	if err != nil {
		return "", errors.Wrapf(err, "failed to get velero version, stdout=%s, stderr=%s", stdout, stderr)
	}

	output := strings.Replace(stdout, "\n", " ", -1)
	fmt.Println("Version:" + output)
	resultCount := 3
	regexpRule := `(?i)client\s*:\s*version\s*:\s*(\S+).+server\s*:\s*version\s*:\s*(\S+)`
	if clientOnly {
		resultCount = 2
		regexpRule = `(?i)client\s*:\s*version\s*:\s*(\S+)`
	}
	regCompiler := regexp.MustCompile(regexpRule)
	versionMatches := regCompiler.FindStringSubmatch(output)
	if len(versionMatches) != resultCount {
		return "", errors.New("failed to parse velero version from output")
	}
	if !clientOnly {
		if versionMatches[1] != versionMatches[2] {
			return "", errors.New("velero server and client version are not matched")
		}
	}
	return versionMatches[1], nil
}

func CheckVeleroVersion(ctx context.Context, veleroCLI string, expectedVer string) error {
	tag := expectedVer
	tagInstalled, err := GetVeleroVersion(ctx, veleroCLI, false)
	if err != nil {
		return errors.WithMessagef(err, "failed to get Velero version")
	}
	if strings.Trim(tag, " ") != strings.Trim(tagInstalled, " ") {
		return errors.New(fmt.Sprintf("velero version %s is not as expected %s", tagInstalled, tag))
	}
	fmt.Printf("Velero version %s is as expected %s\n", tagInstalled, tag)
	return nil
}

func InstallVeleroCLI(ctx context.Context, version string) (string, error) {
	var tempVeleroCliDir string
	name := "velero-" + version + "-" + runtime.GOOS + "-" + runtime.GOARCH
	postfix := ".tar.gz"
	tarball := name + postfix
	err := wait.PollUntilContextTimeout(ctx, time.Second*5, time.Minute*5, true, func(ctx context.Context) (bool, error) {
		tempFile, err := getVeleroCliTarball("https://github.com/vmware-tanzu/velero/releases/download/" + version + "/" + tarball)
		if err != nil {
			return false, errors.WithMessagef(err, "failed to get Velero CLI tarball")
		}
		tempVeleroCliDir, err = os.MkdirTemp("", "velero-test")
		if err != nil {
			return false, errors.WithMessagef(err, "failed to create temp dir for tarball extraction")
		}

		cmd := exec.CommandContext(ctx, "tar", "-xvf", tempFile.Name(), "-C", tempVeleroCliDir)
		defer os.Remove(tempFile.Name())

		if _, err := cmd.Output(); err != nil {
			return false, errors.WithMessagef(err, "failed to extract file from velero CLI tarball")
		}
		return true, nil
	})
	if err != nil {
		return "", errors.WithMessagef(err, "failed to install velero CLI")
	}
	return tempVeleroCliDir + "/" + name + "/velero", nil
}

func getVeleroCliTarball(cliTarballUrl string) (*os.File, error) {
	lastInd := strings.LastIndex(cliTarballUrl, "/")
	tarball := cliTarballUrl[lastInd+1:]

	cli := &http.Client{}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, cliTarballUrl, nil)
	resp, err := cli.Do(req)
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to access Velero CLI tarball")
	}
	defer resp.Body.Close()

	tarballBuf, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to read buffer for tarball %s.", tarball)
	}
	tmpfile, err := os.CreateTemp("", tarball)
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to create temp file for tarball %s locally.", tarball)
	}

	if _, err := tmpfile.Write(tarballBuf); err != nil {
		return nil, errors.WithMessagef(err, "failed to write tarball file %s locally.", tarball)
	}

	return tmpfile, nil
}

func DeleteBackup(ctx context.Context, backupName string, velerocfg *VeleroConfig) error {
	veleroCLI := velerocfg.VeleroCLI
	args := []string{"--namespace", velerocfg.VeleroNamespace, "backup", "delete", backupName, "--confirm"}

	cmd := exec.CommandContext(ctx, veleroCLI, args...)
	fmt.Println("Delete backup Command:" + cmd.String())
	stdout, stderr, err := veleroexec.RunCommand(cmd)
	if err != nil {
		return errors.Wrapf(err, "Fail to get delete backup, stdout=%s, stderr=%s", stdout, stderr)
	}

	output := strings.Replace(stdout, "\n", " ", -1)
	fmt.Println("Backup delete command output:" + output)

	args = []string{"--namespace", velerocfg.VeleroNamespace, "backup", "get", backupName}

	err = wait.PollUntilContextTimeout(context.Background(), 5*time.Second, time.Minute, true,
		func(context.Context) (bool, error) {
			cmd = exec.CommandContext(ctx, veleroCLI, args...)
			fmt.Printf("Try to get backup with cmd: %s \n", cmd.String())
			stdout, stderr, err = veleroexec.RunCommand(cmd)
			if err != nil {
				if strings.Contains(stderr, "not found") {
					fmt.Printf("|| EXPECTED || - Backup %s was deleted successfully according to message %s\n", backupName, stderr)
					return true, nil
				}
				return false, errors.Wrapf(err, "Fail to perform get backup, stdout=%s, stderr=%s", stdout, stderr)
			}

			var status string
			var drList []string
			drList, err = KubectlGetAllDeleteBackupRequest(context.Background(), backupName, velerocfg.VeleroNamespace)
			if len(drList) > 1 {
				return false, errors.New(fmt.Sprintf("Count of DeleteBackupRequest %d is not expected", len(drList)))
			}

			// Record DeleteBackupRequest status for debugging
			for _, dr := range drList {
				status, err = KubectlGetDeleteBackupRequestStatus(context.Background(), dr, velerocfg.VeleroNamespace)
				fmt.Printf("DeleteBackupRequest status: %s\n", status)
			}

			return true, nil
		})

	// Waiting for completion of handling deleteBackupRequest CR
	time.Sleep(1 * time.Minute)

	// Verify deleteBackupRequest are all gone because they are handled successfully
	var drList []string
	drList, err = KubectlGetAllDeleteBackupRequest(context.Background(), backupName, velerocfg.VeleroNamespace)
	if len(drList) > 1 {
		// Log deleteBackupRequest details for debug
		for _, dr := range drList {
			details, err := KubectlGetDeleteBackupRequestDetails(context.Background(), dr, velerocfg.VeleroNamespace)
			if err != nil {
				return errors.Wrapf(err, "fail to get DeleteBackupRequest %s details", dr)
			}
			fmt.Printf("Failed DeleteBackupRequest details: %s", details)
		}
		return errors.New(fmt.Sprintf("Count of DeleteBackupRequest %d is not expected", len(drList)))
	}

	return nil
}

func GetBackup(ctx context.Context, backupName string, veleroCfg *VeleroConfig) (string, string, error) {
	veleroCLI := veleroCfg.VeleroCLI
	args := []string{"--namespace", veleroCfg.VeleroNamespace, "backup", "get", backupName}
	cmd := exec.CommandContext(ctx, veleroCLI, args...)
	return veleroexec.RunCommand(cmd)
}

func IsBackupExist(ctx context.Context, backupName string, veleroCfg *VeleroConfig) (bool, error) {
	out, outerr, err := GetBackup(ctx, backupName, veleroCfg)
	if err != nil {
		if strings.Contains(outerr, "not found") {
			fmt.Printf("Backup CR %s was not found\n", backupName)
			return false, nil
		}
		return false, err
	}
	fmt.Printf("Backup <%s> exist locally according to output \n[%s]\n", backupName, out)
	return true, nil
}

func WaitBackupDeleted(ctx context.Context, backupName string, timeout time.Duration, veleroCfg *VeleroConfig) error {
	return wait.PollImmediate(10*time.Second, timeout, func() (bool, error) {
		if exist, err := IsBackupExist(ctx, backupName, veleroCfg); err != nil {
			return false, err
		} else {
			if exist {
				return false, nil
			} else {
				fmt.Printf("Backup %s does not exist\n", backupName)
				return true, nil
			}
		}
	})
}

func WaitForExpectedStateOfBackup(ctx context.Context, backupName string,
	timeout time.Duration, existing bool, veleroCfg *VeleroConfig) error {
	return wait.PollImmediate(10*time.Second, timeout, func() (bool, error) {
		if exist, err := IsBackupExist(ctx, backupName, veleroCfg); err != nil {
			return false, err
		} else {
			msg := "does not exist as expect"
			if exist {
				msg = "was found as expect"
			}
			if exist == existing {
				fmt.Println("Backup <" + backupName + "> " + msg)
				return true, nil
			} else {
				fmt.Println("Backup <" + backupName + "> " + msg)
				return false, nil
			}
		}
	})
}

func WaitForBackupToBeCreated(ctx context.Context, backupName string, timeout time.Duration, veleroCfg *VeleroConfig) error {
	return WaitForExpectedStateOfBackup(ctx, backupName, timeout, true, veleroCfg)
}

func WaitForBackupToBeDeleted(ctx context.Context, backupName string, timeout time.Duration, veleroCfg *VeleroConfig) error {
	return WaitForExpectedStateOfBackup(ctx, backupName, timeout, false, veleroCfg)
}

func WaitForBackupsToBeDeleted(ctx context.Context, backups []string, timeout time.Duration, veleroCfg *VeleroConfig) error {
	var err error
	for _, backupName := range backups {
		fmt.Println("Waiting for deletion of backup <" + backupName + ">")
		err = WaitForExpectedStateOfBackup(ctx, backupName, timeout, false, veleroCfg)
		if err != nil {
			return err
		}
	}
	fmt.Println("All backups were deleted.")
	return nil
}

func GetBackupsFromBsl(ctx context.Context, veleroCLI, bslName string) ([]string, error) {
	args1 := []string{"get", "backups"}
	if strings.TrimSpace(bslName) != "" {
		args1 = append(args1, "-l", "velero.io/storage-location="+bslName)
	}
	cmds := []*common.OsCommandLine{}

	cmd := &common.OsCommandLine{
		Cmd:  veleroCLI,
		Args: args1,
	}
	cmds = append(cmds, cmd)

	cmd = &common.OsCommandLine{
		Cmd:  "awk",
		Args: []string{"{print $1}"},
	}
	cmds = append(cmds, cmd)

	cmd = &common.OsCommandLine{
		Cmd:  "tail",
		Args: []string{"-n", "+2"},
	}
	cmds = append(cmds, cmd)

	return common.GetListByCmdPipes(ctx, cmds)
}

func GetLatestSuccessBackupsFromBSL(ctx context.Context, veleroCLI, bslName string) (string, error) {
	args1 := []string{"get", "backups"}
	if strings.TrimSpace(bslName) != "" {
		args1 = append(args1, "-l", "velero.io/storage-location="+bslName)
	}
	cmds := []*common.OsCommandLine{}

	cmd := &common.OsCommandLine{
		Cmd:  veleroCLI,
		Args: args1,
	}
	cmds = append(cmds, cmd)

	cmd = &common.OsCommandLine{
		Cmd:  "grep",
		Args: []string{"Completed"},
	}
	cmds = append(cmds, cmd)

	cmd = &common.OsCommandLine{
		Cmd:  "awk",
		Args: []string{"{print $1}"},
	}
	cmds = append(cmds, cmd)

	cmd = &common.OsCommandLine{
		Cmd:  "head",
		Args: []string{"-n", "1"},
	}
	cmds = append(cmds, cmd)

	backups, err := common.GetListByCmdPipes(ctx, cmds)
	if err != nil {
		return "", errors.WithStack(err)
	} else if len(backups) != 1 {
		return "", errors.Errorf("failed to get latest success backup from bsl %s with result %v", bslName, backups)
	}
	return backups[0], nil
}

func GetBackupsForSchedule(
	ctx context.Context,
	client kbclient.Client,
	scheduleName string,
	namespace string,
) ([]velerov1api.Backup, error) {
	backupList := new(velerov1api.BackupList)

	if err := client.List(
		ctx,
		backupList,
		&kbclient.ListOptions{
			Namespace: namespace,
			LabelSelector: labels.SelectorFromSet(map[string]string{
				velerov1api.ScheduleNameLabel: scheduleName,
			}),
		},
	); err != nil {
		return nil, fmt.Errorf("failed to list backup in %s namespace for schedule %s: %s",
			namespace, scheduleName, err.Error())
	}

	return backupList.Items, nil
}

func GetAllBackups(ctx context.Context, veleroCLI string) ([]string, error) {
	return GetBackupsFromBsl(ctx, veleroCLI, "")
}

func DeleteBslResource(ctx context.Context, veleroCLI string, bslName string) error {
	args := []string{"backup-location", "delete", bslName, "--confirm"}

	cmd := exec.CommandContext(ctx, veleroCLI, args...)
	fmt.Println("Delete backup location Command:" + cmd.String())
	stdout, stderr, err := veleroexec.RunCommand(cmd)
	if err != nil {
		return errors.Wrapf(err, "Fail to get delete location, stdout=%s, stderr=%s", stdout, stderr)
	}

	output := strings.Replace(stdout, "\n", " ", -1)
	fmt.Println("Backup location delete command output:" + output)

	fmt.Println(stdout)
	fmt.Println(stderr)
	return nil
}

func SnapshotCRsCountShouldBe(ctx context.Context, namespace, backupName string, expectedCount int) error {
	checkSnapshotCmd := exec.CommandContext(ctx, "kubectl",
		"get", "-n", namespace, "snapshots.backupdriver.cnsdp.vmware.com", "-o=jsonpath='{range .items[*]}{.metadata.labels.velero\\.io\\/backup-name}{\"\\n\"}{end}'")
	fmt.Printf("checkSnapshotCmd cmd =%v\n", checkSnapshotCmd)
	stdout, stderr, err := veleroexec.RunCommand(checkSnapshotCmd)
	if err != nil {
		fmt.Print(stdout)
		fmt.Print(stderr)
		return errors.Wrap(err, fmt.Sprintf("Failed getting snapshot CR of backup %s in namespace %d", backupName, expectedCount))
	}
	count := 0
	stdout = strings.Replace(stdout, "'", "", -1)
	arr := strings.Split(stdout, "\n")
	for _, bn := range arr {
		fmt.Println("Snapshot CR:" + bn)
		if strings.Contains(bn, backupName) {
			count++
		}
	}
	if count == expectedCount {
		return nil
	} else {
		return errors.New(fmt.Sprintf("SnapshotCR count %d of backup %s in namespace %s is not as expected %d", count, backupName, namespace, expectedCount))
	}
}

func BackupRepositoriesCountShouldBe(ctx context.Context, veleroNamespace, targetNamespace string, expectedCount int) error {
	resticArr, err := GetRepositories(ctx, veleroNamespace, targetNamespace)
	if err != nil {
		return errors.Wrapf(err, "Fail to get BackupRepositories")
	}
	if len(resticArr) == expectedCount {
		return nil
	} else {
		return errors.New(fmt.Sprintf("BackupRepositories count %d in namespace %s is not as expected %d", len(resticArr), targetNamespace, expectedCount))
	}
}

func GetRepositories(ctx context.Context, veleroNamespace, targetNamespace string) ([]string, error) {
	cmds := []*common.OsCommandLine{}
	cmd := &common.OsCommandLine{
		Cmd:  "kubectl",
		Args: []string{"get", "-n", veleroNamespace, "backuprepositories.velero.io"},
	}
	cmds = append(cmds, cmd)

	cmd = &common.OsCommandLine{
		Cmd:  "grep",
		Args: []string{targetNamespace},
	}
	cmds = append(cmds, cmd)

	cmd = &common.OsCommandLine{
		Cmd:  "awk",
		Args: []string{"{print $1}"},
	}
	cmds = append(cmds, cmd)

	return common.GetListByCmdPipes(ctx, cmds)
}

// BuildSnapshotCheckPointFromVolumeInfo pulls snapshot handles directly
func BuildSnapshotCheckPointFromVolumeInfo(
	veleroCfg VeleroConfig,
	backupVolumeInfo []*volume.BackupVolumeInfo,
	expectCount int,
	namespaceBackedUp string,
	backupName string,
	KibishiiPVCNameList []string) (SnapshotCheckPoint, error) {
	var snapshotCheckPoint SnapshotCheckPoint

	snapshotCheckPoint.ExpectCount = expectCount
	snapshotCheckPoint.NamespaceBackedUp = namespaceBackedUp
	snapshotCheckPoint.PodName = KibishiiPVCNameList

	if (veleroCfg.CloudProvider == Azure || veleroCfg.CloudProvider == AWS) && strings.EqualFold(veleroCfg.Features, FeatureCSI) {
		snapshotCheckPoint.EnableCSI = true

		var VscCount = 0
		for _, volumeInfo := range backupVolumeInfo {
			if *volumeInfo.CSISnapshotInfo.ReadyToUse == true {
				snapshotCheckPoint.SnapshotIDList = append(snapshotCheckPoint.SnapshotIDList, volumeInfo.CSISnapshotInfo.SnapshotHandle)
				VscCount++
			} else {
				return snapshotCheckPoint, errors.New("CSI snapshot is not ready to use")
			}
		}

		if VscCount != expectCount {
			return snapshotCheckPoint, errors.New(fmt.Sprintf("CSI snapshot count %d is not as expected %d", VscCount, expectCount))
		}
	}

	fmt.Printf("snapshotCheckPoint: %v \n", snapshotCheckPoint)
	return snapshotCheckPoint, nil
}

func GetBackupTTL(ctx context.Context, veleroNamespace, backupName string) (string, error) {
	checkSnapshotCmd := exec.CommandContext(ctx, "kubectl",
		"get", "backup", "-n", veleroNamespace, backupName, "-o=jsonpath='{.spec.ttl}'")
	fmt.Printf("checkSnapshotCmd cmd =%v\n", checkSnapshotCmd)
	stdout, stderr, err := veleroexec.RunCommand(checkSnapshotCmd)
	if err != nil {
		fmt.Print(stdout)
		fmt.Print(stderr)
		return "", errors.Wrap(err, fmt.Sprintf("failed to run command %s", checkSnapshotCmd))
	}
	return stdout, err
}

func GetVersionList(veleroCli, veleroVersion string) []VeleroCLI2Version {
	var veleroCLI2VersionList []VeleroCLI2Version
	veleroVersionList := strings.Split(veleroVersion, ",")
	veleroCliList := strings.Split(veleroCli, ",")

	for _, veleroVersion := range veleroVersionList {
		veleroCLI2VersionList = append(veleroCLI2VersionList,
			VeleroCLI2Version{VeleroVersion: veleroVersion, VeleroCLI: ""})
	}
	for i, veleroCli := range veleroCliList {
		if i == len(veleroVersionList)-1 {
			break
		}
		veleroCLI2VersionList[i].VeleroCLI = veleroCli
	}
	return veleroCLI2VersionList
}
func DeleteAllBackups(ctx context.Context, veleroCfg *VeleroConfig) error {
	client := veleroCfg.ClientToInstallVelero
	backupList := new(velerov1api.BackupList)
	if err := client.Kubebuilder.List(ctx, backupList, &kbclient.ListOptions{Namespace: veleroCfg.VeleroNamespace}); err != nil {
		return fmt.Errorf("failed to list backup object in %s namespace with err %v", veleroCfg.VeleroNamespace, err)
	}
	for _, backup := range backupList.Items {
		fmt.Printf("Backup %s is going to be deleted...\n", backup.Name)
		if err := VeleroBackupDelete(ctx, veleroCfg.VeleroCLI, veleroCfg.VeleroNamespace, backup.Name); err != nil {
			return err
		}
	}
	return nil
}

func DeleteBackups(ctx context.Context, backupNames []string, veleroCfg *VeleroConfig) error {
	client := veleroCfg.ClientToInstallVelero
	backupList := new(velerov1api.BackupList)
	if err := client.Kubebuilder.List(ctx, backupList, &kbclient.ListOptions{Namespace: veleroCfg.VeleroNamespace}); err != nil {
		return fmt.Errorf("failed to list backup object in %s namespace with err %v", veleroCfg.VeleroNamespace, err)
	}
	for _, backup := range backupList.Items {
		for _, bn := range backupNames {
			if backup.Name == bn {
				fmt.Printf("Backup %s is going to be deleted...\n", backup.Name)
				if err := VeleroBackupDelete(ctx, veleroCfg.VeleroCLI, veleroCfg.VeleroNamespace, backup.Name); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func GetSchedule(ctx context.Context, veleroNamespace, scheduleName string) (string, error) {
	checkSnapshotCmd := exec.CommandContext(ctx, "kubectl",
		"get", "schedule", "-n", veleroNamespace, scheduleName, "-o=jsonpath='{.metadata.creationTimestamp}'")
	fmt.Printf("Cmd =%v\n", checkSnapshotCmd)
	stdout, stderr, err := veleroexec.RunCommand(checkSnapshotCmd)
	if err != nil {
		fmt.Print(stdout)
		fmt.Print(stderr)
		return "", errors.Wrap(err, fmt.Sprintf("failed to run command %s", checkSnapshotCmd))
	}
	return stdout, err
}

func VeleroUpgrade(ctx context.Context, veleroCfg VeleroConfig) error {
	crd, err := ApplyCRDs(ctx, veleroCfg.VeleroCLI)
	if err != nil {
		return errors.Wrap(err, "Fail to Apply CRDs")
	}
	fmt.Println(crd)
	deploy, err := UpdateVeleroDeployment(ctx, veleroCfg)
	if err != nil {
		return errors.Wrap(err, "Fail to update Velero deployment")
	}
	fmt.Println(deploy)
	if veleroCfg.UseNodeAgent {
		dsjson, err := KubectlGetDsJson(veleroCfg.VeleroNamespace)
		if err != nil {
			return errors.Wrap(err, "Fail to update Velero deployment")
		}

		err = DeleteVeleroDs(ctx)
		if err != nil {
			return errors.Wrap(err, "Fail to delete Velero ds")
		}
		update, err := UpdateNodeAgent(ctx, veleroCfg, dsjson)
		fmt.Println(update)
		if err != nil {
			return errors.Wrap(err, "Fail to update node agent")
		}
	}
	return waitVeleroReady(ctx, veleroCfg.VeleroNamespace, veleroCfg.UseNodeAgent, veleroCfg.UseNodeAgentWindows)
}

func ApplyCRDs(ctx context.Context, veleroCLI string) ([]string, error) {
	cmds := []*common.OsCommandLine{}

	cmd := &common.OsCommandLine{
		Cmd:  veleroCLI,
		Args: []string{"install", "--crds-only", "--dry-run", "-o", "yaml"},
	}
	cmds = append(cmds, cmd)

	cmd = &common.OsCommandLine{
		Cmd:  "kubectl",
		Args: []string{"apply", "-f", "-"},
	}
	cmds = append(cmds, cmd)
	return common.GetListByCmdPipes(ctx, cmds)
}

func UpdateVeleroDeployment(ctx context.Context, veleroCfg VeleroConfig) ([]string, error) {
	cmds := []*common.OsCommandLine{}

	cmd := &common.OsCommandLine{
		Cmd:  "kubectl",
		Args: []string{"get", "deploy", "-n", veleroCfg.VeleroNamespace, "-ojson"},
	}
	cmds = append(cmds, cmd)

	cmd = &common.OsCommandLine{
		Cmd:  "sed",
		Args: []string{fmt.Sprintf("s#\\\"server\\\",#\\\"server\\\",\\\"--uploader-type=%s\\\",#g", veleroCfg.UploaderType)},
	}
	cmds = append(cmds, cmd)

	cmd = &common.OsCommandLine{
		Cmd:  "sed",
		Args: []string{"s#default-volumes-to-restic#default-volumes-to-fs-backup#g"},
	}
	cmds = append(cmds, cmd)

	cmd = &common.OsCommandLine{
		Cmd:  "sed",
		Args: []string{"s#default-restic-prune-frequency#default-repo-maintain-frequency#g"},
	}
	cmds = append(cmds, cmd)

	cmd = &common.OsCommandLine{
		Cmd:  "sed",
		Args: []string{"s#restic-timeout#fs-backup-timeout#g"},
	}
	cmds = append(cmds, cmd)

	cmd = &common.OsCommandLine{
		Cmd:  "kubectl",
		Args: []string{"apply", "-f", "-"},
	}
	cmds = append(cmds, cmd)

	return common.GetListByCmdPipes(ctx, cmds)
}

func UpdateNodeAgent(ctx context.Context, veleroCfg VeleroConfig, dsjson string) ([]string, error) {
	cmds := []*common.OsCommandLine{}

	cmd := &common.OsCommandLine{
		Cmd:  "echo",
		Args: []string{dsjson},
	}
	cmds = append(cmds, cmd)

	cmd = &common.OsCommandLine{
		Cmd:  "sed",
		Args: []string{"s#\\\"name\\\"\\: \\\"restic\\\"#\\\"name\\\"\\: \\\"node-agent\\\"#g"},
	}
	cmds = append(cmds, cmd)

	cmd = &common.OsCommandLine{
		Cmd:  "sed",
		Args: []string{"s#\\\"restic\\\",#\\\"node-agent\\\",#g"},
	}
	cmds = append(cmds, cmd)

	cmd = &common.OsCommandLine{
		Cmd:  "kubectl",
		Args: []string{"create", "-f", "-"},
	}
	cmds = append(cmds, cmd)

	return common.GetListByCmdPipes(ctx, cmds)
}

func ListVeleroPods(ctx context.Context, veleroNamespace string) ([]string, error) {
	cmds := []*common.OsCommandLine{}
	cmd := &common.OsCommandLine{
		Cmd:  "kubectl",
		Args: []string{"get", "pod", "-n", veleroNamespace, "--no-headers"},
	}
	cmds = append(cmds, cmd)

	cmd = &common.OsCommandLine{
		Cmd:  "awk",
		Args: []string{"{print $1}"},
	}
	cmds = append(cmds, cmd)

	return common.GetListByCmdPipes(ctx, cmds)
}

func BackupPVBNum(ctx context.Context, veleroNamespace, backupName string) (int, error) {
	outputList, err := common.GetResourceWithLabel(
		ctx,
		veleroNamespace,
		"PodVolumeBackup",
		map[string]string{
			velerov1api.BackupNameLabel: backupName,
		},
	)

	return len(outputList), err
}

func RestorePVRNum(ctx context.Context, veleroNamespace, restoreName string) (int, error) {
	outputList, err := common.GetResourceWithLabel(
		ctx,
		veleroNamespace,
		"PodVolumeRestore",
		map[string]string{
			velerov1api.RestoreNameLabel: restoreName,
		},
	)

	return len(outputList), err
}

func IsSupportUploaderType(version string) (bool, error) {
	verSupportUploaderType, err := ver.ParseSemantic("v1.10.0")
	if err != nil {
		return false, err
	}
	v, err := ver.ParseSemantic(version)
	if err != nil {
		return false, err
	}
	if v.AtLeast(verSupportUploaderType) {
		return true, nil
	} else {
		return false, nil
	}
}

func GetVeleroPodName(ctx context.Context) ([]string, error) {
	// Example:
	//    NAME                                  STATUS   VOLUME                                     CAPACITY   ACCESS MODES   STORAGECLASS             AGE
	//    kibishii-data-kibishii-deployment-0   Bound    pvc-94b9fdf2-c30f-4a7b-87bf-06eadca0d5b6   1Gi        RWO            kibishii-storage-class   115s
	cmds := []*common.OsCommandLine{}
	cmd := &common.OsCommandLine{
		Cmd:  "kubectl",
		Args: []string{"get", "pod", "-n", "velero"},
	}
	cmds = append(cmds, cmd)

	cmd = &common.OsCommandLine{
		Cmd:  "grep",
		Args: []string{"velero"},
	}
	cmds = append(cmds, cmd)

	cmd = &common.OsCommandLine{
		Cmd:  "awk",
		Args: []string{"{print $1}"},
	}
	cmds = append(cmds, cmd)

	return common.GetListByCmdPipes(ctx, cmds)
}

// InstallStorageClasses create the "e2e-storage-class" and "e2e-storage-class-2"
// StorageClasses for E2E tests.
//
// e2e-storage-class is the default StorageClass for E2E.
// e2e-storage-class-2 is used for the StorageClass mapping test case.
// Kibishii StorageClass is not covered here.
func InstallStorageClasses(provider string) error {
	ctx, ctxCancel := context.WithTimeout(context.Background(), time.Minute*5)
	defer ctxCancel()

	storageClassFilePath := fmt.Sprintf("../testdata/storage-class/%s.yaml", provider)

	if err := InstallStorageClass(ctx, storageClassFilePath); err != nil {
		return err
	}
	content, err := os.ReadFile(storageClassFilePath)
	if err != nil {
		return errors.Wrapf(err, "failed to get %s when install storage class", storageClassFilePath)
	}

	// Replace the name to e2e-storage-class-2
	newContent := strings.ReplaceAll(
		string(content),
		fmt.Sprintf("name: %s", StorageClassName),
		fmt.Sprintf("name: %s", StorageClassName2),
	)

	tmpFile, err := os.CreateTemp("", "sc-file")
	if err != nil {
		return errors.Wrapf(err, "failed to create temp file  when install storage class")
	}

	defer os.Remove(tmpFile.Name())
	if _, err := tmpFile.WriteString(newContent); err != nil {
		return errors.Wrapf(err, "failed to write content into temp file %s when install storage class", tmpFile.Name())
	}
	return InstallStorageClass(ctx, tmpFile.Name())
}

func GetPvName(ctx context.Context, client TestClient, pvcName, namespace string) (string, error) {
	pvcList, err := GetPvcByPVCName(context.Background(), namespace, pvcName)
	if err != nil {
		return "", err
	}

	if len(pvcList) != 1 {
		return "", errors.New(fmt.Sprintf("Only 1 PV of PVC %s pod %s should be found under namespace %s", pvcList[0], pvcName, namespace))
	}

	pvList, err := GetPvByPvc(context.Background(), namespace, pvcList[0])
	if err != nil {
		return "", err
	}
	if len(pvList) != 1 {
		return "", errors.New(fmt.Sprintf("Only 1 PV of PVC %s pod %s should be found under namespace %s", pvcList[0], pvcName, namespace))
	}

	return pvList[0], nil
}
func DeletePVs(ctx context.Context, client TestClient, pvList []string) error {
	for _, pv := range pvList {
		args := []string{"delete", "pv", pv, "--timeout=0s"}
		fmt.Println(args)
		err := exec.CommandContext(ctx, "kubectl", args...).Run()
		if err != nil {
			return errors.New(fmt.Sprintf("Deleted PV  %s ", pv))
		}
	}
	return nil
}

func CleanAllRetainedPV(ctx context.Context, client TestClient) {
	pvNameList, err := GetAllPVNames(ctx, client)
	if err != nil {
		fmt.Println("fail to list PV")
	}
	for _, pv := range pvNameList {
		args := []string{"patch", "pv", pv, "-p", "{\"spec\":{\"persistentVolumeReclaimPolicy\":\"Delete\"}}"}
		fmt.Println(args)
		cmd := exec.CommandContext(ctx, "kubectl", args...)
		stdout, errMsg, err := veleroexec.RunCommand(cmd)
		if err != nil {
			fmt.Printf("fail to patch PV %s reclaim policy to delete: stdout: %s, stderr: %s", pv, stdout, errMsg)
		}

		args = []string{"delete", "pv", pv, "--timeout=60s"}
		fmt.Println(args)
		cmd = exec.CommandContext(ctx, "kubectl", args...)
		stdout, errMsg, err = veleroexec.RunCommand(cmd)
		if err != nil {
			fmt.Printf("fail to delete PV %s reclaim policy to delete: stdout: %s, stderr: %s", pv, stdout, errMsg)
		}
	}
}

func KubectlGetBackupRepository(ctx context.Context, uploaderType, veleroNamespace string) ([]string, error) {
	args1 := []string{"get", "backuprepository", "-n", veleroNamespace}

	cmds := []*common.OsCommandLine{}

	cmd := &common.OsCommandLine{
		Cmd:  "kubectl",
		Args: args1,
	}
	cmds = append(cmds, cmd)

	cmd = &common.OsCommandLine{
		Cmd:  "grep",
		Args: []string{uploaderType},
	}
	cmds = append(cmds, cmd)

	cmd = &common.OsCommandLine{
		Cmd:  "awk",
		Args: []string{"{print $1}"},
	}
	cmds = append(cmds, cmd)

	return common.GetListByCmdPipes(ctx, cmds)
}

func KubectlGetPodVolumeBackup(ctx context.Context, backupName, veleroNamespace string) ([]string, error) {
	args1 := []string{"get", "podvolumebackup", "-n", veleroNamespace}

	cmds := []*common.OsCommandLine{}

	cmd := &common.OsCommandLine{
		Cmd:  "kubectl",
		Args: args1,
	}
	cmds = append(cmds, cmd)

	cmd = &common.OsCommandLine{
		Cmd:  "grep",
		Args: []string{backupName},
	}
	cmds = append(cmds, cmd)

	cmd = &common.OsCommandLine{
		Cmd:  "awk",
		Args: []string{"{print $1}"},
	}
	cmds = append(cmds, cmd)

	return common.GetListByCmdPipes(ctx, cmds)
}

func KubectlGetDeleteBackupRequestDetails(ctx context.Context, deleteBackupRequest, veleroNamespace string) (string, error) {
	cmd := exec.CommandContext(ctx, "kubectl", "get", "deletebackuprequests", "-n", veleroNamespace, deleteBackupRequest, "-o", "json")
	fmt.Printf("Get DeleteBackupRequest details cmd =%v\n", cmd)
	stdout, stderr, err := veleroexec.RunCommand(cmd)
	if err != nil {
		fmt.Print(stdout)
		fmt.Print(stderr)
		return "", errors.Wrap(err, fmt.Sprintf("failed to run command %s", cmd))
	}
	return stdout, err
}
func KubectlGetDeleteBackupRequestStatus(ctx context.Context, deleteBackupRequest, veleroNamespace string) (string, error) {
	args1 := []string{"get", "deletebackuprequests", "-n", veleroNamespace, deleteBackupRequest, "-o", "json"}

	cmds := []*common.OsCommandLine{}

	cmd := &common.OsCommandLine{
		Cmd:  "kubectl",
		Args: args1,
	}
	cmds = append(cmds, cmd)

	cmd = &common.OsCommandLine{
		Cmd:  "jq",
		Args: []string{"-r", ".status.phase"},
	}
	cmds = append(cmds, cmd)

	ret, err := common.GetListByCmdPipes(ctx, cmds)

	if len(ret) != 1 {
		return "", errors.New(fmt.Sprintf("fail to get status of deletebackuprequests %s", deleteBackupRequest))
	}
	return ret[0], err
}

func KubectlGetAllDeleteBackupRequest(ctx context.Context, backupName, veleroNamespace string) ([]string, error) {
	args1 := []string{"get", "deletebackuprequests", "-n", veleroNamespace}

	cmds := []*common.OsCommandLine{}

	cmd := &common.OsCommandLine{
		Cmd:  "kubectl",
		Args: args1,
	}
	cmds = append(cmds, cmd)

	cmd = &common.OsCommandLine{
		Cmd:  "grep",
		Args: []string{backupName},
	}
	cmds = append(cmds, cmd)

	cmd = &common.OsCommandLine{
		Cmd:  "awk",
		Args: []string{"{print $1}"},
	}
	cmds = append(cmds, cmd)

	return common.GetListByCmdPipes(ctx, cmds)
}

func CreatePriorityClasses(ctx context.Context, client kbclient.Client) error {
	dataMoverPriorityClass := builder.ForPriorityClass(test.PriorityClassNameForDataMover).
		Value(90000).PreemptionPolicy("Never").Result()
	if err := client.Create(ctx, dataMoverPriorityClass); err != nil {
		fmt.Printf("Fail to create PriorityClass %s: %s\n", test.PriorityClassNameForDataMover, err.Error())
		return fmt.Errorf("fail to create PriorityClass %s: %w", test.PriorityClassNameForDataMover, err)
	}

	repoMaintenancePriorityClass := builder.ForPriorityClass(test.PriorityClassNameForRepoMaintenance).
		Value(80000).PreemptionPolicy("Never").Result()
	if err := client.Create(ctx, repoMaintenancePriorityClass); err != nil {
		fmt.Printf("Fail to create PriorityClass %s: %s\n", test.PriorityClassNameForRepoMaintenance, err.Error())
		return fmt.Errorf("fail to create PriorityClass %s: %w", test.PriorityClassNameForRepoMaintenance, err)
	}

	return nil
}

func DeletePriorityClasses(ctx context.Context, client kbclient.Client) error {
	priorityClassDataMover := &schedulingv1api.PriorityClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: test.PriorityClassNameForDataMover,
		},
	}
	if err := client.Delete(ctx, priorityClassDataMover); err != nil {
		return err
	}

	priorityClassRepoMaintenance := &schedulingv1api.PriorityClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: test.PriorityClassNameForRepoMaintenance,
		},
	}
	if err := client.Delete(ctx, priorityClassRepoMaintenance); err != nil {
		return err
	}

	return nil
}
