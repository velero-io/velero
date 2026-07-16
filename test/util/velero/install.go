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
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"golang.org/x/mod/semver"
	appsv1api "k8s.io/api/apps/v1"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/wait"
	clientset "k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/cmd/cli/install"
	velerexec "github.com/vmware-tanzu/velero/pkg/util/exec"
	"github.com/vmware-tanzu/velero/test"
	common "github.com/vmware-tanzu/velero/test/util/common"
	eksutil "github.com/vmware-tanzu/velero/test/util/eks"
	"github.com/vmware-tanzu/velero/test/util/k8s"
)

// we provide more install options other than the standard install.InstallOptions in E2E test
type installOptions struct {
	*install.Options
	RegistryCredentialFile           string
	RestoreHelperImage               string
	VeleroServerDebugMode            bool
	WithoutDisableInformerCacheParam bool
	WorkerOS                         string
}

/*
VeleroInstall is used to install Velero for E2E test

params:

	ctx:              The context
	veleroCfg:        Velero E2E case configuration
	isStandbyCluster: Whether Velero is installed on standby cluster
	objects:          The objects are installed in Velero installed namespace, e.g. the ConfigMaps.
*/
func VeleroInstall(ctx context.Context, veleroCfg *test.VeleroConfig, isStandbyCluster bool, objects ...client.Object) error {
	fmt.Printf("Velero install %s\n", time.Now().Format("2006-01-02 15:04:05"))

	// veleroCfg struct including a set of BSL params and a set of additional BSL params,
	// additional BSL set is for additional BSL test only, so only default BSL set is effective
	// for VeleroInstall().
	//
	// veleroCfg struct including 2 sets of cluster setting, but VeleroInstall() only read
	// default cluster settings, so if E2E test needs install on the standby cluster, default cluster
	// setting should be reset to the value of standby cluster's.
	//
	// Some other setting might not needed by standby cluster installation like "snapshotMoveData", because in
	// standby cluster only restore if performed, so CSI plugin is not needed, but it is installed due to
	// the only one veleroCfg setting is provided as current design, since it will not introduce any issues as
	// we can predict, so keep it intact for now.
	if isStandbyCluster {
		veleroCfg.CloudProvider = veleroCfg.StandbyClusterCloudProvider
	}

	if slices.Contains(test.PublicCloudProviders, veleroCfg.CloudProvider) {
		fmt.Println("For public cloud platforms, object store plugin provider will be set as cloud provider")
		// If ObjectStoreProvider is not provided, then using the value same as CloudProvider
		if veleroCfg.ObjectStoreProvider == "" {
			veleroCfg.ObjectStoreProvider = veleroCfg.CloudProvider
		}
	} else {
		if veleroCfg.ObjectStoreProvider == "" {
			return errors.New("No object store provider specified - must be specified when using kind as the cloud provider") // Must have an object store provider
		}
	}

	pluginsTmp, err := GetPlugins(ctx, *veleroCfg, true)
	if err != nil {
		return errors.WithMessage(err, "Failed to get provider plugins")
	}
	err = k8s.EnsureClusterExists(ctx)
	if err != nil {
		return errors.WithMessage(err, "Failed to ensure Kubernetes cluster exists")
	}

	// TODO - handle this better
	if veleroCfg.CloudProvider == test.Vsphere {
		// We overrider the ObjectStoreProvider here for vSphere because we want to use the aws plugin for the
		// backup, but needed to pick up the provider plugins earlier.  vSphere plugin no longer needs a Volume
		// Snapshot location specified
		if veleroCfg.ObjectStoreProvider == "" {
			veleroCfg.ObjectStoreProvider = test.AWS
		}

		if err := cleanVSpherePluginConfig(
			veleroCfg.ClientToInstallVelero.ClientGo,
			veleroCfg.VeleroNamespace,
			test.VeleroVSphereSecretName,
			test.VeleroVSphereConfigMapName,
		); err != nil {
			return errors.WithMessagef(err, "Failed to clear up vsphere plugin config %s namespace", veleroCfg.VeleroNamespace)
		}
		if err := generateVSpherePlugin(veleroCfg); err != nil {
			return errors.WithMessagef(err, "Failed to config vsphere plugin")
		}
	}

	veleroInstallOptions, err := getProviderVeleroInstallOptions(veleroCfg, pluginsTmp)
	if err != nil {
		return errors.WithMessagef(err, "Failed to get Velero InstallOptions for plugin provider %s", veleroCfg.ObjectStoreProvider)
	}

	_, err = k8s.GetNamespace(ctx, *veleroCfg.ClientToInstallVelero, veleroCfg.VeleroNamespace)
	// We should uninstall Velero for a new installation
	if !apierrors.IsNotFound(err) {
		if err := VeleroUninstall(context.Background(), *veleroCfg); err != nil {
			return errors.Wrapf(err, "Failed to uninstall velero %s", veleroCfg.VeleroNamespace)
		}
	}

	// If velero namespace does not exist, we should create it for service account creation
	if err := k8s.KubectlCreateNamespace(ctx, veleroCfg.VeleroNamespace); err != nil {
		return errors.Wrapf(err, "Failed to create namespace %s to install Velero", veleroCfg.VeleroNamespace)
	}

	// Create Backup Repository ConfigurationMap.
	if _, err := k8s.CreateConfigMap(
		veleroCfg.ClientToInstallVelero.ClientGo,
		veleroCfg.VeleroNamespace,
		test.BackupRepositoryConfigName,
		nil,
		map[string]string{
			test.UploaderTypeKopia: "{\"cacheLimitMB\": 2048, \"fullMaintenanceInterval\": \"normalGC\"}",
		},
	); err != nil {
		return errors.WithMessagef(err,
			"Failed to create %s ConfigMap in %s namespace",
			test.BackupRepositoryConfigName,
			veleroCfg.VeleroNamespace,
		)
	}
	veleroCfg.BackupRepoConfigMap = test.BackupRepositoryConfigName

	// Install the passed-in objects in Velero installed namespace
	for _, obj := range objects {
		if err := veleroCfg.ClientToInstallVelero.Kubebuilder.Create(ctx, obj); err != nil {
			fmt.Printf("fail to create object %s in namespace %s: %s\n", obj.GetName(), obj.GetNamespace(), err.Error())
			return fmt.Errorf("fail to create object %s in namespace %s: %w", obj.GetName(), obj.GetNamespace(), err)
		}
	}

	// For AWS IRSA credential test, AWS IAM service account is required, so if ServiceAccountName and EKSPolicyARN
	// are both provided, we assume IRSA test is running, otherwise skip this IAM service account creation part.
	if veleroCfg.CloudProvider == test.AWS && veleroInstallOptions.ServiceAccountName != "" {
		if veleroCfg.EKSPolicyARN == "" {
			return errors.New("Please provide EKSPolicyARN for IRSA test.")
		}
		if err := k8s.KubectlDeleteClusterRoleBinding(ctx, "velero-cluster-role"); err != nil {
			return errors.Wrapf(err, "Failed to delete clusterrolebinding %s to %s namespace", "velero-cluster-role", veleroCfg.VeleroNamespace)
		}
		if err := k8s.KubectlCreateClusterRoleBinding(ctx, "velero-cluster-role", "cluster-admin", veleroCfg.VeleroNamespace, veleroInstallOptions.ServiceAccountName); err != nil {
			return errors.Wrapf(err, "Failed to create clusterrolebinding %s to %s namespace", "velero-cluster-role", veleroCfg.VeleroNamespace)
		}

		if err := eksutil.KubectlDeleteIAMServiceAcount(ctx, veleroInstallOptions.ServiceAccountName, veleroCfg.VeleroNamespace, veleroCfg.ClusterToInstallVelero); err != nil {
			return errors.Wrapf(err, "Failed to delete service account %s to %s namespace", veleroInstallOptions.ServiceAccountName, veleroCfg.VeleroNamespace)
		}
		if err := eksutil.EksctlCreateIAMServiceAcount(ctx, veleroInstallOptions.ServiceAccountName, veleroCfg.VeleroNamespace, veleroCfg.EKSPolicyARN, veleroCfg.ClusterToInstallVelero); err != nil {
			return errors.Wrapf(err, "Failed to create service account %s to %s namespace", veleroInstallOptions.ServiceAccountName, veleroCfg.VeleroNamespace)
		}
	}

	if err := installVeleroServer(
		ctx,
		veleroCfg.VeleroCLI,
		veleroCfg.VeleroVersion,
		&installOptions{
			Options:                          veleroInstallOptions,
			RegistryCredentialFile:           veleroCfg.RegistryCredentialFile,
			RestoreHelperImage:               veleroCfg.RestoreHelperImage,
			VeleroServerDebugMode:            veleroCfg.VeleroServerDebugMode,
			WithoutDisableInformerCacheParam: veleroCfg.WithoutDisableInformerCacheParam,
			WorkerOS:                         veleroCfg.WorkerOS,
		},
	); err != nil {
		RunDebug(ctx, veleroCfg.VeleroCLI, veleroCfg.VeleroNamespace, "", "")
		return errors.WithMessagef(err, "Failed to install Velero in the cluster")
	}

	if err := CheckBSL(ctx, veleroCfg.VeleroNamespace, common.DefaultBSLName); err != nil {
		RunDebug(ctx, veleroCfg.VeleroCLI, veleroCfg.VeleroNamespace, "", "")
		return fmt.Errorf("fail to wait BSL default till ready: %w", err)
	}

	fmt.Printf("Finish velero install %s\n", time.Now().Format("2006-01-02 15:04:05"))
	return nil
}

// generateVSpherePlugin refers to
// https://github.com/vmware-tanzu/velero-plugin-for-vsphere/blob/v1.3.0/docs/vanilla.md
func generateVSpherePlugin(veleroCfg *test.VeleroConfig) error {
	cli := veleroCfg.ClientToInstallVelero

	if err := k8s.CreateNamespace(
		context.Background(),
		*cli,
		veleroCfg.VeleroNamespace,
	); err != nil {
		return errors.WithMessagef(
			err,
			"Failed to create Velero %s namespace",
			veleroCfg.VeleroNamespace,
		)
	}

	clusterFlavor := "VANILLA"

	if err := createVCCredentialSecret(cli.ClientGo, veleroCfg.VeleroNamespace); err != nil {
		// For TKGs/uTKG the VC secret is not supposed to exist.
		if apierrors.IsNotFound(err) {
			clusterFlavor = "GUEST"
		} else {
			return errors.WithMessagef(
				err,
				"Failed to create virtual center credential secret in %s namespace",
				veleroCfg.VeleroNamespace,
			)
		}
	}

	_, err := k8s.CreateConfigMap(
		cli.ClientGo,
		veleroCfg.VeleroNamespace,
		test.VeleroVSphereConfigMapName,
		nil,
		map[string]string{
			"cluster_flavor":           clusterFlavor,
			"vsphere_secret_name":      test.VeleroVSphereSecretName,
			"vsphere_secret_namespace": veleroCfg.VeleroNamespace,
		},
	)
	if err != nil {
		return errors.WithMessagef(
			err,
			"Failed to create velero-vsphere-plugin-config ConfigMap in %s namespace",
			veleroCfg.VeleroNamespace,
		)
	}

	if err := k8s.WaitForConfigMapComplete(
		cli.ClientGo,
		veleroCfg.VeleroNamespace,
		test.VeleroVSphereConfigMapName,
	); err != nil {
		return errors.Wrap(
			err,
			fmt.Sprintf("Failed to ensure ConfigMap %s completion in namespace: %s",
				test.VeleroVSphereConfigMapName,
				veleroCfg.VeleroNamespace,
			),
		)
	}

	return nil
}

func cleanVSpherePluginConfig(c clientset.Interface, ns, secretName, configMapName string) error {
	//clear secret
	_, err := k8s.GetSecret(c, ns, secretName)
	if err == nil { //exist
		if err := k8s.WaitForSecretDelete(c, ns, secretName); err != nil {
			return errors.WithMessagef(err, "Failed to clear up vsphere plugin secret in %s namespace", ns)
		}
	} else if !apierrors.IsNotFound(err) {
		return errors.WithMessagef(err, "Failed to retrieve vsphere plugin secret in %s namespace", ns)
	}

	//clear configmap
	_, err = k8s.GetConfigMap(c, ns, configMapName)
	if err == nil {
		if err := k8s.WaitForConfigmapDelete(c, ns, configMapName); err != nil {
			return errors.WithMessagef(err, "Failed to clear up vsphere plugin configmap in %s namespace", ns)
		}
	} else if !apierrors.IsNotFound(err) {
		return errors.WithMessagef(err, "Failed to retrieve vsphere plugin configmap in %s namespace", ns)
	}
	return nil
}

// ValidateVeleroVersion checks if the given version is valid
// version can be in the format of 'main', 'release-x.y(-dev)', or 'vX.Y(.Z)'
func ValidateVeleroVersion(version string) error {
	mainRe := regexp.MustCompile(`^main$`)
	releaseRe := regexp.MustCompile(`^release-(\d+)\.(\d+)(-dev)?$`)
	tagRe := regexp.MustCompile(`^v(\d+)\.(\d+)(\.\d+)?$`)

	if mainRe.MatchString(version) || releaseRe.MatchString(version) || tagRe.MatchString(version) {
		return nil
	}

	fmt.Println("Invalid Velero version:", version)
	return fmt.Errorf("invalid Velero version: %s, Velero version must be 'main', 'release-x.y(-dev)', or 'vX.Y.Z'", version)
}

// VersionNoOlderThan checks if the given version is no older than the targetVersion
// version can be in the format of 'main', 'release-x.y(-dev)', or 'vX.Y(.Z)'
// targetVersion must be in the format of 'main', or 'vX.Y.(Z)'
// return true if version is no older than targetVersion
func VersionNoOlderThan(version string, targetVersion string) (bool, error) {
	mainRe := regexp.MustCompile(`^main$`)
	releaseRe := regexp.MustCompile(`^release-(\d+)\.(\d+)(-dev)?$`)
	tagRe := regexp.MustCompile(`^v(\d+)\.(\d+)(\.\d+)?$`)

	if err := ValidateVeleroVersion(version); err != nil {
		return false, err
	}
	if !tagRe.MatchString(targetVersion) && !mainRe.MatchString(targetVersion) {
		fmt.Printf("targetVersion %s is invalid. it must be in the format of 'main', or 'vX.Y.(Z)'.\n", targetVersion)
		return false, fmt.Errorf("targetVersion is invalid. it must be in the format of 'main', or 'vX.Y.(Z)'.")
	}

	fmt.Printf("version: %s, targetVersion: %s\n", version, targetVersion)

	switch {
	case mainRe.MatchString(version):
		// main is always the latest
		return true, nil

	case releaseRe.MatchString(version):
		// release-x.y(-dev) is treated as vX.Y.0
		matches := releaseRe.FindStringSubmatch(version)
		major := matches[1]
		minor := matches[2]

		switch {
		case mainRe.MatchString(targetVersion):
			return false, nil

		default:
			matches := tagRe.FindStringSubmatch(targetVersion)
			targetMajor := matches[1]
			targetMinor := matches[2]
			if major >= targetMajor && minor >= targetMinor {
				return true, nil
			} else {
				return false, nil
			}
		}

	case tagRe.MatchString(version):
		switch {
		case mainRe.MatchString(targetVersion):
			return false, nil

		default:
			if semver.Compare(version, targetVersion) >= 0 {
				return true, nil
			} else {
				return false, nil
			}
		}
	}

	fmt.Printf("Unknown version %s in VersionNoOlderThan\n", version)
	return false, fmt.Errorf("unknown version in VersionNoOlderThan: %s", version)
}

func installVeleroServer(
	ctx context.Context,
	cli string,
	version string,
	options *installOptions,
) error {
	args := []string{"install"}
	namespace := "velero"
	if len(options.Namespace) > 0 {
		args = append(args, "--namespace", options.Namespace)
		namespace = options.Namespace
	}
	if len(options.Image) > 0 {
		args = append(args, "--image", options.Image)
	}
	if options.UseNodeAgent {
		args = append(args, "--use-node-agent")
	}

	// TODO: need to consider align options.UseNodeAgentWindows usage
	// with options.UseNodeAgent
	// Only version after v1.16.0 support windows node agent.
	if options.WorkerOS == common.WorkerOSWindows {
		result, err := VersionNoOlderThan(version, "v1.16")
		if err == nil && result {
			fmt.Println("Install node-agent-windows. The Velero version is ", version)
			args = append(args, "--use-node-agent-windows")
		}
	}

	if options.DefaultVolumesToFsBackup {
		args = append(args, "--default-volumes-to-fs-backup")
	}
	if options.UseVolumeSnapshots {
		args = append(args, "--use-volume-snapshots")
	}
	if len(options.ProviderName) > 0 {
		args = append(args, "--provider", options.ProviderName)
	}
	if len(options.BackupStorageConfig.Data()) > 0 {
		args = append(args, "--backup-location-config", options.BackupStorageConfig.String())
	}
	if len(options.BucketName) > 0 {
		args = append(args, "--bucket", options.BucketName)
	}
	if len(options.Prefix) > 0 {
		args = append(args, "--prefix", options.Prefix)
	}
	//Treat ServiceAccountName priority higher than SecretFile
	if len(options.ServiceAccountName) > 0 {
		args = append(args, "--service-account-name", options.ServiceAccountName)
	} else {
		if len(options.SecretFile) > 0 {
			args = append(args, "--secret-file", options.SecretFile)
		}
	}
	if options.NoSecret {
		args = append(args, "--no-secret")
	}
	if len(options.VolumeSnapshotConfig.Data()) > 0 {
		args = append(args, "--snapshot-location-config", options.VolumeSnapshotConfig.String())
	}
	if len(options.Plugins) > 0 {
		args = append(args, "--plugins", options.Plugins.String())
	}

	if !options.WithoutDisableInformerCacheParam {
		if options.DisableInformerCache {
			args = append(args, "--disable-informer-cache=true")
		} else {
			args = append(args, "--disable-informer-cache=false")
		}
	}

	if len(options.Features) > 0 {
		args = append(args, "--features", options.Features)
	}

	if options.GarbageCollectionFrequency > 0 {
		args = append(args, fmt.Sprintf("--garbage-collection-frequency=%v", options.GarbageCollectionFrequency))
	}

	if options.PodVolumeOperationTimeout > 0 {
		args = append(args, fmt.Sprintf("--pod-volume-operation-timeout=%v", options.PodVolumeOperationTimeout))
	}

	if options.NodeAgentPodCPULimit != "" {
		args = append(args, fmt.Sprintf("--node-agent-pod-cpu-limit=%v", options.NodeAgentPodCPULimit))
	}

	if options.NodeAgentPodCPURequest != "" {
		args = append(args, fmt.Sprintf("--node-agent-pod-cpu-request=%v", options.NodeAgentPodCPURequest))
	}

	if options.NodeAgentPodMemLimit != "" {
		args = append(args, fmt.Sprintf("--node-agent-pod-mem-limit=%v", options.NodeAgentPodMemLimit))
	}

	if options.NodeAgentPodMemRequest != "" {
		args = append(args, fmt.Sprintf("--node-agent-pod-mem-request=%v", options.NodeAgentPodMemRequest))
	}

	if options.VeleroPodCPULimit != "" {
		args = append(args, fmt.Sprintf("--velero-pod-cpu-limit=%v", options.VeleroPodCPULimit))
	}

	if options.VeleroPodCPURequest != "" {
		args = append(args, fmt.Sprintf("--velero-pod-cpu-request=%v", options.VeleroPodCPURequest))
	}

	if options.VeleroPodMemLimit != "" {
		args = append(args, fmt.Sprintf("--velero-pod-mem-limit=%v", options.VeleroPodMemLimit))
	}

	if options.VeleroPodMemRequest != "" {
		args = append(args, fmt.Sprintf("--velero-pod-mem-request=%v", options.VeleroPodMemRequest))
	}

	if len(options.UploaderType) > 0 {
		args = append(args, fmt.Sprintf("--uploader-type=%v", options.UploaderType))
	}

	if options.ItemBlockWorkerCount > 1 {
		args = append(args, fmt.Sprintf("--item-block-worker-count=%d", options.ItemBlockWorkerCount))
	}

	if len(options.PodLabels.Data()) > 0 {
		args = append(args, "--pod-labels", options.PodLabels.String())
	}

	if len(options.ServiceAccountAnnotations.Data()) > 0 {
		args = append(args, "--sa-annotations", options.ServiceAccountAnnotations.String())
	}

	if options.ServerPriorityClassName != "" {
		args = append(args, "--server-priority-class-name", options.ServerPriorityClassName)
	}

	if options.NodeAgentPriorityClassName != "" {
		args = append(args, "--node-agent-priority-class-name", options.NodeAgentPriorityClassName)
	}

	// Only version no older than v1.15 support --backup-repository-configmap.
	if options.BackupRepoConfigMap != "" {
		result, err := VersionNoOlderThan(version, "v1.15")
		if err == nil && result {
			fmt.Println("Associate backup repository ConfigMap. The Velero version is ", version)
			args = append(args, fmt.Sprintf("--backup-repository-configmap=%s", options.BackupRepoConfigMap))
		}
	}

	if options.RepoMaintenanceJobConfigMap != "" {
		args = append(args, fmt.Sprintf("--repo-maintenance-job-configmap=%s", options.RepoMaintenanceJobConfigMap))
	}

	if options.NodeAgentConfigMap != "" {
		args = append(args, fmt.Sprintf("--node-agent-configmap=%s", options.NodeAgentConfigMap))
	}

	if err := createVeleroResources(ctx, cli, namespace, args, options); err != nil {
		return err
	}

	return waitVeleroReady(ctx, namespace, options.UseNodeAgent, options.UseNodeAgentWindows)
}

func createVeleroResources(ctx context.Context, cli, namespace string, args []string, options *installOptions) error {
	args = append(args, "--dry-run", "--output", "json", "--crds-only")

	// get the CRD definitions
	cmd := exec.CommandContext(ctx, cli, args...)
	fmt.Printf("Running cmd %q \n", cmd.String())
	stdout, stderr, err := velerexec.RunCommand(cmd)
	if err != nil {
		return errors.Wrapf(err, "failed to run velero install dry run command with \"--crds-only\" option, stdout=%s, stderr=%s", stdout, stderr)
	}

	// apply the CRDs first
	cmd = exec.CommandContext(ctx, "kubectl", "apply", "-f", "-")
	cmd.Stdin = bytes.NewBufferString(stdout)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	fmt.Printf("Applying velero CRDs...\n")
	if err = cmd.Run(); err != nil {
		return errors.Wrapf(err, "failed to apply the CRDs")
	}

	// wait until the CRDs are ready
	cmd = exec.CommandContext(ctx, "kubectl", "wait", "--for", "condition=established", "-f", "-")
	cmd.Stdin = bytes.NewBufferString(stdout)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	fmt.Printf("Waiting velero CRDs ready...\n")
	if err = cmd.Run(); err != nil {
		return errors.Wrapf(err, "failed to wait the CRDs be ready")
	}

	// Wait the Velero CRD API endpoint is ready
	wait.PollUntilContextTimeout(ctx, k8s.PollInterval, time.Minute, true, func(ctx context.Context) (bool, error) {
		v1VerifyCmd := exec.CommandContext(ctx, "kubectl", "get", "--raw", "/apis/velero.io/v1")
		v1VerifyCmd.Stdout = os.Stdout
		v1VerifyCmd.Stderr = os.Stderr
		if err := v1VerifyCmd.Run(); err != nil {
			fmt.Printf("/apis/velero.io/v1 is not ready: %s.\n", err.Error())
			return false, nil
		}

		v2alpha1VerifyCmd := exec.CommandContext(ctx, "kubectl", "get", "--raw", "/apis/velero.io/v2alpha1")
		v2alpha1VerifyCmd.Stdout = os.Stdout
		v2alpha1VerifyCmd.Stderr = os.Stderr
		if err := v2alpha1VerifyCmd.Run(); err != nil {
			fmt.Printf("/apis/velero.io/v2alpha1 is not ready: %s.\n", err.Error())
			return false, nil
		}
		return true, nil
	})

	// remove the "--crds-only" option from the args
	args = args[:len(args)-1]
	cmd = exec.CommandContext(ctx, cli, args...)
	fmt.Printf("Running cmd %q \n", cmd.String())
	stdout, stderr, err = velerexec.RunCommand(cmd)
	if err != nil {
		return errors.Wrapf(err, "failed to run velero install dry run command, stdout=%s, stderr=%s", stdout, stderr)
	}

	// The install CLI may print warning messages before the generated JSON.
	// Skip any text before the first curly bracket.
	if stdout[0] != '{' {
		newIndex := strings.Index(stdout, "{")
		stdout = stdout[newIndex:]
	}

	resources := &unstructured.UnstructuredList{}
	if err := json.Unmarshal([]byte(stdout), resources); err != nil {
		return errors.Wrapf(err, "failed to unmarshal the resources: %s", stdout)
	}

	if err = patchResources(resources, namespace, options); err != nil {
		return errors.Wrapf(err, "failed to patch resources")
	}

	data, err := json.Marshal(resources)
	if err != nil {
		return errors.Wrapf(err, "failed to marshal resources")
	}

	cmd = exec.CommandContext(ctx, "kubectl", "apply", "-f", "-")
	cmd.Stdin = bytes.NewReader(data)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	fmt.Printf("Running cmd %q \n", cmd.String())
	if err = cmd.Run(); err != nil {
		return errors.Wrapf(err, "failed to apply Velero resources")
	}

	return nil
}

// patch the velero resources
func patchResources(resources *unstructured.UnstructuredList, namespace string, options *installOptions) error {
	i := 0
	size := 2
	var deploy appsv1api.Deployment
	var imagePullSecret corev1api.Secret

	for resourceIndex, resource := range resources.Items {
		// apply the image pull secret to avoid the image pull limit of Docker Hub
		if len(options.RegistryCredentialFile) > 0 && resource.GetKind() == "ServiceAccount" &&
			resource.GetName() == "velero" {
			credential, err := os.ReadFile(options.RegistryCredentialFile)
			if err != nil {
				return errors.Wrapf(err, "failed to read the registry credential file %s", options.RegistryCredentialFile)
			}
			imagePullSecret = corev1api.Secret{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Secret",
					APIVersion: corev1api.SchemeGroupVersion.String(),
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "image-pull-secret",
					Namespace: namespace,
				},
				Type: corev1api.SecretTypeDockerConfigJson,
				Data: map[string][]byte{
					".dockerconfigjson": credential,
				},
			}
			resource.Object["imagePullSecrets"] = []map[string]any{
				{
					"name": "image-pull-secret",
				},
			}
			resources.Items[resourceIndex] = resource
			fmt.Printf("image pull secret %q set for velero serviceaccount \n", "image-pull-secret")

			un, err := toUnstructured(imagePullSecret)
			if err != nil {
				return errors.Wrapf(err, "failed to convert pull secret to unstructure")
			}
			resources.Items = append(resources.Items, un)
			i++
		} else if options.VeleroServerDebugMode && resource.GetKind() == "Deployment" &&
			resource.GetName() == "velero" {
			deployJSONStr, err := json.Marshal(resource.Object)
			if err != nil {
				return errors.Wrapf(err, "failed to marshal velero deployment")
			}
			if err := json.Unmarshal(deployJSONStr, &deploy); err != nil {
				return errors.Wrapf(err, "failed to unmarshal velero deployment")
			}
			veleroDeployIndex := -1
			for containerIndex, container := range deploy.Spec.Template.Spec.Containers {
				if container.Name == "velero" {
					veleroDeployIndex = containerIndex
					container.Args = append(container.Args, "--log-level", "debug")
					break
				}
			}
			if veleroDeployIndex >= 0 {
				deploy.Spec.Template.Spec.Containers[veleroDeployIndex].Args = append(deploy.Spec.Template.Spec.Containers[veleroDeployIndex].Args, "--log-level")
				deploy.Spec.Template.Spec.Containers[veleroDeployIndex].Args = append(deploy.Spec.Template.Spec.Containers[veleroDeployIndex].Args, "debug")
				un, err := toUnstructured(deploy)
				if err != nil {
					return errors.Wrapf(err, "failed to unstructured velero deployment")
				}
				resources.Items = append(resources.Items, un)
				resources.Items = append(resources.Items[:resourceIndex], resources.Items[resourceIndex+1:]...)
			} else {
				return errors.New("failed to get velero container in velero pod")
			}
			i++
		}
		if i == size {
			break
		}
	}

	// customize the restore helper image
	if len(options.RestoreHelperImage) > 0 {
		restoreActionConfig := corev1api.ConfigMap{
			TypeMeta: metav1.TypeMeta{
				Kind:       "ConfigMap",
				APIVersion: corev1api.SchemeGroupVersion.String(),
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "fs-restore-action-config",
				Namespace: namespace,
				Labels: map[string]string{
					"velero.io/plugin-config":      "",
					"velero.io/pod-volume-restore": "RestoreItemAction",
				},
			},
			Data: map[string]string{
				"image": options.RestoreHelperImage,
			},
		}

		un, err := toUnstructured(restoreActionConfig)
		if err != nil {
			return errors.Wrapf(err, "failed to convert restore action config to unstructure")
		}
		resources.Items = append(resources.Items, un)
		fmt.Printf("the restore helper image is set by the configmap %q \n", "fs-restore-action-config")
	}

	return nil
}

func toUnstructured(res any) (unstructured.Unstructured, error) {
	un := unstructured.Unstructured{}
	data, err := json.Marshal(res)
	if err != nil {
		return un, err
	}
	err = json.Unmarshal(data, &un)
	return un, err
}

func waitVeleroReady(ctx context.Context, namespace string, useNodeAgent bool, useNodeAgentWindows bool) error {
	fmt.Println("Waiting for Velero deployment to be ready.")
	// when doing upgrade by the "kubectl apply" the command "kubectl wait --for=condition=available deployment/velero -n velero --timeout=600s" returns directly
	// use "rollout status" instead to avoid this. For more detail information, refer to https://kubernetes.io/docs/concepts/workloads/controllers/deployment/#complete-deployment
	stdout, stderr, err := velerexec.RunCommand(exec.CommandContext(ctx, "kubectl", "rollout", "status",
		"deployment/velero", "-n", namespace))
	if err != nil {
		return errors.Wrapf(err, "fail to wait for the velero deployment ready, stdout=%s, stderr=%s", stdout, stderr)
	}

	if useNodeAgent {
		fmt.Println("Waiting for node-agent daemonset to be ready.")
		err := wait.PollImmediate(5*time.Second, 1*time.Minute, func() (bool, error) {
			stdout, stderr, err := velerexec.RunCommand(exec.CommandContext(ctx, "kubectl", "get", "daemonset/node-agent",
				"-o", "json", "-n", namespace))
			if err != nil {
				return false, errors.Wrapf(err, "failed to get the node-agent daemonset, stdout=%s, stderr=%s", stdout, stderr)
			}
			daemonset := &appsv1api.DaemonSet{}
			if err = json.Unmarshal([]byte(stdout), daemonset); err != nil {
				return false, errors.Wrapf(err, "failed to unmarshal the node-agent daemonset")
			}
			if daemonset.Status.DesiredNumberScheduled == daemonset.Status.NumberAvailable {
				return true, nil
			}
			return false, nil
		})
		if err != nil {
			return errors.Wrap(err, "fail to wait for the node-agent ready")
		}
	}

	if useNodeAgentWindows {
		fmt.Println("Waiting for node-agent-windows DaemonSet to be ready.")
		err := wait.PollUntilContextTimeout(context.Background(), 5*time.Second, 1*time.Minute, true, func(ctx context.Context) (bool, error) {
			stdout, stderr, err := velerexec.RunCommand(exec.CommandContext(ctx, "kubectl", "get", "DaemonSet/node-agent-windows",
				"-o", "json", "-n", namespace))
			if err != nil {
				return false, errors.Wrapf(err, "failed to get the node-agent-windows DaemonSet, stdout=%s, stderr=%s", stdout, stderr)
			}
			ds := &appsv1api.DaemonSet{}
			if err = json.Unmarshal([]byte(stdout), ds); err != nil {
				return false, errors.Wrapf(err, "failed to unmarshal the node-agent-windows DaemonSet")
			}
			if ds.Status.DesiredNumberScheduled == ds.Status.NumberAvailable {
				return true, nil
			}
			return false, nil
		})
		if err != nil {
			return errors.Wrap(err, "fail to wait for the node-agent-windows ready")
		}
	}

	fmt.Printf("Velero is installed and ready to be tested in the %s namespace! ⛵ \n", namespace)
	return nil
}

func IsVeleroReady(ctx context.Context, veleroCfg *test.VeleroConfig) (bool, error) {
	namespace := veleroCfg.VeleroNamespace
	useNodeAgent := veleroCfg.UseNodeAgent
	if useNodeAgent {
		stdout, stderr, err := velerexec.RunCommand(exec.CommandContext(ctx, "kubectl", "get", "daemonset/node-agent",
			"-o", "json", "-n", namespace))
		if err != nil {
			return false, errors.Wrapf(err, "failed to get the node-agent daemonset, stdout=%s, stderr=%s", stdout, stderr)
		} else {
			daemonset := &appsv1api.DaemonSet{}
			if err = json.Unmarshal([]byte(stdout), daemonset); err != nil {
				return false, errors.Wrapf(err, "failed to unmarshal the node-agent daemonset")
			}
			if daemonset.Status.DesiredNumberScheduled != daemonset.Status.NumberAvailable {
				return false, fmt.Errorf("the available number pod %d in node-agent daemonset not equal to scheduled number %d", daemonset.Status.NumberAvailable, daemonset.Status.DesiredNumberScheduled)
			}
		}
	}

	stdout, stderr, err := velerexec.RunCommand(exec.CommandContext(ctx, "kubectl", "get", "deployment/velero",
		"-o", "json", "-n", namespace))
	if err != nil {
		return false, errors.Wrapf(err, "failed to get the velero deployment stdout=%s, stderr=%s", stdout, stderr)
	} else {
		deployment := &appsv1api.Deployment{}
		if err = json.Unmarshal([]byte(stdout), deployment); err != nil {
			return false, errors.Wrapf(err, "failed to unmarshal the velero deployment")
		}
		if deployment.Status.AvailableReplicas != deployment.Status.Replicas {
			return false, fmt.Errorf("the available replicas %d in velero deployment not equal to replicas %d", deployment.Status.AvailableReplicas, deployment.Status.Replicas)
		}
	}

	if err := CheckBSL(ctx, namespace, common.DefaultBSLName); err != nil {
		return false, err
	}

	return true, nil
}

func CheckBSL(ctx context.Context, ns string, bslName string) error {
	// Check BSL with poll
	err := wait.PollUntilContextTimeout(ctx, k8s.PollInterval, time.Minute, true, func(ctx context.Context) (bool, error) {
		stdout, stderr, err := velerexec.RunCommand(exec.CommandContext(ctx, "kubectl", "get", "bsl", bslName,
			"-o", "json", "-n", ns))
		if err != nil {
			return false, errors.Wrapf(err, "failed to get bsl %s stdout=%s, stderr=%s", bslName, stdout, stderr)
		} else {
			bsl := &velerov1api.BackupStorageLocation{}
			if err = json.Unmarshal([]byte(stdout), bsl); err != nil {
				return false, errors.Wrapf(err, "failed to unmarshal the velero bsl")
			}
			if bsl.Status.Phase != velerov1api.BackupStorageLocationPhaseAvailable {
				// BSL is not ready. Continue polling till timeout.
				return false, nil
			}
		}

		return true, nil
	})

	return err
}

func PrepareVelero(ctx context.Context, caseName string, veleroCfg test.VeleroConfig, objects ...client.Object) error {
	ready, err := IsVeleroReady(context.Background(), &veleroCfg)
	if err != nil {
		fmt.Printf("error in checking velero status with %v", err)
		ctx, ctxCancel := context.WithTimeout(context.Background(), time.Minute*5)
		defer ctxCancel()
		VeleroUninstall(ctx, veleroCfg)
		ready = false
	}
	if ready {
		fmt.Printf("velero is ready for case %s \n", caseName)
		return nil
	}
	fmt.Printf("need to install velero for case %s \n", caseName)
	return VeleroInstall(context.Background(), &veleroCfg, false, objects...)
}

func VeleroUninstall(ctx context.Context, veleroCfg test.VeleroConfig) error {
	if stdout, stderr, err := velerexec.RunCommand(exec.CommandContext(
		ctx,
		veleroCfg.VeleroCLI,
		"uninstall",
		"--force",
		"-n",
		veleroCfg.VeleroNamespace,
	)); err != nil {
		return errors.Wrapf(err, "failed to uninstall velero, stdout=%s, stderr=%s", stdout, stderr)
	}
	fmt.Println("Velero uninstalled ⛵")

	return nil
}

// createVCCredentialSecret refer to
// https://github.com/vmware-tanzu/velero-plugin-for-vsphere/blob/v1.3.0/docs/vanilla.md
func createVCCredentialSecret(c clientset.Interface, veleroNamespace string) error {
	secret, err := getVCCredentialSecret(c)
	if err != nil {
		return err
	}

	vsphereCfg, exist := secret.Data["csi-vsphere.conf"]
	if !exist {
		return errors.New("failed to retrieve csi-vsphere config")
	}

	vsphereSecret := &corev1api.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "velero-vsphere-config-secret",
			Namespace: veleroNamespace,
		},
		Type: corev1api.SecretTypeOpaque,
		Data: map[string][]byte{"csi-vsphere.conf": vsphereCfg},
	}
	_, err = c.CoreV1().Secrets(veleroNamespace).Create(
		context.TODO(),
		vsphereSecret,
		metav1.CreateOptions{},
	)
	if err != nil {
		return err
	}

	if err := k8s.WaitForSecretsComplete(
		c,
		veleroNamespace,
		test.VeleroVSphereSecretName,
	); err != nil {
		return errors.Wrap(
			err,
			"Failed to ensure velero-vsphere-config-secret secret completion in namespace kube-system",
		)
	}

	return nil
}

// Reference https://github.com/vmware-tanzu/velero-plugin-for-vsphere/blob/main/docs/vanilla.md#create-vc-credential-secret
// Read secret from kube-system namespace first, if not found, try with vmware-system-csi.
func getVCCredentialSecret(c clientset.Interface) (secret *corev1api.Secret, err error) {
	secret, err = k8s.GetSecret(c, test.KubeSystemNamespace, "vsphere-config-secret")
	if err != nil {
		if apierrors.IsNotFound(err) {
			secret, err = k8s.GetSecret(c, test.VSphereCSIControllerNamespace, "vsphere-config-secret")
		}
	}
	return
}
