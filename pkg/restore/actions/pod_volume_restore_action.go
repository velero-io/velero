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

package actions

import (
	"context"
	"fmt"
	"strings"

	"github.com/vmware-tanzu/velero/pkg/util/boolptr"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	veleroimage "github.com/vmware-tanzu/velero/internal/velero"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/label"
	"github.com/vmware-tanzu/velero/pkg/plugin/framework/common"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	"github.com/vmware-tanzu/velero/pkg/podvolume"
	"github.com/vmware-tanzu/velero/pkg/restorehelper"
	"github.com/vmware-tanzu/velero/pkg/util/kube"
	veleroutil "github.com/vmware-tanzu/velero/pkg/util/velero"
)

const (
	defaultCPURequestLimit = "100m"
	defaultMemRequestLimit = "128Mi"
	defaultCommand         = "/velero-restore-helper"
	restoreHelperUID       = 1000
)

type PodVolumeRestoreAction struct {
	logger      logrus.FieldLogger
	client      corev1client.ConfigMapInterface
	crClient    ctrlclient.Client
	veleroImage string
}

func NewPodVolumeRestoreAction(logger logrus.FieldLogger, client corev1client.ConfigMapInterface, crClient ctrlclient.Client, namespace string) (*PodVolumeRestoreAction, error) {
	deployment, err := veleroutil.GetVeleroServerDeployment(context.TODO(), crClient, namespace)
	if err != nil {
		return nil, err
	}
	image := veleroutil.GetVeleroServerImage(deployment)
	return &PodVolumeRestoreAction{
		logger:      logger,
		client:      client,
		crClient:    crClient,
		veleroImage: image,
	}, nil
}

func (a *PodVolumeRestoreAction) AppliesTo() (velero.ResourceSelector, error) {
	return velero.ResourceSelector{
		IncludedResources: []string{"pods"},
	}, nil
}

func (a *PodVolumeRestoreAction) Execute(input *velero.RestoreItemActionExecuteInput) (*velero.RestoreItemActionExecuteOutput, error) {
	a.logger.Info("Executing PodVolumeRestoreAction")
	defer a.logger.Info("Done executing PodVolumeRestoreAction")

	var pod corev1api.Pod
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(input.Item.UnstructuredContent(), &pod); err != nil {
		return nil, errors.Wrap(err, "unable to convert pod from runtime.Unstructured")
	}

	// At the point when this function is called, the namespace mapping for the restore
	// has not yet been applied to `input.Item` so we can't perform a reverse-lookup in
	// the namespace mapping in the restore spec. Instead, use the pod from the backup
	// so that if the mapping is applied earlier, we still use the correct namespace.
	var podFromBackup corev1api.Pod
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(input.ItemFromBackup.UnstructuredContent(), &podFromBackup); err != nil {
		return nil, errors.Wrap(err, "unable to convert source pod from runtime.Unstructured")
	}

	log := a.logger.WithField("pod", kube.NamespaceAndName(&pod))

	opts := &ctrlclient.ListOptions{
		LabelSelector: label.NewSelectorForBackup(input.Restore.Spec.BackupName),
		Namespace:     input.Restore.Namespace,
	}
	podVolumeBackupList := new(velerov1api.PodVolumeBackupList)
	if err := a.crClient.List(context.TODO(), podVolumeBackupList, opts); err != nil {
		return nil, errors.WithStack(err)
	}

	var podVolumeBackups []*velerov1api.PodVolumeBackup
	for i := range podVolumeBackupList.Items {
		podVolumeBackups = append(podVolumeBackups, &podVolumeBackupList.Items[i])
	}
	// Remove all existing restore-wait init containers first to prevent duplicates
	// This ensures that even if the pod was previously restored with file system backup
	// but now backed up with native datamover or CSI, the unnecessary init container is removed
	var filteredInitContainers []corev1api.Container
	removedCount := 0
	for _, initContainer := range pod.Spec.InitContainers {
		if initContainer.Name != restorehelper.WaitInitContainer && initContainer.Name != restorehelper.WaitInitContainerLegacy {
			filteredInitContainers = append(filteredInitContainers, initContainer)
		} else {
			removedCount++
		}
	}
	pod.Spec.InitContainers = filteredInitContainers
	if removedCount > 0 {
		log.Infof("Removed %d existing restore-wait init container(s)", removedCount)
	}

	volumeSnapshots := podvolume.GetVolumeBackupsForPod(podVolumeBackups, &pod, podFromBackup.Namespace)
	if len(volumeSnapshots) == 0 {
		log.Debug("No pod volume backups found for pod")
		res, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&pod)
		if err != nil {
			return nil, errors.Wrap(err, "unable to convert pod to runtime.Unstructured")
		}
		return velero.NewRestoreItemActionExecuteOutput(&unstructured.Unstructured{Object: res}), nil
	}

	log.Info("Pod volume backups for pod found")
	log.Debugf("Getting plugin config")
	config, err := common.GetPluginConfig(common.PluginKindRestoreItemAction, "velero.io/pod-volume-restore", a.client)
	if err != nil {
		return nil, err
	}

	image := getImage(log, config, a.veleroImage)
	log.Infof("Using image %q", image)

	cpuRequest, memRequest := getResourceRequests(log, config)
	cpuLimit, memLimit := getResourceLimits(log, config)
	if cpuRequest == "" {
		cpuRequest = defaultCPURequestLimit
	}
	if cpuLimit == "" {
		cpuLimit = defaultCPURequestLimit
	}
	if memRequest == "" {
		memRequest = defaultMemRequestLimit
	}
	if memLimit == "" {
		memLimit = defaultMemRequestLimit
	}

	resourceReqs, err := kube.ParseCPUAndMemoryResources(
		cpuRequest,
		memRequest,
		cpuLimit,
		memLimit,
	)
	if err != nil {
		log.Errorf("couldn't parse resource requirements: %s.", err)
		resourceReqs, _ = kube.ParseCPUAndMemoryResources(
			defaultCPURequestLimit,
			defaultMemRequestLimit,
			defaultCPURequestLimit,
			defaultMemRequestLimit,
		)
	}

	runAsUser, runAsGroup, allowPrivilegeEscalation, secCtx := getSecurityContext(log, config)

	var securityContext corev1api.SecurityContext
	securityContextSet := false
	// Use securityContext settings from configmap if available
	if runAsUser != "" || runAsGroup != "" || allowPrivilegeEscalation != "" || secCtx != "" {
		securityContext, err = kube.ParseSecurityContext(runAsUser, runAsGroup, allowPrivilegeEscalation, secCtx)
		if err != nil {
			log.Errorf("Using default securityContext values, couldn't parse securityContext requirements: %s.", err)
		} else {
			securityContextSet = true
		}
	}
	// if securityContext configmap is unavailable but first container in pod has a SecurityContext set, then copy this security context
	if !securityContextSet && len(pod.Spec.Containers) != 0 && pod.Spec.Containers[0].SecurityContext != nil {
		securityContext = *pod.Spec.Containers[0].SecurityContext.DeepCopy()
		securityContextSet = true
	}
	if !securityContextSet {
		securityContext = defaultSecurityCtx()
	}

	initContainerBuilder := newRestoreInitContainerBuilder(image, string(input.Restore.UID))
	initContainerBuilder.Resources(&resourceReqs)
	initContainerBuilder.SecurityContext(&securityContext)

	for volumeName := range volumeSnapshots {
		mount := &corev1api.VolumeMount{
			Name:      volumeName,
			MountPath: "/restores/" + volumeName,
		}
		initContainerBuilder.VolumeMounts(mount)
	}
	initContainerBuilder.Command(getCommand(log, config))

	initContainer := *initContainerBuilder.Result()
	// Since we've already removed all restore-wait init containers above,
	// we can simply prepend the new init container
	pod.Spec.InitContainers = append([]corev1api.Container{initContainer}, pod.Spec.InitContainers...)

	res, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&pod)
	if err != nil {
		return nil, errors.Wrap(err, "unable to convert pod to runtime.Unstructured")
	}

	return velero.NewRestoreItemActionExecuteOutput(&unstructured.Unstructured{Object: res}), nil
}

func getCommand(log logrus.FieldLogger, config *corev1api.ConfigMap) []string {
	if config == nil {
		log.Debug("No config found for plugin")
		return []string{defaultCommand}
	}

	if config.Data["command"] == "" {
		log.Debugf("No custom command configured")
		return []string{defaultCommand}
	}

	log.Debugf("Using custom command %s", config.Data["command"])
	return []string{config.Data["command"]}
}

func getImage(log logrus.FieldLogger, config *corev1api.ConfigMap, defaultImage string) string {
	if config == nil {
		log.Debug("No config found for plugin")
		return defaultImage
	}

	image := config.Data["image"]
	if image == "" {
		log.Debugf("No custom image configured")
		return defaultImage
	}

	log = log.WithField("image", image)

	parts := strings.Split(image, "/")

	if len(parts) == 1 {
		// Image supplied without registry part
		log.Infof("Plugin config contains image name without registry name. Using default init container image: %q", defaultImage)
		return defaultImage
	}

	if !(strings.Contains(parts[len(parts)-1], ":")) {
		tag := veleroimage.ImageTag()
		// tag-less image name: add default image tag for this version of Velero
		log.Infof("Plugin config contains image name without tag. Adding tag: %q", tag)
		return fmt.Sprintf("%s:%s", image, tag)
	}
	// tagged image name
	log.Debugf("Plugin config contains image name with tag")
	return image
}

// getResourceRequests extracts the CPU and memory requests from a ConfigMap.
// The 0 values are valid if the keys are not present
func getResourceRequests(log logrus.FieldLogger, config *corev1api.ConfigMap) (string, string) {
	if config == nil {
		log.Debug("No config found for plugin")
		return "", ""
	}

	return config.Data["cpuRequest"], config.Data["memRequest"]
}

// getResourceLimits extracts the CPU and memory limits from a ConfigMap.
// The 0 values are valid if the keys are not present
func getResourceLimits(log logrus.FieldLogger, config *corev1api.ConfigMap) (string, string) {
	if config == nil {
		log.Debug("No config found for plugin")
		return "", ""
	}

	return config.Data["cpuLimit"], config.Data["memLimit"]
}

// getSecurityContext extracts securityContext runAsUser, runAsGroup, allowPrivilegeEscalation, and securityContext from a ConfigMap.
func getSecurityContext(log logrus.FieldLogger, config *corev1api.ConfigMap) (string, string, string, string) {
	if config == nil {
		log.Debug("No config found for plugin")
		return "", "", "", ""
	}

	return config.Data["secCtxRunAsUser"],
		config.Data["secCtxRunAsGroup"],
		config.Data["secCtxAllowPrivilegeEscalation"],
		config.Data["secCtx"]
}

func newRestoreInitContainerBuilder(image, restoreUID string) *builder.ContainerBuilder {
	return builder.ForContainer(restorehelper.WaitInitContainer, image).
		Args(restoreUID).
		Env([]*corev1api.EnvVar{
			{
				Name: "POD_NAMESPACE",
				ValueFrom: &corev1api.EnvVarSource{
					FieldRef: &corev1api.ObjectFieldSelector{
						FieldPath: "metadata.namespace",
					},
				},
			},
			{
				Name: "POD_NAME",
				ValueFrom: &corev1api.EnvVarSource{
					FieldRef: &corev1api.ObjectFieldSelector{
						FieldPath: "metadata.name",
					},
				},
			},
		}...)
}

// defaultSecurityCtx returns a default security context for the init container, which has the level "restricted" per
// Pod Security Standards.
func defaultSecurityCtx() corev1api.SecurityContext {
	uid := int64(restoreHelperUID)
	return corev1api.SecurityContext{
		AllowPrivilegeEscalation: boolptr.False(),
		Capabilities: &corev1api.Capabilities{
			Drop: []corev1api.Capability{"ALL"},
		},
		SeccompProfile: &corev1api.SeccompProfile{
			Type: corev1api.SeccompProfileTypeRuntimeDefault,
		},
		RunAsUser:    &uid,
		RunAsNonRoot: boolptr.True(),
	}
}
