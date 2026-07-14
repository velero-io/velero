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

package bslworker

import (
	"fmt"

	appsv1api "k8s.io/api/apps/v1"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	veleroutil "github.com/vmware-tanzu/velero/pkg/util/velero"
)

// identityEnvVars are provider identity/credential environment variables that must
// NOT be inherited from the central Velero server into a worker pod: doing so would
// hand the worker the Velero server's identity and defeat per-BSL isolation. A worker
// obtains its identity from its own ServiceAccount, an admission webhook keyed on
// PodLabels (e.g. Azure Workload Identity), and/or explicit projected TokenVolumes.
var identityEnvVars = sets.New(
	"AZURE_CLIENT_ID",
	"AZURE_TENANT_ID",
	"AZURE_CLIENT_SECRET",
	"AZURE_CLIENT_CERTIFICATE_PATH",
	"AZURE_CLIENT_CERTIFICATE_PASSWORD",
	"AZURE_FEDERATED_TOKEN_FILE",
	"AZURE_AUTHORITY_HOST",
	"AZURE_USERNAME",
	"AZURE_PASSWORD",
	"AWS_ROLE_ARN",
	"AWS_WEB_IDENTITY_TOKEN_FILE",
	"AWS_ACCESS_KEY_ID",
	"AWS_SECRET_ACCESS_KEY",
	"AWS_SESSION_TOKEN",
	"AWS_SHARED_CREDENTIALS_FILE",
	"AWS_PROFILE",
	"AWS_CONTAINER_CREDENTIALS_FULL_URI",
	"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
	"AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
	"GOOGLE_APPLICATION_CREDENTIALS",
)

// filterInheritedEnv drops identity/credential env vars from the inherited set. In
// addition to the explicit identityEnvVars denylist, it drops any env var whose value
// is sourced from a Secret (valueFrom.secretKeyRef): the central Velero server's
// credentials are held in Secrets (e.g. cloud-credentials), so no Secret-sourced value
// must ever be inherited into a worker regardless of its name.
func filterInheritedEnv(in []corev1api.EnvVar) []corev1api.EnvVar {
	out := make([]corev1api.EnvVar, 0, len(in))
	for _, e := range in {
		if identityEnvVars.Has(e.Name) {
			continue
		}
		if e.ValueFrom != nil && e.ValueFrom.SecretKeyRef != nil {
			continue
		}
		out = append(out, e)
	}
	return out
}

// nonSecretVolumes returns the inherited volumes with Secret-backed volumes removed,
// plus the set of names retained. Secret volumes (e.g. cloud-credentials) are dropped
// so the central Velero server's credentials never reach the worker; the plugins and
// scratch EmptyDir volumes needed to run the object-store plugin are kept.
func nonSecretVolumes(in []corev1api.Volume) ([]corev1api.Volume, sets.Set[string]) {
	out := make([]corev1api.Volume, 0, len(in))
	kept := sets.New[string]()
	for _, v := range in {
		if v.Secret != nil {
			continue
		}
		out = append(out, *v.DeepCopy())
		kept.Insert(v.Name)
	}
	return out, kept
}

// mountsForVolumes returns the inherited mounts whose volume was retained.
func mountsForVolumes(in []corev1api.VolumeMount, kept sets.Set[string]) []corev1api.VolumeMount {
	out := make([]corev1api.VolumeMount, 0, len(in))
	for _, m := range in {
		if kept.Has(m.Name) {
			out = append(out, *m.DeepCopy())
		}
	}
	return out
}

// tokenProjectionVolumes turns the BSL's ProjectedServiceAccountToken entries into
// projected volumes and their corresponding mounts.
func tokenProjectionVolumes(tokens []velerov1api.ProjectedServiceAccountToken) ([]corev1api.Volume, []corev1api.VolumeMount) {
	volumes := make([]corev1api.Volume, 0, len(tokens))
	mounts := make([]corev1api.VolumeMount, 0, len(tokens))
	for i, tok := range tokens {
		name := fmt.Sprintf("bsl-worker-token-%d", i)
		path := tok.Path
		if path == "" {
			path = "token"
		}
		volumes = append(volumes, corev1api.Volume{
			Name: name,
			VolumeSource: corev1api.VolumeSource{
				Projected: &corev1api.ProjectedVolumeSource{
					Sources: []corev1api.VolumeProjection{
						{
							ServiceAccountToken: &corev1api.ServiceAccountTokenProjection{
								Audience:          tok.Audience,
								ExpirationSeconds: tok.ExpirationSeconds,
								Path:              path,
							},
						},
					},
				},
			},
		})
		mounts = append(mounts, corev1api.VolumeMount{
			Name:      name,
			MountPath: tok.MountPath,
			ReadOnly:  true,
		})
	}
	return volumes, mounts
}

// BuildWorkerService builds the headless-capable ClusterIP Service that fronts the
// worker pod for the given BackupStorageLocation in the resolved namespace.
func BuildWorkerService(bsl *velerov1api.BackupStorageLocation, namespace string) *corev1api.Service {
	return &corev1api.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      WorkerServiceName(bsl.Name),
			Namespace: namespace,
			Labels:    WorkerSelectorLabels(bsl.Name),
		},
		Spec: corev1api.ServiceSpec{
			Selector: WorkerSelectorLabels(bsl.Name),
			Ports: []corev1api.ServicePort{
				{
					Name:       "grpc",
					Port:       WorkerGRPCPort,
					TargetPort: intstr.FromInt32(WorkerGRPCPort),
					Protocol:   corev1api.ProtocolTCP,
				},
			},
		},
	}
}

// BuildWorkerDeployment builds the worker Deployment for a BackupStorageLocation by
// inheriting the plugin-runtime infrastructure from the Velero server Deployment
// (image, init containers that populate /plugins, EmptyDir volumes, security
// contexts, image pull secrets, non-identity env) while replacing the identity with
// the BSL's worker ServiceAccount, pod labels/annotations, and projected token
// volumes, and mounting the worker's TLS materials.
func BuildWorkerDeployment(
	bsl *velerov1api.BackupStorageLocation,
	veleroDeployment *appsv1api.Deployment,
	namespace string,
	logLevel string,
	logFormat string,
) *appsv1api.Deployment {
	worker := bsl.Spec.Worker

	inheritedVolumes, kept := nonSecretVolumes(veleroutil.GetVolumesFromVeleroServer(veleroDeployment))
	inheritedMounts := mountsForVolumes(veleroutil.GetVolumeMountsFromVeleroServer(veleroDeployment), kept)
	env := filterInheritedEnv(veleroutil.GetEnvVarsFromVeleroServer(veleroDeployment))

	// TLS materials (read-only) for the mutual-TLS server.
	tlsVolume := corev1api.Volume{
		Name: "bsl-worker-tls",
		VolumeSource: corev1api.VolumeSource{
			Secret: &corev1api.SecretVolumeSource{
				SecretName: WorkerTLSSecretName(bsl.Name),
			},
		},
	}
	tlsMount := corev1api.VolumeMount{
		Name:      "bsl-worker-tls",
		MountPath: WorkerTLSMountPath,
		ReadOnly:  true,
	}

	volumes := append(inheritedVolumes, tlsVolume)
	mounts := append(inheritedMounts, tlsMount)

	tokenVolumes, tokenMounts := tokenProjectionVolumes(worker.TokenVolumes)
	volumes = append(volumes, tokenVolumes...)
	mounts = append(mounts, tokenMounts...)

	// Pod labels: worker selector + user PodLabels (e.g.
	// azure.workload.identity/use: "true" so the webhook injects the identity).
	// Third-party identity labels are intentionally NOT inherited from the Velero
	// server, so the worker does not adopt the server's identity.
	podLabels := WorkerSelectorLabels(bsl.Name)
	for k, v := range worker.PodLabels {
		podLabels[k] = v
	}

	podAnnotations := map[string]string{}
	for k, v := range worker.PodAnnotations {
		podAnnotations[k] = v
	}

	container := corev1api.Container{
		Name:            WorkerContainerName,
		Image:           veleroutil.GetVeleroServerImage(veleroDeployment),
		ImagePullPolicy: corev1api.PullIfNotPresent,
		Command:         []string{"/velero"},
		Args: []string{
			"backup-store-server",
			fmt.Sprintf("--provider=%s", bsl.Spec.Provider),
			fmt.Sprintf("--listen=0.0.0.0:%d", WorkerGRPCPort),
			fmt.Sprintf("--tls-cert-file=%s/%s", WorkerTLSMountPath, ServerCertFileName),
			fmt.Sprintf("--tls-key-file=%s/%s", WorkerTLSMountPath, ServerKeyFileName),
			fmt.Sprintf("--tls-ca-cert-file=%s/%s", WorkerTLSMountPath, CACertFileName),
			fmt.Sprintf("--log-level=%s", logLevel),
			fmt.Sprintf("--log-format=%s", logFormat),
		},
		Env:             env,
		VolumeMounts:    mounts,
		SecurityContext: veleroutil.GetContainerSecurityContextsFromVeleroServer(veleroDeployment),
		Ports: []corev1api.ContainerPort{
			{
				Name:          "grpc",
				ContainerPort: WorkerGRPCPort,
				Protocol:      corev1api.ProtocolTCP,
			},
		},
		ReadinessProbe: &corev1api.Probe{
			ProbeHandler: corev1api.ProbeHandler{
				TCPSocket: &corev1api.TCPSocketAction{
					Port: intstr.FromInt32(WorkerGRPCPort),
				},
			},
			InitialDelaySeconds: 5,
			PeriodSeconds:       10,
		},
		TerminationMessagePolicy: corev1api.TerminationMessageFallbackToLogsOnError,
	}
	if worker.Resources != nil {
		container.Resources = *worker.Resources
	}

	replicas := int32(1)
	podSpec := corev1api.PodSpec{
		ServiceAccountName: worker.ServiceAccountName,
		InitContainers:     inheritedInitContainers(veleroDeployment),
		Containers:         []corev1api.Container{container},
		Volumes:            volumes,
		SecurityContext:    veleroutil.GetPodSecurityContextsFromVeleroServer(veleroDeployment),
		ImagePullSecrets:   veleroutil.GetImagePullSecretsFromVeleroServer(veleroDeployment),
		NodeSelector:       worker.NodeSelector,
		Tolerations:        worker.Tolerations,
	}

	return &appsv1api.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      WorkerDeploymentName(bsl.Name),
			Namespace: namespace,
			Labels:    WorkerSelectorLabels(bsl.Name),
		},
		Spec: appsv1api.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: WorkerSelectorLabels(bsl.Name),
			},
			Template: corev1api.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      podLabels,
					Annotations: podAnnotations,
				},
				Spec: podSpec,
			},
		},
	}
}

// inheritedInitContainers deep-copies the Velero server's init containers, which
// populate the shared /plugins EmptyDir with the object-store provider binaries.
func inheritedInitContainers(deployment *appsv1api.Deployment) []corev1api.Container {
	src := deployment.Spec.Template.Spec.InitContainers
	out := make([]corev1api.Container, len(src))
	for i := range src {
		out[i] = *src[i].DeepCopy()
	}
	return out
}
