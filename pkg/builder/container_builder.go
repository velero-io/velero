/*
Copyright 2019 the Velero contributors.

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

package builder

import (
	"encoding/json"
	"fmt"
	"strings"

	corev1api "k8s.io/api/core/v1"
	apimachineryRuntime "k8s.io/apimachinery/pkg/runtime"
	utilrand "k8s.io/apimachinery/pkg/util/rand"

	"github.com/vmware-tanzu/velero/pkg/label"
)

// ContainerBuilder builds Container objects
type ContainerBuilder struct {
	object *corev1api.Container
}

// ForContainer is the constructor for ContainerBuilder.
func ForContainer(name, image string) *ContainerBuilder {
	return &ContainerBuilder{
		object: &corev1api.Container{
			Name:  name,
			Image: image,
		},
	}
}

// ForPluginContainer is a helper builder specifically for plugin init containers
func ForPluginContainer(image string, pullPolicy corev1api.PullPolicy, existingContainers []corev1api.Container) *ContainerBuilder {
	volumeMount := ForVolumeMount("plugins", "/target").Result()
	return ForContainer(getName(image, existingContainers), image).PullPolicy(pullPolicy).VolumeMounts(volumeMount)
}

// getName returns the 'name' component of a docker image that includes the entire string
// except the registry name, and transforms the combined string into a DNS-1123 compatible name
// that fits within the 63-character limit for Kubernetes container names.
// It appends a random string if there is a collision with existing container names.
func getName(image string, existingContainers []corev1api.Container) string {
	// Convert existingContainers to a map for O(1) collision lookups
	existingNames := make(map[string]bool, len(existingContainers))
	for _, c := range existingContainers {
		existingNames[c.Name] = true
	}

	slashIndex := strings.Index(image, "/")
	slashCount := 0
	if slashIndex >= 0 {
		slashCount = strings.Count(image[slashIndex:], "/")
	}

	start := 0
	if slashCount > 1 || slashIndex == 0 {
		// always start after the first slash when there is a registry name
		// or if the string starts with a slash.
		start = slashIndex + 1
	}

	// If the image spec is by digest, remove the digest.
	// If it is by tag, remove the tag.
	// Otherwise (implicit :latest) leave it alone.
	end := len(image)
	atIndex := strings.LastIndex(image, "@")
	if atIndex > 0 {
		end = atIndex
	} else {
		colonIndex := strings.LastIndex(image, ":")
		if colonIndex > 0 {
			end = colonIndex
		}
	}

	// https://github.com/distribution/distribution/blob/main/docs/spec/api.md#overview
	// valid repository names match the regex [a-z0-9]+(?:[._-][a-z0-9]+)*
	// image repository names can container [._] but [._] are not allowed in RFC-1123 labels.
	// replace '/', '_' and '.' with '-'
	re := strings.NewReplacer("/", "-",
		"_", "-",
		".", "-")
	name := re.Replace(image[start:end])

	// Ensure the name doesn't exceed Kubernetes container name length limit
	name = label.GetValidName(name)

	for existingNames[name] {
		name = re.Replace(image[start:end])
		if len(name) > 57 {
			// Leave 6 characters for "-xxxxx" random string
			name = name[:57]
			name = strings.TrimSuffix(name, "-")
		}
		name = fmt.Sprintf("%s-%s", name, utilrand.String(5))
		name = label.GetValidName(name)
	}

	return name
}

// Result returns the built Container.
func (b *ContainerBuilder) Result() *corev1api.Container {
	return b.object
}

// ResultRawExtension returns the Container as runtime.RawExtension.
func (b *ContainerBuilder) ResultRawExtension() apimachineryRuntime.RawExtension {
	result, err := json.Marshal(b.object)
	if err != nil {
		return apimachineryRuntime.RawExtension{}
	}
	return apimachineryRuntime.RawExtension{
		Raw: result,
	}
}

// Args sets the container's Args.
func (b *ContainerBuilder) Args(args ...string) *ContainerBuilder {
	b.object.Args = append(b.object.Args, args...)
	return b
}

// VolumeMounts sets the container's VolumeMounts.
func (b *ContainerBuilder) VolumeMounts(volumeMounts ...*corev1api.VolumeMount) *ContainerBuilder {
	for _, v := range volumeMounts {
		b.object.VolumeMounts = append(b.object.VolumeMounts, *v)
	}
	return b
}

// Resources sets the container's Resources.
func (b *ContainerBuilder) Resources(resources *corev1api.ResourceRequirements) *ContainerBuilder {
	b.object.Resources = *resources
	return b
}

// SecurityContext sets the container's SecurityContext.
func (b *ContainerBuilder) SecurityContext(securityContext *corev1api.SecurityContext) *ContainerBuilder {
	b.object.SecurityContext = securityContext
	return b
}

func (b *ContainerBuilder) Env(vars ...*corev1api.EnvVar) *ContainerBuilder {
	for _, v := range vars {
		b.object.Env = append(b.object.Env, *v)
	}
	return b
}

func (b *ContainerBuilder) PullPolicy(pullPolicy corev1api.PullPolicy) *ContainerBuilder {
	b.object.ImagePullPolicy = pullPolicy
	return b
}

func (b *ContainerBuilder) Command(command []string) *ContainerBuilder {
	if b.object.Command == nil {
		b.object.Command = []string{}
	}

	b.object.Command = append(b.object.Command, command...)

	return b
}
