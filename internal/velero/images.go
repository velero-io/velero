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
	"fmt"

	"github.com/velero-io/velero/pkg/buildinfo"
)

// Use Dockerhub as the default registry if the build process didn't supply a registry
func imageRegistry() string {
	if buildinfo.ImageRegistry == "" {
		return "velero"
	}
	return buildinfo.ImageRegistry
}

// ImageTag returns the image tag that should be used by Velero images.
// It uses the Version from the buildinfo or "latest" if the build process didn't supply a version.
func ImageTag() string {
	if buildinfo.Version == "" {
		return "latest"
	}
	return buildinfo.Version
}

// DefaultVeleroImage returns the default container image to use for this version of Velero.
func DefaultVeleroImage() string {
	return fmt.Sprintf("%s/%s:%s", imageRegistry(), "velero", ImageTag())
}
