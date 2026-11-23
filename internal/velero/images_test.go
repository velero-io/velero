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
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/velero-io/velero/pkg/buildinfo"
)

func TestImageTag(t *testing.T) {
	testCases := []struct {
		name             string
		buildInfoVersion string
		want             string
	}{
		{
			name: "tag is latest when buildinfo.Version is empty",
			want: "latest",
		},
		{
			name:             "tag is buildinfo.Version when not empty",
			buildInfoVersion: "custom-build-version",
			want:             "custom-build-version",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			originalVersion := buildinfo.Version
			buildinfo.Version = tc.buildInfoVersion
			defer func() {
				buildinfo.Version = originalVersion
			}()

			assert.Equal(t, tc.want, ImageTag())
		})
	}
}

func TestImageRegistry(t *testing.T) {
	testCases := []struct {
		name              string
		buildInfoRegistry string
		want              string
	}{
		{
			name: "registry is velero when buildinfo.ImageRegistry is empty",
			want: "velero",
		},
		{
			name:              "registry is buildinfo.ImageRegistry when not empty",
			buildInfoRegistry: "custom-build-image-registry",
			want:              "custom-build-image-registry",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			originalImageRegistry := buildinfo.ImageRegistry
			buildinfo.ImageRegistry = tc.buildInfoRegistry
			defer func() {
				buildinfo.ImageRegistry = originalImageRegistry
			}()

			assert.Equal(t, tc.want, imageRegistry())
		})
	}
}

func testDefaultImage(t *testing.T, defaultImageFn func() string, imageName string) {
	t.Helper()
	testCases := []struct {
		name              string
		buildInfoVersion  string
		buildInfoRegistry string
		want              string
	}{
		{
			name: "image uses velero as registry and latest as tag when buildinfo.ImageRegistry and buildinfo.Version are empty",
			want: fmt.Sprintf("velero/%s:latest", imageName),
		},
		{
			name:              "image uses buildinfo.ImageRegistry as registry when not empty",
			buildInfoRegistry: "custom-build-image-registry",
			want:              fmt.Sprintf("custom-build-image-registry/%s:latest", imageName),
		},
		{
			name:             "image uses buildinfo.Version as tag when not empty",
			buildInfoVersion: "custom-build-version",
			want:             fmt.Sprintf("velero/%s:custom-build-version", imageName),
		},
		{
			name:              "image uses both buildinfo.ImageRegistry and buildinfo.Version when not empty",
			buildInfoRegistry: "custom-build-image-registry",
			buildInfoVersion:  "custom-build-version",
			want:              fmt.Sprintf("custom-build-image-registry/%s:custom-build-version", imageName),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			originalImageRegistry := buildinfo.ImageRegistry
			originalVersion := buildinfo.Version
			buildinfo.ImageRegistry = tc.buildInfoRegistry
			buildinfo.Version = tc.buildInfoVersion
			defer func() {
				buildinfo.ImageRegistry = originalImageRegistry
				buildinfo.Version = originalVersion
			}()

			assert.Equal(t, tc.want, defaultImageFn())
		})
	}
}

func TestDefaultVeleroImage(t *testing.T) {
	testDefaultImage(t, DefaultVeleroImage, "velero")
}
