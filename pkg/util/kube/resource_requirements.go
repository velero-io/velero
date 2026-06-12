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

package kube

import (
	"github.com/cockroachdb/errors"
	corev1api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/vmware-tanzu/velero/pkg/constant"
)

// ParseCPUAndMemoryResources is a helper function that parses CPU and memory requests and limits,
// using default values for ephemeral storage.
func ParseCPUAndMemoryResources(cpuRequest, memRequest, cpuLimit, memLimit string) (corev1api.ResourceRequirements, error) {
	return ParseResourceRequirements(
		cpuRequest,
		memRequest,
		constant.DefaultEphemeralStorageRequest,
		cpuLimit,
		memLimit,
		constant.DefaultEphemeralStorageLimit,
	)
}

// ParseResourceRequirements takes a set of CPU, memory, ephemeral storage requests and limit string
// values and returns a ResourceRequirements struct to be used in a Container.
// An error is returned if we cannot parse the request/limit.
func ParseResourceRequirements(
	cpuRequest,
	memRequest,
	ephemeralStorageRequest,
	cpuLimit,
	memLimit,
	ephemeralStorageLimit string,
) (corev1api.ResourceRequirements, error) {
	resources := corev1api.ResourceRequirements{
		Requests: corev1api.ResourceList{},
		Limits:   corev1api.ResourceList{},
	}

	parsedCPURequest, err := resource.ParseQuantity(cpuRequest)
	if err != nil {
		return resources, errors.Wrapf(err, `couldn't parse CPU request "%s"`, cpuRequest)
	}

	parsedMemRequest, err := resource.ParseQuantity(memRequest)
	if err != nil {
		return resources, errors.Wrapf(err, `couldn't parse memory request "%s"`, memRequest)
	}

	parsedEphemeralStorageRequest, err := resource.ParseQuantity(ephemeralStorageRequest)
	if err != nil {
		return resources, errors.Wrapf(err, `couldn't parse ephemeral storage request "%s"`, ephemeralStorageRequest)
	}

	parsedCPULimit, err := resource.ParseQuantity(cpuLimit)
	if err != nil {
		return resources, errors.Wrapf(err, `couldn't parse CPU limit "%s"`, cpuLimit)
	}

	parsedMemLimit, err := resource.ParseQuantity(memLimit)
	if err != nil {
		return resources, errors.Wrapf(err, `couldn't parse memory limit "%s"`, memLimit)
	}

	parsedEphemeralStorageLimit, err := resource.ParseQuantity(ephemeralStorageLimit)
	if err != nil {
		return resources, errors.Wrapf(err, `couldn't parse ephemeral storage limit "%s"`, ephemeralStorageLimit)
	}

	// A quantity of 0 is treated as unbounded
	unbounded := resource.MustParse("0")

	if parsedCPULimit != unbounded && parsedCPURequest.Cmp(parsedCPULimit) > 0 {
		return resources, errors.WithStack(errors.Errorf(`CPU request "%s" must be less than or equal to CPU limit "%s"`, cpuRequest, cpuLimit))
	}

	if parsedMemLimit != unbounded && parsedMemRequest.Cmp(parsedMemLimit) > 0 {
		return resources, errors.WithStack(errors.Errorf(`Memory request "%s" must be less than or equal to Memory limit "%s"`, memRequest, memLimit))
	}

	if parsedEphemeralStorageLimit != unbounded && parsedEphemeralStorageRequest.Cmp(parsedEphemeralStorageLimit) > 0 {
		return resources, errors.WithStack(errors.Errorf(`Ephemeral storage request "%s" must be less than or equal to Ephemeral storage limit "%s"`, ephemeralStorageRequest, ephemeralStorageLimit))
	}

	// Only set resources if they are not unbounded
	if parsedCPURequest != unbounded {
		resources.Requests[corev1api.ResourceCPU] = parsedCPURequest
	}
	if parsedMemRequest != unbounded {
		resources.Requests[corev1api.ResourceMemory] = parsedMemRequest
	}
	if parsedEphemeralStorageRequest != unbounded {
		resources.Requests[corev1api.ResourceEphemeralStorage] = parsedEphemeralStorageRequest
	}
	if parsedCPULimit != unbounded {
		resources.Limits[corev1api.ResourceCPU] = parsedCPULimit
	}
	if parsedMemLimit != unbounded {
		resources.Limits[corev1api.ResourceMemory] = parsedMemLimit
	}
	if parsedEphemeralStorageLimit != unbounded {
		resources.Limits[corev1api.ResourceEphemeralStorage] = parsedEphemeralStorageLimit
	}

	return resources, nil
}
