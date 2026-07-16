/*
Copyright 2020 the Velero contributors.

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

package storage

import (
	"context"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
)

// DefaultBackupLocationInfo holds server default backup storage location information
type DefaultBackupLocationInfo struct {
	// StorageLocation is the name of the backup storage location designated as the default on the server side.
	// Deprecated TODO(2.0)
	StorageLocation string
	// ServerValidationFrequency is the server default validation frequency for all backup storage locations
	ServerValidationFrequency time.Duration
}

// IsReadyToValidate calculates if a given backup storage location is ready to be validated.
//
// Rules:
// Users can choose a validation frequency per location. This will override the server's default value
// To skip/stop validation, set the frequency to zero
// This will always return "true" for the first attempt at validating a location, regardless of its validation frequency setting
// Otherwise, it returns "ready" only when NOW is equal to or after the next validation time
// (next validation time: last validation time + validation frequency)
func IsReadyToValidate(bslValidationFrequency *metav1.Duration, lastValidationTime *metav1.Time, serverValidationFrequency time.Duration, log logrus.FieldLogger) bool {
	validationFrequency := serverValidationFrequency
	// If the bsl validation frequency is not specifically set, skip this block and continue, using the server's default
	if bslValidationFrequency != nil {
		validationFrequency = bslValidationFrequency.Duration
	}

	if validationFrequency < 0 {
		log.Debugf("Validation period must be non-negative, changing from %d to %d", validationFrequency, serverValidationFrequency)
		validationFrequency = serverValidationFrequency
	}

	lastValidation := lastValidationTime
	if lastValidation == nil {
		// Regardless of validation frequency, we want to validate all BSLs at least once.
		return true
	}

	if validationFrequency == 0 {
		// Validation was disabled so return false.
		log.Debug("Validation period for this backup location is set to 0, skipping validation")
		return false
	}

	// We want to validate BSL only if the set validation frequency/ interval has elapsed.
	nextValidation := lastValidation.Add(validationFrequency) // next validation time: last validation time + validation frequency
	return !time.Now().UTC().Before(nextValidation)           // ready only when NOW is equal to or after the next validation time
}

// ListBackupStorageLocations verifies if there are any backup storage locations.
// For all purposes, if either there is an error while attempting to fetch items or
// if there are no items an error would be returned since the functioning of the system
// would be haulted.
func ListBackupStorageLocations(ctx context.Context, kbClient client.Client, namespace string) (velerov1api.BackupStorageLocationList, error) {
	var locations velerov1api.BackupStorageLocationList
	if err := kbClient.List(ctx, &locations, &client.ListOptions{
		Namespace: namespace,
	}); err != nil {
		return velerov1api.BackupStorageLocationList{}, err
	}

	if len(locations.Items) == 0 {
		return velerov1api.BackupStorageLocationList{}, errors.New("no backup storage locations found")
	}

	return locations, nil
}

func GetDefaultBackupStorageLocations(ctx context.Context, kbClient client.Client, namespace string) (*velerov1api.BackupStorageLocationList, error) {
	locations := new(velerov1api.BackupStorageLocationList)
	defaultLocations := new(velerov1api.BackupStorageLocationList)
	if err := kbClient.List(context.Background(), locations, &client.ListOptions{Namespace: namespace}); err != nil {
		return defaultLocations, errors.Wrapf(err, "failed to list backup storage locations in namespace %s", namespace)
	}

	for _, location := range locations.Items {
		if location.Spec.Default {
			defaultLocations.Items = append(defaultLocations.Items, location)
		}
	}
	return defaultLocations, nil
}
