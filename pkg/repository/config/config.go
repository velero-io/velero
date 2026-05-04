/*
Copyright 2018, 2019 the Velero contributors.

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

package config

import (
	"strings"
)

type BackendType string

const (
	AWSBackend   BackendType = "velero.io/aws"
	AzureBackend BackendType = "velero.io/azure"
	GCPBackend   BackendType = "velero.io/gcp"
	FSBackend    BackendType = "velero.io/fs"
	SFTPBackend  BackendType = "velero.io/sftp"

	// CredentialsFileKey is the key within a BSL config that is checked to see if
	// the BSL is using its own credentials, rather than those in the environment
	CredentialsFileKey = "credentialsFile"
)

// GetBackendType returns a backend type that is known by Velero.
// If the provider doesn't indicate a known backend type, but the endpoint is
// specified, Velero regards it as a S3 compatible object store and return AWSBackend as the type.
func GetBackendType(provider string, config map[string]string) BackendType {
	if !strings.Contains(provider, "/") {
		provider = "velero.io/" + provider
	}

	bt := BackendType(provider)
	if IsBackendTypeValid(bt) {
		return bt
	} else if config != nil && config["s3Url"] != "" {
		return AWSBackend
	} else {
		return bt
	}
}

func IsBackendTypeValid(backendType BackendType) bool {
	return (backendType == AWSBackend || backendType == AzureBackend || backendType == GCPBackend || backendType == FSBackend || backendType == SFTPBackend)
}
