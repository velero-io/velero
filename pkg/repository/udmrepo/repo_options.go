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

package udmrepo

import (
	"maps"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	StorageTypeS3    = "s3"
	StorageTypeAzure = "azure"
	StorageTypeFs    = "filesystem"
	StorageTypeGcs   = "gcs"

	GenOptionMaintainMode  = "mode"
	GenOptionMaintainFull  = "full"
	GenOptionMaintainQuick = "quick"

	GenOptionOwnerName   = "username"
	GenOptionOwnerDomain = "domainname"

	StoreOptionS3KeyID            = "accessKeyID"
	StoreOptionS3Provider         = "providerName"
	StoreOptionS3SecretKey        = "secretAccessKey"
	StoreOptionS3Token            = "sessionToken"
	StoreOptionS3Endpoint         = "endpoint"
	StoreOptionS3DisableTLS       = "doNotUseTLS"
	StoreOptionS3DisableTLSVerify = "skipTLSVerify"

	StoreOptionFsPath = "fspath"

	StoreOptionGcsReadonly = "readonly"

	StoreOptionOssBucket = "bucket"
	StoreOptionOssRegion = "region"
	StoreOptionCACert    = "caCert"

	StoreOptionCredentialFile = "credFile"
	StoreOptionPrefix         = "prefix"
	StoreOptionPrefixName     = "unified-repo"

	StoreOptionGenHashAlgo    = "hashAlgo"
	StoreOptionGenEncryptAlgo = "encryptAlgo"
	StoreOptionGenSplitAlgo   = "splitAlgo"

	StoreOptionGenRetentionMode   = "retentionMode"
	StoreOptionGenRetentionPeriod = "retentionPeriod"
	StoreOptionGenReadOnly        = "readOnly"

	StoreOptionCacheLimit = "cacheLimitMB"
	StoreOptionCacheDir   = "cacheDir"

	ThrottleOptionReadOps       = "ThrottleReadOPS"
	ThrottleOptionWriteOps      = "ThrottleWriteOPS"
	ThrottleOptionListOps       = "ThrottleListOPS"
	ThrottleOptionUploadBytes   = "ThrottleUploadBytes"
	ThrottleOptionDownloadBytes = "ThrottleDownloadBytes"
	// FullMaintenanceInterval will overwrite kopia maintenance interval
	// options are fastGC for 12 hours, eagerGC for 6 hours, normalGC for 24 hours
	StoreOptionKeyFullMaintenanceInterval                                = "fullMaintenanceInterval"
	FastGC                                FullMaintenanceIntervalOptions = "fastGC"
	FastGCInterval                        time.Duration                  = 12 * time.Hour
	EagerGC                               FullMaintenanceIntervalOptions = "eagerGC"
	EagerGCInterval                       time.Duration                  = 6 * time.Hour
	NormalGC                              FullMaintenanceIntervalOptions = "normalGC"
	NormalGCInterval                      time.Duration                  = 24 * time.Hour
)

type FullMaintenanceIntervalOptions string

const (
	defaultUsername = "default"
	defaultDomain   = "default"
)

type RepoOptions struct {
	// StorageType is a repository specific string to identify a backup storage, i.e., "s3", "filesystem"
	StorageType string
	// RepoPassword is the backup repository's password, if any
	RepoPassword string
	// ConfigFilePath is a custom path to save the repository's configuration, if any
	ConfigFilePath string
	// GeneralOptions takes other repository specific options
	GeneralOptions map[string]string
	// StorageOptions takes storage specific options
	StorageOptions map[string]string

	// Description is a description of the backup repository/backup repository operation.
	// It is for logging/debugging purpose only and doesn't control any behavior of the backup repository.
	Description string
}

// PasswordGetter defines the method to get a repository password.
type PasswordGetter interface {
	GetPassword(param any) (string, error)
}

// StoreOptionsGetter defines the methods to get the storage related options.
type StoreOptionsGetter interface {
	GetStoreType(param any) (string, error)
	GetStoreOptions(param any) (map[string]string, error)
}

// NewRepoOptions creates a new RepoOptions for different purpose
func NewRepoOptions(optionFuncs ...func(*RepoOptions) error) (*RepoOptions, error) {
	options := &RepoOptions{
		GeneralOptions: make(map[string]string),
		StorageOptions: make(map[string]string),
	}

	for _, optionFunc := range optionFuncs {
		err := optionFunc(options)
		if err != nil {
			return nil, err
		}
	}

	return options, nil
}

// WithPassword sets the RepoPassword to RepoOptions, the password is acquired through
// the provided interface
func WithPassword(getter PasswordGetter, param any) func(*RepoOptions) error {
	return func(options *RepoOptions) error {
		password, err := getter.GetPassword(param)
		if err != nil {
			return err
		}

		options.RepoPassword = password

		return nil
	}
}

// WithConfigFile sets the ConfigFilePath to RepoOptions
func WithConfigFile(workPath string, repoID string) func(*RepoOptions) error {
	return func(options *RepoOptions) error {
		options.ConfigFilePath = getRepoConfigFile(workPath, repoID)
		return nil
	}
}

// WithGenOptions sets the GeneralOptions to RepoOptions
func WithGenOptions(genOptions map[string]string) func(*RepoOptions) error {
	return func(options *RepoOptions) error {
		for k, v := range genOptions {
			options.GeneralOptions[k] = v
		}

		return nil
	}
}

// WithStoreOptions sets the StorageOptions to RepoOptions, the store options are acquired through
// the provided interface
func WithStoreOptions(getter StoreOptionsGetter, param any) func(*RepoOptions) error {
	return func(options *RepoOptions) error {
		storeType, err := getter.GetStoreType(param)
		if err != nil {
			return err
		}

		storeOptions, err := getter.GetStoreOptions(param)
		if err != nil {
			return err
		}

		options.StorageType = storeType

		maps.Copy(options.StorageOptions, storeOptions)

		return nil
	}
}

// WithDescription sets the Description to RepoOptions
func WithDescription(desc string) func(*RepoOptions) error {
	return func(options *RepoOptions) error {
		options.Description = desc
		return nil
	}
}

// GetRepoUser returns the default username that is used to manipulate the Unified Repo
func GetRepoUser() string {
	return defaultUsername
}

// GetRepoDomain returns the default user domain that is used to manipulate the Unified Repo
func GetRepoDomain() string {
	return defaultDomain
}

func getRepoConfigFile(workPath string, repoID string) string {
	if workPath == "" {
		home := os.Getenv("HOME")
		if home != "" {
			workPath = filepath.Join(home, "udmrepo")
		} else {
			workPath = filepath.Join(os.TempDir(), "udmrepo")
		}
	}

	name := "repo-" + strings.ToLower(repoID) + ".conf"

	return filepath.Join(workPath, name)
}
