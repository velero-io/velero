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

package provider

import (
	"context"
	"encoding/base64"
	"fmt"
	"maps"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/vmware-tanzu/velero/internal/credentials"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	repoconfig "github.com/vmware-tanzu/velero/pkg/repository/config"
	repokey "github.com/vmware-tanzu/velero/pkg/repository/keys"
	"github.com/vmware-tanzu/velero/pkg/repository/udmrepo"
	reposervice "github.com/vmware-tanzu/velero/pkg/repository/udmrepo/service"
)

type unifiedRepoProvider struct {
	credentialGetter credentials.CredentialGetter
	workPath         string
	repoService      udmrepo.BackupRepoService
	repoBackend      string
	log              logrus.FieldLogger
}

type unifiedRepoConfigProvider struct {
	repoService udmrepo.BackupRepoService
	repoBackend string
	log         logrus.FieldLogger
}

// this func is assigned to a package-level variable so it can be
// replaced when unit-testing
var getS3Credentials = repoconfig.GetS3Credentials
var getGCPCredentials = repoconfig.GetGCPCredentials
var getS3BucketRegion = repoconfig.GetAWSBucketRegion

type localFuncTable struct {
	getStorageVariables   func(*velerov1api.BackupStorageLocation, string, string, map[string]string, credentials.CredentialGetter) (map[string]string, error)
	getStorageCredentials func(*velerov1api.BackupStorageLocation, credentials.FileStore) (map[string]string, error)
}

var funcTable = localFuncTable{
	getStorageVariables:   getStorageVariables,
	getStorageCredentials: getStorageCredentials,
}

const (
	repoOpDescMaintain = "repo maintenance"
	repoOpDescForget   = "forget"

	repoConnectDesc = "unified repo"
)

// NewUnifiedRepoProvider creates the service provider for Unified Repo
func NewUnifiedRepoProvider(
	credentialGetter credentials.CredentialGetter,
	repoBackend string,
	log logrus.FieldLogger,
) Provider {
	repo := unifiedRepoProvider{
		credentialGetter: credentialGetter,
		repoBackend:      repoBackend,
		log:              log,
	}

	repo.repoService = createRepoService(repoBackend, log)

	return &repo
}

func NewUnifiedRepoConfigProvider(
	repoBackend string,
	log logrus.FieldLogger,
) ConfigProvider {
	repo := unifiedRepoConfigProvider{
		repoBackend: repoBackend,
		log:         log,
	}

	repo.repoService = createRepoService(repoBackend, log)

	return &repo
}

func (urp *unifiedRepoProvider) InitRepo(ctx context.Context, param RepoParam) error {
	log := urp.log.WithFields(logrus.Fields{
		"BSL name":  param.BackupLocation.Name,
		"repo name": param.BackupRepo.Name,
		"repo UID":  param.BackupRepo.UID,
	})

	log.Debug("Start to init repo")

	if param.BackupLocation.Spec.AccessMode == velerov1api.BackupStorageLocationAccessModeReadOnly {
		return errors.Errorf("cannot create new backup repo for read-only backup storage location %s/%s", param.BackupLocation.Namespace, param.BackupLocation.Name)
	}

	repoOption, err := udmrepo.NewRepoOptions(
		udmrepo.WithPassword(urp, param),
		udmrepo.WithConfigFile(urp.workPath, string(param.BackupRepo.UID)),
		udmrepo.WithGenOptions(
			map[string]string{
				udmrepo.GenOptionOwnerName:   udmrepo.GetRepoUser(),
				udmrepo.GenOptionOwnerDomain: udmrepo.GetRepoDomain(),
			},
		),
		udmrepo.WithStoreOptions(urp, param),
		udmrepo.WithDescription(repoConnectDesc),
	)

	if err != nil {
		return errors.Wrap(err, "error to get repo options")
	}

	err = urp.repoService.Create(ctx, *repoOption)
	if err != nil {
		return errors.Wrap(err, "error to init backup repo")
	}

	log.Debug("Init repo complete")

	return nil
}

func (urp *unifiedRepoProvider) ConnectToRepo(ctx context.Context, param RepoParam) error {
	log := urp.log.WithFields(logrus.Fields{
		"BSL name":  param.BackupLocation.Name,
		"repo name": param.BackupRepo.Name,
		"repo UID":  param.BackupRepo.UID,
	})

	log.Debug("Start to connect repo")

	repoOption, err := udmrepo.NewRepoOptions(
		udmrepo.WithPassword(urp, param),
		udmrepo.WithConfigFile(urp.workPath, string(param.BackupRepo.UID)),
		udmrepo.WithGenOptions(
			map[string]string{
				udmrepo.GenOptionOwnerName:   udmrepo.GetRepoUser(),
				udmrepo.GenOptionOwnerDomain: udmrepo.GetRepoDomain(),
			},
		),
		udmrepo.WithStoreOptions(urp, param),
		udmrepo.WithDescription(repoConnectDesc),
	)

	if err != nil {
		return errors.Wrap(err, "error to get repo options")
	}

	err = urp.repoService.Connect(ctx, *repoOption)
	if err != nil {
		return errors.Wrap(err, "error to connect backup repo")
	}

	log.Debug("Connect repo complete")

	return nil
}

func (urp *unifiedRepoProvider) PrepareRepo(ctx context.Context, param RepoParam) error {
	log := urp.log.WithFields(logrus.Fields{
		"BSL name":  param.BackupLocation.Name,
		"repo name": param.BackupRepo.Name,
		"repo UID":  param.BackupRepo.UID,
	})

	log.Info("Start to prepare repo")

	repoOption, err := udmrepo.NewRepoOptions(
		udmrepo.WithPassword(urp, param),
		udmrepo.WithConfigFile(urp.workPath, string(param.BackupRepo.UID)),
		udmrepo.WithGenOptions(
			map[string]string{
				udmrepo.GenOptionOwnerName:   udmrepo.GetRepoUser(),
				udmrepo.GenOptionOwnerDomain: udmrepo.GetRepoDomain(),
			},
		),
		udmrepo.WithStoreOptions(urp, param),
		udmrepo.WithDescription(repoConnectDesc),
	)

	if err != nil {
		return errors.Wrap(err, "error to get repo options")
	}

	readOnly := (param.BackupLocation.Spec.AccessMode == velerov1api.BackupStorageLocationAccessModeReadOnly)

	if ready, err := urp.repoService.IsReady(ctx, *repoOption, readOnly); err != nil {
		return errors.Wrap(err, "error to check backup repo")
	} else if ready {
		log.Info("Repo has already been initialized")
		return nil
	}

	if readOnly {
		return errors.Errorf("cannot create new backup repo for read-only backup storage location %s/%s", param.BackupLocation.Namespace, param.BackupLocation.Name)
	}

	err = urp.repoService.Create(ctx, *repoOption)
	if err != nil {
		return errors.Wrap(err, "error to create backup repo")
	}

	log.Info("Prepare repo complete")

	return nil
}

func (urp *unifiedRepoProvider) BoostRepoConnect(ctx context.Context, param RepoParam) error {
	log := urp.log.WithFields(logrus.Fields{
		"BSL name":  param.BackupLocation.Name,
		"repo name": param.BackupRepo.Name,
		"repo UID":  param.BackupRepo.UID,
	})

	log.Debug("Start to boost repo connect")

	repoOption, err := udmrepo.NewRepoOptions(
		udmrepo.WithPassword(urp, param),
		udmrepo.WithConfigFile(urp.workPath, string(param.BackupRepo.UID)),
		udmrepo.WithDescription(repoConnectDesc),
	)

	if err != nil {
		return errors.Wrap(err, "error to get repo options")
	}

	bkRepo, err := urp.repoService.Open(ctx, *repoOption)
	if err == nil {
		if c := bkRepo.Close(ctx); c != nil {
			log.WithError(c).Error("Failed to close repo")
		}

		return nil
	}

	return urp.ConnectToRepo(ctx, param)
}

func (urp *unifiedRepoProvider) PruneRepo(ctx context.Context, param RepoParam) error {
	log := urp.log.WithFields(logrus.Fields{
		"BSL name":  param.BackupLocation.Name,
		"repo name": param.BackupRepo.Name,
		"repo UID":  param.BackupRepo.UID,
	})

	log.Debug("Start to prune repo")

	repoOption, err := udmrepo.NewRepoOptions(
		udmrepo.WithPassword(urp, param),
		udmrepo.WithConfigFile(urp.workPath, string(param.BackupRepo.UID)),
		udmrepo.WithDescription(repoOpDescMaintain),
	)

	if err != nil {
		return errors.Wrap(err, "error to get repo options")
	}

	err = urp.repoService.Maintain(ctx, *repoOption)
	if err != nil {
		return errors.Wrap(err, "error to prune backup repo")
	}

	log.Debug("Prune repo complete")

	return nil
}

func (urp *unifiedRepoProvider) EnsureUnlockRepo(ctx context.Context, param RepoParam) error {
	return nil
}

func (urp *unifiedRepoProvider) Forget(ctx context.Context, snapshotID string, param RepoParam) error {
	log := urp.log.WithFields(logrus.Fields{
		"BSL name":   param.BackupLocation.Name,
		"repo name":  param.BackupRepo.Name,
		"repo UID":   param.BackupRepo.UID,
		"snapshotID": snapshotID,
	})

	log.Debug("Start to forget snapshot")

	repoOption, err := udmrepo.NewRepoOptions(
		udmrepo.WithPassword(urp, param),
		udmrepo.WithConfigFile(urp.workPath, string(param.BackupRepo.UID)),
		udmrepo.WithDescription(repoOpDescForget),
	)

	if err != nil {
		return errors.Wrap(err, "error to get repo options")
	}

	bkRepo, err := urp.repoService.Open(ctx, *repoOption)
	if err != nil {
		return errors.Wrap(err, "error to open backup repo")
	}

	defer func() {
		c := bkRepo.Close(ctx)
		if c != nil {
			log.WithError(c).Error("Failed to close repo")
		}
	}()

	err = bkRepo.DeleteManifest(ctx, udmrepo.ID(snapshotID))
	if err != nil {
		return errors.Wrap(err, "error to delete manifest")
	}

	err = bkRepo.Flush(ctx)
	if err != nil {
		return errors.Wrap(err, "error to flush repo")
	}

	log.Debug("Forget snapshot complete")

	return nil
}

func (urp *unifiedRepoProvider) BatchForget(ctx context.Context, snapshotIDs []string, param RepoParam) []error {
	log := urp.log.WithFields(logrus.Fields{
		"BSL name":    param.BackupLocation.Name,
		"repo name":   param.BackupRepo.Name,
		"repo UID":    param.BackupRepo.UID,
		"snapshotIDs": snapshotIDs,
	})

	log.Debug("Start to batch forget snapshot")

	repoOption, err := udmrepo.NewRepoOptions(
		udmrepo.WithPassword(urp, param),
		udmrepo.WithConfigFile(urp.workPath, string(param.BackupRepo.UID)),
		udmrepo.WithDescription(repoOpDescForget),
	)

	if err != nil {
		return []error{errors.Wrap(err, "error to get repo options")}
	}

	bkRepo, err := urp.repoService.Open(ctx, *repoOption)
	if err != nil {
		return []error{errors.Wrap(err, "error to open backup repo")}
	}

	defer func() {
		c := bkRepo.Close(ctx)
		if c != nil {
			log.WithError(c).Error("Failed to close repo")
		}
	}()

	errs := []error{}
	for _, snapshotID := range snapshotIDs {
		err = bkRepo.DeleteManifest(ctx, udmrepo.ID(snapshotID))
		if err != nil {
			errs = append(errs, errors.Wrapf(err, "error to delete manifest %s", snapshotID))
		}
	}

	err = bkRepo.Flush(ctx)
	if err != nil {
		return []error{errors.Wrap(err, "error to flush repo")}
	}

	log.Debug("Forget snapshot complete")

	return errs
}

func (urp *unifiedRepoProvider) DefaultMaintenanceFrequency() time.Duration {
	return urp.repoService.DefaultMaintenanceFrequency()
}

func (urp *unifiedRepoProvider) ClientSideCacheLimit(repoOption map[string]string) int64 {
	return urp.repoService.ClientSideCacheLimit(repoOption)
}

func (urp *unifiedRepoProvider) GetPassword(param any) (string, error) {
	_, ok := param.(RepoParam)
	if !ok {
		return "", errors.Errorf("invalid parameter, expect %T, actual %T", RepoParam{}, param)
	}

	repoPassword, err := getRepoPassword(urp.credentialGetter.FromSecret)
	if err != nil {
		return "", errors.Wrap(err, "error to get repo password")
	}

	return repoPassword, nil
}

func (urp *unifiedRepoProvider) GetStoreType(param any) (string, error) {
	repoParam, ok := param.(RepoParam)
	if !ok {
		return "", errors.Errorf("invalid parameter, expect %T, actual %T", RepoParam{}, param)
	}

	return getStorageType(repoParam.BackupLocation), nil
}

func (urp *unifiedRepoProvider) GetStoreOptions(param any) (map[string]string, error) {
	repoParam, ok := param.(RepoParam)
	if !ok {
		return map[string]string{}, errors.Errorf("invalid parameter, expect %T, actual %T", RepoParam{}, param)
	}

	storeVar, err := funcTable.getStorageVariables(repoParam.BackupLocation, urp.repoBackend, repoParam.BackupRepo.Spec.VolumeNamespace, repoParam.BackupRepo.Spec.RepositoryConfig, urp.credentialGetter)
	if err != nil {
		return map[string]string{}, errors.Wrap(err, "error to get storage variables")
	}

	storeCred, err := funcTable.getStorageCredentials(repoParam.BackupLocation, urp.credentialGetter.FromFile)
	if err != nil {
		return map[string]string{}, errors.Wrap(err, "error to get repo credentials")
	}

	storeOptions := make(map[string]string)
	maps.Copy(storeOptions, storeVar)
	maps.Copy(storeOptions, storeCred)

	if repoParam.CacheDir != "" {
		storeOptions[udmrepo.StoreOptionCacheDir] = repoParam.CacheDir
	}

	return storeOptions, nil
}

func (urcp *unifiedRepoConfigProvider) DefaultMaintenanceFrequency() time.Duration {
	return urcp.repoService.DefaultMaintenanceFrequency()
}

func (urcp *unifiedRepoConfigProvider) ClientSideCacheLimit(repoOption map[string]string) int64 {
	return urcp.repoService.ClientSideCacheLimit(repoOption)
}

func getRepoPassword(secretStore credentials.SecretStore) (string, error) {
	if secretStore == nil {
		return "", errors.New("invalid credentials interface")
	}

	rawPass, err := secretStore.Get(repokey.RepoKeySelector())
	if err != nil {
		return "", errors.Wrap(err, "error to get password")
	}

	return strings.TrimSpace(rawPass), nil
}

func getStorageType(backupLocation *velerov1api.BackupStorageLocation) string {
	backendType := repoconfig.GetBackendType(backupLocation.Spec.Provider, backupLocation.Spec.Config)

	switch backendType {
	case repoconfig.AWSBackend:
		return udmrepo.StorageTypeS3
	case repoconfig.AzureBackend:
		return udmrepo.StorageTypeAzure
	case repoconfig.GCPBackend:
		return udmrepo.StorageTypeGcs
	case repoconfig.FSBackend:
		return udmrepo.StorageTypeFs
	case repoconfig.SFTPBackend:
		return udmrepo.StorageTypeSftp
	default:
		return ""
	}
}

func getStorageCredentials(backupLocation *velerov1api.BackupStorageLocation, credentialsFileStore credentials.FileStore) (map[string]string, error) {
	result := make(map[string]string)
	var err error

	if credentialsFileStore == nil {
		return map[string]string{}, errors.New("invalid credentials interface")
	}

	backendType := repoconfig.GetBackendType(backupLocation.Spec.Provider, backupLocation.Spec.Config)
	if !repoconfig.IsBackendTypeValid(backendType) {
		return map[string]string{}, errors.New("invalid storage provider")
	}

	config := backupLocation.Spec.Config
	if config == nil {
		config = map[string]string{}
	}

	if backupLocation.Spec.Credential != nil {
		config[repoconfig.CredentialsFileKey], err = credentialsFileStore.Path(backupLocation.Spec.Credential)
		if err != nil {
			return map[string]string{}, errors.Wrap(err, "error get credential file in bsl")
		}
	}

	switch backendType {
	case repoconfig.AWSBackend:
		credValue, err := getS3Credentials(config)
		if err != nil {
			return map[string]string{}, errors.Wrap(err, "error get s3 credentials")
		}

		if credValue != nil {
			result[udmrepo.StoreOptionS3KeyID] = credValue.AccessKeyID
			result[udmrepo.StoreOptionS3Provider] = credValue.Source
			result[udmrepo.StoreOptionS3SecretKey] = credValue.SecretAccessKey
			result[udmrepo.StoreOptionS3Token] = credValue.SessionToken
		}
	case repoconfig.AzureBackend:
		if config[repoconfig.CredentialsFileKey] != "" {
			result[repoconfig.CredentialsFileKey] = config[repoconfig.CredentialsFileKey]
		}
	case repoconfig.GCPBackend:
		result[udmrepo.StoreOptionCredentialFile] = getGCPCredentials(config)
	case repoconfig.SFTPBackend:
		if backupLocation.Spec.Credential != nil {
			result[repoconfig.CredentialsFileKey] = config[repoconfig.CredentialsFileKey]
		}
	}

	return result, nil
}

// Translates user specified options (backupRepoConfig) to internal parameters
// so we would accept only the options that are well defined in the internal system.
// Users' inputs should not be treated as safe any time.
// We remove the unnecessary parameters and keep the modules/logics below safe
func getStorageVariables(backupLocation *velerov1api.BackupStorageLocation, repoBackend string, repoName string, backupRepoConfig map[string]string, credGetter credentials.CredentialGetter) (map[string]string, error) {
	result := make(map[string]string)

	backendType := repoconfig.GetBackendType(backupLocation.Spec.Provider, backupLocation.Spec.Config)
	if !repoconfig.IsBackendTypeValid(backendType) {
		return map[string]string{}, errors.New("invalid storage provider")
	}

	config := backupLocation.Spec.Config
	if config == nil {
		config = map[string]string{}
	}

	bucket := strings.Trim(config["bucket"], "/")
	prefix := strings.Trim(config["prefix"], "/")
	if backupLocation.Spec.ObjectStorage != nil {
		bucket = strings.Trim(backupLocation.Spec.ObjectStorage.Bucket, "/")
		prefix = strings.Trim(backupLocation.Spec.ObjectStorage.Prefix, "/")
	}

	prefix = path.Join(prefix, repoBackend, repoName) + "/"

	region := config["region"]

	if backendType == repoconfig.AWSBackend {
		s3URL := config["s3Url"]
		disableTLS := false

		var err error
		if s3URL == "" {
			if region == "" {
				region, err = getS3BucketRegion(bucket, config)
				if err != nil {
					return map[string]string{}, errors.Wrap(err, "error get s3 bucket region")
				}
			}

			s3URL = fmt.Sprintf("s3-%s.amazonaws.com", region)
			disableTLS = false
		} else {
			url, err := url.Parse(s3URL)
			if err != nil {
				return map[string]string{}, errors.Wrapf(err, "error to parse s3Url %s", s3URL)
			}

			if url.Path != "" && url.Path != "/" {
				return map[string]string{}, errors.Errorf("path is not expected in s3Url %s", s3URL)
			}

			s3URL = url.Host
			disableTLS = url.Scheme == "http"
		}

		result[udmrepo.StoreOptionS3Endpoint] = strings.Trim(s3URL, "/")
		result[udmrepo.StoreOptionS3DisableTLSVerify] = config["insecureSkipTLSVerify"]
		result[udmrepo.StoreOptionS3DisableTLS] = strconv.FormatBool(disableTLS)
	} else if backendType == repoconfig.AzureBackend {
		for k, v := range config {
			result[k] = v
		}
	}

	result[udmrepo.StoreOptionOssBucket] = bucket
	result[udmrepo.StoreOptionPrefix] = prefix
	if backupLocation.Spec.ObjectStorage != nil {
		var caCertData []byte

		// Try CACertRef first (new method), then fall back to CACert (deprecated)
		if backupLocation.Spec.ObjectStorage.CACertRef != nil {
			caCertString, err := credGetter.FromSecret.Get(backupLocation.Spec.ObjectStorage.CACertRef)
			if err != nil {
				return nil, errors.Wrap(err, "error getting CA certificate from secret")
			}
			caCertData = []byte(caCertString)
		} else if backupLocation.Spec.ObjectStorage.CACert != nil {
			caCertData = backupLocation.Spec.ObjectStorage.CACert
		}

		if caCertData != nil {
			result[udmrepo.StoreOptionCACert] = base64.StdEncoding.EncodeToString(caCertData)
		}
	}
	result[udmrepo.StoreOptionOssRegion] = strings.Trim(region, "/")
	result[udmrepo.StoreOptionFsPath] = config["fspath"]

	// SFTP backend variables
	if backendType == repoconfig.SFTPBackend {
		result[udmrepo.StoreOptionSFTPHost] = config["sftpHost"]
		result[udmrepo.StoreOptionSFTPPort] = config["sftpPort"]
		result[udmrepo.StoreOptionSFTPPath] = config["sftpPath"]
		result[udmrepo.StoreOptionSFTPUsername] = config["sftpUsername"]
		result[udmrepo.StoreOptionSFTPKeyPath] = config["sftpKeyPath"]
		result[udmrepo.StoreOptionSFTPKeyData] = config["sftpKeyData"]
		result[udmrepo.StoreOptionSFTPPassword] = config["sftpPassword"]
		result[udmrepo.StoreOptionSFTPKnownHostsData] = config["sftpKnownHostsData"]
	}

	// We remove the unnecessary parameters and keep the modules/logics below safe
	if backupRepoConfig != nil {
		// range of valid params to keep, everything else will be discarded.
		validParams := []string{
			udmrepo.StoreOptionCacheLimit,
			udmrepo.StoreOptionKeyFullMaintenanceInterval,
		}
		for _, param := range validParams {
			if v, found := backupRepoConfig[param]; found {
				result[param] = v
			}
		}
	}

	return result, nil
}

func createRepoService(repoBackend string, log logrus.FieldLogger) udmrepo.BackupRepoService {
	return reposervice.Create(repoBackend, log)
}
