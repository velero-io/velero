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

// this func is assigned to a package-level variable so it can be
// replaced when unit-testing
var getAzureCredentials = repoconfig.GetAzureCredentials
var getS3Credentials = repoconfig.GetS3Credentials
var getGCPCredentials = repoconfig.GetGCPCredentials
var getS3BucketRegion = repoconfig.GetAWSBucketRegion
var getAzureStorageDomain = repoconfig.GetAzureStorageDomain

type localFuncTable struct {
	getStorageVariables   func(*velerov1api.BackupStorageLocation, string, string, credentials.FileStore) (map[string]string, error)
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

	repo.repoService = createRepoService(log)

	return &repo
}

func (urp *unifiedRepoProvider) InitRepo(ctx context.Context, param RepoParam) error {
	log := urp.log.WithFields(logrus.Fields{
		"BSL name":  param.BackupLocation.Name,
		"repo name": param.BackupRepo.Name,
		"repo UID":  param.BackupRepo.UID,
	})

	log.Debug("Start to init repo")

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

	err = urp.repoService.Init(ctx, *repoOption, true)
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

	err = urp.repoService.Init(ctx, *repoOption, false)
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

	log.Debug("Start to prepare repo")

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

	err = urp.repoService.Init(ctx, *repoOption, false)
	if err == nil {
		log.Debug("Repo has already been initialized remotely")
		return nil
	}

	err = urp.repoService.Init(ctx, *repoOption, true)
	if err != nil {
		return errors.Wrap(err, "error to init backup repo")
	}

	log.Debug("Prepare repo complete")

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

func (urp *unifiedRepoProvider) DefaultMaintenanceFrequency(ctx context.Context, param RepoParam) time.Duration {
	return urp.repoService.DefaultMaintenanceFrequency()
}

func (urp *unifiedRepoProvider) GetPassword(param interface{}) (string, error) {
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

func (urp *unifiedRepoProvider) GetStoreType(param interface{}) (string, error) {
	repoParam, ok := param.(RepoParam)
	if !ok {
		return "", errors.Errorf("invalid parameter, expect %T, actual %T", RepoParam{}, param)
	}

	return getStorageType(repoParam.BackupLocation), nil
}

func (urp *unifiedRepoProvider) GetStoreOptions(param interface{}) (map[string]string, error) {
	repoParam, ok := param.(RepoParam)
	if !ok {
		return map[string]string{}, errors.Errorf("invalid parameter, expect %T, actual %T", RepoParam{}, param)
	}

	storeVar, err := funcTable.getStorageVariables(repoParam.BackupLocation, urp.repoBackend, repoParam.BackupRepo.Spec.VolumeNamespace, urp.credentialGetter.FromFile)
	if err != nil {
		return map[string]string{}, errors.Wrap(err, "error to get storage variables")
	}

	storeCred, err := funcTable.getStorageCredentials(repoParam.BackupLocation, urp.credentialGetter.FromFile)
	if err != nil {
		return map[string]string{}, errors.Wrap(err, "error to get repo credentials")
	}

	storeOptions := make(map[string]string)
	for k, v := range storeVar {
		storeOptions[k] = v
	}

	for k, v := range storeCred {
		storeOptions[k] = v
	}

	return storeOptions, nil
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
			result[udmrepo.StoreOptionS3Provider] = credValue.ProviderName
			result[udmrepo.StoreOptionS3SecretKey] = credValue.SecretAccessKey
			result[udmrepo.StoreOptionS3Token] = credValue.SessionToken
		}
	case repoconfig.AzureBackend:
		storageAccount, accountKey, err := getAzureCredentials(config)
		if err != nil {
			return map[string]string{}, errors.Wrap(err, "error get azure credentials")
		}
		result[udmrepo.StoreOptionAzureStorageAccount] = storageAccount
		result[udmrepo.StoreOptionAzureKey] = accountKey

	case repoconfig.GCPBackend:
		result[udmrepo.StoreOptionCredentialFile] = getGCPCredentials(config)
	}

	return result, nil
}

func getStorageVariables(backupLocation *velerov1api.BackupStorageLocation, repoBackend string, repoName string,
	credentialFileStore credentials.FileStore) (map[string]string, error) {
	result := make(map[string]string)

	backendType := repoconfig.GetBackendType(backupLocation.Spec.Provider, backupLocation.Spec.Config)
	if !repoconfig.IsBackendTypeValid(backendType) {
		return map[string]string{}, errors.New("invalid storage provider")
	}

	config := backupLocation.Spec.Config
	if config == nil {
		config = map[string]string{}
	}

	if backupLocation.Spec.Credential != nil {
		credsFile, err := credentialFileStore.Path(backupLocation.Spec.Credential)
		if err != nil {
			return map[string]string{}, errors.WithStack(err)
		}
		config[repoconfig.CredentialsFileKey] = credsFile
	}

	bucket := strings.Trim(config["bucket"], "/")
	prefix := strings.Trim(config["prefix"], "/")
	if backupLocation.Spec.ObjectStorage != nil {
		bucket = strings.Trim(backupLocation.Spec.ObjectStorage.Bucket, "/")
		prefix = strings.Trim(backupLocation.Spec.ObjectStorage.Prefix, "/")
	}

	prefix = path.Join(prefix, repoBackend, repoName) + "/"

	region := config["region"]

	switch backendType {
	case repoconfig.AWSBackend:
		s3URL := config["s3Url"]
		disableTLS := false

		var err error
		if s3URL == "" {
			if region == "" {
				region, err = getS3BucketRegion(bucket)
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
			disableTLS = (url.Scheme == "http")
		}

		result[udmrepo.StoreOptionS3Endpoint] = strings.Trim(s3URL, "/")
		result[udmrepo.StoreOptionS3DisableTLSVerify] = config["insecureSkipTLSVerify"]
		result[udmrepo.StoreOptionS3DisableTLS] = strconv.FormatBool(disableTLS)

		if backupLocation.Spec.ObjectStorage != nil && backupLocation.Spec.ObjectStorage.CACert != nil {
			result[udmrepo.StoreOptionS3CustomCA] = base64.StdEncoding.EncodeToString(backupLocation.Spec.ObjectStorage.CACert)
		}
	case repoconfig.AzureBackend:
		domain, err := getAzureStorageDomain(config)
		if err != nil {
			return map[string]string{}, errors.Wrapf(err, "error to get azure storage domain")
		}

		result[udmrepo.StoreOptionAzureDomain] = domain
	}

	result[udmrepo.StoreOptionOssBucket] = bucket
	result[udmrepo.StoreOptionPrefix] = prefix
	result[udmrepo.StoreOptionOssRegion] = strings.Trim(region, "/")
	result[udmrepo.StoreOptionFsPath] = config["fspath"]

	return result, nil
}

func createRepoService(log logrus.FieldLogger) udmrepo.BackupRepoService {
	return reposervice.Create(log)
}
