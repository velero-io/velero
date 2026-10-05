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

package azure

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	_ "github.com/Azure/azure-sdk-for-go/sdk/azcore/arm/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
)

const (
	// the keys of Azure BSL config:
	// https://github.com/vmware-tanzu/velero-plugin-for-microsoft-azure/blob/main/backupstoragelocation.md
	BSLConfigResourceGroup               = "resourceGroup"
	BSLConfigStorageAccount              = "storageAccount"
	BSLConfigStorageAccountAccessKeyName = "storageAccountKeyEnvVar"
	BSLConfigSubscriptionID              = "subscriptionId"
	BSLConfigStorageAccountURI           = "storageAccountURI"
	BSLConfigUseAAD                      = "useAAD"
	BSLConfigActiveDirectoryAuthorityURI = "activeDirectoryAuthorityURI"

	serviceNameBlob cloud.ServiceName = "blob"
)

func init() {
	cloud.AzureChina.Services[serviceNameBlob] = cloud.ServiceConfiguration{
		Endpoint: "blob.core.chinacloudapi.cn",
	}
	cloud.AzureGovernment.Services[serviceNameBlob] = cloud.ServiceConfiguration{
		Endpoint: "blob.core.usgovcloudapi.net",
	}
	cloud.AzurePublic.Services[serviceNameBlob] = cloud.ServiceConfiguration{
		Endpoint: "blob.core.windows.net",
	}
}

// NewStorageClient creates a blob storage client(data plane) with the provided config which contains BSL config and the credential file name.
// The returned azblob.SharedKeyCredential is needed for Azure plugin to generate the SAS URL when auth with storage
// account access key
func NewStorageClient(log logrus.FieldLogger, config map[string]string) (*azblob.Client, *azblob.SharedKeyCredential, error) {
	// rename to bslCfg for easy understanding
	bslCfg := config

	// storage account is required
	storageAccount := bslCfg[BSLConfigStorageAccount]
	if storageAccount == "" {
		return nil, nil, errors.Errorf("%s is required in BSL", BSLConfigStorageAccount)
	}

	// read the credentials provided by users
	creds, err := LoadCredentials(config)
	if err != nil {
		return nil, nil, err
	}
	// exchange the storage account access key if needed
	creds, err = GetStorageAccountCredentials(bslCfg, creds)
	if err != nil {
		return nil, nil, err
	}

	// get the storage account URI
	uri, err := getStorageAccountURI(log, bslCfg, creds)
	if err != nil {
		return nil, nil, err
	}

	clientOptions, err := GetClientOptions(bslCfg, creds)
	if err != nil {
		return nil, nil, err
	}
	blobClientOptions := &azblob.ClientOptions{
		ClientOptions: clientOptions,
	}

	// auth with storage account access key
	accessKey := creds[CredentialKeyStorageAccountAccessKey]
	if accessKey != "" {
		log.Info("auth with the storage account access key")
		cred, err := azblob.NewSharedKeyCredential(storageAccount, accessKey)
		if err != nil {
			return nil, nil, errors.Wrap(err, "failed to create storage account access key credential")
		}
		client, err := azblob.NewClientWithSharedKeyCredential(uri, cred, blobClientOptions)
		if err != nil {
			return nil, nil, errors.Wrap(err, "failed to create blob client with the storage account access key")
		}
		return client, cred, nil
	}

	// auth with Azure AD
	log.Info("auth with Azure AD")
	cred, err := NewCredential(creds, clientOptions)
	if err != nil {
		return nil, nil, err
	}
	client, err := azblob.NewClient(uri, cred, blobClientOptions)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to create blob client with the Azure AD credential")
	}
	return client, nil, nil
}

// GetStorageAccountCredentials returns the credentials to interactive with storage account according to the config of BSL
// and credential file by the following order:
// 1. Return the storage account access key directly if it is provided
// 2. Return the content of the credential file directly if "userAAD" is set as true in BSL config
// 3. Call Azure API to exchange the storage account access key
func GetStorageAccountCredentials(bslCfg map[string]string, creds map[string]string) (map[string]string, error) {
	// use storage account access key if specified
	if name := bslCfg[BSLConfigStorageAccountAccessKeyName]; name != "" {
		accessKey := creds[name]
		if accessKey == "" {
			return nil, errors.Errorf("no storage account access key with key %s found in credential", name)
		}
		creds[CredentialKeyStorageAccountAccessKey] = accessKey
		return creds, nil
	}

	// use AAD
	if bslCfg[BSLConfigUseAAD] != "" {
		useAAD, err := strconv.ParseBool(bslCfg[BSLConfigUseAAD])
		if err != nil {
			return nil, errors.Errorf("failed to parse bool from useAAD string: %s", bslCfg[BSLConfigUseAAD])
		}

		if useAAD {
			return creds, nil
		}
	}

	// exchange the storage account access key
	accessKey, err := exchangeStorageAccountAccessKey(bslCfg, creds)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to get storage account access key")
	}
	creds[CredentialKeyStorageAccountAccessKey] = accessKey
	return creds, nil
}

// getStorageAccountURI returns the storage account URI by the following order:
// 1. Return the storage account URI directly if it is specified in BSL config
// 2. Try to call Azure API to get the storage account URI if possible(Background: https://github.com/vmware-tanzu/velero/issues/6163)
// 3. Fall back to return the default URI
func getStorageAccountURI(log logrus.FieldLogger, bslCfg map[string]string, creds map[string]string) (string, error) {
	// if the URI is specified in the BSL, return it directly
	uri := bslCfg[BSLConfigStorageAccountURI]
	if uri != "" {
		log.Infof("the storage account URI %q is specified in the BSL, use it directly", uri)
		return uri, nil
	}

	storageAccount := bslCfg[BSLConfigStorageAccount]

	cloudCfg, err := getCloudConfiguration(bslCfg, creds)
	if err != nil {
		return "", err
	}

	// the default URI
	uri = fmt.Sprintf("https://%s.%s", storageAccount, cloudCfg.Services[serviceNameBlob].Endpoint)

	// the storage account access key cannot be used to get the storage account properties,
	// so fallback to the default URI
	if name := bslCfg[BSLConfigStorageAccountAccessKeyName]; name != "" && creds[name] != "" {
		log.Infof("auth with the storage account access key, cannot retrieve the storage account properties, fallback to use the default URI %q", uri)
		return uri, nil
	}

	client, err := newStorageAccountManagemenClient(bslCfg, creds)
	if err != nil {
		log.Infof("failed to create the storage account management client: %v, fallback to use the default URI %q", err, uri)
		return uri, nil
	}

	resourceGroup := GetFromLocationConfigOrCredential(bslCfg, creds, BSLConfigResourceGroup, CredentialKeyResourceGroup)
	// we cannot get the storage account properties without the resource group, so fallback to the default URI
	if resourceGroup == "" {
		log.Infof("resource group isn't set which is required to retrieve the storage account properties, fallback to use the default URI %q", uri)
		return uri, nil
	}

	properties, err := client.GetProperties(context.Background(), resourceGroup, storageAccount, nil)
	// get error, fallback to the default URI
	if err != nil {
		log.Infof("failed to retrieve the storage account properties: %v, fallback to use the default URI %q", err, uri)
		return uri, nil
	}

	uri = *properties.Account.Properties.PrimaryEndpoints.Blob
	log.Infof("use the storage account URI retrieved from the storage account properties %q", uri)
	return uri, nil
}

// try to exchange the storage account access key with the provided credentials
func exchangeStorageAccountAccessKey(bslCfg, creds map[string]string) (string, error) {
	client, err := newStorageAccountManagemenClient(bslCfg, creds)
	if err != nil {
		return "", err
	}

	resourceGroup := GetFromLocationConfigOrCredential(bslCfg, creds, BSLConfigResourceGroup, CredentialKeyResourceGroup)
	if resourceGroup == "" {
		return "", errors.New("resource group is required in BSL or credential to exchange the storage account access key")
	}
	storageAccount := bslCfg[BSLConfigStorageAccount]
	if storageAccount == "" {
		return "", errors.Errorf("%s is required in the BSL to exchange the storage account access key", BSLConfigStorageAccount)
	}

	expand := "kerb"
	resp, err := client.ListKeys(context.Background(), resourceGroup, storageAccount, &armstorage.AccountsClientListKeysOptions{
		Expand: &expand,
	})
	if err != nil {
		return "", errors.Wrap(err, "failed to list storage account access keys")
	}
	for _, key := range resp.Keys {
		if key == nil || key.Permissions == nil {
			continue
		}
		if strings.EqualFold(string(*key.Permissions), string(armstorage.KeyPermissionFull)) {
			return *key.Value, nil
		}
	}
	return "", errors.New("no storage key with Full permissions found")
}

// new a management client for the storage account
func newStorageAccountManagemenClient(bslCfg map[string]string, creds map[string]string) (*armstorage.AccountsClient, error) {
	clientOptions, err := GetClientOptions(bslCfg, creds)
	if err != nil {
		return nil, err
	}

	cred, err := NewCredential(creds, clientOptions)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to create Azure AD credential")
	}

	subID := GetFromLocationConfigOrCredential(bslCfg, creds, BSLConfigSubscriptionID, CredentialKeySubscriptionID)
	if subID == "" {
		return nil, errors.New("subscription ID is required in BSL or credential to create the storage account client")
	}

	client, err := armstorage.NewAccountsClient(subID, cred, &arm.ClientOptions{
		ClientOptions: clientOptions,
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to create the storage account client")
	}

	return client, nil
}
