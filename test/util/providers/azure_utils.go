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

package providers

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v5"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/bloberror"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
	"github.com/cockroachdb/errors"

	"github.com/vmware-tanzu/velero/pkg/cmd/util/flag"
	"github.com/vmware-tanzu/velero/pkg/util/dotenv"
	. "github.com/vmware-tanzu/velero/test"
)

type AzureStorage string

const (
	subscriptionIDConfigKey = "subscriptionId"
	subscriptionIDEnvVar    = "AZURE_SUBSCRIPTION_ID"
	cloudNameEnvVar         = "AZURE_CLOUD_NAME"
	resourceGroupEnvVar     = "AZURE_RESOURCE_GROUP"
	storageAccountKey       = "AZURE_STORAGE_ACCOUNT_ACCESS_KEY"
	storageAccount          = "storageAccount"
	subscriptionID          = "subscriptionId"
	resourceGroup           = "resourceGroup"
)

var environments = map[string]cloud.Configuration{
	"AZURECHINACLOUD":        cloud.AzureChina,
	"AZURECLOUD":             cloud.AzurePublic,
	"AZUREGERMANCLOUD":       cloud.AzurePublic,
	"AZUREPUBLICCLOUD":       cloud.AzurePublic,
	"AZUREUSGOVERNMENT":      cloud.AzureGovernment,
	"AZUREUSGOVERNMENTCLOUD": cloud.AzureGovernment,
}

// newAzureCredential returns either an EnvironmentCredential (when
// AZURE_CLIENT_SECRET / certificate / username‑password variables are present)
// or DefaultAzureCredential (which supports Managed Identity, Workload
// Identity + many others).  Both satisfy azcore.TokenCredential.
func newAzureCredential(cloudCfg cloud.Configuration) (azcore.TokenCredential, error) {
	// Try environment‑based first
	envCred, envErr := azidentity.NewEnvironmentCredential(&azidentity.EnvironmentCredentialOptions{
		ClientOptions: azcore.ClientOptions{Cloud: cloudCfg},
	})
	if envErr == nil {
		// envCred succeeds only when enough env vars are set;
		_, testErr := envCred.GetToken(context.Background(), policy.TokenRequestOptions{
			Scopes: []string{cloudCfg.Services[cloud.ResourceManager].Audience + "/.default"},
		})
		if testErr == nil {
			return envCred, nil
		}
	}

	// Fall back to DefaultAzureCredential (includes Managed Identity & OIDC Workload Identity)
	defaultCred, defErr := azidentity.NewDefaultAzureCredential(&azidentity.DefaultAzureCredentialOptions{
		ClientOptions: azcore.ClientOptions{Cloud: cloudCfg},
	})
	if defErr != nil {
		return nil, fmt.Errorf("EnvironmentCredential failed: %v; DefaultAzureCredential failed: %v", envErr, defErr)
	}
	return defaultCred, nil
}

// cloudConfigurationFromName returns cloud configuration based on the common name specified.
func cloudConfigurationFromName(name string) (cloud.Configuration, error) {
	name = strings.ToUpper(name)
	env, ok := environments[name]
	if !ok {
		return env, fmt.Errorf("there is no cloud configuration matching the name %q", name)
	}

	return env, nil
}

func getStorageCredential(cloudCredentialsFile, bslConfig string) (string, string, error) {
	config := flag.NewMap()
	config.Set(bslConfig)
	accountName := config.Data()[storageAccount]
	// Account name must be provided in config
	if len(accountName) == 0 {
		return "", "", errors.New("Please provide bucket as Azure account name ")
	}
	subscriptionID := config.Data()[subscriptionID]
	resourceGroupCfg := config.Data()[resourceGroup]
	accountKey, err := getStorageAccountKey(cloudCredentialsFile, accountName, subscriptionID, resourceGroupCfg)
	if err != nil {
		return "", "", errors.Wrapf(err, "Fail to get storage key of bucket %s", accountName)
	}
	return accountName, accountKey, nil
}

func loadCredentialsIntoEnv(credentialsFile string) error {
	if credentialsFile == "" {
		return nil
	}

	if err := dotenv.Overload(credentialsFile); err != nil {
		return errors.Wrapf(err, "error loading environment from credentials file (%s)", credentialsFile)
	}
	return nil
}

func parseCloudConfiguration(cloudName string) (cloud.Configuration, error) {
	if cloudName == "" {
		fmt.Println("cloudName is empty")
		return cloud.AzurePublic, nil
	}

	cloudConfiguration, err := cloudConfigurationFromName(cloudName)
	return cloudConfiguration, errors.WithStack(err)
}

func getStorageAccountKey(credentialsFile, accountName, subscriptionID, resourceGroupCfg string) (string, error) {
	if err := loadCredentialsIntoEnv(credentialsFile); err != nil {
		return "", err
	}
	storageKey := os.Getenv(storageAccountKey)
	if storageKey != "" {
		return storageKey, nil
	}
	if os.Getenv(cloudNameEnvVar) == "" {
		return "", errors.New("Credential file should contain AZURE_CLOUD_NAME")
	}
	var resourceGroup string
	if os.Getenv(resourceGroupEnvVar) == "" {
		if resourceGroupCfg == "" {
			return "", errors.New("Credential file should contain AZURE_RESOURCE_GROUP or AZURE_STORAGE_ACCOUNT_ACCESS_KEY")
		} else {
			resourceGroup = resourceGroupCfg
		}
	} else {
		resourceGroup = os.Getenv(resourceGroupEnvVar)
	}
	// get Azure cloud from AZURE_CLOUD_NAME, if it exists. If the env var does not
	// exist, parseCloudConfiguration will return cloud.AzurePublic.
	cloudConfiguration, err := parseCloudConfiguration(os.Getenv(cloudNameEnvVar))
	if err != nil {
		return "", errors.Wrap(err, "unable to parse azure cloud name environment variable")
	}

	// get subscription ID from object store config or AZURE_SUBSCRIPTION_ID environment variable
	if subscriptionID == "" {
		return "", errors.New("azure subscription ID not found in object store's config or in environment variable")
	}

	cred, err := newAzureCredential(cloudConfiguration)
	if err != nil {
		return "", errors.Wrap(err, "failed to obtain Azure credential")
	}

	// get storageAccountsClient
	storageAccountsClient, err := armstorage.NewAccountsClient(subscriptionID, cred, &arm.ClientOptions{
		ClientOptions: policy.ClientOptions{
			Cloud: cloudConfiguration,
		},
	})
	if err != nil {
		return "", errors.Wrap(err, "error creating new AccountsClient")
	}

	// get storage key
	res, err := storageAccountsClient.ListKeys(context.TODO(), resourceGroup, accountName, &armstorage.AccountsClientListKeysOptions{Expand: to.Ptr("kerb")})
	if err != nil {
		return "", errors.WithStack(err)
	}
	if len(res.Keys) == 0 {
		return "", errors.New("No storage keys found")
	}

	for _, key := range res.Keys {
		// uppercase both strings for comparison because the ListKeys call returns e.g. "FULL" but
		// the armstorage.KeyPermissionFull constant in the SDK is defined as "Full".
		if strings.EqualFold(string(*key.Permissions), string(armstorage.KeyPermissionFull)) {
			storageKey = *key.Value
			break
		}
	}

	if storageKey == "" {
		return "", errors.New("No storage key with Full permissions found")
	}

	return storageKey, nil
}

func handleErrors(err error) {
	if err != nil {
		if bloberror.HasCode(err, bloberror.ContainerAlreadyExists) {
			return
		}
		log.Fatal(err)
	}
}

func getRequiredValues(getValue func(string) string, keys ...string) (map[string]string, error) {
	missing := []string{}
	results := map[string]string{}

	for _, key := range keys {
		if val := getValue(key); val == "" {
			missing = append(missing, key)
		} else {
			results[key] = val
		}
	}

	if len(missing) > 0 {
		return nil, errors.Errorf("the following keys do not have values: %s", strings.Join(missing, ", "))
	}

	return results, nil
}

func deleteBlob(client *azblob.Client, containerName, blobName string) error {
	_, err := client.DeleteBlob(context.Background(), containerName, blobName, nil)
	return err
}

func (s AzureStorage) IsObjectsInBucket(cloudCredentialsFile, bslBucket, bslPrefix, bslConfig, backupName string) (bool, error) {
	ctx := context.Background()
	accountName, accountKey, err := getStorageCredential(cloudCredentialsFile, bslConfig)
	if err != nil {
		log.Fatal("Fail to get : accountName and accountKey, " + err.Error())
	}
	credential, err := azblob.NewSharedKeyCredential(accountName, accountKey)
	if err != nil {
		log.Fatal("Invalid credentials with error: " + err.Error())
	}

	containerName := bslBucket

	serviceURL := fmt.Sprintf("https://%s.blob.core.windows.net/", accountName)

	client, err := azblob.NewClientWithSharedKeyCredential(serviceURL, credential, nil)
	if err != nil {
		log.Fatal("Failed to get client with error: " + err.Error())
	}
	// Create the container, if container is already exist, then do nothing
	_, err = client.CreateContainer(ctx, containerName, &container.CreateOptions{})
	handleErrors(err)

	fmt.Printf("Finding backup %s blobs in Azure container/bucket %s\n", backupName, containerName)
	pager := client.NewListBlobsFlatPager(containerName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return false, errors.Wrapf(err, "Fail to list blobs client")
		}
		for _, blobInfo := range page.Segment.BlobItems {
			if strings.Contains(*blobInfo.Name, backupName) {
				fmt.Printf("Blob name: %s exist in %s\n", backupName, *blobInfo.Name)
				return true, nil
			}
		}
	}
	return false, nil
}

func (s AzureStorage) DeleteObjectsInBucket(cloudCredentialsFile, bslBucket, bslPrefix, bslConfig, backupObject string) error {
	ctx := context.Background()
	accountName, accountKey, err := getStorageCredential(cloudCredentialsFile, bslConfig)
	if err != nil {
		return errors.Wrapf(err, "Fail to get storage account name and  key of bucket %s", bslBucket)
	}

	credential, err := azblob.NewSharedKeyCredential(accountName, accountKey)
	if err != nil {
		log.Fatal("Invalid credentials with error: " + err.Error())
	}

	containerName := bslBucket

	serviceURL := fmt.Sprintf("https://%s.blob.core.windows.net/", accountName)

	client, err := azblob.NewClientWithSharedKeyCredential(serviceURL, credential, nil)
	if err != nil {
		log.Fatal("Failed to get client with error: " + err.Error())
	}
	_, err = client.CreateContainer(ctx, containerName, &container.CreateOptions{})
	handleErrors(err)

	fmt.Println("Listing the blobs in the container:")
	pager := client.NewListBlobsFlatPager(containerName, nil)
	for pager.More() {
		page, err := pager.NextPage(context.TODO())
		if err != nil {
			return errors.Wrapf(err, "Fail to list blobs client")
		}
		for _, blobInfo := range page.Segment.BlobItems {
			if strings.Contains(*blobInfo.Name, bslPrefix+backupObject+"/") {
				err := deleteBlob(client, containerName, *blobInfo.Name)
				if err != nil {
					log.Fatal("Invalid credentials with error: " + err.Error())
				}
				fmt.Printf("Deleted blob: %s according to backup resource %s\n", *blobInfo.Name, bslPrefix+backupObject+"/")
			}
		}
	}
	return nil
}

func (s AzureStorage) IsSnapshotExisted(cloudCredentialsFile, bslConfig, backupName string, snapshotCheck SnapshotCheckPoint) error {
	ctx := context.Background()

	if err := loadCredentialsIntoEnv(cloudCredentialsFile); err != nil {
		return err
	}
	// we need AZURE_SUBSCRIPTION_ID, AZURE_RESOURCE_GROUP
	envVars, err := getRequiredValues(os.Getenv, subscriptionIDEnvVar, resourceGroupEnvVar)
	if err != nil {
		return errors.Wrap(err, "unable to get all required environment variables")
	}
	fmt.Printf("Using Azure subscription ID %s and resource group %s\n", envVars[subscriptionIDEnvVar], envVars[resourceGroupEnvVar])

	// Get Azure cloud from AZURE_CLOUD_NAME, if it exists. If the env var does not
	// exist, parseCloudConfiguration will return cloud.AzurePublic.
	cloudConfiguration, err := parseCloudConfiguration(os.Getenv(cloudNameEnvVar))
	if err != nil {
		return errors.Wrap(err, "unable to parse azure cloud name environment variable")
	}

	// set a different subscriptionId for snapshots if specified
	snapshotsSubscriptionID := envVars[subscriptionIDEnvVar]

	cred, err := newAzureCredential(cloudConfiguration)
	if err != nil {
		return errors.Wrap(err, "failed to get Azure credential")
	}

	credType := fmt.Sprintf("%T", cred)
	fmt.Printf("Azure credential resolved to %s\n", credType)

	// set up clients
	snapshotsClient, err := armcompute.NewSnapshotsClient(snapshotsSubscriptionID, cred, &arm.ClientOptions{
		ClientOptions: policy.ClientOptions{
			Cloud: cloudConfiguration,
		},
	})
	if err != nil {
		return errors.Wrap(err, "error getting snapshots client")
	}
	pager := snapshotsClient.NewListByResourceGroupPager(envVars[resourceGroupEnvVar], &armcompute.SnapshotsClientListByResourceGroupOptions{})
	snapshotCountFound := 0
	backupNameInSnapshot := ""
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			errors.Wrap(err, fmt.Sprintf("Fail to list snapshots %s\n", envVars[resourceGroupEnvVar]))
		}
		if page.Value == nil {
			return errors.New(fmt.Sprintf("No snapshots in Azure resource group %s\n", envVars[resourceGroupEnvVar]))
		}
		fmt.Printf("Found %d snapshots in Azure resource group %s\n", len(page.Value), envVars[resourceGroupEnvVar])
		for _, v := range page.Value {
			if snapshotCheck.EnableCSI {
				for _, s := range snapshotCheck.SnapshotIDList {
					fmt.Println("Azure CSI local snapshot CR: " + s)
					fmt.Println("Azure provider snapshot name: " + *v.Name)
					if strings.Contains(s, *v.Name) {
						fmt.Printf("Azure snapshot %s is created.\n", s)
						snapshotCountFound++
					}
				}
			} else {
				fmt.Println(v.Tags)
				backupNameInSnapshot = *v.Tags["velero.io-backup"]
				fmt.Println(backupNameInSnapshot)
				if backupName == backupNameInSnapshot {
					snapshotCountFound++
				}
			}
		}
	}
	if snapshotCountFound != snapshotCheck.ExpectCount {
		return errors.New(fmt.Sprintf("Snapshot count %d is not as expected %d\n", snapshotCountFound, snapshotCheck.ExpectCount))
	} else {
		fmt.Printf("Snapshot count %d is as expected %d\n", snapshotCountFound, snapshotCheck.ExpectCount)
		return nil
	}
}

func (s AzureStorage) GetObject(cloudCredentialsFile, bslBucket, bslPrefix, bslConfig, objectKey string) (io.ReadCloser, error) {
	ctx := context.Background()
	accountName, accountKey, err := getStorageCredential(cloudCredentialsFile, bslConfig)
	if err != nil {
		return nil, errors.Wrapf(err, "Fail to get storage account name and  key of bucket %s", bslBucket)
	}

	credential, err := azblob.NewSharedKeyCredential(accountName, accountKey)
	if err != nil {
		log.Fatal("Invalid credentials with error: " + err.Error())
	}

	containerName := bslBucket

	serviceURL := fmt.Sprintf("https://%s.blob.core.windows.net/", accountName)

	client, err := azblob.NewClientWithSharedKeyCredential(serviceURL, credential, nil)
	if err != nil {
		log.Fatal("Failed to get client with error: " + err.Error())
	}
	_, err = client.CreateContainer(ctx, containerName, &container.CreateOptions{})
	handleErrors(err)

	blobName := strings.Join([]string{bslPrefix, objectKey}, "/")
	downloadResponse, err := client.DownloadStream(ctx, containerName, blobName, &azblob.DownloadStreamOptions{})
	if err != nil {
		handleErrors(err)
	}

	return downloadResponse.Body, nil
}
