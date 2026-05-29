# End-to-end tests

Document for running Velero end-to-end test suite.

The E2E tests are validating end-to-end behavior of Velero including install, backup and restore operations. These tests take longer to complete and is not expected to be part of day-to-day developer workflow. It is for this reason that they are disabled when running unit tests. This is accomplished by running unit tests in [`short`](https://golang.org/pkg/testing/#Short) mode using the `-short` flag to `go test`.

If you previously ran unit tests using the `go test ./...` command or any of its variations, then you will now run the same command with the  `-short` flag to `go test` to accomplish the same behavior. Alternatively, you can use the `make test` command to run unit tests.

## 1. Prerequisites

Running the E2E tests expects:
1. One or two running Kubernetes clusters, migration scenario needs 2 clusters:
    1. With DNS and CNI installed.
    1. Compatible with Velero- running Kubernetes v1.10 or later.
    1. With necessary storage drivers/provisioners installed.

1. `kubectl` installed locally.

### Note for migration scenario
_Default Cluster_ refers to source cluster to backup from. Whereas _Standby Cluster_ refers to destination cluster to restore to.

## 2. Limitations

These are the current set of limitations with the E2E tests.

1. E2E tests only accepts credentials only for a single provider and for that reason, only tests for a single provider can be run at a time.
1. To avoid debugging or coding effort, we only have one test suite for Velero E2E test, and run in random order as ginkgo default behavior.
1. Flag `-install-velero` is for purpose of having tests on an existed Velero instance, but by default `-install-velero` is set to true, because it's mandatory for some of cases to testing on specific version of Velero, such as upgrade and migration tests. In upgrade tests, we must install a specific old version and then upgrade it to  the target version, multiple installations is involved here, also migration tests have the same situation with upgrade tests, therefore if you're going to test against an existed Velero instance, make sure to skip upgrade and migration tests from a single E2E test execution.
1. To improve E2E test execution efficiency, E2E tests will skip re-installation between test cases except for those which need a fresh Velero installation like upgrade , migration and some other test cases. When starting a E2E test execution which setting flag `-install-velero` with the default value(true), there will be a Velero installation at the beginning, then test cases will be run in random order, and test cases behavior is as below: 
    1. If the scheduled test case is upgrade (or other cases needs a fresh Velero installation), then upgrade test will uninstall the current Velero instance at the beginning and uninstall the tested Velero instance in the end to avoid unexpected installation parameters for the following test cases. 
    1. If the scheduled test case is the normal one,  it will check the existence of Velero instance, if no one there then start a new standard instaillation, otherwise proceeding test steps.


## 3. Configuration for E2E tests

Below is a list of the configuration used by E2E tests.
These configuration parameters are expected as values to the following command line flags:

1. `--credentials-file`: File containing credentials for backup and volume provider. Required.
1. `--bucket`: Name of the object storage bucket where backups from e2e tests should be stored. Required.
1. `--cloud-provider`: The cloud the tests will be run in.  Appropriate plugins will be installed except for kind which requires the object-store-provider to be specified.
1. `--object-store-provider`: Object store provider to use. Required when kind is the cloud provider.
1. `--velerocli`: Path to the velero application to use. Optional, by default uses `velero` in the `$PATH`
1. `--velero-image`: Image for the velero server to be tested. Optional, by default uses `velero/velero:main`
1. `--restore-helper-image`: Image for the velero restore helper to be tested. Optional, by default it is the built-in image address of velero image.
1. `--plugins `: Provider plugins to be tested.
1. `--bsl-config`: Configuration to use for the backup storage location. Format is key1=value1,key2=value2. Optional.
1. `--prefix`: Prefix in the `bucket`, under which all Velero data should be stored within the bucket. Optional.
1. `--vsl-config`: Configuration to use for the volume snapshot location. Format is key1=value1,key2=value2. Optional.
1. `--velero-namespace`: Namespace to install velero in. Optional, defaults to "velero".
1. `--install-velero`: Specifies whether to install/uninstall velero for the tests.  Optional, defaults to "true".
1. `--use-node-agent`: Whether deploy node agent DaemonSet velero during the test.  Optional.
1. `--use-volume-snapshots`: Whether or not to create snapshot location automatically. Set to false if you do not plan to create volume snapshots via a storage provider.
1. `--additional-bsl-plugins`: Additional plugins to be tested.
1. `--additional-bsl-object-store-provider`: Provider of object store plugin for additional backup storage location. Required if testing multiple credentials support.
1. `--additional-bsl-bucket`: Name of the object storage bucket for additional backup storage location. Required if testing multiple credentials support.
1. `--additional-bsl-prefix`: Prefix in the `additional-bsl-bucket`, under which all Velero data should be stored. Optional.
1. `--additional-bsl-config`: Configuration to use for the additional backup storage location. Format is key1=value1,key2=value2. Optional.
1. `--additional-bsl-credentials-file`: File containing credentials for the additional backup storage location. Required if testing multiple credentials support.
1. `--velero-version`: Image version for the velero server to be tested with. It's set for upgrade test to verify Velero image version is installed as expected. Required if upgrade test is included in the test.
1. `--upgrade-from-velero-version`: Comma-separated list of Velero version to be tested with for the pre-upgrade velero server.
1. `--upgrade-from-velero-cli`: Comma-separated list of velero application for the pre-upgrade velero server.
1. `--migrate-from-velero-version`: Comma-separated list of Velero version to be tested with on source cluster.
1. `--migrate-from-velero-cli`: Comma-separated list of velero application on source cluster.
1. `--features`: Comma-separated list of features to enable for this Velero process.
1. `--registry-credential-file`: File containing credential for the image registry, follows the same format rules as the ~/.docker/config.json file. This credential will be loaded in Velero server pod to help on Docker Hub rate limit issue.
1. `--kibishii-directory`: The file directory or URL path to install Kibishii. It's configurable in case the default path is not accessible for your own test environment.
1. `--debug-e2e-test`: <true/false> A Switch for enable or disable test data cleaning action.
1. `--garbage-collection-frequency`: frequency of garbage collection. It is a parameter for Velero installation. Optional.
1. `--velero-server-debug-mode`: A switch for enable or disable having debug log of Velero server.
1. `--default-cluster-context`: Default (source) cluster's kube config context, it's for migration test.
1. `--standby-cluster-context`: Standby (destination) cluster's kube config context, it's for migration test.
1. `--uploader-type`: Type of uploader for persistent volume backup.
1. `--snapshot-move-data`: A Switch for taking backup with Velero's data mover, if data-mover-plugin is not provided, using built-in plugin.
1. `--data-mover-plugin`: Customized plugin for data mover.
1. `--standby-cluster-cloud-provider`: Cloud provider for standby cluster.
1. `--standby-cluster-plugins`: Plugins provider for standby cluster.
1. `--standby-cluster-object-store-provider`: Object store provider for standby cluster.
1. `--debug-velero-pod-restart`: A switch for debugging velero pod restart.
1. `--fail-fast`: A switch for for failing fast on meeting error.
1. `--has-vsphere-plugin`: A switch to indicate whether the Velero vSphere plugin is installed for vSphere environment.
1. `--worker-os`: A switch to indicate the workload should be ran on windows or linux OS.
1. `--image-registry-proxy`: specifies a custom image registry proxy to be used for pulling container images.

These configurations or parameters are used to generate install options for Velero for each test suite.

Tests can be run with the Kubernetes cluster hosted in various cloud providers or in a _kind_ cluster with storage in
a specified object store type.  Currently supported cloud provider types are _aws_, _azure_, _vsphere_ and _kind_.

## 4. Running tests

### Parameters for `make`

E2E tests can be run from the Velero repository root by running `make test-e2e`. While running E2E tests using `make` the E2E test configuration values are passed using `make` variables.

Below is a mapping between `make` variables to E2E configuration flags.
1. `CREDS_FILE`: `-credentials-file`. Required.
1. `BSL_BUCKET`: `-bucket`. Required.
1. `CLOUD_PROVIDER`: `-cloud-provider`. Required
1. `OBJECT_STORE_PROVIDER`: `-object-store-provider`. Required when kind is the cloud provider.
1. `VELERO_CLI`: the `-velerocli`. Optional.
1. `VELERO_IMAGE`: the `-velero-image`. Optional.
1. `RESTORE_HELPER_IMAGE `: the `-restore-helper-image`. Optional.
1. `VERSION `: the `-velero-version`. Optional.
1. `VELERO_NAMESPACE `: the `-velero-namespace`. Optional.
1. `PLUGINS `: the `-plugins`. Optional.
1. `BSL_PREFIX`: `-prefix`. Optional.
1. `BSL_CONFIG`: `-bsl-config`. Optional. Example: BSL_CONFIG="region=us-east-1". May be required for some object store provider
1. `VSL_CONFIG`: `-vsl-config`. Optional.
1. `UPGRADE_FROM_VELERO_CLI `: `-upgrade-from-velero-cli`. Optional.
1. `UPGRADE_FROM_VELERO_VERSION `: `-upgrade-from-velero-version`. Optional.
1. `MIGRATE_FROM_VELERO_CLI `: `-migrate-from-velero-cli`. Optional.
1. `MIGRATE_FROM_VELERO_VERSION `: `-migrate-from-velero-version`. Optional.
1. `ADDITIONAL_BSL_PLUGINS `: `-additional-bsl-plugins`. Optional.
1. `ADDITIONAL_OBJECT_STORE_PROVIDER`: `-additional-bsl-object-store-provider`. Optional.
1. `ADDITIONAL_CREDS_FILE`: `-additional-bsl-bucket`. Optional.
1. `ADDITIONAL_BSL_BUCKET`: `-additional-bsl-prefix`. Optional.
1. `ADDITIONAL_BSL_PREFIX`: `-additional-bsl-config`. Optional.
1. `ADDITIONAL_BSL_CONFIG`: `-additional-bsl-credentials-file`. Optional.
1. `FEATURES`: `-features`. Optional.
1. `REGISTRY_CREDENTIAL_FILE`: `-registry-credential-file`. Optional.
1. `KIBISHII_DIRECTORY`: `-kibishii-directory`. Optional.
1. `VELERO_SERVER_DEBUG_MODE`: `-velero-server-debug-mode`. Optional.
1. `DEFAULT_CLUSTER`: `-default-cluster-context`. Optional.
1. `STANDBY_CLUSTER`: `-standby-cluster-context`. Optional.
1. `UPLOADER_TYPE`: `-uploader-type`. Optional.
1. `SNAPSHOT_MOVE_DATA`: `-snapshot-move-data`. Optional.
1. `DATA_MOVER_plugin`: `-data-mover-plugin`. Optional.
1. `STANDBY_CLUSTER_CLOUD_PROVIDER`: `-standby-cluster-cloud-provider`. Optional.
1. `STANDBY_CLUSTER_PLUGINS`: `-dstandby-cluster-plugins`. Optional.
1. `STANDBY_CLUSTER_OBJECT_STORE_PROVIDER`: `-standby-cluster-object-store-provider`. Optional.
1. `INSTALL_VELERO `: `-install-velero`. Optional.
1. `DEBUG_VELERO_POD_RESTART`: `-debug-velero-pod-restart`. Optional.
1. `FAIL_FAST`: `--fail-fast`. Optional.
1. `HAS_VSPHERE_PLUGIN`: `--has-vsphere-plugin`. Optional.
1. `WORKER_OS`: `--worker-os`. Optional.
1. `IMAGE_REGISTRY_PROXY`: `--image-registry-proxy.` Optional.

### Examples

#### Basic examples:

1. Run Velero tests in a kind cluster with AWS (or MinIO) as the storage provider:
    
Start kind cluster
``` bash
kind create cluster
```

``` bash
BSL_PREFIX=<PREFIX_UNDER_BUCKET> \
BSL_BUCKET=<BUCKET_FOR_E2E_TEST_BACKUP> \
CREDS_FILE=/path/to/aws-creds \
CLOUD_PROVIDER=kind \
OBJECT_STORE_PROVIDER=aws \
make test-e2e
```

Stop kind cluster
``` bash
kind delete cluster
```

1. Run Velero tests in an AWS cluster:
```bash
BSL_PREFIX=<PREFIX_UNDER_BUCKET> \
BSL_BUCKET=<BUCKET_FOR_E2E_TEST_BACKUP> \
CREDS_FILE=/path/to/aws-creds \
CLOUD_PROVIDER=aws \
make test-e2e
```

1. Run Velero tests in a Microsoft Azure cluster:
```bash
BSL_CONFIG="resourceGroup=$AZURE_BACKUP_RESOURCE_GROUP,storageAccount=$AZURE_STORAGE_ACCOUNT_ID,subscriptionId=$AZURE_BACKUP_SUBSCRIPTION_ID" \
BSL_BUCKET=<BUCKET_FOR_E2E_TEST_BACKUP> \
CREDS_FILE=/path/to/azure-creds \
CLOUD_PROVIDER=azure \
make test-e2e
```

Please refer to `velero-plugin-for-microsoft-azure` documentation for instruction: 
* [set up permissions for Velero](https://github.com/vmware-tanzu/velero-plugin-for-microsoft-azure#set-permissions-for-velero)
* [set up azure storage account and blob container](https://github.com/vmware-tanzu/velero-plugin-for-microsoft-azure#setup-azure-storage-account-and-blob-container)

1. Run Multi-API group and version tests using MinIO as the backup storage location: 
   ``` bash
   BSL_CONFIG="region=minio,s3ForcePathStyle=true,s3Url=<ip address>:9000" \
   BSL_PREFIX=<prefix> \
   BSL_BUCKET=<bucket> \
   CREDS_FILE=<absolute path to MinIO credentials file> \
   CLOUD_PROVIDER=kind \
   OBJECT_STORE_PROVIDER=aws \
   VELERO_NAMESPACE="velero" \
   GINKGO_LABELS="APIGroup && APIVersion" \
   make test-e2e
   ```

1. Run Velero tests in a kind cluster with AWS (or MinIO) as the storage provider and use Microsoft Azure as the storage provider for an additional Backup Storage Location:

```bash
CLOUD_PROVIDER=kind \
OBJECT_STORE_PROVIDER=aws \
BSL_BUCKET=<BUCKET_FOR_E2E_TEST_BACKUP> \
BSL_PREFIX=<PREFIX_UNDER_BUCKET> \
CREDS_FILE=/path/to/aws-creds \
ADDITIONAL_OBJECT_STORE_PROVIDER=azure \
ADDITIONAL_BSL_BUCKET=<BUCKET_FOR_AZURE_BSL> \
ADDITIONAL_BSL_PREFIX=<PREFIX_UNDER_BUCKET> \
ADDITIONAL_BSL_CONFIG=<CONFIG_FOR_AZURE_BUCKET> \
ADDITIONAL_CREDS_FILE=/path/to/azure-creds \
make test-e2e
```

#### Upgrade examples:

1. Run Velero upgrade tests with pre-upgrade version:

This example will run 1 upgrade tests: v1.11.0 ~ target.

``` bash
CLOUD_PROVIDER=aws \
BSL_BUCKET=<BUCKET_FOR_E2E_TEST_BACKUP> \
CREDS_FILE=/path/to/aws-creds \
UPGRADE_FROM_VELERO_VERSION=v1.11.0 \
make test-e2e
```

1. Run Velero upgrade tests with pre-upgrade version list:

This example will run 2 upgrade tests: v1.10.2 ~ target and v1.11.0 ~ target.

```bash
CLOUD_PROVIDER=aws \
BSL_BUCKET=<BUCKET_FOR_E2E_TEST_BACKUP> \
CREDS_FILE=/path/to/aws-creds \
UPGRADE_FROM_VELERO_VERSION=v1.10.2,v1.11.0 \
make test-e2e
```

#### Migration examples:

1. Migration between 2 cluster of the same provider tests:
    
Before running migration test, we should prepare `kube-config` file which contains config of each cluster under test, and set `DEFAULT_CLUSTER` and `STANDBY_CLUSTER` with the corresponding context value in `kube-config` file.

`MIGRATE_FROM_VELERO_VERSION` includes a keyword of `self`, which means migration from Velero under test (specified by `VELERO_IMAGE`) to the same Velero. This variable can be set to `v1.10.0`, `v1.10.0,v1.11.1`, `self` or `v1.11.0,self`.

```bash
CLOUD_PROVIDER=aws \
BSL_BUCKET=<BUCKET_FOR_E2E_TEST_BACKUP> \
CREDS_FILE=/path/to/aws-creds \
DEFAULT_CLUSTER=<CONTEXT_OF_WORKLOAD_CLUSTER_DEFAULT> \
STANDBY_CLUSTER=<CONTEXT_OF_WORKLOAD_CLUSTER_STANDBY> \
MIGRATE_FROM_VELERO_VERSION=v1.11.0,self \
make test-e2e
```

1. Data mover tests:

The example shows all essential `make` variables for a data mover test which is migrate from a AKS cluster to a EKS cluster. 

Note: STANDBY_CLUSTER_CLOUD_PROVIDER and STANDBY_CLUSTER_OBJECT_STORE_PROVIDER is essential here, it is for identify plugins to be installed on target cluster, since DEFAULT cluster's provider is different from STANDBY cluster, plugins are different as well.
```bash
CLOUD_PROVIDER=azure \
DEFAULT_CLUSTER=<AKS_CLUSTER_KUBECONFIG_CONTEXT> \
STANDBY_CLUSTER=<EKS_CLUSTER_KUBECONFIG_CONTEXT> \ 
FEATURES=EnableCSI \
OBJECT_STORE_PROVIDER=aws \
CREDS_FILE=<AWS_CREDENTIAL_FILE> \ 
BSL_CONFIG=region=<AWS_REGION> \ 
BSL_BUCKET=<S3_BUCKET> \ 
BSL_PREFIX=<S3_BUCKET_PREFIC> \ 
VSL_CONFIG=region=<AWS_REGION> \ 
SNAPSHOT_MOVE_DATA=true \ 
STANDBY_CLUSTER_CLOUD_PROVIDER=aws \ 
STANDBY_CLUSTER_OBJECT_STORE_PROVIDER=aws \
GINKGO_LABELS="Migration" \
make test-e2e
```

#### Filtering tests

In release-1.15, Velero bumps the [Ginkgo](https://onsi.github.io/ginkgo/) version to [v2](https://onsi.github.io/ginkgo/MIGRATING_TO_V2).
Velero E2E start to use [labels](https://onsi.github.io/ginkgo/#spec-labels) to filter cases instead of [`-focus` and `-skip`](https://onsi.github.io/ginkgo/#focused-specs) parameters.

Both `make run-e2e` and `make run-perf` CLI support using parameter `GINKGO_LABELS` to filter test cases.

`GINKGO_LABELS` is interpreted into `ginkgo run` CLI's parameter [`--label-filter`](https://onsi.github.io/ginkgo/#spec-labels).


E2E tests can be run with specific cases to be included and/or excluded using the commands below:

1. Run Velero tests with specific cases to be included:
```bash
GINKGO_LABELS="Basic && FSBackup" \
CLOUD_PROVIDER=aws \
BSL_BUCKET=example-bucket \
CREDS_FILE=/path/to/aws-creds \
make test-e2e \
```

In this example, only case have both `Basic` and `FSBackup` labels are included.

1. Run Velero tests with specific cases to be excluded:
```bash
GINKGO_LABELS="!(Scale || Schedule || TTL || (Upgrade && FSBackup) || (Migration && FSBackup))" \
CLOUD_PROVIDER=aws \
BSL_BUCKET=example-bucket \
CREDS_FILE=/path/to/aws-creds \
make test-e2e
```

In this example, cases are labelled as 
* `Scale`
* `Schedule`
* `TTL`
* `Upgrade` and `FSBackup`
* `Migration` and `FSBackup` 
will be skipped.

#### VKS environment test
1. Run the CSI data mover test. 

`HAS_VSPHERE_PLUGIN` should be set to `false` to not install the Velero vSphere plugin.
``` bash
CLOUD_PROVIDER=vsphere \
DEFAULT_CLUSTER=wl-antreav1301 \
STANDBY_CLUSTER=wl-antreav1311 \
DEFAULT_CLUSTER_NAME=192.168.0.4 \
STANDBY_CLUSTER_NAME=192.168.0.3 \
FEATURES=EnableCSI \
PLUGINS=velero/velero-plugin-for-aws:main \
HAS_VSPHERE_PLUGIN=false \
OBJECT_STORE_PROVIDER=aws \
CREDS_FILE=$HOME/aws-credential \
BSL_CONFIG=region=us-east-1 \
BSL_BUCKET=nightly-normal-account4-test \
BSL_PREFIX=nightly \
ADDITIONAL_BSL_PLUGINS=velero/velero-plugin-for-aws:main \
ADDITIONAL_OBJECT_STORE_PROVIDER=aws \
ADDITIONAL_BSL_CONFIG=region=us-east-1 \
ADDITIONAL_BSL_BUCKET=nightly-restrict-account-test \
ADDITIONAL_BSL_PREFIX=nightly \
ADDITIONAL_CREDS_FILE=$HOME/aws-credential \
VELERO_IMAGE=velero/velero:main \
RESTORE_HELPER_IMAGE=velero/velero:main \
VERSION=main \
SNAPSHOT_MOVE_DATA=true \
STANDBY_CLUSTER_CLOUD_PROVIDER=vsphere \
STANDBY_CLUSTER_OBJECT_STORE_PROVIDER=aws \
STANDBY_CLUSTER_PLUGINS=velero/velero-plugin-for-aws:main \
DISABLE_INFORMER_CACHE=true \
REGISTRY_CREDENTIAL_FILE=$HOME/.docker/config.json \
GINKGO_LABELS=Migration \
KIBISHII_DIRECTORY=$HOME/kibishii/kubernetes/yaml/ \
make test-e2e
```

## 6. Full Tests execution

As we provided several examples for E2E test execution, if no filter is involved and despite difference of test environment, 
that is a full test that covered all features on some certain environment.
Unfortunately, to prevent long time running or for some special test scenarios,
there're some tests need to be run in a single execution or pipeline with specific parameters provided. 


### Suggested pipelines for full test
Following pipelines should cover all E2E tests along with proper filters:

1. **CSI pipeline:** As we can see lots of labels in E2E test code, there're many snapshot-labeled test scripts. To cover CSI scenario, a pipeline with CSI enabled should be a good choice, otherwise, we will double all the snapshot cases for CSI scenario, it's very time-wasting. By providing `FEATURES=EnableCSI` and  `PLUGINS=<provider-plugin-images>`, a CSI pipeline is ready for testing.
1. **Data mover pipeline:** Data mover scenario is the same scenario with migaration test except the restriction of migaration between different providers, so it better to separated it out from other pipelines. Please refer the example in previous.
1. **File system backup pipeline:** Set `UPLOADER_TYPE` to `kopia` for all file system backup test cases;
1. **Long time pipeline:** Long time cases should be group into one pipeline, currently these test cases with labels `Scale`, `Schedule` or `TTL` can be group into a pipeline, and make sure to skip them off in any other pipelines.
    
**Note:** please organize filters among proper pipelines for other test cases.

## 7. Adding tests

### API clients
When adding a test, aim to instantiate an API client only once at the beginning of the test. There is a constructor `newTestClient` that facilitates the configuration and instantiation of clients. Also, please use the `kubebuilder` runtime controller client for any new test, as we will phase out usage of `client-go` API clients.

## 8. TestCase frame related
TestCase frame provide a serials of interface to concatenate one complete e2e test. it's makes the testing be concise and explicit.

### VeleroBackupRestoreTest interface 
VeleroBackupRestoreTest interface provided a standard workflow of backup and restore, which makes the whole testing process clearer and code reusability.

For programming conventions, Take ResourcePoliciesCase case for example:
#### Init
- It's need first call the base `TestCase` Init function to generate random number as UUIDgen and set one default timeout duration
- Assigning CaseBaseName variable with a case related prefix, all others variables will follow the prefix
- Assigning NamespacesTotal variable, and generating namespaces
- Assigning values to the inner variable for specific case
- For BackupArgs, as Velero installation is using global Velero configuration, it's NEED to specify the value of the variable snapshot-volumes or default-volumes-to-fs-backup explicitly.

#### CreateResources
- It's better to set a global timeout in CreateResources function which is the real beginning of one e2e test

#### Destroy
- It only cleans up resources in currently test namespaces, if you wish to clean up all resources including resources created which are not in currently test namespaces, it's better to override base Destroy function

#### Clean
- Clean function only clean resources in namespaces which has the prefix CaseBaseName. So the the names of test namespaces should start with prefix of CaseBaseName.
- It's better to override base Clean function, if need to clean up all resources including resources created which is not in currently test namespaces.

#### Velero Installation
- Velero is installed with global velero config before the E2E test start, so if the case (such as upgrade/migration, etc.) does not want to use the global velero config, it is NEED TO UNINSTALL velero, or the global velero config may affect the current test.

### TestFunc 
The TestFunc function concatenate all the flows in a test.
It will reduce the frequency of velero installation by installing and checking Velero with the global Velero. It's Need to explicit reinstall Velero if the case has special configuration, such as API Group test case we need to enable feature EnableCSI.

### Tips
Look for the ⛵ emoji printed at the end of each install and uninstall log. There should not be two install/uninstall in a row, and there should be tests between an install and an uninstall. 

## 9. Troubleshooting

## `Failed to get bucket region` error
If velero log shows `level=error msg="Failed to get bucket region, bucket: xbucket, error: operation error S3: HeadBucket, failed to resolve service endpoint, endpoint rule error, A region must be set when sending requests to S3." backup-storage-location=velero/default cmd=/plugins/velero-plugin-for-aws controller=backup-storage-location logSource="/go/src/velero-plugin-for-aws/velero-plugin-for-aws/object_store.go:136" pluginName=velero-plugin-for-aws`, it means you need to set `BSL_CONFIG` to include `region=<region>`.

## fail fast
If need to debug the failed test case, please set the `FAIL_FAST=true` for the `make test-e2e` CLI.
If `FAIL_FAST` is enabled, the pipeline with failed test case will not delete the test bed,
and the resources(including Velero instance, CRs, and other k8s resources) created during the test are kept.
