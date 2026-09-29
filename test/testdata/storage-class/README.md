The `test/testdata/storage-class` directory contains the StorageClass YAMLs used for E2E.
The public cloud provider (including AWS, Azure and GCP) has two StorageClasses.
* The `provider-name`.yaml contains the default StorageClass for the provider. It uses the CSI provisioner.
* The `provider-name`-legacy.yaml contains the legacy StorageClass for the provider. It uses the in-tree volume plugin as the provisioner. By far, there is no E2E case using them.

The vSphere environment also has two StorageClass files.
* The vsphere-legacy.yaml is used for the TKGm environment.
* The vsphere.yaml is used for the VKS environment.

The ZFS StorageClasses only have the default one. There is no in-tree volume plugin used StorageClass used in E2E.

The kind StorageClass uses the local-path provisioner. Will consider adding the CSI provisioner when there is a need.

The StorageClass names are configurable, and the flag also decides who owns the class.

With neither flag set, the tests create both classes from the provider's file above and
delete them afterwards, which is the default behaviour.

Passing `--storage-class` or `--storage-class-2` (or setting `E2E_STORAGE_CLASS` /
`E2E_STORAGE_CLASS_2`) names a class that already exists in the cluster. That class
belongs to whoever set it up: the tests neither create nor delete it, and fail early if
it is missing. This is how a cluster with a different provisioner is targeted without
editing this test data, for example pointing at the `csi-hostpath-sc` class that
csi-driver-host-path ships.

Setting `--storage-class-2` to the empty string runs without a second StorageClass. The
cases that map between two classes skip, and everything else runs.
