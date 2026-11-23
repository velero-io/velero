The `test/testdata/storage-class` directory contains the StorageClass YAMLs used for E2E.
The public cloud provider (including AWS, Azure and GCP) has two StorageClasses.
* The `provider-name`.yaml contains the default StorageClass for the provider. It uses the CSI provisioner.
* The `provider-name`-legacy.yaml contains the legacy StorageClass for the provider. It uses the in-tree volume plugin as the provisioner. By far, there is no E2E case using them.

The vSphere environment also has two StorageClass files.
* The vsphere-legacy.yaml is used for the TKGm environment.
* The vsphere.yaml is used for the VKS environment.

The ZFS StorageClasses only have the default one. There is no in-tree volume plugin used StorageClass used in E2E.

The kind StorageClass uses the local-path provisioner. Will consider adding the CSI provisioner when there is a need.

The StorageClass definitions are configurable. `--storage-class-file` and
`--storage-class-file-2` take a manifest for each class, so a cluster whose volumes
need a different provisioner or parameters can be targeted without editing the files
here, for example pointing at a CSI driver on kind. The class names stay
`e2e-storage-class` and `e2e-storage-class-2`, since the test cases refer to them;
only the definition changes. Unset, the provider's own file above is used for both.

Setting `--storage-class-file-2` to the empty string runs without a second
StorageClass. The cases that map between two of them skip, and everything else runs.
