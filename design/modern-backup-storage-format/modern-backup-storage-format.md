# Backup Storage Format With Morden Encryption And Compression

## Glossary & Abbreviation
**Backup Storage**: The storage to persist the backup data and metadata. Check [Unified Repository design][1] for details.   
**BSL**: BackupStorageLocation. The Velero custom resource defining the Backup Storage.  
**Backup Storage Format**: The layout and format of the data in the Backup Storage.  
**Backup Repository**: Backup repository is layered between BR data movers and Backup Storage to provide BR related features for volume data. It is introduced in [Unified Repository design][1].  
**AEAD**: Authenticated Encryption with Associated Data. A cryptographic encryption mode that simultaneously guarantees confidentiality, integrity, and authenticity of data (e.g., AES-256-GCM).  
**AAD**: Additional Authenticated Data. Plaintext context data bound to the AEAD ciphertext and authenticated by the tag without being encrypted.  
**ESO**: External Secrets Operator. A Kubernetes operator that synchronizes secrets from external APIs (like HashiCorp Vault, AWS Secrets Manager, Azure Key Vault) into native Kubernetes `Secret` resources.  
**Zstd**: Zstandard. A real-time data compression algorithm developed by Meta providing high compression ratios and extremely fast decompression throughput.    
**HKDF**: HMAC-based Extract-and-Expand Key Derivation Function. Used to deterministically derive cryptographically isolated, domain-separated sub-keys.  
**CSE**: Client-Side Encryption. Encryption performed directly by the client before data is transmitted or uploaded to the backup storage.  
**SSE**: Server-Side Encryption. Encryption performed transparently at rest by the backup storage provider or storage appliance on receiving data.  


## Background

Velero persists backup data of Kubernetes resources and volumes, metadata, and logs into backup storages configured via BackupStorageLocation (BSL). Currently, the Backup Storage Format has several critical architectural and security limitations:

- **Lack of Complete Client-Side Encryption**  
   Backup data of Kubernetes resources are unencrypted. While backup storage providers may offer server-side encryption (SSE), Velero does not protect against compromised backup storage, rogue backup storage admins, or untrusted backup storage targets. Kubernetes `Secret` objects, private keys, tokens, and container environment variables reside in plaintext inside the archive.

- **Vulnerability to Malicious Data Injection ("Poisoned Backup" Attacks)**  
   Because Velero runs with `cluster-admin` privileges in Kubernetes and holds cloud provider IAM credentials:
   - An attacker with write access to the backup storage can modify `<backup-name>.tar.gz` to inject privileged containers, backdoors, or `restore.velero.io/exec` annotations, achieving Remote Code Execution (RCE) in the cluster upon restore.
   - An attacker can modify snapshot IDs in `<backup-name>-volumesnapshots.json.gz`. During backup deletion/garbage collection, Velero's `backup_deletion_controller` will call the cloud provider API to delete those snapshot IDs, acting as a "Deletion Oracle" to delete live, critical production snapshots.
   - An attacker can inject a forged `velero-backup.json`. The `backup_sync_controller` will adopt it into the cluster as a valid, completed backup ready for automated restore.

- **Inconsistent and Unsafe Public Exposure for Third Parties**  
   Third-party systems (dashboards, audit engines, and reporting tools) integrating with Velero frequently need to inspect volume backup progress, status, and size metrics. Currently, all metadata files are mixed together, and internal files contain raw infrastructure handles (e.g., `snapshotHandle`, `volumeHandle`) that pose security risks if exposed.

- **Slow Decompression Throughput with Gzip**  
   All files currently use single-threaded `compress/gzip`. Decompressing large manifest archives during disaster recovery can become a bottleneck, increasing Recovery Time Objective (RTO).

- **Lack of Key Management**  
   The backup repository already uses client-side encryption with a password stored in `velero-repo-credentials`. However, the password is not configurable after the backup repository is created. And it also lacks of an end to end key management to cover the whole lifecycle of a password.


## Goals

- **Deliver Backup Storage Format 2.0**  
   Establish a modernized, secure, and authenticated storage layout for Velero backups.

- **End-to-End Client-Side Authenticated Encryption**  
   Encrypt all internal resource backup data before uploading to the backup storage, using AEAD with Additional Authenticated Data (AAD) to prevent exfiltration, tampering, file swapping, and truncation attacks.

- **Unified Encryption Password for Resources and Volumes**  
   Share the encryption password between the resource backup engine and the volume backup engine (backup repository) under a single secret configuration and key management.

- **Vault-Ready Secret Architecture with Dynamic Lifecycle**  
   Allow the encryption password to be configured during BSL creation or modified/rotated afterwards via a Kubernetes Secret in the Velero namespace. Ensure compatibility with External Secrets Operator (ESO).

- **Auxiliary Data Classification and Optional Encryption**  
   Establish a formal classification and separation for Auxiliary Data distinct from unconditionally encrypted Core Data. Support optional, user-configurable encryption for sensitive auxiliary files. Strictly enforced as write-only for Velero core workflow to safely fulfill third-party observability without workflow tampering risks.

- **Modernize Compression with Zstandard (`zstd`)**  
   Adopt Zstandard compression across all compressed artifacts for 3x–5x faster decompression during disaster recovery restores.

- **Dual-Suite Persistence Architecture**  
   Implement Backup Storage Format 2.0 cleanly as a separate implementation alongside the frozen legacy store behind the existing `BackupStore` interface, avoiding invasive changes across controllers and making future legacy deprecation trivial.

- **Backward Compatibility**  
   Ensure Velero can switch between new and legacy Backup Storage Format implementations so as to seamlessly restore legacy Format backups.


## Non-Goals

- **Backup Storage Format 2.0 implementation supports legacy backup format**  
  Backup Storage Format 2.0 is aimed to replace legacy format gradually, so there is no plan to support legacy format (Format 1.x) in Backup Storage Format 2.0 implementation.

- **File Regulation or Modernization**  
  All existing files are kept as is in the backup storage. Files may be consolidated to remove redundancy or file names may be better regulated, this could be done with a future design.

- **Extend Unified Repo interface for data integrity check**  
  Velero expects backup repository providers to use AEAD encryption to guarantee the data integrity, so there is no plan to extend Unified Repo interface to support extra data integrity check workflows.

- **WORM Support**  
  Velero at present doesn't support WORM (Write Only Read Many) backup storage, this design has no goal to fix this gap.

- **File Deletion Detection**  
  Files may be deleted from the backup storage by accident or attack, missing files may cause Velero behaves erroneously. This design won't aim to solve this file omission problem considering the architecture flexibility, object storage characteristic. If it becomes a concern, a separate design is required to solve it.  
  

## Architecture

### Format 1.x vs. Format 2.0

Format 2.0 fully covers Format 1.x from functionality, but strategically, Format 1.x will be there as is. Users are free to select Format 2.x or Format 2.0 when creating a new BSL.  
For long-term, Format 1.x may be deprecated when Format 2.0 is mostly adopted.  

### Format 1.x vs. Format 2.0 Directory Layout

Below are the backup storage file layout before and after the change:

```text
Format 1.x (Legacy)                                Format 2.0 (Modernized & Encrypted)
<bucket>/[<prefix>/]                              <bucket>/[<prefix>/]
├── backups/                                      ├── velero-storage.json                             [ENCRYPTED]
│   └── <backup-name>/                            ├── backups/
│       ├── velero-backup.json (Plaintext)        │   └── <backup-name>/
│       ├── <name>.tar.gz     (Plaintext)         │       ├── velero-backup.json                      [ENCRYPTED]
│       ├── <name>-logs.gz    (Plaintext)         │       ├── <name>.tar.zst                          [ENCRYPTED]
│       ├── <name>-results.gz (Plaintext)         │       ├── <name>-results.json.zst                 [ENCRYPTED]
│       ├── <name>-volumeinfo.json.gz             │       ├── <name>-volumeinfo.json.zst              [ENCRYPTED]
│       ├── <name>-volumesnapshots.json.gz        │       ├── <name>-volumesnapshots.json.zst         [ENCRYPTED]
│       ├── <name>-podvolumebackups.json.gz       │       ├── <name>-podvolumebackups.json.zst        [ENCRYPTED]
│       ├── <name>-itemoperations.json.gz         │       ├── <name>-itemoperations.json.zst          [ENCRYPTED]
│       ├── <name>-resource-list.json.gz          │       ├── <name>-public.json                      [PLAINTEXT]
│       └──                                       │       ├── <name>-logs.zst                         [CONFIGURABLY ENCRYPTED]
│                                                 │       └── <name>-resource-list.json.zst           [CONFIGURABLY ENCRYPTED]
├── restores/                                     ├── restores/
│   └── <restore-name>/                           │   └── <restore-name>/
│       ├── restore-<name>-logs.gz                │       ├── restore-<name>-results.json.zst         [ENCRYPTED]
│       ├── restore-<name>-results.gz             │       ├── restore-<name>-volumeinfo.json.zst      [ENCRYPTED]
│       ├── <name>-volumeinfo.json.gz             │       ├── restore-<name>-itemoperations.json.zst  [ENCRYPTED]
│       ├── restore-<name>-itemoperations.json.gz │       ├── restore-<name>-public.json              [PLAINTEXT]
│       └── restore-<name>-resource-list.json.gz  │       ├── restore-<name>-logs.zst                 [CONFIGURABLY ENCRYPTED]
│                                                 │       └── restore-<name>-resource-list.json.zst   [CONFIGURABLY ENCRYPTED]
└── kopia/ (Encrypted repo data)                  └── kopia/ (Encrypted repo data)
```

Except encryption and compression, logical contents in files are mostly not changed. Some duplication and merge are made to make sure this rule -- a file is either used by Velero Core workflow or for Auxiliary purposes.  
Core files are used by Velero internal workflows, e.g., backup and restore. They should be strictly encrypted, tampering the files may change Velero workflows so damage the backup or restore.  
Auxiliary files are used for observability telemetry, diagnostic results, execution logs, and resource catalogs, so will be used by both Velero (non-core workflows) and 3rd tools. Velero core workflows should keep write-only to these files, so tampering these files won't affect Velero core workflows.   

Auxiliary files may contain sensitive information as well, though are less sensitive than Core files, so they still require encryption. On the other hand, once these files are encrypted, 3rd must call Velero's SDK to retrieve the data.  
It is highly recommended to make Velero backup storage fully encrypted, but it is up to the callers to make trade-off on whether to refactor their data or leave the Auxiliary data unencrypted with security risks.  
From Velero side, a configurable encryption solution is provided, users or 3rd tools could choose to encrypt these files or not.

There are special Auxiliary files `<name>-public.json` which are called Public Data Interface, they are kept as plaintext all the time. These files store the most commonly used observability information for backup/restore, if the requirements are for basic observation, these files are sufficient, so the caller don't need to retrieve the encrypted data. E.g., Velero commands `velero backup describe` and `velero restore describe` will use these files.    

Below lists the Core files:
- `velero-storage.json`
- `<backup-name>/velero-backup`
- `<backup-name>/<name>.tar.zst`
- `<backup-name>/<name>-results.json.zst`
- `<backup-name>/<name>-volumeinfo.json.zst`
- `<backup-name>/<name>-volumesnapshots.json.zst`
- `<backup-name>/<name>-podvolumebackups.json.zst`
- `<backup-name>/<name>-itemoperations.json.zst`
- `<restore-name>/<name>-results.json.zst`
- `<restore-name>/<name>-volumeinfo.json.zst`
- `<restore-name>/<name>-itemoperations.json.zst`

Below lists the Auxiliary files:
- `<backup-name>/<name>-public.json`
- `<backup-name>/<name>-logs.zst`
- `<backup-name>/<name>-resource-list.json.zst`
- `<restore-name>/<name>-public.json`
- `<restore-name>/<name>-logs.zst`
- `<restore-name>/<name>-resource-list.json.zst`

`<name>-results.json.zst` files (backup and restore) are for a single purpose -- composing Public Data Interface. However, they are not Auxiliary files, client or 3rd tools should not read this file directly.  


### Root Storage Descriptor (RSD)
Root Storage Descriptor (`velero-storage.json`) is a new file added to the backup storage, it includes the information describing Velero usage of the backup storage, e.g., the encryption and compression information.  

### Format Switch
The implementation for Format 1.x is kept as is. And a new implementation for Format 2.0 is added.  
In Root Storage Descriptor, a piece of format version information is recorded, so if Format version 2.0, the new implementation is called; otherwise, it fallbacks the old implementation.  

The same format version also exists in BSL spec, so the value in BSL must match the truth of the data in the backup storage, otherwise, the BSL goes to `Unavailable`.   

### Unified Encryption Password

In the normal workflow, a single password configured in a Kubernetes Secret is provided by users. Velero use this password for all data encryption, i.e., resource data, metadata, volume data.  

Velero never transfer or copy the Kubernetes Secret to other persistent location.  

A Key Encryption Key (KEK) is derived from the user password. The KEK then encrypts a per-BSL Master Key (BMK). From this Master Key, Velero deterministically derives:
- **Resource Data Encryption Key (`DEK_resource`)**: A 256-bit Data Encryption Key derived per BSL via HKDF with domain separation to encrypt Kubernetes resource backup data and Velero metadata files with AES-256-GCM.
- **Backup Repository Passwords (`DEK_repo`)**: Backup repository passwords derived per backup repository via HKDF with strict domain separation. The password is provided to the backup repository through the existing workflow of Unified Repo. How the password is used is decided by the specific backup repository.  

The Kubernetes Secret is provided by callers, e.g., users, or ESO/Gitops tools. The secret should be in Velero namespace. Multiple BSLs could share the same secret through different keys.  
BMK is a 256 bits random key generated during BSL initialization, after that, BMK is never changed.
DEK_resource and DEK_repo are derived from BMK so they are unchanged as well after BSL is initialized.  
DEK_resource and DEK_repo stays in memory all the time, they are never persisted.   
KEK is generated from User Password so in the case of user password rotation, KEK is also rotated and a new wrap of BMK should be generated.  
BMK, KEK and DEK are never exposed to users in all concirmstances.  

Velero never persist the above keys in plain texts.  

For resource backup data, Velero always uses AES-256-GCM which covers both data encryption and data integrity verification.  
For volume backup data, the encryption method is decided by the backup repository implementing the Unified Repo. For the built-in Kopia repository, Velero uses the default encryption method which is also AES-256-GCM.

This means, for Velero built-in data path, it guarantees the backup data tamper-proof in Backup Storage Format 2.0, no need to add any extra mechanism.  

```text
[User Password in Secret]
            │
            ▼ (Salt)
[Key Encryption Key (KEK)]              [BSL Master Key (BMK)]
            │                                     │
            │                                     │
            └──────────────────┬──────────────────┘
                               │ KEK Wraps MK (AES-256-GCM)
                               ▼
         ┌────────────────────────────────────────────┐
         │ Backup Store:                              │
         │ velero-storage.json (Contains BMK Envelope)│
         └─────────────────────┬──────────────────────┘
                               │
                               │ (Unwrapped into RAM via KEK during operations)
                               ▼
                      [BSL Master Key (BMK)]
                               │
                               ▼ In-Memory HKDF Derivation
             ┌─────────────────┴─────────────────┐
             ▼                                   ▼
       [DEK_resource]                        [DEK_repo]
        - Encrypts resource tar & metadata    - Backup repository password
```

#### Cloned RSD in BSL

A clone of RSD is stored into the corresponding BSL CR, for three purposes:  
- To guarantee a recovery when Root Storage Descriptor is lost or corrupted, make another redundancy in the cluster etcd
- To deliver the encryption envelop to other modules from Velero server, e.g., data mover pods, repository maintenance jobs, so that they don't need to access the backup storage unnecessarily
- To do a cross check against the RSD in the backup storage so as to detect unexpected mutation of the RSD in backup storage

The cloned RSD in BSL is not fully trustful, therefore:
- When recover RSD from the BSL clone, users should guarantee the cloned data is correct
- The backup repository is initialized by Velero server only, so that other modules won't create a backup repository with wrong password that is from the cloned RSD
- Velero server never unwrap BMK from the BSL clone, instead it always get it from the RSD in backup storage. The BSL clone is used for cross check only

RSD in BSL and in the backup storage may mismatch in below cases:
1. Password rotation happens in the current cluster, so the BSL's status is set as `Unavailable`
1. Password rotation happens in another cluster. Since Velero in the current cluster is not aware of it, the BSL's status is kept as is
2. New cluster onboarding, users create a new BSL CR in the current cluster and point it to an existing backup storage
3. BSL update, users update the BSL and point it to a different backup storage, so the BSL's status is set as `Unavailable`
4. ETCD data rollback, corruption or accidentally update to the BSL. Since Velero in the current cluster is not aware of it, the BSL's status is kept as is

In all these cases:
- If the RSD is still available and working, the BMK generated from it is still valid, because BMK is created once and immutable. Then the activities, e.g., backup, restore, repository maintenance, could work normally without breaking
- If the RSD is either absent or not working, a BSL sync is required to retrieve the RSD from the backup storage 

#### Password Rotation
It guarantees O(1) complexity for password rotation. That is the complexity is not increase along with the number of backups or backup repositories.   

To fully secure the password rotation process, a Password Rotation Request is introduced.  

Password rotation involves two secrets:
 - `active-password`: the existing/active password the BSL is using, it is referred by the BSL CR
 - `target-password`: the new password to be changed to, it is referred by the Password Rotation Request CR

Users should carefully follow some rules for password rotation:
1. Always use the Password Rotation Request for changing `active-password`; they should not change it directly in BSL.  
2. When multiple clusters share the same BSL, Password Rotation Request should be launched in each of the clusters with **Exactly the same** password. Otherwise, RSD encryption envelop will be overwritten. It is not recommended to launch the rotations among multiple clusters simultaneously, users should launch it one after another.   

Velero does below steps for the password rotation:
1. Set BSL CR to `unavailable`
2. Computes KEK_old from `active-password`
3. Unwraps BMK from `velero-storage.json` in memory
4. Computes KEK_new from `target-password`
5. Re-wraps BMK in memory
6. Update `velero-storage.json` in the backup storage
7. Update the `active-password` in BSL CR and set BSL to `available`

The existing backup data or Velero metadata is not touched, and the existing backup repositories' password is not changed, because the DEK is not changed.  

Password rotation is launched by an explicit request by users, just changing the secrets won't trigger the rotation. This is for two purposes:
- Ensure password rotation is always under users' awareness, so that they have oppotunity to backup the RSD
- Ensure the BSL is set to `unavailable` before the rotation, so that no new activities are launched during the password rotation

After password rotation starts, no new backup storage access activities should be started; existing activities which have already been running could continue, no functionality breaks.  

Password rotation steps are processed strictly in sequence. In that way, at a time, the system is always encrypted with `active-password` in the BSL CR, as long as the BSL is in `available` state; otherwise, BSL is not ready to use and password rotation will retry.  

When the password rotation completes, the old `active-password` secret is out of use, Velero won't delete is automatically because the secret may be managed by other gitOps secret management tools. Users should delete it based on their own secret management policies.  

### Root Storage Descriptor Recovery
The information in Root Storage Descriptor is critical, once it is lost or corrupted, all the data in the backup storage will be inaccessible. There are mechanisms from different levels to protect the system from falling to this catersphic situation.  

#### Detect Root Storage Descriptor Corruption/Lost/Tampering
Below mechanisms are used to detect corruption of Root Storage Descriptor:
1. Calculate a hash of fields in `velero-storage.json` and save it to `velero-storage.json` for cross check
2. Check BMK in `velero-storage.json` through the same AES-256-GCM
3. Check BMK fingerprint. While 1 and 2 are mostly for detection of unintentional changes, this is for detection of intentional changes from attackers, which may silently poison the backup data

A periodical sync task is required for each backup storage to do this detection. When any level of checks fail, the BSL will be set to `unavailable` and data operations, including write and read, are forbidden.  
Once BSL is unavailable due to RSD check errors, users need to interfere and recover the RSD manually.     

#### Recover Root Storage Descriptor
3 tiers of reduncencies for Root Storage Descriptor are recommended:
1. [out of scope of Velero] A side by side protection of Recover Root Storage Descriptor from the backup storage is highly recommended. E.g., enable the object versioning for this `velero-storage.json` object in the object storage
2. [default and automatic] Clone in BSL. Since the BSL clone is not fully trustful, users need to do manual checks and guarantee it is correct, before restoring it to the backup storage.
3. [out of current Velero instance] A side by side protection of RSD from Velero Self Protection. Velero Self Protection is a separate feature in backlog for backup/restore Velero's own data which includes the RSD as well. Once this feature is ready, users is expected to do backups before password rotation and when the Recover RSD in the backup storage is detected as corrupted/lost, it could be restored from the Self Protection backup.

To use Tier-1 reduncency, users need to stop all Velero activities of the backup storage location and rollback the `velero-storage.json` from the storage side. Velero is unaware of this process.  

To use Tier-2 and Tier-3 redundancy, BSL is either available or restored from Velero self protection backup, then users need to extract the Root Storage Descriptor from the BSL, stop all Velero activities of the backup storage location and upload to the backup storage.  
The Recover Root Storage Descriptor in the backup storage is always the source of truth, so Velero won't sync it back to the backup storage automatically.  

### Modernize Compression

gzip is not performing well in compression ratio for Velero resource backup tarballs, the sliding window size is only 32KB, so Kubernetes resources which are typically several or dozens of KB in size and there are duplicated data among resources, the compression ratio is poor.  

For Format 2.0, Zstd is used for compression. Zstd is a modern compression method with much larger sliding window size, so brings much better compression/decompression throughput, compression ratio, and is also optimized for modern CPU and Kubernetes environments. Below is a detailed compression between gzip and Zstd:  

| Feature / Dimension | gzip | Zstandard |
| :--- | :--- | :--- |
| **Sliding Window Size** | **Strictly Fixed at 32 KB** | **Configurable: 4 MB Default** (Supports up to 2 GB) |
| **Compression Throughput** | ~30 – 45 MB/s per core (Level 6 Default) | **~250 – 350 MB/s per core** (Level 3 `SpeedDefault`) |
| **Decompression Throughput** | ~200 – 320 MB/s per core | **~1,200 – 1,800 MB/s per core** |
| **Compression Ratio** | Baseline ($1.00\times$) | **~1.15x – 1.25x better** ($15\%\text{--}25\%$ smaller footprint) |
| **Decompression Scalability** | Bound to bit-level serial Huffman decoding | Optimized for branch prediction & SIMD/AVX2/NEON register pipelines |
| **Encoder Memory Footprint** | ~256 KB – 1 MB | **~8 MB – 12 MB** (at 4 MB window size) |
| **Decoder Memory Footprint** | ~32 KB | **~4 MB** (determined by stream window size) |
| **CPU Throttling Resilience** | **Poor**: High CPU time per byte frequently triggers Kubernetes CFS quota throttling | **Excellent**: Low CPU instructions per byte minimizes throttling spikes under cgroups v1/v2 quotas |

### Encryption and Data Integrity

For resource data, Format 2.0 always uses AES-256-GCM which is a method of AEAD. Specifically, it produces ciphertext together with an authentication tag covering both the encrypted data and AAD. During decryption, the tag is verified; modification of the ciphertext or AAD causes verification to fail.  
Therefore, it provides data integrity verification alongside confidentiality, without requiring a separate checksum for data integrity verification.  

For volume data, Velero delegates authenticated encryption and integrity verification to the backup repository and relies on it to report authentication failures.  
For Velero built-in backup repository, Velero uses the default encryption method of Kopia repository, which is also AES-256-GCM, so data integrity verification is already covered.  


### Velero CSE and SSE

CSE is required to meet the requirements for end-to-end confidentiality and integrity of backup content, independently of storage access permissions.  

Even when SSE operates correctly, it does not establish that the content was produced by Velero or belongs to the expected backup context. Or in another word, SSE cannot provide end to end backup data integrity.  
Velero CSE requires a separate key to encrypt content and generate valid authentication tags, and binds protected files to their backup context. That is to say, as long as the data could be decrypted, it guarantees that the data stream is complete and matches the expected backup.    

CSE and SSE are complementary. Velero encrypts and authenticates protected content before persistency; SSE can then encrypt that ciphertext again at the storage layer.  

Below lists the threat models, which layer fixes them and how:  

| Threat Model | Mitigating Layer | SSE | Velero CSE |
| :--- | :--- | :--- | :--- |
| **Physical Storage Media Theft**| **Both** | 🏆 Physical disk blocks are encrypted under storage system KMS keys. | 🏆 Bytes written to storage are already opaque AES-256-GCM ciphertext. |
| **Compromised Storage Credentials** | **CSE** | ❌ Storage system automatically decrypts SSE for any identity with read permissions. | 🏆 Workload manifests and secrets are encrypted before uploading; storage holds only ciphertext. |
| **Tampered Backup Data** | **CSE** | ❌ SSE only encrypts writes at rest; it blindly encrypts and accepts any malicious payload written by an authorized storage writer. | 🏆 Enforces AES-256-GCM authenticated streaming encryption with GMAC tags and AAD context binding. Any modified bit or injected backdoor fails authentication and aborts the restore. |
| **Accidental Open or Misconfigured Storage Exposure** | **CSE** | ❌ Storage system automatically decrypts and serves plaintext manifests to any caller allowed by storage policy. | 🏆 Unauthorized downloaders only receive opaque AES-256-GCM ciphertext streams; unauthorized downloaders cannot inspect cluster secrets or configurations without the cluster encryption key. |
| **Cross-Backup Swapping / File Substitution Attack** | **CSE** | ❌ SSE is file-agnostic; it decrypts any file verifying workload context. | 🏆 AAD strictly binds `bslID`, `backupName`, and `fileName` into the GMAC polynomial computation. Moving `<name>.tar.zst` from `backup-A` to `backup-B` alters the AAD context string, causing GMAC verification to fail immediately upon restore. |
| **Storage Infrastructure Operator Threat & Untrusted Shared Storage** | **CSE** | ❌ Storage platform manages or holds access to the underlying SSE storage encryption keys. | 🏆 Key derivation and unwrapping occur strictly in customer Kubernetes cluster RAM. Infrastructure operators and storage platform admins cannot decrypt workload archives because root keys never leave the customer cluster/vault. |
| **Snapshot Deletion Oracle Manipulation** | **CSE** | ❌ SSE allows storage writers to alter metadata files as long as they have storage write permissions. | 🏆 Internal volume snapshot metadata is unconditionally encrypted with AES-256-GCM. The garbage-collection controller cannot be tricked into deleting wrong volume snapshots because tampered snapshot metadata files fail GMAC authentication. |
| **Emergency Out-of-Band Storage Revocation** | **SSE** | 🏆 Disabling or revoking the KMS key  at the storage layer instantly denies all storage read/write access cluster-wide. | ℹ️ Revocation must be performed within Kubernetes by updating or deleting the in-cluster Secret. |
| **Automated Storage Compliance Auditing** | **SSE** | 🏆 Fulfills storage security benchmarks and compliance policies requiring storage-level encryption at rest. | N/A |

## Detailed Design

### Data for Resource Backup/Restore

Below are the data flow in Format 2.0 for backup and restore:  

```
Serialize (JSON/TAR) ──► Compress (zstd) ──► Encrypt (AES-256-GCM) ──► Upload
```

```
Download ──► Decrypt & Authenticate GMAC ──► Decompress (zstd) ──► Deserialize (TAR/JSON) ──► Apply
```

### Data for Volume Backup/Restore

The data flow for volume backup/restore is not changed. Merely, in Format 1.x, the backup repository password is from a predefined Kubernetes secret `velero-repo-credentials` (default value `static-passw0rd`); in Format 2.0, the password is from a dynamically derived `DEK_repo` and unknown by users.


### RSD Spec
Below is the spec of RSD:
```go
type StorageDescriptor struct {
    FormatVersion                 string                         `json:"formatVersion"`
    BSLID                         string                         `json:"bslID"`
    MinVeleroVersion              string                         `json:"minVeleroVersion"`
    Compression                   CompressionConfig              `json:"compression"`
    KDF                           KDFConfig                      `json:"kdf"`
    HeaderChecksum                string                         `json:"headerChecksum"`
    Encryption                    EncryptionEnvelope             `json:"encryption"`
    AuxiliaryDataEncryption       *AuxiliaryDataEncryption `json:"auxiliaryDataEncryption,omitempty"`
}

type CompressionConfig struct {
    Algorithm string `json:"algorithm"`
    Level     int    `json:"level"`
}

type KDFConfig struct {
    Algorithm  string    `json:"algorithm"`
    Salt       string    `json:"salt"`
    Iterations int       `json:"iterations"`
    PRF        string    `json:"prf"`
}

type EncryptionEnvelope struct {
    Algorithm            string `json:"algorithm"`
    WrappedKey           string `json:"wrappedKey"`
    KeyFingerprint       string `json:"keyFingerprint"`
}

type AuxiliaryDataEncryption struct {
    EncryptResourceList bool `json:"encryptResourceList,omitempty"`
    EncryptLogs         bool `json:"encryptLogs,omitempty"`
}
```

### BSL Spec
Below are the modified/added fields into BSL:

```go
type BackupStorageLocationSpec struct {
    // StorageFormat specifies the backup storage format version for this location.
    // Supported values:
    // - "1.1.0": Legacy format (gzip compression, unencrypted manifests, no RSD).
    // - "2.0.0": Modern format (zstd compression, AES-256-GCM client-side encryption, RSD).
    // If omitted, defaults to "1.1.0"
    // +optional
    StorageFormat string `json:"storageFormat,omitempty"`

    // Encryption specifies client-side encryption settings for backups stored in this location.
    // +optional
    Encryption *BSLEncryptionConfig `json:"encryption,omitempty"`
}

type BSLEncryptionConfig struct {
    // SecretKeyRef specifies the Kubernetes Secret containing the passphrase.
    // Fallback to bsl-encryption secret if not specified.
    // +optional
    SecretKeyRef *corev1.SecretKeySelector `json:"secretKeyRef,omitempty"`

    // AuxiliaryDataEncryptionConfig specifies initialization-time encryption settings for auxiliary data.
    // Configured by the user when creating the BSL CR.
    // +optional
    // +kubebuilder:validation:XValidation:rule="self == oldSelf",message="auxiliaryDataEncryptionConfig is immutable after BSL creation"
    AuxiliaryDataEncryptionConfig *AuxiliaryDataEncryption `json:"auxiliaryDataEncryptionConfig,omitempty"`
}

type BackupStorageLocationStatus struct {
    // StorageDescriptor records the in-cluster clone of the root storage descriptor.
    // +optional
    StorageDescriptor *StorageDescriptor `json:"storageDescriptor,omitempty"`
}
```

### BSL Initialization
At present, when creating a new BSL, nothing is written to the backup storage, only the connection to the backup storage is verified.  
For Format 2.0, when a new BSL is created, the Root Storage Descriptor needs to be generated and written to the backup storage.  
Below diagram shows what happens during BSL initialization.    

```text
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                                                                                                             │
│ [Admin / GitOps]        [API Server]                      [Velero Server]                              [Backup Storage]     │
│        │                     │                                   │                                            │             │
│  Apply BSL CR with Secret    │                                   │                                            │             │
│        ├────────────────────►│                                   │                                            │             │
│        │                     │                                   │                                            │             │
│        │                     │            Reconcile              │                                            │             │
│        │                     ├──────────────────────────────────►│                                            │             │
│        │                     │                                   │                                            │             │
│        │                     │          Fetch Passphrase         │                                            │             │
│        │                     │◄──────────────────────────────────┤                                            │             │
│        │                     │       (bsl-encryption Secret)     │                                            │             │
│        │                     │──────────────────────────────────►│                                            │             │
│        │                     │                                   │                                            │             │
│        │                     │                                   │                 Probe RSD                  │             │
│        │                     │                                   ├───────────────────────────────────────────►│             │
│        │                     │                                   │               (NoSuchObject)               │             │
│        │                     │                                   │◄───────────────────────────────────────────┤             │
│        │                     │                                   │                                            │             │
│        │                     │                                   │  Generate RSD:                             │             │
│        │                     │                                   │  • bslID = UUID                            │             │
│        │                     │                                   │  • BMK = 256-bit random bytes              │             │
│        │                     │                                   │  • Salt = 16-byte random bytes             │             │
│        │                     │                                   │  • AAD = RSD header                        │             │
│        │                     │                                   │  • iter = 600000                           │             │
│        │                     │                                   │  • KEK = PBKDF2(Passphrase, Salt, iter)    │             │
│        │                     │                                   │  • wrappedKey =                            │             │
│        │                     │                                   │    AES-GCM-Encrypt(KEK, BMK, AAD)          │             │
│        │                     │                                   │  • keyFingerprint =                        │             │
│        │                     │                                   │    "sha256:" + Hex(SHA256(BMK))            │             │
│        │                     │                                   │  • headerChecksum =                        │             │
│        │                     │                                   │    "sha256:" + Hex(SHA256(header))         │             │
│        │                     │                                   │                                            │             │
│        │                     │                                   │                 Upload RSD                 │             │
│        │                     │                                   ├───────────────────────────────────────────►│             │
│        │                     │                                   │                    (OK)                    │             │
│        │                     │                                   │◄───────────────────────────────────────────┤             │
│        │                     │                                   │                                            │             │
│        │                     │                                   │   In-Memory Key Processing:                │             │
│        │                     │                                   │   • Cache BMK                              │             │
│        │                     │                                   │                                            │             │
│        │                     │         Patch BSL Status          │                                            │             │
│        │                     │◄──────────────────────────────────┤                                            │             │
│        │                     │  • storageDescriptor = RSD        │                                            │             │
│        │                     │  • lastValidationTime = Now()     │                                            │             │
│        │                     │  • phase = "Available"            │                                            │             │
│        │     BSL Ready       │                                   │                                            │             │
│        │◄────────────────────┤                                   │                                            │             │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

BSL initialization can happen in one cluster only. Therefore, RSD initialization must use atomic create-if-absent and must never overwrite an existing RSD. If the RSD already exists in the backup storage, the BSL initialization automatically switches to BSL Sync.  

Parameters should be added to `velero backup-location create` and `velero backup-location delete` CLI accordingly.  

### BSL Sync
BSL is synced and verified against the existing backup storage in below cases:
1. Whenever an existing BSL's status is `Unavailable`
2. When a new BSL CR is created and the backup storage is already created by other clusters. This is a special case of 1
3. A periodical sync time reaches 

In normal cases, the BSL is either set as `Unavailable` so a sync starts immediately or the RSD in the BSL is still usable so an immediate sync is not required.  

The periodical sync is used to take case of below cases:
- Immediate sync is not required as the RSD is still usable but in long term, make it synced with the backup storage
- Fix the BSL for any abnormal cases (e.g., unexpected update of BSL) that RSD in BSL is not working but BSL keeps in `Available` state

The workflow for BSL sync (for either periodical sync or on demand sync) is as below:  

```text
┌────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                                                                                                            │
│      [API Server]                           [Velero Server]                                  [Backup Storage]              │
│           │                                        │                                                │                      │
│      Sync Trigger                                  │                                                │                      │
│           ├───────────────────────────────────────►│                                                │                      │
│           │                                        │                                                │                      │
│      Fetch Passphrase                              │                                                │                      │
│           │◄───────────────────────────────────────┤                                                │                      │
│           │  (Secret: active-password)             │                                                │                      │
│           ├───────────────────────────────────────►│                                                │                      │
│           │                                        │                                                │                      │
│           │                                        │                       Read RSD                 │                      │
│           │                                        ├───────────────────────────────────────────────►│                      │
│           │                                        │                                                │                      │
│           │                                        │◄───────────────────────────────────────────────┤                      │
│           │                                        │                    velero-storage.json         │                      │
│           │                                        │                                                │                      │
│           │                                        │  Fast Integrity Check                          │                      │
│           │                                        │  • Assert BSL format vs. RSD format            │                      │
│           │                                        │  • (Fail BSL Sync if mismatch)                 │                      │
│           │                                        │  • Compute SHA256                              │                      │
│           │                                        │  • Assert with headerChecksum                  │                      │
│           │                                        │  • (Fail BSL Sync if corrupted)                │                      │
│           │                                        │                                                │                      │
│           │                                        │  Key Unwrapping                                │                      │
│           │                                        │  • KEK = PBKDF2(Pass, salt, iter)              │                      │
│           │                                        │  • BMK =                                       │                      │
│           │                                        │    AES-256-GCM-Decrypt(KEK, wrappedKey, AAD)   │                      │
│           │                                        │                                                │                      │
│           │                                        │  ┌─────────────────────────────────────────────┤                      │
│           │                                        │  │ Decryption Succeeded?                       │                      │
│           │                                        │  ├─────────────────────────────────────────────┤                      │
│           │                                        │  ▼ SUCCESS:                                    │                      │
│           │                                        │  • Assert SHA256(BMK) with keyFingerprint      │                      │
│           │                                        │  • (Fail BSL Sync if no match)                 │                      │
│           │                                        │  • Assert keyFingerprint with BSL Clone        │                      │
│           │                                        │  • (Fail BSL Sync if no match)                 │                      │
│           │                                        │  • Cache BMK                                   │                      │
│           │                                        │                                                │                      │
│           │                                        │  ▼ FAILURE:                                    │                      │
│           │                                        │  • Fail BSL Sync                               │                      │
│           │                                        │                                                │                      │
│       Patch BSL Status                             │                                                │                      │
│           │◄───────────────────────────────────────┤                                                │                      │
│           │  • storageDescriptor = RSD             │                                                │                      │
│           │  • phase = "Available"                 │                                                │                      │
│           │  • lastValidationTime = Now()          │                                                │                      │
└────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

#### Fail BSL Sync
BSL sync failure happens in below cases:
1. Failure on fast integrity check: this indicates to the data corruption of RSD in the backup storage
2. Failure on BMK unwrapping: this means the in-cluster secret cannot decrypt the key envelop, which implies wrong password in the secret, or wrong backup storage location is referred by the BSL, or corruption of RSD in the backup storage, or rollbacked RSD in the backup storage
3. Failure on BMK fingerprint check: this may imply attacks to the data in backup storage, e.g., an attacker generates a new and keep the BMK fingerprint (because BMK fingerprint is never changed, once it is changed, it is detected as an attack immediately); this may also imply wrong operations during manual compose RSD in the backup storage, e.g., for disaster recovery of RSD

Along with this action, Velero sets the BSL to `unavailable`. And users need to do manual steps to recover the RSD and BSL, varying on different cases:

| Failure Mode| Storage State | Recovery Procedure |
| :--- | :--- | :--- |
| **Passphrase Failure** | **Valid & Intact** | Update the `Secret` with the valid password. Velero immediately retries decryption, unwraps `BMK`, and heals to `Available`. |
| **Missing RSD** | **Missing** | Restore previous version via RSD backup, OR export from `BSL` clone and upload to backup storage. |
| **Corrupted RSD** | **Corrupted** (invalid JSON syntax or `headerChecksum` digest mismatch) | Restore previous version via RSD backup, OR export from `BSL` clone and upload to backup storage. |
| **BMK Tampering** | **Foreign / Rogue BMK**: RSD was replaced with an envelope wrapping a different BMK | Investigate unauthorized bucket tampering or accidental bucket prefix collision. Restore previous version via RSD backup, OR export from `BSL` clone and upload to backup storage. |
| **keyFingerprint Inconsistency** | **Malformed / Tampered**: File decrypts, but `SHA-256(BMK) != keyFingerprint` |  Restore previous version via RSD backup, OR export from `BSL` clone and upload to backup storage. |
| **In-Cluster Secret Missing** | `actrive_password secret missing' or key in the secret is missing or empty` | Create or repair the `Secret` in the Velero namespace. |

Before using the BSL clone RSD, verification should be done first, the verification is similar to the storage RSD verification:

```text
+-----------------------------------------------------------------------------------------+
|  [Check 1: Presence Check]                                                             |
|  Get BSL from cluster                                                                  |
|         │                                                                              |
|         ▼ PASS                                                                         |
|  [Check 2: Check clone RSD availability from BSL]                                      |
|         │                                                                              |
|         ▼ PASS                                                                         |
|  [Check 3: Structural Completeness]                                                    |
|  Validate all required fields: bslID, salt, iterations, wrappedKey, keyFingerprint     |
|         │                                                                              |
|         ▼ PASS                                                                         |
|  [Check 4: Header headerChecksum]                                                      |
|  Assert SHA-256(RSD) == headerChecksum                                                 |
|         │                                                                              |
|         ▼ PASS                                                                         |
|  [Check 5: Decryptability & Key Binding]                                               |
|  Assert SHA-256(AES-GCM-Decrypt(wrappedKey)) == keyFingerprint                         |
+----------------------------------------------------------------------------------------+
```
Once the verification fails, the clone RSD cannot be used by the recovery.  

A CLI `velero rsd verify` is provided to provide this verification. The CLI supports both BSL verification or standalone RSD verification.  
For BSL verification, BSL name is the only parameter.  
For standalone RSD verification, `rsd-file` and `password-file` should be specified for the location of the RSD and password.  

### BMK Envelop Delivery
Data mover pods and backup repository maintenance jobs retrieve BMK envelop from the cloned RSD in BSL, in this way, they will not need to access RSD in the backup storage.   

Below diagram takes data mover pods for example to show the sequence of backup repository access. Backup repository maintenance jobs are doing exactly the same.  

```text
┌──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│       Backup Repository                     API Server                    Data Mover Controller                   Data Mover         │
│              │                                  │                                  │                                  │              │
│              │                                  │                                  │                                  │              │
│              │                                  │              Read BSL            │                                  │              │
│              │                                  │◄─────────────────────────────────│                                  │              │
│              │                                  │           Returns: { Phase }     │                                  │              │
│              │                                  │─────────────────────────────────►│                                  │              │
│              │                                  │                                  │                                  │              │
│              │                                  │ ┌───────────────────────────────────────┐                           │              │
│              │                                  │ │ NODE-AGENT BSL AVAILABILITY CHECK:    │                           │              │
│              │                                  │ │ ├─► BSL.Status.Phase != "Available":  │                           │              │
│              │                                  │ │ │   • Abort and reconcile later       │                           │              │
│              │                                  │ └───────────────────────────────────────┘                           │              │
│              │                                  │                                  │                                  │              │
│              │                                  │                                  │                Launch            │              │
│              │                                  │                                  │─────────────────────────────────►│              │
│              │                                  │                                  │                                  │              │
│              │                                  │                             Read BSL                                │              │
│              │                                  │◄────────────────────────────────────────────────────────────────────│              │
│              │                                  │            Returns: { Phase, StorageDescriptor, SecretRef }         │              │
│              │                                  │────────────────────────────────────────────────────────────────────►│              │
│              │                                  │                                  │                                  │              │
│              │                      ┌──────────────────────────────────────────────────────┐                          │              │
│              │                      │ DATA MOVER BSL AVAILABILITY CHECK:                   │                          │              │ 
│              │                      │ ├─► If BSL.Status.Phase != "Available":              │                          │              │
│              │                      │ │   • Abort and retry later                          │                          │              │
│              │                      └──────────────────────────────────────────────────────┘                          │              │
│              │                                  │                                  │                                  │              │
│              │                                  │                       Read bsl-encryption secret                    │              │
│              │                                  │◄────────────────────────────────────────────────────────────────────│              │
│              │                                  │                        Returns: user passphrase                     │              │
│              │                                  │────────────────────────────────────────────────────────────────────►│              │
│              │                                  │                                  │                                  │              │
│              │                      ┌─────────────────────────────────────────────────────────┐                       │              │
│              │                      │ IN-MEMORY KEY DERIVATION:                               │                       │              │
│              │                      │ • KEK = PBKDF2(passphrase, salt, iterations)            │                       │              │
│              │                      │ • BMK = AES-256-GCM-Decrypt(KEK, wrappedMasterKey, AAD) │                       │              │
│              │                      │ • Assert SHA256(BMK) == BSL.Status.keyFingerprint       │                       │              │
│              │                      │ • (Fail if no match)                                    │                       │              │ 
│              │                      │ • DEK_repo = HKDF-Expand(HKDF(salt=bslID, BMK), repo)   │                       │              │
│              │                      │ • memclr(BMK, KEK, passphrase)                          │                       │              │
│              │                      └─────────────────────────────────────────────────────────┘                       │              │
│              │                                  │                                  │                                  │              │
│              │                                            Connect to Backup Repo                                      │              │
│              │◄───────────────────────────────────────────────────────────────────────────────────────────────────────│              │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

BSL status is probed in two steps. Failure of the check will trigger retries so won't fail the tasks:
- At the beginning of the controllers reconciling a data mover CR (e.g., DataUpload, DataDownload, PodVolumeBackup, PodVolumeRestore), if the BSL is not in `available` state, the reconcile aborts and the next reconcile will retry
- At the beginning of the data mover pods retrieving DEK_repo to connect to the backup repository, if the BSL is not in `available` state, the data mover execution will wait and retry

The BMK fingerprint check is also done by the data mover, once the check fails, the task will fail.  

Velero server caches the BMK because it is used by Velero server for multiple purposes. The key is cached lazily for first time usage or after BSL updates. The cache is shared by all controllers inside Velero server.    

### Password Rotation

#### Password Rotation Request

A new CRD is added for password rotation request:

```go
type BSLKeyRotationRequest struct {
    Spec   BSLKeyRotationRequestSpec   `json:"spec,omitempty"`
    Status BSLKeyRotationRequestStatus `json:"status,omitempty"`
}

type BSLKeyRotationRequestSpec struct {
    // BackupStorageLocation is the name of the BackupStorageLocation whose 
    // encryption password will be rotated.
    BackupStorageLocation string `json:"backupStorageLocation"`
    // TargetSecretKeyRef references the new encryption credential to rotate to.
    TargetSecretKeyRef corev1.SecretKeySelector `json:"targetSecretKeyRef"`
}

type BSLKeyRotationRequestPhase string
const (
    BSLKeyRotationRequestPhaseNew        BSLKeyRotationRequestPhase = "New"
    BSLKeyRotationRequestPhaseInProgress BSLKeyRotationRequestPhase = "InProgress"
    BSLKeyRotationRequestPhaseCompleted  BSLKeyRotationRequestPhase = "Completed"
    BSLKeyRotationRequestPhaseFailed     BSLKeyRotationRequestPhase = "Failed"
)

type BSLKeyRotationRequestStatus struct {
    // Phase is the current lifecycle phase of this rotation request.
    Phase BSLKeyRotationRequestPhase `json:"phase,omitempty"`
    // StartTime is when rotation execution started.
    // +optional
    StartTime *metav1.Time `json:"startTime,omitempty"`
    // CompletionTime is when rotation successfully completed.
    // +optional
    CompletionTime *metav1.Time `json:"completionTime,omitempty"`
    // Message provides detailed human-readable status or error information.
    // +optional
    Message string `json:"message,omitempty"`
}
```

#### Admission and State Transition

The controller access `New` or `InProgress` requests, for `InProgress` requests, the controller resumes/retries the rotation operation.  

Multiple rotation request for the same BSL is not allowed, the controller will:  
- If an `InProgress` request exists, continue it and reject additional `New` requests as Failed
- If several `New` requests exist, choose one by creation timestamp, then reject the others as Failed

An annotation `velero.io/key-rotation-in-progress: "true"` is introduced. It prevents BSL sync from processing the BSL (since BSL is set to `Unavailable`) and signals that rotation reconciliation should continue. Reconciliation sets it before changing storage.  

There is an admission stage before modifying the RSD or BSL.  

The admission does below things:
- Verify the BSL is ReadWrite
- Read the BSL’s `active-password` and validate the storage RSD using that password, including headerchecksum and BMK fingerprint check
- If the verification with `active-password` fails, do the same verification with `target-password`
- Update the request status `Phase` to `InProgress`

On verification failure during the admission, the controller removes the `velero.io/key-rotation-in-progress` annotation from the BSL and then
set the rotation request as `Failed`.  
On transient errors during the admission, the controller will retry the rotation request.  

By the end the BSL is updated and restored to the original state before the rotation, specifically, if the BSL is in `Unavailable` state, the state is not changed to `Available`.  

The BSL is updated in an atomic operation, so it never happens that the BSL fields are in inconsistent states.  
However, BSL may be inconsistent with backup storage when the upload succeeds but BSL update fails, in this case, admission could still pass using the `target-password` and rotation could continue.  

#### Rotation Workflow

Below is the diagram for password rotation workflow:

```text
                       Reconcile rotation request
                                  |
                         Check request phase
                                  |
                 +----------------+---------------+
                 |                                |
            New request                     InProgress request
                 |                                |
                 +---------- ADMISSION -----------+
                 |                                |
                 |   Verification failure: stop   |
                 |   Transient error: retry        |
                 |                                |
        Set phase InProgress                      |
                 |                                |
                 +---- Verified RSD and BMK -------+
                          |
             BSL credentials already updated?
             - Active reference = target reference
             - Clone matches verified storage RSD
                    /                    \
                  Yes                    No
                   |                      |
                   |          Set or retain rotation annotation
                   |               Set BSL Unavailable
                   |                      |
                   |          Verified using target credential?
                   |                 /                 \
                   |               Yes                 No
                   |                |                   |
                   |           Skip upload     Read target password
                   |                |          Wrap BMK; upload RSD
                   |                |                   |
                   |                |          Success / transient error
                   |                |              |           |
                   |                +--------------+     Retry as InProgress
                   |                      |
                   +----------------------+
                          |
                 Update BSL atomically:
                 - Secret reference and RSD clone
                 - Restore pre-rotation availability state
                 - Remove rotation annotation
                          |
                   Success / API error
                      |          |
                      |    Retry as InProgress
                      |
                 Mark request Completed
                          |
                  API error: retry as InProgress
```

### Encryption

Resource data and Velero metadata are encrypted/decrypted with `DEK_resource` in below way:

```
Encryption:
  AAD = Encode(bslID, backupName, fileName)
  ciphertext, tag = AES-GCM-Encrypt(DEK, nonce, compressedData, AAD)

Decryption:
  AAD = Encode(bslID, backupName, fileName)
  compressedData = AES-GCM-Decrypt(DEK, nonce, ciphertext, tag, AAD)
```

The encryption/decryption happens per file and binds contexts of BSL, backup and file.  

### Compression

The compression algorithm and parameters are hard-coded as below, it not necessary to allow users to change:
- Algorithm: `zstd`
- Level: `zstd.SpeedDefault`
- Window size: `4MB`
- Concurrency: `1`

Compression is enabled by default and not allowed to be disabled for resource backup data.  

At present, gzip compression is scattered and embedded in the specific workflow, we need to add an abstraction layer which adapts to call either gzip or zstd according to the format. So the places that are calling compression needs to be refactored to call this abstraction.  

### Backup Repository Connection

A `DEK_repo` is generated for each backup repository, it should not be exposed to users.  
On the other hand, users may need to connect to backup repository manually, e.g., for Kopia repository, use Kopia CLI to get more diagnostic information of the repository.  

Previously, we suggest users to use the backup repository connection method/CLI to connect to the repository, e.g., using `kopia repository connect` CLI.
However, with Format 2.0, the backup repository password is fully managed by Velero through `DEK_repo`, users cannot use the repository native method/CLI for the connection since they cannot specify the repo password.  

To cope with this problem, Velero provides a new CLI `velero repository connect` to connect to the repository. When users call this CLI, Velero retrieves the `active-password` secret in the cluster, unwrap `DEK_repo` through the secret and call the connect functionality to the backup repository.  
Under the Unfied Repository architecture, the repository provider must implement `Connect` method for Velero to connect to the backup repository, so it is always guaranteed that this CLI could be implemented.  
After the backup repository is connected, users could use the backup repository's own commands to operate the backup repository.  

`velero repo connect` CLI supports in-cluster mode and DR mode, while in-cluster mode is used by normal cases when the cluster is still available; and DR mode is used to support the scenarios that the cluster has gone so there is no way to access the BSL and secret.  

Here are the parameters for in-cluster mode:
- `bsl`: the BSL CR for this backup repository

Here are the parameters for DR mode:
- `rsd-file`: the file that stores the root storage descriptor for the backup storage 
- `password-file`: the file where the password for the backup storage is stored

Here are the parameters shared by the both mode:
- `source-namespace`: the namespace that the backup is created for
- `repository-type`: the type of the backup repository, optional, default to `kopia`
- `read-only`: whether to create read-only connection, optional, applied to the supported backup repository only
- `config-file`: path of the config file for the connection, optional, applied to the backup repository that use local config file only

Different backup repositories may have their own specific parameters for connection, these parameters could be passed to the CLI as is, the CLI will convey all the parameters to the backup repository connection functionality.  

For symentric consideration, another CLI `velero repo disconnect` is provided to disconnect from the backup repository.  

### Auxiliary Data Isolation

**Rule: Auxiliary Data must be write-only to Velero core workflow.**  
This rule should be strictly followed Format V2 and it is also helpful for Format V1.x. Therefore, below code needs to be refactored to keep this rule:  
- In restore-finalizer, it visits the restore resource-list to identify the restored PVC, while resource-list is a Auxiliary Data. This is actually a fault of the existing code, it is more reasonable to visit volume-info instead of resource-list to fulfill this purpose.

### Backup Storage Observability

#### Public Data Interface

There is a public data interface file for backup and restore representively. Here are the structs:

```go
type PublicBackupInfo struct {
	BackupName string                     `json:"backupName,omitempty"`
	Warnings *ResultMessages              `json:"warnings,omitempty"`
	Errors   *ResultMessages              `json:"errors,omitempty"`
	VolumeInfo []*PublicVolumeInfo        `json:"volumeInfo,omitempty"`
	ItemOperations []*ItemOperationStatus `json:"itemOperations,omitempty"`
}

type PublicRestoreInfo struct {
	RestoreName string                    `json:"restoreName,omitempty"`
	BackupName string                     `json:"backupName,omitempty"`
	Warnings *ResultMessages              `json:"warnings,omitempty"`
	Errors   *ResultMessages              `json:"errors,omitempty"`
	VolumeInfo []*PublicVolumeInfo        `json:"volumeInfo,omitempty"`
	ItemOperations []*ItemOperationStatus `json:"itemOperations,omitempty"`
}

type ResultMessages struct {
	Velero     []string            `json:"velero,omitempty"`
	Cluster    []string            `json:"cluster,omitempty"`
	Namespaces map[string][]string `json:"namespaces,omitempty"`
}

type ItemOperationStatus struct {
	Phase          string       `json:"phase,omitempty"`
	Error          string       `json:"error,omitempty"`
	NCompleted     int64        `json:"nCompleted,omitempty"`
	NTotal         int64        `json:"nTotal,omitempty"`
	OperationUnits string       `json:"operationUnits,omitempty"`
	Description    string       `json:"description,omitempty"`
	Created        *metav1.Time `json:"created,omitempty"`
	Started        *metav1.Time `json:"started,omitempty"`
	Updated        *metav1.Time `json:"updated,omitempty"`
}

type PublicVolumeInfo struct {
	PVCName               string                 `json:"pvcName,omitempty"`
	PVCNamespace          string                 `json:"pvcNamespace,omitempty"`
	PVName                string                 `json:"pvName,omitempty"`
	Method                Method                 `json:"method,omitempty"`
	SnapshotDataMoved     bool                   `json:"snapshotDataMoved"`
	PreserveLocalSnapshot bool                   `json:"preserveLocalSnapshot,omitempty"`
	Skipped               bool                   `json:"skipped,omitempty"`
	SkippedReason         string                 `json:"skippedReason,omitempty"`
	StartTimestamp        *metav1.Time           `json:"startTimestamp,omitempty"`
	CompletionTimestamp   *metav1.Time           `json:"completionTimestamp,omitempty"`
	Result                VolumeResult           `json:"result,omitempty"`
	VolumeType            string                 `json:"volumeType,omitempty"`
	FallbackFull          bool                   `json:"fallbackFull,omitempty"`
	CSISnapshotInfo          *PublicCSISnapshotInfo          `json:"csiSnapshotInfo,omitempty"`
	SnapshotDataMovementInfo *PublicSnapshotDataMovementInfo `json:"snapshotDataMovementInfo,omitempty"`
	NativeSnapshotInfo       *PublicNativeSnapshotInfo       `json:"nativeSnapshotInfo,omitempty"`
	PodVolumeInfo            *PublicPodVolumeInfo            `json:"podVolumeInfo,omitempty"`
}

type PublicCSISnapshotInfo struct {
	Driver     string `json:"driver,omitempty"`
	Size       int64  `json:"size,omitempty"`
	ReadyToUse *bool  `json:"readyToUse,omitempty"`
}

type PublicSnapshotDataMovementInfo struct {
	DataMover       string `json:"dataMover,omitempty"`
	UploaderType    string `json:"uploaderType,omitempty"`
	Size            int64  `json:"size,omitempty"`
	IncrementalSize *int64 `json:"incrementalSize,omitempty"`
	SourceSize      int64  `json:"sourceSize,omitempty"`
	Phase           string `json:"phase,omitempty"`
}

type PublicNativeSnapshotInfo struct {
	VolumeType string        `json:"volumeType,omitempty"`
	VolumeAZ   string        `json:"volumeAZ,omitempty"`
	IOPS       string        `json:"iops,omitempty"`
	Phase      SnapshotPhase `json:"phase,omitempty"`
}

type PublicPodVolumeInfo struct {
	Size            int64  `json:"size,omitempty"`
	IncrementalSize *int64 `json:"incrementalSize,omitempty"`
	SourceSize      int64  `json:"sourceSize,omitempty"`
	UploaderType    string `json:"uploaderType,omitempty"`
	VolumeName      string `json:"volumeName,omitempty"`
	PodName         string `json:"podName,omitempty"`
	PodNamespace    string `json:"podNamespace,omitempty"`
	Phase           string `json:"phase,omitempty"`
}
```

The fields in these structs are sanitized, so that no highly sensitive information is included, since the public interface files are never encrypted.  

The fields still include `Warnings` and `Errors` which are regarded as sensitive information in some way, because they may expose in-cluster information, e.g., secret or configmap names. Including these fields are a trade-off for observability, most observability scenarios require to know the result of the backup/restore and `Warnings` and `Errors` are important parts of them which could help users to validate if the backup/restore is useful.  
In future, if this is still concerned, a dedicated desensitization operation could be introduced to remove the sensitive data from `Warnings` and `Errors`.  

The existing backup/restore describe CLI should be refactored to use the information from the public interface of backup storage only, if the data is there.   
Additionally, below information should be removed from backup/restore describe since they are highly sensitive information and not helpful for observation or troubleshooting:
- SnapshotHandle: exposing it allows an attacker to directly clone, mount, or exfiltrate the snapshot disk image outside of Kubernetes and without Velero encryption keys.
- VolumeHandle: it exposes production storage LUNs.

#### Configurable Encryption

Users could configure whether to encrypt the Auxiliary Data when initialize the BSL, but they cannot change it after the BSL is initialized.  
A new field `AuxiliaryDataEncryptionConfig` is added to BSL spec to allow users to configure the encryption for Auxiliary Data.  
Users could select whether to encrypt the items of Auxiliary Data individually, e.g., backup/restore logs, resource list, etc.  

Below are the mechanisms to prevent users from modifying the configuration after BSL is initialized, either in cluster or in backup storage:
- Modifying auxiliary Data encryption configuration in RSD in backup storage will cause headerchecksum failure and also BSL becoming to `unavailable`
- In BSL controller, modifying auxiliary Data encryption configuration in BSL spec will cause BSL becoming to `unavailable` since BSL RSD clone drifts from main RSD
- A `+kubebuilder:validation:XValidation:rule="self == oldSelf"` marker is added to the BSL CRD, so that the API server will refuse mutating the auxiliary Data encryption fields 

#### Auxiliary Data Download API

A SDK will be provided by Velero for downloading the Auxiliary Data, including below functionalities:
- DownloadBackupLog
- DownloadRestoreLog
- DownloadBackupResourceList
- DownloadRestoreResourceList

The SDK will retrieve the raw file from the backup storage, decrypt it to plaintext, and then write it to the given receiver. The workflow is like below diagram:  

```text
      SDK                                 K8s API                          Object Storage (S3)
       │                                     │                                      │
       │── Create DownloadRequest CR ────►   │                                      │
       │                                     │ Server Controller signs S3 URL       │
       │◄─ Get Presigned S3 URL ──────────   │                                      │
       │                                     │                                      │
       │── Read Secret via kubeconfig ───►   │                                      │
       │                                     │                                      │
       │                                     │                                      │
       │── Stream S3 Presigned URL ───────────────────────────────────────────────► │
       │◄─ Download Encrypted Stream─────────────────────────────────────────────── │
       │                                                                            │
       │ - Derive KEK (PBKDF2) + DEK_resource (HKDF)                                │
       │ - AES-256-GCM chunked stream decrypt                                       │
       │ - zstd stream decompress                                                   │
       │                                                                            │
       ▼                                                                            │
```

The SDK is in auto-fit mode, which works for both encrypted data and unencrypted data.  

Below are the definition for the SDK:
```go
type AuxiliaryDataDownload interface {
	DownloadBackupLog(ctx context.Context, bsl *velerov1api.BackupStorageLocation, backupName string, w io.Writer, timeout time.Duration) error
	DownloadRestoreLog(ctx context.Context, bsl *velerov1api.BackupStorageLocation, restoreName string, w io.Writer, timeout time.Duration) error
	DownloadBackupResourceList(ctx context.Context, bsl *velerov1api.BackupStorageLocation, backupName string, w io.Writer, timeout time.Duration) error
	DownloadRestoreResourceList(ctx context.Context, bsl *velerov1api.BackupStorageLocation, restoreName string, w io.Writer, timeout time.Duration) error
}
```

Velero's `velero backup describe`, `velero restore describe`, `velero backup log` and `velero restore log` CLI will also be refactored to use this SDK.   

### Backup Download

Velero allows to download the backup tarball to a specified location. This functionality will be kept to Velero CLI. However, Velero won't provide a SDK for this functionality. 3rd tools should is never expected to use non-AuxiliaryData directly; and is always expected to use Velero for restore.  

### Dual Suite Object Store Interface

At present, Velero supports only object store for resource backup and the object store access is through the `BackupStore` interface.  

Two more methods are added into the interface to persist the public data interface file:  
```go
	PutPublicBackupInfo(backup string, publicInfo io.Reader) error
	PutPublicRestoreInfo(restore string, publicInfo io.Reader) error
```

There are two implementations for `BackupStore`, v1.x implementation and v2 implementation.  

`AuxiliaryDataDownload` implementation creates `DownloadRequest` CR to request to download the required data, so it won't call `BackupStore` interface directly:  

```text
┌────────────────────────────────────────────────────────────┐
│                     Velero SERVER                          │
│                                                            │
│                persistence.BackupStore                     │
│                                                            │
│           ┌───────────────────────────────┐                │
│           │ ObjectBackupStoreGetter.Get() │                │
│           └──────────────┬────────────────┘                │
│              ┌───────────┴───────────┐                     │
│              ▼                       ▼                     │
│     v1ObjectBackupStore     v2ObjectBackupStore            │
│     (Format 1.x: gzip)      (Format 2.0: zstd + AES-GCM)   │
└──────────────────────────────┬─────────────────────────────┘
                               │
                        DownloadRequest CR
                               │
                               ▼
┌────────────────────────────────────────────────────────────┐
│                CLIENT / CLI / 3RD PARTY                    │
│                                                            │
│               AuxiliaryDataDownload (SDK)                  │
└────────────────────────────────────────────────────────────┘
```

## Restart

Velero server caches decrypted BMK in a lazy manner, so Velero server restart doesn't require changes.  
Velero node-agent doesn't require BMK or even the RSD, so restart node-agent doesn't require changes.  

## CLI

Below new CLI are added:
- `velero rsd verify`
- `velero repo connect`
- `velero repo disconnect`

The output of below CLI would be refactored to remove the sensitive data:
- `velero backup describe`
- `velero restore describe`

Below new parameters are added to `velero backup-location create`:

| Parameter | Type / Default | Description |
| :--- | :--- | :--- |
| `--storage-format <string>` | string (default `"1.1.0"`) | Storage format version for the BSL. Allowed values: `"2.0.0"` or `"1.1.0"`. |
| `--bsl-secret-name <string>` | string (default `"velero-bsl-secret"`) | Name of the Kubernetes Secret in the Velero namespace containing the BSL encryption password. |
| `--encrypt-logs` | bool (default `true`) | Configures encrypting backup and restore execution logs for the BSL. |
| `--encrypt-resource-list` | bool (default `true`) | Configures encrypting backup resource list for the BSL. |

Below new parameters are added to `velero backup-location delete`:

| Parameter | Type / Default | Description |
| :--- | :--- | :--- |
| `--delete-bsl-secrets` | bool (default `false`) | When set, Velero **deletes the BSL Secrets** when deleting the BSL. |

## Installation

Below new parameters/functionalities are added:  

| Parameter | Type / Default | Description |
| :--- | :--- | :--- |
| `--storage-format <string>` | string (default `"1.1.0"`) | Storage format version for the default BSL. Allowed values: `"2.0.0"` or `"1.1.0"`. |
| `--bsl-secret-name <string>` | string (default `"velero-bsl-secret"`) | Name of the Kubernetes Secret in the Velero namespace containing the BSL encryption password for the default BSL. |
| `--encrypt-logs` | bool (default `true`) | Configures encrypting backup and restore execution logs for the default BSL. |
| `--encrypt-resource-list` | bool (default `true`) | Configures encrypting backup resource list for the default BSL. |
| `--preserve-bsl-secrets` | bool (default `false`) | When set, Velero uninstall **preserves the `velero` namespace and the BSL Secrets**. |

The uninstallation option `--preserve-bsl-secrets` is required because the BSL secrets are provided by users, users may need a copy before deleting them.  
When the option is not specified, Velero uninstallation should print a warning to notify users that the secrets will be deleted.  

## Backwards Compatibility

With this solution Format 2.0 is used for new BSLs only; Format 1.x is kept for old BSLs. Therefore, though Format 2.0 has no backwards compatibility consideration, this overall solution is fully backwards compatible.  





[1]: ../Implemented/unified-repo-and-kopia-integration/unified-repo-and-kopia-integration.md
