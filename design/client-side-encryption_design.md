# Proposal for client-side encryption

## Abstract

Currently only PersistentVolumes are stored in a Restic/Kopia repository, which means that only they are encrypted and the rest of the backup is not.
It is desired that the cluster backup can be encrypted which overall will lead to better security.

## Background

As of today, Velero stores only PersistentVolume data in a Restic/Kopia repository.
This repository is encrypted while the rest of the backup is not.
Backups should be safe against illegal access and tampering.
It is therefore desired to have the ability to store this data in an encrypted manner.

## Goals

- Encryption of the main cluster backup file with AES.
- Basic configuration of the encryption, e.g. turning it on and off.
- Ability to change encryption key for future backups

## Non Goals

- Other ciphers than AES (can be added later).
- Encrypting anything other than the main backup file.
- re-encrypt old backups if new encryption key was set

## High-Level Design

Encryption will happen during the backup process before the objects are persisted (e.g. written to an object store).
Decryption will happen during a restore after the persisted objects have been read.
The encryption key will be stored in a Kubernetes secret by the user.
Encryption can be configured through commandline arguments to the velero server.
The user can change the encryption key by creating a new encryption key secret and configuring it in Velero's configuration.
If a backup is encrypted, it contains a flag and the name of the used encryption key secret in its metadata.
For backwards compatibility reasons, only the main backup archive will be encrypted.

## Detailed Design

### Configuration

To enable encryption, a feature flag is introduced:
```go
// EncryptionFeatureFlag is the feature flag string that defines whether or not client-side-encryption features are being used.
const EncryptionFeatureFlag = "EnableEncryption"
```

A commandline flag is added to the `velero server` command to set the name of the secret containing the encryption key:
```go
type serverConfig struct {
    ...
	encryptionSecret string
}
```

```go
command.Flags().StringVar(&config.encryptionSecret, "encryption-secret", config.encryptionSecret, "Name of the secret that contains the key to encrypt backups with. Used only if the 'EnableEncryption' feature flag is set.")
```

### En-/Decryption implementation

Encryption is located in the `encryption` package.
The `encryptor` interface has been introduced to provide abstraction over the used encryption standard.
The default (and for now only) encryptor implementation is the `aesEncryptor`:
```go
type encryptor interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

type aesEncryptor struct {
	gcm cipher.AEAD
	key []byte
}

func (aes *aesEncryptor) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, aes.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to create nonce for encryption: %w", err)
	}

	cipherBytes := aes.gcm.Seal(nonce, nonce, plaintext, nil)
	return cipherBytes, nil
}

func (aes *aesEncryptor) Decrypt(ciphertext []byte) ([]byte, error) {
    nonceSize := aes.gcm.NonceSize()
    if len(ciphertext) <= nonceSize {
        return nil, fmt.Errorf("failed to decrypt: ciphertext (length %d) too short", len(ciphertext))
    }

    nonce, cipherBytesWithoutNonce := ciphertext[:nonceSize], ciphertext[nonceSize:]
    plainBytes, err := aes.gcm.Open(nil, nonce, cipherBytesWithoutNonce, nil)
    if err != nil {
        return nil, fmt.Errorf("failed to decrypt ciphertext: %w", err)
    }

    return plainBytes, nil
}

func newAesEncryptor(key string) (*aesEncryptor, error) {
	keyBytes := []byte(key)
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create Galois Counter Mode for cipher: %w", err)
	}

	return &aesEncryptor{
		gcm: aesGCM,
		key: keyBytes,
	}, nil
}
```

Backup and restore rely on writers and readers to handle the backup content.
Therefore, encryption has been implemented in a writer, decryption in a reader.

#### Encryption Writer

```go
// NewEncryptionWriter provides a writer that encrypts whatever is written with the given key and writes it into the given writer.
func NewEncryptionWriter(out io.Writer, encryptionKey string) (io.WriteCloser, error) {
	encryptor, err := newAesEncryptor(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES encryptor: %w", err)
	}

	return &encryptionWriter{
		encryptor: encryptor,
		plaintext: make([]byte, 0),
		out:       out,
	}, nil
}

type encryptionWriter struct {
	encryptor encryptor
	plaintext []byte
	out       io.Writer
	isClosed  bool
}

func (ew *encryptionWriter) Write(p []byte) (n int, err error) {
	if ew.isClosed {
		return 0, fmt.Errorf("failed to write: encryption writer is closed")
	}

	ew.plaintext = append(ew.plaintext, p...)
	return len(p), nil
}

func (ew *encryptionWriter) Close() error {
	if ew.isClosed {
		return nil
	}

	ciphertext, err := ew.encryptor.Encrypt(ew.plaintext)
	if err != nil {
		return fmt.Errorf("failed to encrypt: %w", err)
	}

	ew.isClosed = true

	_, err = ew.out.Write(ciphertext)
	if err != nil {
		return fmt.Errorf("failed to write cipher text to output writer: %w", err)
	}

	return nil
}
```

#### Decryption Reader

```go
// NewDecryptionReader provides a reader that decrypts the contents of the given reader with the given key.
func NewDecryptionReader(in io.Reader, encryptionKey string) (io.Reader, error) {
	encryptor, err := newAesEncryptor(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES encryptor: %w", err)
	}

	buf := new(bytes.Buffer)
	_, err = io.Copy(buf, in)
	if err != nil {
		return nil, fmt.Errorf("failed to copy input to buffer: %w", err)
	}

	ciphertext := buf.Bytes()
	plaintext, err := encryptor.Decrypt(ciphertext)
	if err != nil {
		return nil, err
	}

	return bytes.NewReader(plaintext), nil
}
```

### Storing the encryption status

To discern if and how a given backup is encrypted, the `BackupStatus` gets extended by an `Encryption` field of type `EncryptionStatus`:
```go
// BackupStatus captures the current status of a Velero backup.
type BackupStatus struct {
    ...

    // Encryption contains metadata about and whether encryption was used.
    // +optional
    Encryption EncryptionStatus `json:"encryption,omitempty"`
}

// EncryptionKeyRetrieverType is used to decide which encryption.KeyRetriever implementation
// should be used to read the encryption key.
type EncryptionKeyRetrieverType string

// EncryptionKeyRetrieverConfig contains configuration values for the encryption.KeyRetriever implementation
// to discern where to read the encryption key.
type EncryptionKeyRetrieverConfig map[string]string

// EncryptionStatus contains information about the encryption of a backup.
type EncryptionStatus struct {
    // IsEncrypted indicates whether this backup is encrypted.
    // +optional
    IsEncrypted bool `json:"isEncrypted,omitempty"`
    // KeyRetrieverType is the source the encryption key is read from.
    // +optional
    KeyRetrieverType EncryptionKeyRetrieverType `json:"keyRetrieverType,omitempty"`
    // KeyRetrieverConfig contains configuration for a key retriever to fetch the encryption key.
    // +optional
    KeyRetrieverConfig EncryptionKeyRetrieverConfig `json:"keyRetrieverConfig,omitempty"`
}
```

### Retrieving the encryption key

To allow for different methods of storing and retrieving encryption keys, the `encryption.KeyRetriever` interface has been introduced:

```go
// SecretKeyRetrieverType designates a KeyRetriever that fetches the encryption key from a Kubernetes secret.
const SecretKeyRetrieverType velerov1.EncryptionKeyRetrieverType = "secret"

// KeyRetriever is used to fetch an encryption key.
type KeyRetriever interface {
    // GetKey fetches an encryption key.
    GetKey() (string, error)
    // RetrieverType designates the source this KeyRetriever fetches the encryption key from.
    RetrieverType() velerov1.EncryptionKeyRetrieverType
    // Config contains configuration another KeyRetriever of the same type might use to fetch the encryption key.
    Config() velerov1.EncryptionKeyRetrieverConfig
}

// KeyRetrieverFor creates a KeyRetriever of the given type according to the given configuration.
func KeyRetrieverFor(retrieverType velerov1.EncryptionKeyRetrieverType, keyLocation velerov1.EncryptionKeyRetrieverConfig, client crlClient.Client) (retriever KeyRetriever, err error) {
    defer func() {
        if err != nil {
            err = fmt.Errorf("could not create encryption key retriever for type '%s': %w", retrieverType, err)
        }
    }()

    switch retrieverType {
    case SecretKeyRetrieverType:
        return newSecretKeyRetriever(client, keyLocation)
    default:
        return nil, fmt.Errorf("could not find encryption key retriever for type '%s'", retrieverType)
    }
}
```

For now, the only key retriever that will be implemented is the `secretKeyRetriever` which fetches the key from a Kubernetes secret:

```go
const encryptionKeySecretField = "encryptionKey"

const (
    locationNamespaceKey  = "namespace"
    locationSecretNameKey = "secretName"
)

type secretKeyRetriever struct {
    client     crlClient.Client
    secretName string
    namespace  string
}

func newSecretKeyRetriever(client crlClient.Client, keyLocation velerov1.EncryptionKeyRetrieverConfig) (*secretKeyRetriever, error) {
    secretName := keyLocation[locationSecretNameKey]
    if secretName == "" {
        return nil, fmt.Errorf("secret name cannot be empty")
    }

    namespace := keyLocation[locationNamespaceKey]
    if namespace == "" {
        return nil, fmt.Errorf("namespace cannot be empty")
    }

    return &secretKeyRetriever{client: client, secretName: secretName, namespace: namespace}, nil
}

// RetrieverType designates the source this KeyRetriever fetches the encryption key from.
// In this case, a secret.
func (s *secretKeyRetriever) RetrieverType() velerov1.EncryptionKeyRetrieverType {
    return SecretKeyRetrieverType
}

// Config contains configuration another KeyRetriever of the same type might use to fetch the encryption key.
func (s *secretKeyRetriever) Config() velerov1.EncryptionKeyRetrieverConfig {
    return SecretKeyConfig(s.secretName, s.namespace)
}

// GetKey fetches an encryption key from a Kubernetes secret.
func (s *secretKeyRetriever) GetKey() (string, error) {
    secret := corev1.Secret{}
    err := s.client.Get(context.Background(), crlClient.ObjectKey{Name: s.secretName, Namespace: s.namespace}, &secret)
    if err != nil {
        return "", fmt.Errorf("failed to get encryption key secret '%s': %w", s.secretName, err)
    }

    key, ok := secret.Data[encryptionKeySecretField]
    if !ok {
        return "", fmt.Errorf("encryption key secret '%s' lacks field '%s'", s.secretName, encryptionKeySecretField)
    }

    return string(key), nil
}

// SecretKeyConfig creates the retriever config for a key retriever that fetches the encryption key from a secret.
func SecretKeyConfig(secretName, namespace string) velerov1.EncryptionKeyRetrieverConfig {
    return velerov1.EncryptionKeyRetrieverConfig{
        locationSecretNameKey: secretName,
        locationNamespaceKey:  namespace,
    }
}
```

### Encryption on backup

The `kubernetesBackupper` gets extended by a namespace and the encryption secret:
```go
type kubernetesBackupper struct {
    ...
	veleroNamespace  string
    encryptionSecret string
}

func NewKubernetesBackupper(
    ...
    veleroNamespace  string,
    encryptionSecret string,
) (Backupper, error) {
    ...
}
```

The namespace is the namespace velero runs in.
It is necessary to find the encryption secret.

Encryption happens in the `BackupWithResolvers` method:
```go
func (kb *kubernetesBackupper) BackupWithResolvers(log logrus.FieldLogger,
	backupRequest *Request,
	backupFile io.Writer,
	backupItemActionResolver framework.BackupItemActionResolverV2,
	volumeSnapshotterGetter VolumeSnapshotterGetter) (backupErr error) {

    var backupContent io.Writer
    if features.IsEnabled(velerov1api.EncryptionFeatureFlag) {
        encryptionKeyRetriever, err := encryption.KeyRetrieverFor(
            encryption.SecretKeyRetrieverType,
            encryption.SecretKeyConfig(kb.encryptionSecret, kb.veleroNamespace),
            kb.kbClient,
        )
        if err != nil {
            log.WithError(errors.WithStack(err)).Debugf("Error from KeyRetrieverFor")
            return err
        }
        
        encryptionKey, err := encryptionKeyRetriever.GetKey()
        if err != nil {
            log.WithError(errors.WithStack(err)).Debugf("Error from encryptionKeyRetriever.GetKey")
            return err
        }
        
        encryptedContent, err := encryption.NewEncryptionWriter(backupFile, encryptionKey)
        if err != nil {
            log.WithError(errors.WithStack(err)).Debugf("Error from NewEncryptionWriter")
            return err
        }
        
        backupContent = encryptedContent
        backupRequest.Backup.Status.Encryption.IsEncrypted = true
        backupRequest.Backup.Status.Encryption.KeyRetrieverType = encryptionKeyRetriever.RetrieverType()
        backupRequest.Backup.Status.Encryption.KeyRetrieverConfig = encryptionKeyRetriever.Config()
    
        defer func() {
            err = encryptedContent.Close()
            if err != nil {
                log.WithError(errors.WithStack(err)).Debugf("Error from backupContent.Close")
                backupErr = err
            }
        }()
    } else {
        backupContent = backupFile
    }

    gzippedData := gzip.NewWriter(backupContent)
    ...
}
```

### Decryption on restore

The `kubernetesRestorer` gets extended by a namespace:
```go
type kubernetesRestorer struct {
    ...
    veleroNamespace string
}

func NewKubernetesRestorer(
    ...
    veleroNamespace string,
) (Restorer, error) {
    ...
}
```

The namespace is the namespace velero runs in.
It is necessary to find the encryption secret.

The namespace also needs to be passed to `restoreContext`:
```go
type restoreContext struct {
    ...
    veleroNamespace string
}
```

Decryption then happens in the `execute` method of the `restoreContext`:
```go
func (ctx *restoreContext) execute() (results.Result, results.Result) {
    warnings, errs := results.Result{}, results.Result{}

    ctx.log.Infof("Starting restore of backup %s", kube.NamespaceAndName(ctx.backup))

    var backupContent io.Reader
    var err error
    if ctx.backup.Status.Encryption.IsEncrypted {
    encryptionKeyRetriever, err := encryption.KeyRetrieverFor(
        ctx.backup.Status.Encryption.KeyRetrieverType,
        ctx.backup.Status.Encryption.KeyRetrieverConfig,
        ctx.kbClient,
    )
    if err != nil {
        ctx.log.Errorf("error creating encryption key retriever: %s", err.Error())
        errs.AddVeleroError(err)
        return warnings, errs
    }

    encryptionKey, err := encryptionKeyRetriever.GetKey()
    if err != nil {
        ctx.log.Errorf("error getting encryption key from secret: %s", err.Error())
        errs.AddVeleroError(err)
        return warnings, errs
    }

    backupContent, err = encryption.NewDecryptionReader(ctx.backupReader, encryptionKey)
    if err != nil {
        ctx.log.Errorf("error decrypting backup: %s", err.Error())
        errs.AddVeleroError(err)
        return warnings, errs
    }

    } else {
        backupContent = ctx.backupReader
    }

    dir, err := archive.NewExtractor(ctx.log, ctx.fileSystem).UnzipAndExtractBackup(backupContent)
    ...
}
```

## Alternatives Considered

There are other ways this could be implemented.
One valid way would be to do it on a per-backup basis instead of globally.
This could be implemented by adding the fields `isEncrypted` and `encryptionSecret` to the backup spec instead of its status.
An advantage of this would be that there is no need for a feature flag  or the `encryptionSecret` flag anymore.
On the other hand, it would be fatal if a user forgets to encrypt the backup.
But as most users will likely automate their backups anyway, this shouldn't pose that much of a problem.

This could also be implemented in object store plugins.
Then however, it has to be implemented in every single object store plugin.
This is not viable.

We could just make use of server-side encryption of an object store.
But what about object stores that do not support this?
Also, client-side encryption is a lot safer, since the backups are encrypted during transit as well.

## Security Considerations

Overall this feature should increase the security of the product by encrypting secrets and application configurations.
However, the security of this feature has to be ensured to avoid giving users a false sense of security.
Since only the main backup archive is encrypted, it should be documented precisely what information gets encrypted and what not.
Unencrypted information includes:
- CSI-VolumeSnapshotClasses
- CSI-VolumeSnapshotContents (despite the name, these do not contain the contents of the backup)
- CSI-VolumeSnapshots
- Item-Operations
- Backup-Logs
- PodVolumeBackups
- a resource list containing the names and kinds of the backed up resources
- Results (errors, warnings) of the backup operation
- (native) VolumeSnapshots
- the velero backup custom resource

If the secrets containing the encryption keys are deleted, users might lose access to their backups.
Therefore, users should back up their encryption keys outside the cluster.

## Compatibility

Encrypting the whole backup would introduce major breaking changes for object store plugins and maybe even more.
Therefore, only the main backup archive is encrypted.

If unencrypted backups exist when the feature is activated, they will stay unencrypted and can still be restored.
Likewise, when the feature gets disabled, encrypted backups can still be decrypted.
It is also possible to change the encryption key without losing access to previous backups.
This is due to the backups containing metadata about their encryption.
If this metadata is absent, the backup is assumed to be unencrypted.
Currently, this encryption status contains a flag whether the backup is encrypted, as well as the name of the secret containing the key it was encrypted with.
In the future, the encryption status can be extended by the type of encryption without losing backwards compatibility by assuming the default to be AES.

There should be no breaking changes.

## Implementation

A working prototype already exists.
Therefore, minimal effort is needed to implement this.
Timelines are almost entirely dependent on how fast this goes through and how many things need to be changed before it can be merged.

Since this is a feature that we ([Cloudogu GmbH](https://cloudogu.com)) need, we agree to contribute this feature.

## Open Issues

As described under [Security Considerations](#security-considerations), only the main backup archive is encrypted.
While this is already a major step, it would probably even better if we could encrypt the entire backup.
However, this is not possible without introducing breaking changes.

It is unclear if a default encryption key should be generated if none is specified.

It would be nice to implement different encryption standards besides AES.
If the need exists, this can be added in the future.
