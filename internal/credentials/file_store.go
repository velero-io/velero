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

package credentials

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/cockroachdb/errors"
	corev1api "k8s.io/api/core/v1"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/vmware-tanzu/velero/pkg/util/filesystem"
	"github.com/vmware-tanzu/velero/pkg/util/kube"
)

// FileStore defines operations for interacting with credentials
// that are stored on a file system.
type FileStore interface {
	// Path returns a path on disk where the secret key defined by
	// the given selector is serialized.
	Path(selector *corev1api.SecretKeySelector) (string, error)
}

type namespacedFileStore struct {
	client    kbclient.Client
	namespace string
	fsRoot    string
	fs        filesystem.Interface
}

// NewNamespacedFileStore returns a FileStore which can interact with credentials
// for the given namespace and will store them under the given fsRoot.
func NewNamespacedFileStore(client kbclient.Client, namespace string, fsRoot string, fs filesystem.Interface) (FileStore, error) {
	fsNamespaceRoot := filepath.Join(fsRoot, namespace)

	if err := fs.MkdirAll(fsNamespaceRoot, 0755); err != nil {
		return nil, err
	}

	return &namespacedFileStore{
		client:    client,
		namespace: namespace,
		fsRoot:    fsNamespaceRoot,
		fs:        fs,
	}, nil
}

// Path returns a path on disk where the secret key defined by
// the given selector is serialized.
func (n *namespacedFileStore) Path(selector *corev1api.SecretKeySelector) (string, error) {
	creds, err := kube.GetSecretKey(n.client, n.namespace, selector)
	if err != nil {
		return "", errors.Wrap(err, "unable to get key for secret")
	}

	keyFilePath := filepath.Join(n.fsRoot, fmt.Sprintf("%s-%s", selector.Name, selector.Key))

	// owner RW perms, group R perms, no public perms
	file, err := n.fs.OpenFile(keyFilePath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0640)
	if err != nil {
		return "", errors.Wrap(err, "unable to open credentials file for writing")
	}

	if _, err := file.Write(creds); err != nil {
		return "", errors.Wrap(err, "unable to write credentials to store")
	}

	if err := file.Close(); err != nil {
		return "", errors.Wrap(err, "unable to close credentials file")
	}

	return keyFilePath, nil
}
