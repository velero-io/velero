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

package bslworker

import (
	"context"
	"os"
	"path/filepath"

	"github.com/cockroachdb/errors"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// CASecretName is the Secret (in the Velero namespace) holding the Velero-managed
	// CA that signs all worker server certificates and the central client certificate.
	CASecretName = "velero-bsl-worker-ca"

	// caKeyFileName is the CA private key key within the CA Secret.
	caKeyFileName = "ca.key"
)

// EnsureCA loads the Velero-managed CA from its Secret in namespace, generating and
// persisting a new CA if none exists yet. It is safe against a create race between
// multiple Velero replicas.
func EnsureCA(ctx context.Context, c client.Client, namespace string) (*CA, error) {
	key := types.NamespacedName{Name: CASecretName, Namespace: namespace}

	var secret corev1api.Secret
	err := c.Get(ctx, key, &secret)
	if err == nil {
		return LoadCA(secret.Data[CACertFileName], secret.Data[caKeyFileName])
	}
	if !apierrors.IsNotFound(err) {
		return nil, errors.Wrap(err, "getting CA secret")
	}

	ca, err := GenerateCA(CASecretName)
	if err != nil {
		return nil, err
	}

	newSecret := &corev1api.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      CASecretName,
			Namespace: namespace,
		},
		Data: map[string][]byte{
			CACertFileName: ca.CertPEM,
			caKeyFileName:  ca.KeyPEM,
		},
	}
	if err := c.Create(ctx, newSecret); err != nil {
		if apierrors.IsAlreadyExists(err) {
			// Another replica created it first; load theirs.
			if getErr := c.Get(ctx, key, &secret); getErr == nil {
				return LoadCA(secret.Data[CACertFileName], secret.Data[caKeyFileName])
			}
		}
		return nil, errors.Wrap(err, "creating CA secret")
	}
	return ca, nil
}

// WriteClientMaterials issues a central client certificate from ca and writes the
// client cert, key, and CA certificate into dir, returning their file paths. These
// are consumed by the WorkerGetterFactory to authenticate to workers.
func WriteClientMaterials(ca *CA, dir string) (certFile, keyFile, caFile string, err error) {
	pair, err := ca.IssueClientCert(CASecretName + "-client")
	if err != nil {
		return "", "", "", err
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", "", errors.Wrapf(err, "creating client materials dir %q", dir)
	}

	certFile = filepath.Join(dir, ClientCertFileName)
	keyFile = filepath.Join(dir, ClientKeyFileName)
	caFile = filepath.Join(dir, CACertFileName)

	for _, f := range []struct {
		path string
		data []byte
	}{
		{certFile, pair.CertPEM},
		{keyFile, pair.KeyPEM},
		{caFile, ca.CertPEM},
	} {
		if err := os.WriteFile(f.path, f.data, 0o600); err != nil {
			return "", "", "", errors.Wrapf(err, "writing %q", f.path)
		}
	}
	return certFile, keyFile, caFile, nil
}
