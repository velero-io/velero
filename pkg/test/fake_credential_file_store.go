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

package test

import (
	"context"

	corev1api "k8s.io/api/core/v1"
)

// FileStore defines operations for interacting with credentials
// that are stored on a file system.
type FileStore interface {
	// Path returns a path on disk where the secret key defined by
	// the given selector is serialized.
	Path(ctx context.Context, selector *corev1api.SecretKeySelector) (string, error)
}

type fakeCredentialsFileStore struct {
	path string
	err  error
}

// Path returns a path on disk where the secret key defined by
// the given selector is serialized.
func (f *fakeCredentialsFileStore) Path(ctx context.Context, selector *corev1api.SecretKeySelector) (string, error) {
	return f.path, f.err
}

// NewFakeCredentialsFileStore creates a FileStore which will return the given path
// and error when Path is called.
func NewFakeCredentialsFileStore(path string, err error) FileStore {
	return &fakeCredentialsFileStore{
		path: path,
		err:  err,
	}
}

// SecretStore defines operations for interacting with credentials
// that are stored in Secret.
type SecretStore interface {
	// Get returns the secret key defined by the given selector
	Get(ctx context.Context, selector *corev1api.SecretKeySelector) (string, error)
}

type fakeCredentialsSecretStore struct {
	data string
	err  error
}

// Get returns the secret data.
func (f *fakeCredentialsSecretStore) Get(ctx context.Context, selector *corev1api.SecretKeySelector) (string, error) {
	return f.data, f.err
}

// NewFakeCredentialsSecretStore creates a SecretStore which will return the given data
// and error when Get is called.
// data is the secret value to return (e.g., certificate content).
// err is the error to return, if any.
func NewFakeCredentialsSecretStore(data string, err error) SecretStore {
	return &fakeCredentialsSecretStore{
		data: data,
		err:  err,
	}
}
