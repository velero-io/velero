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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCertReloaderPicksUpRenewedCert(t *testing.T) {
	ca, err := GenerateCA("velero-bsl-worker-ca")
	require.NoError(t, err)

	dir := t.TempDir()
	certFile := filepath.Join(dir, ServerCertFileName)
	keyFile := filepath.Join(dir, ServerKeyFileName)

	first, err := ca.IssueServerCert("worker.velero.svc", []string{"worker.velero.svc"}, nil)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(certFile, first.CertPEM, 0600))
	require.NoError(t, os.WriteFile(keyFile, first.KeyPEM, 0600))

	reloader, err := newCertReloader(certFile, keyFile)
	require.NoError(t, err)

	got, err := reloader.current()
	require.NoError(t, err)
	firstLeaf := got.Certificate[0]

	// Renew: overwrite the files with a new cert and advance the mod time so the
	// reloader detects the change (write granularity can otherwise collide).
	second, err := ca.IssueServerCert("worker.velero.svc", []string{"worker.velero.svc"}, nil)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(certFile, second.CertPEM, 0600))
	require.NoError(t, os.WriteFile(keyFile, second.KeyPEM, 0600))
	future := time.Now().Add(time.Hour)
	require.NoError(t, os.Chtimes(certFile, future, future))

	got, err = reloader.current()
	require.NoError(t, err)
	assert.NotEqual(t, firstLeaf, got.Certificate[0], "reloader should serve the renewed certificate")
}

func TestCertReloaderFailsFastOnMissingFiles(t *testing.T) {
	_, err := newCertReloader(filepath.Join(t.TempDir(), "missing.crt"), filepath.Join(t.TempDir(), "missing.key"))
	assert.Error(t, err)
}
