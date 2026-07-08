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
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCertNeedsRenewal(t *testing.T) {
	ca, err := GenerateCA("velero-bsl-worker-ca")
	require.NoError(t, err)

	pair, err := ca.IssueServerCert("worker.velero.svc", []string{"worker.velero.svc"}, nil)
	require.NoError(t, err)

	// A freshly issued cert (valid for certValidity, well beyond certRenewalWindow)
	// does not need renewal.
	assert.False(t, CertNeedsRenewal(pair.CertPEM))

	// Missing or unparseable material always needs renewal so callers self-heal.
	assert.True(t, CertNeedsRenewal(nil))
	assert.True(t, CertNeedsRenewal([]byte("not a pem")))
}

func TestCAOutlivesLeafCerts(t *testing.T) {
	ca, err := GenerateCA("velero-bsl-worker-ca")
	require.NoError(t, err)

	pair, err := ca.IssueServerCert("worker.velero.svc", []string{"worker.velero.svc"}, nil)
	require.NoError(t, err)

	// The CA must expire strictly after the leaf certs it signs, so leaf certs never
	// chain to an already-expired CA.
	block, _ := pem.Decode(pair.CertPEM)
	require.NotNil(t, block)
	leaf, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.True(t, ca.cert.NotAfter.After(leaf.NotAfter))
}
