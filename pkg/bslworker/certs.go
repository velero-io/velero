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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"

	"github.com/cockroachdb/errors"
)

// certValidity is how long generated leaf (server/client) certificates remain valid.
// The worker controller reissues worker server certificates before expiry (see
// certRenewalWindow and BackupStorageLocationWorkerReconciler.ensureTLSSecret).
const certValidity = 365 * 24 * time.Hour

// caValidity is how long the signing CA remains valid. It is deliberately much longer
// than certValidity so the CA does not expire out from under still-valid leaf certs;
// the CA is generated once and persisted in a Secret.
const caValidity = 10 * 365 * 24 * time.Hour

// certRenewalWindow is how long before a leaf certificate's expiry it is proactively
// reissued, leaving ample time for the worker pod to restart and pick up the new
// material well before the old certificate becomes invalid.
const certRenewalWindow = 90 * 24 * time.Hour

// KeyPair is a PEM-encoded certificate and its private key.
type KeyPair struct {
	CertPEM []byte
	KeyPEM  []byte
}

// CA is a PEM-encoded certificate authority used to issue and verify worker
// server/client certificates.
type CA struct {
	CertPEM []byte
	KeyPEM  []byte

	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, errors.Wrap(err, "generating certificate serial number")
	}
	return serial, nil
}

func encodeKey(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, errors.Wrap(err, "marshaling private key")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

// GenerateCA creates a new self-signed certificate authority for signing worker
// server and client certificates. commonName labels the CA (e.g. "velero-bsl-worker-ca").
func GenerateCA(commonName string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errors.Wrap(err, "generating CA key")
	}

	serial, err := newSerial()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, errors.Wrap(err, "creating CA certificate")
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, errors.Wrap(err, "parsing CA certificate")
	}

	keyPEM, err := encodeKey(key)
	if err != nil {
		return nil, err
	}

	return &CA{
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  keyPEM,
		cert:    cert,
		key:     key,
	}, nil
}

// LoadCA reconstructs a CA from its PEM-encoded certificate and key, so existing
// worker certificates can be verified and new ones issued across restarts.
func LoadCA(certPEM, keyPEM []byte) (*CA, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, errors.New("decoding CA certificate PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "parsing CA certificate")
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("decoding CA key PEM")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "parsing CA key")
	}

	return &CA{CertPEM: certPEM, KeyPEM: keyPEM, cert: cert, key: key}, nil
}

// issue creates a certificate/key signed by the CA with the given subject, SANs, and
// extended key usage.
func (c *CA) issue(commonName string, dnsNames []string, ipAddresses []net.IP, extKeyUsage []x509.ExtKeyUsage) (*KeyPair, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errors.Wrap(err, "generating certificate key")
	}

	serial, err := newSerial()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(certValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  extKeyUsage,
		DNSNames:     dnsNames,
		IPAddresses:  ipAddresses,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, errors.Wrap(err, "creating certificate")
	}

	keyPEM, err := encodeKey(key)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  keyPEM,
	}, nil
}

// IssueServerCert issues a server certificate for a worker, valid for the given DNS
// names (the worker Service DNS) and IP addresses.
func (c *CA) IssueServerCert(commonName string, dnsNames []string, ipAddresses []net.IP) (*KeyPair, error) {
	return c.issue(commonName, dnsNames, ipAddresses, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
}

// IssueClientCert issues a client certificate for the central Velero process to
// authenticate to workers.
func (c *CA) IssueClientCert(commonName string) (*KeyPair, error) {
	return c.issue(commonName, nil, nil, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
}

// CertNeedsRenewal reports whether the PEM-encoded leaf certificate is missing,
// unparseable, or within certRenewalWindow of (or past) its expiry, and so should be
// reissued. Unparseable/empty input returns true so callers self-heal by reissuing.
func CertNeedsRenewal(certPEM []byte) bool {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return true
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return true
	}
	return time.Now().After(cert.NotAfter.Add(-certRenewalWindow))
}
