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
	"crypto/tls"
	"crypto/x509"
	"os"
	"sync"
	"time"

	"github.com/cockroachdb/errors"
)

// TLS material file names as they are mounted into the central Velero pod and the
// worker pod from their respective TLS Secrets.
const (
	// CACertFileName is the PEM-encoded CA certificate that both sides use to verify
	// the other's certificate.
	CACertFileName = "ca.crt"
	// ServerCertFileName / ServerKeyFileName are the worker server certificate/key.
	ServerCertFileName = "tls.crt"
	ServerKeyFileName  = "tls.key"
	// ClientCertFileName / ClientKeyFileName are the central client certificate/key.
	ClientCertFileName = "client.crt"
	ClientKeyFileName  = "client.key"
)

// loadCAPool reads a PEM-encoded CA bundle from caFile into a certificate pool.
func loadCAPool(caFile string) (*x509.CertPool, error) {
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, errors.Wrapf(err, "reading CA certificate %q", caFile)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.Errorf("no valid CA certificates found in %q", caFile)
	}
	return pool, nil
}

// certReloader loads an X.509 key pair from files and transparently reloads it when
// the certificate file changes on disk. Worker server certificates are reissued into
// the worker's TLS Secret before expiry; the kubelet propagates the updated Secret to
// the mounted volume, and this reloader lets a long-lived, never-restarted worker (or
// central client) start serving/presenting the renewed certificate without a restart.
type certReloader struct {
	certFile string
	keyFile  string

	mu      sync.RWMutex
	cached  *tls.Certificate
	modTime time.Time
}

// newCertReloader creates a reloader and eagerly loads the key pair once so that
// invalid material fails fast at startup.
func newCertReloader(certFile, keyFile string) (*certReloader, error) {
	r := &certReloader{certFile: certFile, keyFile: keyFile}
	if _, err := r.reload(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *certReloader) reload() (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return nil, errors.Wrap(err, "loading certificate/key")
	}
	r.mu.Lock()
	r.cached = &cert
	if fi, statErr := os.Stat(r.certFile); statErr == nil {
		r.modTime = fi.ModTime()
	}
	r.mu.Unlock()
	return &cert, nil
}

// current returns the cached key pair, reloading first if the certificate file's
// modification time advanced. On a reload error it falls back to the cached pair so a
// transient read never breaks in-flight handshakes.
func (r *certReloader) current() (*tls.Certificate, error) {
	r.mu.RLock()
	cached, modTime := r.cached, r.modTime
	r.mu.RUnlock()

	fi, err := os.Stat(r.certFile)
	if err != nil {
		return cached, nil
	}
	if fi.ModTime().After(modTime) {
		if reloaded, rErr := r.reload(); rErr == nil {
			return reloaded, nil
		}
	}
	return cached, nil
}

// GetCertificate serves the (reloaded) server certificate during a TLS handshake.
func (r *certReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return r.current()
}

// GetClientCertificate presents the (reloaded) client certificate during a TLS handshake.
func (r *certReloader) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return r.current()
}

// LoadServerTLSConfig builds a *tls.Config for the worker's gRPC server that presents
// the server certificate and requires+verifies the central client's certificate
// (mutual TLS) against the shared CA. The server certificate is served through a
// reloader so an in-place renewal is picked up without restarting the worker.
func LoadServerTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	reloader, err := newCertReloader(certFile, keyFile)
	if err != nil {
		return nil, errors.Wrap(err, "loading worker server certificate/key")
	}

	caPool, err := loadCAPool(caFile)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		GetCertificate: reloader.GetCertificate,
		ClientAuth:     tls.RequireAndVerifyClientCert,
		ClientCAs:      caPool,
		MinVersion:     tls.VersionTLS13,
	}, nil
}

// LoadClientTLSConfig builds a *tls.Config for the central client that presents the
// client certificate and verifies the worker's server certificate against the shared
// CA. serverName must match the worker server certificate's SAN (the worker Service
// DNS name). The client certificate is presented through a reloader so an in-place
// renewal is picked up without restarting the central process.
func LoadClientTLSConfig(certFile, keyFile, caFile, serverName string) (*tls.Config, error) {
	reloader, err := newCertReloader(certFile, keyFile)
	if err != nil {
		return nil, errors.Wrap(err, "loading central client certificate/key")
	}

	caPool, err := loadCAPool(caFile)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		GetClientCertificate: reloader.GetClientCertificate,
		RootCAs:              caPool,
		ServerName:           serverName,
		MinVersion:           tls.VersionTLS13,
	}, nil
}
