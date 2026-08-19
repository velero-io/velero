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

package downloadrequest

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	"github.com/vmware-tanzu/velero/pkg/cmd/util/cacert"
	"github.com/vmware-tanzu/velero/pkg/util"
)

// createSelfSignedCertificate creates a self-signed certificate for testing.
// This allows us to test the BSL CA certificate functionality by ensuring
// that the client properly validates server certificates against the CA cert
// provided in the BackupStorageLocation configuration.
func createSelfSignedCertificate(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()

	// Generate a private key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create certificate template for a self-signed certificate
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Test Org"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Test City"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:              []string{"localhost"},
	}

	// Create the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)

	// Encode certificate and key to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	// Create tls.Certificate
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	return tlsCert, certPEM
}

func TestStream(t *testing.T) {
	// Create a test server that returns download content
	testContent := "test backup content"
	downloadServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if strings.Contains(r.URL.Path, "log") {
			// For logs, return gzipped content
			gzipWriter := gzip.NewWriter(w)
			gzipWriter.Write([]byte(testContent))
			gzipWriter.Close()
		} else {
			w.Write([]byte(testContent))
		}
	}))
	defer downloadServer.Close()

	testCases := []struct {
		name               string
		target             velerov1api.DownloadTargetKind
		timeout            time.Duration
		setupClient        func(*testing.T, kbclient.WithWatch)
		expectedError      bool
		expectedErrMessage string
		validateContent    func(*testing.T, *bytes.Buffer)
	}{
		{
			name:    "successful backup log download",
			target:  velerov1api.DownloadTargetKindBackupLog,
			timeout: 5 * time.Second,
			setupClient: func(t *testing.T, client kbclient.WithWatch) {
				t.Helper()
				// Simulate controller updating the DownloadRequest with URL
				go func() {
					time.Sleep(10 * time.Millisecond)
					list := &velerov1api.DownloadRequestList{}
					err := client.List(t.Context(), list)
					assert.NoError(t, err)

					for _, dr := range list.Items {
						dr.Status.DownloadURL = downloadServer.URL + "/log"
						dr.Status.Phase = velerov1api.DownloadRequestPhaseProcessed
						err := client.Update(t.Context(), &dr)
						assert.NoError(t, err)
					}
				}()
			},
			expectedError: false,
			validateContent: func(t *testing.T, buf *bytes.Buffer) {
				t.Helper()
				// Logs should be decompressed
				assert.Equal(t, testContent, buf.String())
			},
		},
		{
			name:    "successful backup contents download",
			target:  velerov1api.DownloadTargetKindBackupContents,
			timeout: 5 * time.Second,
			setupClient: func(t *testing.T, client kbclient.WithWatch) {
				t.Helper()
				// Simulate controller updating the DownloadRequest with URL
				go func() {
					time.Sleep(10 * time.Millisecond)
					list := &velerov1api.DownloadRequestList{}
					err := client.List(t.Context(), list)
					assert.NoError(t, err)

					for _, dr := range list.Items {
						dr.Status.DownloadURL = downloadServer.URL + "/contents"
						dr.Status.Phase = velerov1api.DownloadRequestPhaseProcessed
						err := client.Update(t.Context(), &dr)
						assert.NoError(t, err)
					}
				}()
			},
			expectedError: false,
			validateContent: func(t *testing.T, buf *bytes.Buffer) {
				t.Helper()
				assert.Equal(t, testContent, buf.String())
			},
		},
		{
			name:    "timeout waiting for download URL",
			target:  velerov1api.DownloadTargetKindBackupLog,
			timeout: 50 * time.Millisecond,
			setupClient: func(t *testing.T, client kbclient.WithWatch) {
				t.Helper()
			},
			expectedError:      true,
			expectedErrMessage: "download request download url timeout",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().
				WithScheme(util.VeleroScheme).
				Build()

			if tc.setupClient != nil {
				tc.setupClient(t, fakeClient)
			}

			var buf bytes.Buffer
			ctx := t.Context()

			err := Stream(ctx, fakeClient, "test-ns", "test-backup", tc.target, &buf, tc.timeout, false, "")

			if tc.expectedError {
				require.Error(t, err)
				if tc.expectedErrMessage != "" {
					assert.Contains(t, err.Error(), tc.expectedErrMessage)
				}
			} else {
				require.NoError(t, err)
				if tc.validateContent != nil {
					tc.validateContent(t, &buf)
				}
			}
		})
	}
}

func TestStreamWithBSLCACert(t *testing.T) {
	// Create a test server that returns download content
	testContent := "test backup content with BSL CA cert"

	// Create self-signed certificate for TLS testing
	tlsCert, serverCACertPEM := createSelfSignedCertificate(t)

	// Create TLS test server for testing CA certificate functionality
	tlsServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if strings.Contains(r.URL.Path, "log") {
			// For logs, return gzipped content
			gzipWriter := gzip.NewWriter(w)
			gzipWriter.Write([]byte(testContent))
			gzipWriter.Close()
		} else {
			w.Write([]byte(testContent))
		}
	}))
	tlsServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}
	tlsServer.StartTLS()
	defer tlsServer.Close()

	// Also create a regular HTTP server for non-TLS tests
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if strings.Contains(r.URL.Path, "log") {
			// For logs, return gzipped content
			gzipWriter := gzip.NewWriter(w)
			gzipWriter.Write([]byte(testContent))
			gzipWriter.Close()
		} else {
			w.Write([]byte(testContent))
		}
	}))
	defer httpServer.Close()

	testCases := []struct {
		name               string
		target             velerov1api.DownloadTargetKind
		bslCACert          string
		timeout            time.Duration
		setupClient        func(*testing.T, kbclient.WithWatch)
		useTLS             bool
		expectedError      bool
		expectedErrMessage string
		validateContent    func(*testing.T, *bytes.Buffer)
	}{
		{
			name:      "successful TLS backup log download with correct BSL CA cert",
			target:    velerov1api.DownloadTargetKindBackupLog,
			bslCACert: string(serverCACertPEM),
			timeout:   5 * time.Second,
			useTLS:    true,
			setupClient: func(t *testing.T, client kbclient.WithWatch) {
				t.Helper()
				// Simulate controller updating the DownloadRequest with URL
				go func() {
					time.Sleep(10 * time.Millisecond)
					list := &velerov1api.DownloadRequestList{}
					err := client.List(t.Context(), list)
					assert.NoError(t, err)

					for _, dr := range list.Items {
						dr.Status.DownloadURL = tlsServer.URL + "/log"
						dr.Status.Phase = velerov1api.DownloadRequestPhaseProcessed
						err := client.Update(t.Context(), &dr)
						assert.NoError(t, err)
					}
				}()
			},
			expectedError: false,
			validateContent: func(t *testing.T, buf *bytes.Buffer) {
				t.Helper()
				// Logs should be decompressed
				assert.Equal(t, testContent, buf.String())
			},
		},
		{
			name:      "successful TLS backup contents download with correct BSL CA cert",
			target:    velerov1api.DownloadTargetKindBackupContents,
			bslCACert: string(serverCACertPEM),
			timeout:   5 * time.Second,
			useTLS:    true,
			setupClient: func(t *testing.T, client kbclient.WithWatch) {
				t.Helper()
				// Simulate controller updating the DownloadRequest with URL
				go func() {
					time.Sleep(10 * time.Millisecond)
					list := &velerov1api.DownloadRequestList{}
					err := client.List(t.Context(), list)
					assert.NoError(t, err)

					for _, dr := range list.Items {
						dr.Status.DownloadURL = tlsServer.URL + "/contents"
						dr.Status.Phase = velerov1api.DownloadRequestPhaseProcessed
						err := client.Update(t.Context(), &dr)
						assert.NoError(t, err)
					}
				}()
			},
			expectedError: false,
			validateContent: func(t *testing.T, buf *bytes.Buffer) {
				t.Helper()
				assert.Equal(t, testContent, buf.String())
			},
		},
		{
			name:      "failed TLS download with wrong BSL CA cert",
			target:    velerov1api.DownloadTargetKindBackupContents,
			bslCACert: "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKHHIgKwERfFMA0GCSqGSIb3DQEBCwUAMBkxFzAVBgNVBAMTDmRp\nZmZlcmVudC1jZXJ0MB4XDTE5MDQwMTAwMDAwMFoXDTI5MDQwMTAwMDAwMFowGTEX\nMBUGA1UEAxMOZGlmZmVyZW50LWNlcnQwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJ\nAoGBAOO4V+XrhVEGbTqnO2FM5eVFaM3KMKc3M9/C1aeg3vvY+Th3OhqJBxEYFxXL\nZoSqkwL/E6BjQb0NdSyJY9wdM4Ie3gElcZBKYVpHXYYAVhrepRCRVJEIHdBN8ybr\nFoBBDjd/ID1qy8Gdp3RihPFNvCNx0RWWqPAJtNXWJvCiNRCDAgMBAAEwDQYJKoZI\nhvcNAQELBQADgYEAGEwwGz7HAmH0J3pAJzQKPCb8HJG8hTjD6qkMon3Bp6gZ\n-----END CERTIFICATE-----\n",
			timeout:   5 * time.Second,
			useTLS:    true,
			setupClient: func(t *testing.T, client kbclient.WithWatch) {
				t.Helper()
				// Simulate controller updating the DownloadRequest with URL
				go func() {
					time.Sleep(10 * time.Millisecond)
					list := &velerov1api.DownloadRequestList{}
					err := client.List(t.Context(), list)
					assert.NoError(t, err)

					for _, dr := range list.Items {
						dr.Status.DownloadURL = tlsServer.URL + "/contents"
						dr.Status.Phase = velerov1api.DownloadRequestPhaseProcessed
						err := client.Update(t.Context(), &dr)
						assert.NoError(t, err)
					}
				}()
			},
			expectedError:      true,
			expectedErrMessage: "x509",
		},
		{
			name:      "successful HTTP download with empty BSL CA cert",
			target:    velerov1api.DownloadTargetKindBackupContents,
			bslCACert: "",
			timeout:   5 * time.Second,
			useTLS:    false,
			setupClient: func(t *testing.T, client kbclient.WithWatch) {
				t.Helper()
				// Simulate controller updating the DownloadRequest with URL
				go func() {
					time.Sleep(10 * time.Millisecond)
					list := &velerov1api.DownloadRequestList{}
					err := client.List(t.Context(), list)
					assert.NoError(t, err)

					for _, dr := range list.Items {
						dr.Status.DownloadURL = httpServer.URL + "/contents"
						dr.Status.Phase = velerov1api.DownloadRequestPhaseProcessed
						err := client.Update(t.Context(), &dr)
						assert.NoError(t, err)
					}
				}()
			},
			expectedError: false,
			validateContent: func(t *testing.T, buf *bytes.Buffer) {
				t.Helper()
				assert.Equal(t, testContent, buf.String())
			},
		},
		{
			name:      "timeout waiting for download URL with BSL CA cert",
			target:    velerov1api.DownloadTargetKindBackupLog,
			bslCACert: "test-ca-cert-content",
			timeout:   50 * time.Millisecond,
			setupClient: func(t *testing.T, client kbclient.WithWatch) {
				t.Helper()
			},
			expectedError:      true,
			expectedErrMessage: "download request download url timeout",
		},
		{
			name:      "failed TLS download with malformed BSL CA cert",
			target:    velerov1api.DownloadTargetKindBackupLog,
			bslCACert: "-----BEGIN CERTIFICATE-----\nINVALID CERT DATA\n-----END CERTIFICATE-----\n",
			timeout:   5 * time.Second,
			useTLS:    true,
			setupClient: func(t *testing.T, client kbclient.WithWatch) {
				t.Helper()
				// Simulate controller updating the DownloadRequest with URL
				go func() {
					time.Sleep(10 * time.Millisecond)
					list := &velerov1api.DownloadRequestList{}
					err := client.List(t.Context(), list)
					assert.NoError(t, err)

					for _, dr := range list.Items {
						dr.Status.DownloadURL = tlsServer.URL + "/log"
						dr.Status.Phase = velerov1api.DownloadRequestPhaseProcessed
						err := client.Update(t.Context(), &dr)
						assert.NoError(t, err)
					}
				}()
			},
			expectedError:      true,
			expectedErrMessage: "x509", // Should fail due to malformed cert not being added to pool
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().
				WithScheme(util.VeleroScheme).
				Build()

			if tc.setupClient != nil {
				tc.setupClient(t, fakeClient)
			}

			var buf bytes.Buffer
			ctx := t.Context()

			err := StreamWithBSLCACert(ctx, fakeClient, "test-ns", "test-backup", tc.target, &buf, tc.timeout, false, "", tc.bslCACert)

			if tc.expectedError {
				require.Error(t, err)
				if tc.expectedErrMessage != "" {
					assert.Contains(t, err.Error(), tc.expectedErrMessage)
				}
			} else {
				require.NoError(t, err)
				if tc.validateContent != nil {
					tc.validateContent(t, &buf)
				}
			}
		})
	}
}

func TestDownload(t *testing.T) {
	testContent := "test content for download"
	compressedContent := new(bytes.Buffer)
	gzipWriter := gzip.NewWriter(compressedContent)
	gzipWriter.Write([]byte(testContent))
	gzipWriter.Close()

	testCases := []struct {
		name                  string
		serverHandler         http.HandlerFunc
		target                velerov1api.DownloadTargetKind
		insecureSkipTLSVerify bool
		caCertFile            string
		bslCACert             string
		expectedContent       string
		expectedError         bool
		errorType             error
		expectedErrMsg        string
	}{
		{
			name: "successful download with gzip for logs",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write(compressedContent.Bytes())
			},
			target:          velerov1api.DownloadTargetKindBackupLog,
			expectedContent: testContent,
			expectedError:   false,
		},
		{
			name: "error decompressed data exceeds the limit",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write(compressedContent.Bytes())
			},
			target:         velerov1api.DownloadTargetKindBackupLog,
			expectedError:  true,
			expectedErrMsg: "decompressed data exceeds the limit",
		},
		{
			name: "successful download without gzip for backup contents",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(testContent))
			},
			target:          velerov1api.DownloadTargetKindBackupContents,
			expectedContent: testContent,
			expectedError:   false,
		},
		{
			name: "404 not found error",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
			target:        velerov1api.DownloadTargetKindBackupLog,
			expectedError: true,
			errorType:     ErrNotFound,
		},
		{
			name: "500 internal server error",
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("internal server error"))
			},
			target:        velerov1api.DownloadTargetKindBackupLog,
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			originalLimit := unzipLimit
			if tc.expectedErrMsg == "decompressed data exceeds the limit" {
				unzipLimit = 10
			}
			defer func() { unzipLimit = originalLimit }()

			server := httptest.NewServer(tc.serverHandler)
			defer server.Close()

			var buf bytes.Buffer
			err := download(
				t.Context(),
				server.URL,
				tc.target,
				&buf,
				tc.insecureSkipTLSVerify,
				tc.caCertFile,
				tc.bslCACert,
			)

			if tc.expectedError {
				require.Error(t, err)
				if tc.errorType != nil {
					assert.Equal(t, tc.errorType, err)
				}
				if tc.expectedErrMsg != "" {
					assert.Contains(t, err.Error(), tc.expectedErrMsg)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedContent, buf.String())
			}
		})
	}
}

// TestStreamWithBSLCACertEndToEnd tests the complete flow from BSL to download with CA cert
func TestStreamWithBSLCACertEndToEnd(t *testing.T) {
	testContent := "end-to-end test content"

	// Create self-signed certificate for TLS testing
	tlsCert, serverCACertPEM := createSelfSignedCertificate(t)

	// Create TLS test server
	tlsServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if strings.Contains(r.URL.Path, "log") {
			// For logs, return gzipped content
			gzipWriter := gzip.NewWriter(w)
			gzipWriter.Write([]byte(testContent))
			gzipWriter.Close()
		} else {
			w.Write([]byte(testContent))
		}
	}))
	tlsServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}
	tlsServer.StartTLS()
	defer tlsServer.Close()

	// Create BSL with CA cert
	bsl := builder.ForBackupStorageLocation("test-ns", "test-bsl").
		Provider("aws").
		Bucket("test-bucket").
		CACert(serverCACertPEM).
		Result()

	// Create backup that references the BSL
	backup := builder.ForBackup("test-ns", "test-backup").
		StorageLocation("test-bsl").
		Result()

	// Setup fake client with BSL and backup
	fakeClient := fake.NewClientBuilder().
		WithScheme(util.VeleroScheme).
		WithRuntimeObjects(bsl, backup).
		Build()

	// Helper function to simulate controller updating the DownloadRequest
	simulateControllerUpdate := func() {
		go func() {
			time.Sleep(10 * time.Millisecond)
			list := &velerov1api.DownloadRequestList{}
			err := fakeClient.List(t.Context(), list)
			assert.NoError(t, err)

			for _, dr := range list.Items {
				dr.Status.DownloadURL = tlsServer.URL + "/log"
				dr.Status.Phase = velerov1api.DownloadRequestPhaseProcessed
				err := fakeClient.Update(t.Context(), &dr)
				assert.NoError(t, err)
			}
		}()
	}

	// Test the complete flow
	ctx := t.Context()

	// First, try to download WITHOUT the CA cert - this should fail
	simulateControllerUpdate()
	var bufFail bytes.Buffer
	err := StreamWithBSLCACert(ctx, fakeClient, "test-ns", "test-backup", velerov1api.DownloadTargetKindBackupLog, &bufFail, 5*time.Second, false, "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "x509") // Should fail with certificate validation error

	// Now get CA cert from BSL through backup
	cacertStr, err := cacert.GetCACertFromBackup(ctx, fakeClient, "test-ns", backup)
	require.NoError(t, err)
	require.Equal(t, string(serverCACertPEM), cacertStr)

	// Try again with the CA cert - this should succeed
	simulateControllerUpdate()
	var bufSuccess bytes.Buffer
	err = StreamWithBSLCACert(ctx, fakeClient, "test-ns", "test-backup", velerov1api.DownloadTargetKindBackupLog, &bufSuccess, 5*time.Second, false, "", cacertStr)
	require.NoError(t, err)

	// Verify content was downloaded and decompressed correctly
	assert.Equal(t, testContent, bufSuccess.String())
}

// TestBackwardCompatibilityWithoutBSLCACert tests that old download requests work without BSL CA cert
func TestBackwardCompatibilityWithoutBSLCACert(t *testing.T) {
	testContent := "backward compatibility test content"

	// Create HTTP (not HTTPS) server to simulate old behavior where TLS wasn't required
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if strings.Contains(r.URL.Path, "log") {
			// For logs, return gzipped content
			gzipWriter := gzip.NewWriter(w)
			gzipWriter.Write([]byte(testContent))
			gzipWriter.Close()
		} else {
			w.Write([]byte(testContent))
		}
	}))
	defer httpServer.Close()

	// Create BSL without CA cert (simulating old configuration)
	bsl := builder.ForBackupStorageLocation("test-ns", "test-bsl").
		Provider("aws").
		Bucket("test-bucket").
		// No CACert() call - simulating pre-CA cert support
		Result()

	// Create backup that references the BSL
	backup := builder.ForBackup("test-ns", "test-backup").
		StorageLocation("test-bsl").
		Result()

	// Setup fake client with BSL and backup
	fakeClient := fake.NewClientBuilder().
		WithScheme(util.VeleroScheme).
		WithRuntimeObjects(bsl, backup).
		Build()

	// Simulate controller updating the DownloadRequest with HTTP URL (old behavior)
	go func() {
		time.Sleep(10 * time.Millisecond)
		list := &velerov1api.DownloadRequestList{}
		err := fakeClient.List(t.Context(), list)
		assert.NoError(t, err)

		for _, dr := range list.Items {
			dr.Status.DownloadURL = httpServer.URL + "/log"
			dr.Status.Phase = velerov1api.DownloadRequestPhaseProcessed
			err := fakeClient.Update(t.Context(), &dr)
			assert.NoError(t, err)
		}
	}()

	ctx := t.Context()

	// Test 1: Stream function (without BSL CA cert parameter) should work
	var buf1 bytes.Buffer
	err := Stream(ctx, fakeClient, "test-ns", "test-backup", velerov1api.DownloadTargetKindBackupLog, &buf1, 5*time.Second, false, "")
	require.NoError(t, err)
	assert.Equal(t, testContent, buf1.String())

	// Test 2: StreamWithBSLCACert with empty BSL CA cert should also work
	go func() {
		time.Sleep(10 * time.Millisecond)
		list := &velerov1api.DownloadRequestList{}
		err := fakeClient.List(t.Context(), list)
		assert.NoError(t, err)

		for _, dr := range list.Items {
			dr.Status.DownloadURL = httpServer.URL + "/contents"
			dr.Status.Phase = velerov1api.DownloadRequestPhaseProcessed
			err := fakeClient.Update(t.Context(), &dr)
			assert.NoError(t, err)
		}
	}()

	var buf2 bytes.Buffer
	err = StreamWithBSLCACert(ctx, fakeClient, "test-ns", "test-backup", velerov1api.DownloadTargetKindBackupContents, &buf2, 5*time.Second, false, "", "")
	require.NoError(t, err)
	assert.Equal(t, testContent, buf2.String())

	// Test 3: Getting CA cert from BSL should return empty string (not error)
	cacert, err := cacert.GetCACertFromBackup(ctx, fakeClient, "test-ns", backup)
	require.NoError(t, err)
	assert.Empty(t, cacert)
}

// TestMixedEnvironmentHTTPAndHTTPS tests environment with both HTTP and HTTPS endpoints
func TestMixedEnvironmentHTTPAndHTTPS(t *testing.T) {
	testContentHTTP := "http content"
	testContentHTTPS := "https content"

	// Create HTTP server
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(testContentHTTP))
	}))
	defer httpServer.Close()

	// Create HTTPS server with self-signed cert
	tlsCert, serverCACertPEM := createSelfSignedCertificate(t)
	httpsServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(testContentHTTPS))
	}))
	httpsServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}
	httpsServer.StartTLS()
	defer httpsServer.Close()

	// Create two BSLs - one for HTTP (old) and one for HTTPS (new)
	bslHTTP := builder.ForBackupStorageLocation("test-ns", "bsl-http").
		Provider("aws").
		Bucket("http-bucket").
		// No CA cert for HTTP
		Result()

	bslHTTPS := builder.ForBackupStorageLocation("test-ns", "bsl-https").
		Provider("aws").
		Bucket("https-bucket").
		CACert(serverCACertPEM).
		Result()

	// Create backups for each BSL
	backupHTTP := builder.ForBackup("test-ns", "backup-http").
		StorageLocation("bsl-http").
		Result()

	backupHTTPS := builder.ForBackup("test-ns", "backup-https").
		StorageLocation("bsl-https").
		Result()

	// Setup fake client
	fakeClient := fake.NewClientBuilder().
		WithScheme(util.VeleroScheme).
		WithRuntimeObjects(bslHTTP, bslHTTPS, backupHTTP, backupHTTPS).
		Build()

	ctx := t.Context()

	// Test HTTP backup download (backward compatible)
	go func() {
		time.Sleep(10 * time.Millisecond)
		list := &velerov1api.DownloadRequestList{}
		err := fakeClient.List(t.Context(), list)
		assert.NoError(t, err)

		for _, dr := range list.Items {
			if strings.Contains(dr.Name, "backup-http") {
				dr.Status.DownloadURL = httpServer.URL
				dr.Status.Phase = velerov1api.DownloadRequestPhaseProcessed
				err := fakeClient.Update(t.Context(), &dr)
				assert.NoError(t, err)
			}
		}
	}()

	var bufHTTP bytes.Buffer
	err := Stream(ctx, fakeClient, "test-ns", "backup-http", velerov1api.DownloadTargetKindBackupContents, &bufHTTP, 5*time.Second, false, "")
	require.NoError(t, err)
	assert.Equal(t, testContentHTTP, bufHTTP.String())

	// Test HTTPS backup download (requires CA cert)
	go func() {
		time.Sleep(10 * time.Millisecond)
		list := &velerov1api.DownloadRequestList{}
		err := fakeClient.List(t.Context(), list)
		assert.NoError(t, err)

		for _, dr := range list.Items {
			if strings.Contains(dr.Name, "backup-https") {
				dr.Status.DownloadURL = httpsServer.URL
				dr.Status.Phase = velerov1api.DownloadRequestPhaseProcessed
				err := fakeClient.Update(t.Context(), &dr)
				assert.NoError(t, err)
			}
		}
	}()

	// First try without CA cert - should fail
	var bufHTTPSFail bytes.Buffer
	err = Stream(ctx, fakeClient, "test-ns", "backup-https", velerov1api.DownloadTargetKindBackupContents, &bufHTTPSFail, 5*time.Second, false, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "x509")

	// Get CA cert from HTTPS BSL
	cacertStr, err := cacert.GetCACertFromBackup(ctx, fakeClient, "test-ns", backupHTTPS)
	require.NoError(t, err)
	require.Equal(t, string(serverCACertPEM), cacertStr)

	// Try again with CA cert - should succeed
	go func() {
		time.Sleep(10 * time.Millisecond)
		list := &velerov1api.DownloadRequestList{}
		err := fakeClient.List(t.Context(), list)
		assert.NoError(t, err)

		for _, dr := range list.Items {
			if strings.Contains(dr.Name, "backup-https") {
				dr.Status.DownloadURL = httpsServer.URL
				dr.Status.Phase = velerov1api.DownloadRequestPhaseProcessed
				err := fakeClient.Update(t.Context(), &dr)
				assert.NoError(t, err)
			}
		}
	}()

	var bufHTTPSSuccess bytes.Buffer
	err = StreamWithBSLCACert(ctx, fakeClient, "test-ns", "backup-https", velerov1api.DownloadTargetKindBackupContents, &bufHTTPSSuccess, 5*time.Second, false, "", cacertStr)
	require.NoError(t, err)
	assert.Equal(t, testContentHTTPS, bufHTTPSSuccess.String())
}

// TestBSLUpgradeScenario tests the scenario where a BSL is upgraded to include CA cert
func TestBSLUpgradeScenario(t *testing.T) {
	testContent := "bsl upgrade test content"

	// Create self-signed certificate for TLS testing
	tlsCert, serverCACertPEM := createSelfSignedCertificate(t)

	// Create HTTPS server
	httpsServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if strings.Contains(r.URL.Path, "log") {
			// For logs, return gzipped content
			gzipWriter := gzip.NewWriter(w)
			gzipWriter.Write([]byte(testContent))
			gzipWriter.Close()
		} else {
			w.Write([]byte(testContent))
		}
	}))
	httpsServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}
	httpsServer.StartTLS()
	defer httpsServer.Close()

	// Create BSL initially without CA cert (pre-upgrade state)
	bsl := builder.ForBackupStorageLocation("test-ns", "test-bsl").
		Provider("aws").
		Bucket("test-bucket").
		// Initially no CA cert
		Result()

	// Create an old backup that references this BSL
	oldBackup := builder.ForBackup("test-ns", "old-backup").
		StorageLocation("test-bsl").
		Result()

	// Setup fake client
	fakeClient := fake.NewClientBuilder().
		WithScheme(util.VeleroScheme).
		WithRuntimeObjects(bsl, oldBackup).
		Build()

	ctx := t.Context()

	// Test 1: Old backup with HTTPS URL should fail without CA cert
	go func() {
		time.Sleep(10 * time.Millisecond)
		list := &velerov1api.DownloadRequestList{}
		err := fakeClient.List(t.Context(), list)
		assert.NoError(t, err)

		for _, dr := range list.Items {
			dr.Status.DownloadURL = httpsServer.URL + "/log"
			dr.Status.Phase = velerov1api.DownloadRequestPhaseProcessed
			err := fakeClient.Update(t.Context(), &dr)
			assert.NoError(t, err)
		}
	}()

	var bufFail bytes.Buffer
	err := Stream(ctx, fakeClient, "test-ns", "old-backup", velerov1api.DownloadTargetKindBackupLog, &bufFail, 5*time.Second, false, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "x509")

	// Simulate BSL upgrade - get current BSL and update it
	currentBSL := &velerov1api.BackupStorageLocation{}
	err = fakeClient.Get(ctx, kbclient.ObjectKey{Namespace: "test-ns", Name: "test-bsl"}, currentBSL)
	require.NoError(t, err)

	// Update the BSL to include CA cert
	// Ensure ObjectStorage is initialized
	if currentBSL.Spec.ObjectStorage == nil {
		currentBSL.Spec.ObjectStorage = &velerov1api.ObjectStorageLocation{}
	}
	currentBSL.Spec.ObjectStorage.CACert = serverCACertPEM // CA cert added after upgrade

	err = fakeClient.Update(ctx, currentBSL)
	require.NoError(t, err)

	// Test 2: After BSL upgrade, old backup should work with new CA cert
	cacertStr, err := cacert.GetCACertFromBackup(ctx, fakeClient, "test-ns", oldBackup)
	require.NoError(t, err)
	require.Equal(t, string(serverCACertPEM), cacertStr)

	go func() {
		time.Sleep(10 * time.Millisecond)
		list := &velerov1api.DownloadRequestList{}
		err := fakeClient.List(t.Context(), list)
		assert.NoError(t, err)

		for _, dr := range list.Items {
			dr.Status.DownloadURL = httpsServer.URL + "/log"
			dr.Status.Phase = velerov1api.DownloadRequestPhaseProcessed
			err := fakeClient.Update(t.Context(), &dr)
			assert.NoError(t, err)
		}
	}()

	var bufSuccess bytes.Buffer
	err = StreamWithBSLCACert(ctx, fakeClient, "test-ns", "old-backup", velerov1api.DownloadTargetKindBackupLog, &bufSuccess, 5*time.Second, false, "", cacertStr)
	require.NoError(t, err)
	assert.Equal(t, testContent, bufSuccess.String())

	// Test 3: New backup created after upgrade should also work
	newBackup := builder.ForBackup("test-ns", "new-backup").
		StorageLocation("test-bsl").
		Result()

	err = fakeClient.Create(ctx, newBackup)
	require.NoError(t, err)

	cacertStr2, err := cacert.GetCACertFromBackup(ctx, fakeClient, "test-ns", newBackup)
	require.NoError(t, err)
	require.Equal(t, string(serverCACertPEM), cacertStr2)
}

// TestConcurrentDownloadsWithBSLCACert tests multiple concurrent downloads with CA cert
func TestConcurrentDownloadsWithBSLCACert(t *testing.T) {
	testContent := "concurrent test content"

	// Create self-signed certificate for TLS testing
	tlsCert, serverCACertPEM := createSelfSignedCertificate(t)

	// Create TLS test server
	tlsServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate some processing time
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(testContent))
	}))
	tlsServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}
	tlsServer.StartTLS()
	defer tlsServer.Close()

	// Run multiple concurrent downloads
	numConcurrent := 5
	errors := make(chan error, numConcurrent)
	results := make(chan string, numConcurrent)

	for i := range numConcurrent {
		go func(idx int) {
			var buf bytes.Buffer
			err := download(
				t.Context(),
				tlsServer.URL,
				velerov1api.DownloadTargetKindBackupContents,
				&buf,
				false,
				"",
				string(serverCACertPEM),
			)
			if err != nil {
				errors <- err
				return
			}
			results <- buf.String()
		}(i)
	}

	// Collect results
	for i := range numConcurrent {
		select {
		case err := <-errors:
			t.Fatalf("Concurrent download %d failed: %v", i, err)
		case result := <-results:
			assert.Equal(t, testContent, result)
		case <-time.After(5 * time.Second):
			t.Fatal("Timeout waiting for concurrent downloads")
		}
	}
}

func TestDownloadWithBSLCACert(t *testing.T) {
	testContent := "test content with BSL CA cert"

	// Create self-signed certificate for TLS testing
	tlsCert, serverCACertPEM := createSelfSignedCertificate(t)

	// Create TLS test server with self-signed cert
	tlsServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(testContent))
	}))
	tlsServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}
	tlsServer.StartTLS()
	defer tlsServer.Close()

	// Create HTTP test server for non-TLS tests
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(testContent))
	}))
	defer httpServer.Close()

	testCases := []struct {
		name                  string
		url                   string
		target                velerov1api.DownloadTargetKind
		insecureSkipTLSVerify bool
		bslCACert             string
		expectedContent       string
		expectedError         bool
		expectedErrContains   string
	}{
		{
			name:            "successful TLS download with correct BSL CA cert",
			url:             tlsServer.URL,
			target:          velerov1api.DownloadTargetKindBackupContents,
			bslCACert:       string(serverCACertPEM),
			expectedContent: testContent,
			expectedError:   false,
		},
		{
			name:                  "successful TLS download with insecureSkipTLSVerify",
			url:                   tlsServer.URL,
			target:                velerov1api.DownloadTargetKindBackupContents,
			insecureSkipTLSVerify: true,
			bslCACert:             "",
			expectedContent:       testContent,
			expectedError:         false,
		},
		{
			name:                "failed TLS download without CA cert or insecureSkipTLSVerify",
			url:                 tlsServer.URL,
			target:              velerov1api.DownloadTargetKindBackupContents,
			bslCACert:           "",
			expectedError:       true,
			expectedErrContains: "x509",
		},
		{
			name:                "failed TLS download with wrong BSL CA cert",
			url:                 tlsServer.URL,
			target:              velerov1api.DownloadTargetKindBackupContents,
			bslCACert:           "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKHHIgKwERfFMA0GCSqGSIb3DQEBCwUAMBkxFzAVBgNVBAMTDmRp\nZmZlcmVudC1jZXJ0MB4XDTE5MDQwMTAwMDAwMFoXDTI5MDQwMTAwMDAwMFowGTEX\nMBUGA1UEAxMOZGlmZmVyZW50LWNlcnQwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJ\nAoGBAOO4V+XrhVEGbTqnO2FM5eVFaM3KMKc3M9/C1aeg3vvY+Th3OhqJBxEYFxXL\nZoSqkwL/E6BjQb0NdSyJY9wdM4Ie3gElcZBKYVpHXYYAVhrepRCRVJEIHdBN8ybr\nFoBBDjd/ID1qy8Gdp3RihPFNvCNx0RWWqPAJtNXWJvCiNRCDAgMBAAEwDQYJKoZI\nhvcNAQELBQADgYEAGEwwGz7HAmH0J3pAJzQKPCb8HJG8hTjD6qkMon3Bp6gZ\n-----END CERTIFICATE-----\n",
			expectedError:       true,
			expectedErrContains: "x509",
		},
		{
			name:            "successful HTTP download with empty BSL CA cert",
			url:             httpServer.URL,
			target:          velerov1api.DownloadTargetKindBackupContents,
			bslCACert:       "",
			expectedContent: testContent,
			expectedError:   false,
		},
		{
			name:            "successful TLS download with multiple CA certs in PEM block",
			url:             tlsServer.URL,
			target:          velerov1api.DownloadTargetKindBackupContents,
			bslCACert:       "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKHHIgKwERfFMA0GCSqGSIb3DQEBCwUAMBkxFzAVBgNVBAMTDmRp\nZmZlcmVudC1jZXJ0MB4XDTE5MDQwMTAwMDAwMFoXDTI5MDQwMTAwMDAwMFowGTEX\nMBUGA1UEAxMOZGlmZmVyZW50LWNlcnQwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJ\nAoGBAOO4V+XrhVEGbTqnO2FM5eVFaM3KMKc3M9/C1aeg3vvY+Th3OhqJBxEYFxXL\nZoSqkwL/E6BjQb0NdSyJY9wdM4Ie3gElcZBKYVpHXYYAVhrepRCRVJEIHdBN8ybr\nFoBBDjd/ID1qy8Gdp3RihPFNvCNx0RWWqPAJtNXWJvCiNRCDAgMBAAEwDQYJKoZI\nhvcNAQELBQADgYEAGEwwGz7HAmH0J3pAJzQKPCb8HJG8hTjD6qkMon3Bp6gZ\n-----END CERTIFICATE-----\n" + string(serverCACertPEM), // First cert is wrong, but second is correct
			expectedContent: testContent,
			expectedError:   false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := download(
				t.Context(),
				tc.url,
				tc.target,
				&buf,
				tc.insecureSkipTLSVerify,
				"",
				tc.bslCACert,
			)

			if tc.expectedError {
				require.Error(t, err)
				if tc.expectedErrContains != "" {
					assert.Contains(t, err.Error(), tc.expectedErrContains)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedContent, buf.String())
			}
		})
	}
}

// TestCACertFallback tests the fallback behavior when caCertFile fails
func TestCACertFallback(t *testing.T) {
	testContent := "test content for CA cert fallback"

	// Create self-signed certificate for TLS testing
	tlsCert, serverCACertPEM := createSelfSignedCertificate(t)

	// Create TLS test server
	tlsServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(testContent))
	}))
	tlsServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}
	tlsServer.StartTLS()
	defer tlsServer.Close()

	// Create a temporary file path that doesn't exist
	nonExistentFile := "/tmp/non-existent-ca-cert-file.pem"

	testCases := []struct {
		name                string
		caCertFile          string
		bslCACert           string
		expectedError       bool
		expectedErrContains string
		expectedContent     string
	}{
		{
			name:            "successful download with BSL cert when caCertFile fails",
			caCertFile:      nonExistentFile,
			bslCACert:       string(serverCACertPEM),
			expectedError:   false,
			expectedContent: testContent,
		},
		{
			name:                "failed download when both caCertFile and BSL cert are invalid",
			caCertFile:          nonExistentFile,
			bslCACert:           "",
			expectedError:       true,
			expectedErrContains: "couldn't open cacert",
		},
		{
			name:            "BSL cert used when caCertFile is empty",
			caCertFile:      "",
			bslCACert:       string(serverCACertPEM),
			expectedError:   false,
			expectedContent: testContent,
		},
		{
			name:            "successful download with valid caCertFile (BSL cert ignored)",
			caCertFile:      "", // Will be set to a valid temp file in test
			bslCACert:       "invalid cert that should be ignored",
			expectedError:   false,
			expectedContent: testContent,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			caCertFile := tc.caCertFile

			// For the last test case, create a valid temp file
			if tc.name == "successful download with valid caCertFile (BSL cert ignored)" {
				tmpFile, err := os.CreateTemp(t.TempDir(), "test-ca-cert-*.pem")
				require.NoError(t, err)
				defer os.Remove(tmpFile.Name())

				_, err = tmpFile.Write(serverCACertPEM)
				require.NoError(t, err)
				tmpFile.Close()

				caCertFile = tmpFile.Name()
			}

			var buf bytes.Buffer
			err := download(
				t.Context(),
				tlsServer.URL,
				velerov1api.DownloadTargetKindBackupContents,
				&buf,
				false,
				caCertFile,
				tc.bslCACert,
			)

			if tc.expectedError {
				require.Error(t, err)
				if tc.expectedErrContains != "" {
					assert.Contains(t, err.Error(), tc.expectedErrContains)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedContent, buf.String())
			}
		})
	}
}
