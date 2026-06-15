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
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/google/uuid"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"

	veleroV1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
)

// ErrNotFound is exported for external packages to check for when a file is
// not found
var ErrNotFound = errors.New("file not found")
var ErrDownloadRequestDownloadURLTimeout = errors.New("download request download url timeout, check velero server logs for errors. backup storage location may not be available")

func Stream(
	ctx context.Context,
	kbClient kbclient.Client,
	namespace, name string,
	kind veleroV1api.DownloadTargetKind,
	w io.Writer,
	timeout time.Duration,
	insecureSkipTLSVerify bool,
	caCertFile string,
) error {
	return StreamWithBSLCACert(ctx, kbClient, namespace, name, kind, w, timeout, insecureSkipTLSVerify, caCertFile, "")
}

// StreamWithBSLCACert is like Stream but accepts an additional bslCACert parameter
// that contains the cacert from the BackupStorageLocation config
func StreamWithBSLCACert(
	ctx context.Context,
	kbClient kbclient.Client,
	namespace, name string,
	kind veleroV1api.DownloadTargetKind,
	w io.Writer,
	timeout time.Duration,
	insecureSkipTLSVerify bool,
	caCertFile string,
	bslCACert string,
) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	downloadURL, err := getDownloadURL(ctx, kbClient, namespace, name, kind)
	if err != nil {
		return err
	}

	if err := download(ctx, downloadURL, kind, w, insecureSkipTLSVerify, caCertFile, bslCACert); err != nil {
		return err
	}

	return nil
}

func getDownloadURL(
	ctx context.Context,
	kbClient kbclient.Client,
	namespace, name string,
	kind veleroV1api.DownloadTargetKind,
) (string, error) {
	uuid, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}

	reqName := fmt.Sprintf("%s-%s", name, uuid.String())
	created := builder.ForDownloadRequest(namespace, reqName).Target(kind, name).Result()

	if err := kbClient.Create(ctx, created, &kbclient.CreateOptions{}); err != nil {
		return "", errors.WithStack(err)
	}

	for {
		select {
		case <-ctx.Done():
			return "", ErrDownloadRequestDownloadURLTimeout

		case <-time.After(25 * time.Millisecond):
			updated := &veleroV1api.DownloadRequest{}
			if err := kbClient.Get(ctx, kbclient.ObjectKey{Name: created.Name, Namespace: namespace}, updated); err != nil {
				return "", errors.WithStack(err)
			}

			if updated.Status.DownloadURL != "" {
				return updated.Status.DownloadURL, nil
			}
		}
	}
}

func download(
	ctx context.Context,
	downloadURL string,
	kind veleroV1api.DownloadTargetKind,
	w io.Writer,
	insecureSkipTLSVerify bool,
	caCertFile string,
	caCertByteString string,
) error {
	var caPool *x509.CertPool
	var err error

	// Initialize caPool once
	caPool, err = x509.SystemCertPool()
	if err != nil {
		caPool = x509.NewCertPool()
	}

	// Try to load CA cert from file first
	if len(caCertFile) > 0 {
		caCert, err := os.ReadFile(caCertFile)
		if err != nil {
			// If caCertFile fails and BSL cert is available, fall back to it
			if len(caCertByteString) > 0 {
				fmt.Fprintf(os.Stderr, "Warning: Failed to open CA certificate file %s: %v. Using CA certificate from backup storage location instead.\n", caCertFile, err)
				caPool.AppendCertsFromPEM([]byte(caCertByteString))
			} else {
				// If no BSL cert available, return the original error
				return errors.Wrapf(err, "couldn't open cacert")
			}
		} else {
			caPool.AppendCertsFromPEM(caCert)
		}
	} else if len(caCertByteString) > 0 {
		// If no caCertFile specified, use BSL cert if available
		caPool.AppendCertsFromPEM([]byte(caCertByteString))
	}

	defaultTransport := http.DefaultTransport.(*http.Transport)
	// same settings as the default transport
	// aside from TLSClientConfig
	httpClient := new(http.Client)
	httpClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecureSkipTLSVerify, //nolint:gosec // This parameter is useful for some scenarios.
			RootCAs:            caPool,
		},
		DialContext:           defaultTransport.DialContext,
		ForceAttemptHTTP2:     defaultTransport.ForceAttemptHTTP2,
		MaxIdleConns:          defaultTransport.MaxIdleConns,
		Proxy:                 defaultTransport.Proxy,
		TLSHandshakeTimeout:   defaultTransport.TLSHandshakeTimeout,
		ExpectContinueTimeout: defaultTransport.ExpectContinueTimeout,
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return err
	}

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		if urlErr, ok := err.(*url.Error); ok {
			if _, ok := urlErr.Err.(x509.UnknownAuthorityError); ok {
				return fmt.Errorf("%s\n\nThe --insecure-skip-tls-verify flag can also be used to accept any TLS certificate for the download, but it is susceptible to man-in-the-middle attacks", err.Error())
			}
		}
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return errors.Wrapf(err, "request failed: unable to decode response body")
		}

		if resp.StatusCode == http.StatusNotFound {
			return ErrNotFound
		}

		return errors.Errorf("request failed: %v", string(body))
	}

	reader := resp.Body
	if kind != veleroV1api.DownloadTargetKindBackupContents {
		// need to decompress logs
		gzipReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			return err
		}
		defer gzipReader.Close()
		reader = gzipReader
	}

	_, err = io.Copy(w, reader)
	return err
}
