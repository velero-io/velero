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

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/util/wait"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
)

// ErrNotFound is exported for external packages to check for when a file is
// not found
var ErrNotFound = errors.New("file not found")
var ErrDownloadRequestDownloadURLTimeout = errors.New("download request download url timeout, check velero server logs for errors. backup storage location may not be available")

func Stream(ctx context.Context, kbClient kbclient.Client, namespace, name string, kind velerov1api.DownloadTargetKind, w io.Writer, timeout time.Duration, insecureSkipTLSVerify bool, caCertFile string) error {
	uuid, err := uuid.NewRandom()
	if err != nil {
		return errors.WithStack(err)
	}

	reqName := fmt.Sprintf("%s-%s", name, uuid.String())
	created := builder.ForDownloadRequest(namespace, reqName).Target(kind, name).Result()

	if err := kbClient.Create(context.Background(), created, &kbclient.CreateOptions{}); err != nil {
		return errors.WithStack(err)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	key := kbclient.ObjectKey{Name: created.Name, Namespace: namespace}
	timeStreamFirstCheck := time.Now()
	downloadURLTimeout := false
	checkFunc := func() {
		// if timeout has been reached, cancel request
		if time.Now().After(timeStreamFirstCheck.Add(timeout)) {
			downloadURLTimeout = true
			cancel()
		}
		updated := &velerov1api.DownloadRequest{}
		if err := kbClient.Get(ctx, key, updated); err != nil {
			return
		}

		// TODO: once the minimum supported Kubernetes version is v1.9.0, remove the following check.
		// See http://issue.k8s.io/51046 for details.
		if updated.Name != created.Name {
			return
		}

		if updated.Status.DownloadURL != "" {
			created = updated
			cancel()
		}
	}

	wait.Until(checkFunc, 25*time.Millisecond, ctx.Done())
	if downloadURLTimeout {
		return ErrDownloadRequestDownloadURLTimeout
	}

	var caPool *x509.CertPool
	if len(caCertFile) > 0 {
		caCert, err := os.ReadFile(caCertFile)
		if err != nil {
			return errors.Wrapf(err, "couldn't open cacert")
		}
		// bundle the passed in cert with the system cert pool
		// if it's available, otherwise create a new pool just
		// for this.
		caPool, err = x509.SystemCertPool()
		if err != nil {
			caPool = x509.NewCertPool()
		}
		caPool.AppendCertsFromPEM(caCert)
	}

	defaultTransport := http.DefaultTransport.(*http.Transport)
	// same settings as the default transport
	// aside from timeout and TLSClientConfig
	httpClient := new(http.Client)
	httpClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecureSkipTLSVerify, //nolint:gosec
			RootCAs:            caPool,
		},
		IdleConnTimeout:       timeout,
		DialContext:           defaultTransport.DialContext,
		ForceAttemptHTTP2:     defaultTransport.ForceAttemptHTTP2,
		MaxIdleConns:          defaultTransport.MaxIdleConns,
		Proxy:                 defaultTransport.Proxy,
		TLSHandshakeTimeout:   defaultTransport.TLSHandshakeTimeout,
		ExpectContinueTimeout: defaultTransport.ExpectContinueTimeout,
	}

	httpReq, err := http.NewRequest(http.MethodGet, created.Status.DownloadURL, nil)
	if err != nil {
		return err
	}

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		if urlErr, ok := err.(*url.Error); ok {
			if _, ok := urlErr.Err.(x509.UnknownAuthorityError); ok {
				return fmt.Errorf("%s\n\nThe --insecure-skip-tls-verify flag can also be used to accept any TLS certificate for the download, but it is susceptible to man-in-the-middle attacks.", err.Error())
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
	if kind != velerov1api.DownloadTargetKindBackupContents {
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
