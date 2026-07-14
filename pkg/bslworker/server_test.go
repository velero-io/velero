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
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeObjectStore is a minimal in-memory velero.ObjectStore used to exercise the
// worker server and remote client over a real mTLS gRPC connection.
type fakeObjectStore struct {
	initConfig map[string]string
	objects    map[string][]byte
}

func newFakeObjectStore() *fakeObjectStore {
	return &fakeObjectStore{objects: map[string][]byte{}}
}

func (f *fakeObjectStore) Init(config map[string]string) error {
	f.initConfig = config
	return nil
}

func (f *fakeObjectStore) PutObject(_ string, key string, body io.Reader) error {
	data, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	f.objects[key] = data
	return nil
}

func (f *fakeObjectStore) ObjectExists(_ string, key string) (bool, error) {
	_, ok := f.objects[key]
	return ok, nil
}

func (f *fakeObjectStore) GetObject(_ string, key string) (io.ReadCloser, error) {
	data, ok := f.objects[key]
	if !ok {
		return nil, io.EOF
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (f *fakeObjectStore) ListCommonPrefixes(_ string, prefix string, _ string) ([]string, error) {
	return []string{prefix + "sub/"}, nil
}

func (f *fakeObjectStore) ListObjects(_ string, prefix string) ([]string, error) {
	var keys []string
	for k := range f.objects {
		keys = append(keys, k)
	}
	_ = prefix
	return keys, nil
}

func (f *fakeObjectStore) DeleteObject(_ string, key string) error {
	delete(f.objects, key)
	return nil
}

func (f *fakeObjectStore) CreateSignedURL(_ string, key string, _ time.Duration) (string, error) {
	return "https://signed/" + key, nil
}

// writeTLSMaterials generates a CA plus server and client certificates (valid for
// 127.0.0.1) and writes them to a temp dir, returning the file paths.
func writeTLSMaterials(t *testing.T) (caFile, serverCert, serverKey, clientCert, clientKey string) {
	t.Helper()

	ca, err := GenerateCA("test-ca")
	require.NoError(t, err)

	server, err := ca.IssueServerCert("test-server", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	require.NoError(t, err)

	client, err := ca.IssueClientCert("test-client")
	require.NoError(t, err)

	dir := t.TempDir()
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, data, 0600))
		return p
	}

	return write("ca.crt", ca.CertPEM),
		write("server.crt", server.CertPEM),
		write("server.key", server.KeyPEM),
		write("client.crt", client.CertPEM),
		write("client.key", client.KeyPEM)
}

// TestServerClientRoundTrip validates that the worker server and the remote client
// interoperate over a real mutual-TLS gRPC connection across all ObjectStore methods.
func TestServerClientRoundTrip(t *testing.T) {
	caFile, serverCert, serverKey, clientCert, clientKey := writeTLSMaterials(t)

	serverTLS, err := LoadServerTLSConfig(serverCert, serverKey, caFile)
	require.NoError(t, err)

	backend := newFakeObjectStore()
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv := NewServer(logger, backend, serverTLS)
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.ServeListener(ctx, listener)
	}()

	clientTLS, err := LoadClientTLSConfig(clientCert, clientKey, caFile, "127.0.0.1")
	require.NoError(t, err)

	getter := NewRemoteObjectStoreGetter(logger, listener.Addr().String(), clientTLS)
	defer getter.Close()

	store, err := getter.GetObjectStore("velero.io/azure")
	require.NoError(t, err)

	// Init should reach the backend with the given config.
	require.NoError(t, store.Init(map[string]string{"bucket": "b", "prefix": "p"}))
	assert.Equal(t, map[string]string{"bucket": "b", "prefix": "p"}, backend.initConfig)

	// PutObject / GetObject round-trip (exercises client- and server-streaming).
	payload := bytes.Repeat([]byte("velero-"), 5000) // > one 16 KiB chunk
	require.NoError(t, store.PutObject("b", "key1", bytes.NewReader(payload)))

	exists, err := store.ObjectExists("b", "key1")
	require.NoError(t, err)
	assert.True(t, exists)

	rc, err := store.GetObject("b", "key1")
	require.NoError(t, err)
	got, err := io.ReadAll(rc)
	require.NoError(t, err)
	require.NoError(t, rc.Close())
	assert.Equal(t, payload, got)

	keys, err := store.ListObjects("b", "")
	require.NoError(t, err)
	assert.Equal(t, []string{"key1"}, keys)

	prefixes, err := store.ListCommonPrefixes("b", "p/", "/")
	require.NoError(t, err)
	assert.Equal(t, []string{"p/sub/"}, prefixes)

	url, err := store.CreateSignedURL("b", "key1", time.Minute)
	require.NoError(t, err)
	assert.Equal(t, "https://signed/key1", url)

	require.NoError(t, store.DeleteObject("b", "key1"))
	exists, err = store.ObjectExists("b", "key1")
	require.NoError(t, err)
	assert.False(t, exists)

	cancel()
	require.NoError(t, <-serveErr)
}

// TestClientRejectsUntrustedServer ensures the client refuses a server whose
// certificate is signed by a different CA (guards the mutual-TLS trust boundary).
func TestClientRejectsUntrustedServer(t *testing.T) {
	// Server uses CA #1.
	caFile, serverCert, serverKey, _, _ := writeTLSMaterials(t)
	serverTLS, err := LoadServerTLSConfig(serverCert, serverKey, caFile)
	require.NoError(t, err)

	// Client trusts an unrelated CA #2 and presents its cert.
	otherCA, otherServerCert, otherServerKey, otherClientCert, otherClientKey := writeTLSMaterials(t)
	_ = otherServerCert
	_ = otherServerKey

	backend := newFakeObjectStore()
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv := NewServer(logger, backend, serverTLS)
	go func() { _ = srv.ServeListener(ctx, listener) }()

	clientTLS, err := LoadClientTLSConfig(otherClientCert, otherClientKey, otherCA, "127.0.0.1")
	require.NoError(t, err)

	getter := NewRemoteObjectStoreGetter(logger, listener.Addr().String(), clientTLS)
	defer getter.Close()

	store, err := getter.GetObjectStore("velero.io/azure")
	require.NoError(t, err)

	// The RPC must fail because the server cert is not signed by CA #2.
	assert.Error(t, store.Init(map[string]string{"bucket": "b"}))
}
