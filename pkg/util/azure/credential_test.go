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

package azure

import (
	"os"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCredential(t *testing.T) {
	options := policy.ClientOptions{}

	// invalid client secret credential (missing tenant ID)
	creds := map[string]string{
		CredentialKeyClientID:     "clientid",
		CredentialKeyClientSecret: "secret",
	}
	_, err := NewCredential(creds, options)
	require.Error(t, err)

	// valid client secret credential
	creds = map[string]string{
		CredentialKeyTenantID:     "tenantid",
		CredentialKeyClientID:     "clientid",
		CredentialKeyClientSecret: "secret",
	}
	tokenCredential, err := NewCredential(creds, options)
	require.NoError(t, err)
	assert.IsType(t, &azidentity.ClientSecretCredential{}, tokenCredential)

	// client certificate credential
	certData, err := readCertData()
	require.NoError(t, err)
	creds = map[string]string{
		CredentialKeyTenantID:          "tenantid",
		CredentialKeyClientID:          "clientid",
		CredentialKeyClientCertificate: certData,
	}
	tokenCredential, err = NewCredential(creds, options)
	require.NoError(t, err)
	assert.IsType(t, &azidentity.ClientCertificateCredential{}, tokenCredential)

	// workload identity credential
	os.Setenv(CredentialKeyTenantID, "tenantid")
	os.Setenv(CredentialKeyClientID, "clientid")
	os.Setenv("AZURE_FEDERATED_TOKEN_FILE", "/tmp/token")
	creds = map[string]string{}
	tokenCredential, err = NewCredential(creds, options)
	require.NoError(t, err)
	assert.IsType(t, &azidentity.WorkloadIdentityCredential{}, tokenCredential)
	os.Clearenv()

	// a leftover AZURE_USERNAME must not hijack credential selection. Username/password
	// handling was removed from newConfigCredential in #9041, so routing on it sends the
	// caller into a function that cannot serve it and short-circuits the workload
	// identity and managed identity branches below.
	os.Setenv(CredentialKeyTenantID, "tenantid")
	os.Setenv(CredentialKeyClientID, "clientid")
	os.Setenv("AZURE_FEDERATED_TOKEN_FILE", "/tmp/token")
	creds = map[string]string{CredentialKeyUsername: "username"}
	tokenCredential, err = NewCredential(creds, options)
	require.NoError(t, err)
	assert.IsType(t, &azidentity.WorkloadIdentityCredential{}, tokenCredential)
	os.Clearenv()

	// ... and must not short-circuit managed identity either
	creds = map[string]string{
		CredentialKeyClientID: "clientid",
		CredentialKeyUsername: "username",
	}
	tokenCredential, err = NewCredential(creds, options)
	require.NoError(t, err)
	assert.IsType(t, &azidentity.ManagedIdentityCredential{}, tokenCredential)

	// managed identity credential
	creds = map[string]string{CredentialKeyClientID: "clientid"}
	tokenCredential, err = NewCredential(creds, options)
	require.NoError(t, err)
	assert.IsType(t, &azidentity.ManagedIdentityCredential{}, tokenCredential)
}

func Test_newConfigCredential(t *testing.T) {
	options := configCredentialOptions{}

	// tenantID not specified
	creds := map[string]string{}
	_, err := newConfigCredential(creds, options)
	require.Error(t, err)

	// clientID not specified
	creds = map[string]string{
		CredentialKeyTenantID: "clientid",
	}
	_, err = newConfigCredential(creds, options)
	require.Error(t, err)

	// client secret
	creds = map[string]string{
		CredentialKeyTenantID:     "clientid",
		CredentialKeyClientID:     "clientid",
		CredentialKeyClientSecret: "secret",
	}
	credential, err := newConfigCredential(creds, options)
	require.NoError(t, err)
	require.NotNil(t, credential)
	_, ok := credential.(*azidentity.ClientSecretCredential)
	require.True(t, ok)

	// client certificate
	certData, err := readCertData()
	require.NoError(t, err)
	creds = map[string]string{
		CredentialKeyTenantID:          "clientid",
		CredentialKeyClientID:          "clientid",
		CredentialKeyClientCertificate: certData,
	}
	credential, err = newConfigCredential(creds, options)
	require.NoError(t, err)
	require.NotNil(t, credential)
	_, ok = credential.(*azidentity.ClientCertificateCredential)
	require.True(t, ok)
}

func readCertData() (string, error) {
	data, err := os.ReadFile("testdata/certificate.pem")
	if err != nil {
		return "", err
	}
	return string(data), nil
}
