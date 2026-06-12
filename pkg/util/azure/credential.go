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
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/cockroachdb/errors"
)

// NewCredential constructs a Credential that tries the config credential, workload identity credential
// and managed identity credential according to the provided creds.
func NewCredential(creds map[string]string, options policy.ClientOptions) (azcore.TokenCredential, error) {
	additionalTenants := []string{}
	if tenants := creds[CredentialKeyAdditionallyAllowedTenants]; tenants != "" {
		additionalTenants = strings.Split(tenants, ";")
	}

	// config credential
	if len(creds[CredentialKeyClientSecret]) > 0 ||
		len(creds[CredentialKeyClientCertificate]) > 0 ||
		len(creds[CredentialKeyClientCertificatePath]) > 0 ||
		len(creds[CredentialKeyUsername]) > 0 {
		return newConfigCredential(creds, configCredentialOptions{
			ClientOptions:              options,
			AdditionallyAllowedTenants: additionalTenants,
		})
	}

	// workload identity credential
	if len(os.Getenv("AZURE_FEDERATED_TOKEN_FILE")) > 0 {
		return azidentity.NewWorkloadIdentityCredential(&azidentity.WorkloadIdentityCredentialOptions{
			AdditionallyAllowedTenants: additionalTenants,
			ClientOptions:              options,
		})
	}

	// managed identity credential
	o := &azidentity.ManagedIdentityCredentialOptions{ClientOptions: options, ID: azidentity.ClientID(creds[CredentialKeyClientID])}
	return azidentity.NewManagedIdentityCredential(o)
}

type configCredentialOptions struct {
	azcore.ClientOptions
	AdditionallyAllowedTenants []string
}

// newConfigCredential works similar as the azidentity.EnvironmentCredential but reads the credentials from a map
// rather than environment variables. This is required for Velero to run B/R concurrently
// https://github.com/Azure/azure-sdk-for-go/blob/sdk/azidentity/v1.3.0/sdk/azidentity/environment_credential.go#L80
func newConfigCredential(creds map[string]string, options configCredentialOptions) (azcore.TokenCredential, error) {
	tenantID := creds[CredentialKeyTenantID]
	if tenantID == "" {
		return nil, errors.Errorf("%s is required", CredentialKeyTenantID)
	}
	clientID := creds[CredentialKeyClientID]
	if clientID == "" {
		return nil, errors.Errorf("%s is required", CredentialKeyClientID)
	}

	// client secret
	if clientSecret := creds[CredentialKeyClientSecret]; clientSecret != "" {
		return azidentity.NewClientSecretCredential(tenantID, clientID, clientSecret, &azidentity.ClientSecretCredentialOptions{
			AdditionallyAllowedTenants: options.AdditionallyAllowedTenants,
			ClientOptions:              options.ClientOptions,
		})
	}

	// raw certificate or certificate file
	if rawCerts, certsPath := []byte(creds[CredentialKeyClientCertificate]), creds[CredentialKeyClientCertificatePath]; len(rawCerts) > 0 || len(certsPath) > 0 {
		var err error
		// raw certificate isn't specified while certificate path is specified
		if len(rawCerts) == 0 {
			rawCerts, err = os.ReadFile(certsPath)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to read certificate file %s", certsPath)
			}
		}

		var password []byte
		if v := creds[CredentialKeyClientCertificatePassword]; v != "" {
			password = []byte(v)
		}
		certs, key, err := azidentity.ParseCertificates(rawCerts, password)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse certificate")
		}
		o := &azidentity.ClientCertificateCredentialOptions{
			AdditionallyAllowedTenants: options.AdditionallyAllowedTenants,
			ClientOptions:              options.ClientOptions,
		}
		if v, ok := creds[CredentialKeySendCertChain]; ok {
			o.SendCertificateChain = v == "1" || strings.ToLower(v) == "true"
		}
		return azidentity.NewClientCertificateCredential(tenantID, clientID, certs, key, o)
	}

	return nil, errors.New("incomplete credential configuration. Only AZURE_TENANT_ID and AZURE_CLIENT_ID are set")
}
