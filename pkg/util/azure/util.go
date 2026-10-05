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
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/cockroachdb/errors"

	"github.com/vmware-tanzu/velero/pkg/util/dotenv"
)

const (
	// the keys of Azure variables in credential
	CredentialKeySubscriptionID             = "AZURE_SUBSCRIPTION_ID"               // #nosec
	CredentialKeyResourceGroup              = "AZURE_RESOURCE_GROUP"                // #nosec
	CredentialKeyCloudName                  = "AZURE_CLOUD_NAME"                    // #nosec
	CredentialKeyStorageAccountAccessKey    = "AZURE_STORAGE_KEY"                   // #nosec
	CredentialKeyAdditionallyAllowedTenants = "AZURE_ADDITIONALLY_ALLOWED_TENANTS"  // #nosec
	CredentialKeyTenantID                   = "AZURE_TENANT_ID"                     // #nosec
	CredentialKeyClientID                   = "AZURE_CLIENT_ID"                     // #nosec
	CredentialKeyClientSecret               = "AZURE_CLIENT_SECRET"                 // #nosec
	CredentialKeyClientCertificate          = "AZURE_CLIENT_CERTIFICATE"            // #nosec
	CredentialKeyClientCertificatePath      = "AZURE_CLIENT_CERTIFICATE_PATH"       // #nosec
	CredentialKeyClientCertificatePassword  = "AZURE_CLIENT_CERTIFICATE_PASSWORD"   // #nosec
	CredentialKeySendCertChain              = "AZURE_CLIENT_SEND_CERTIFICATE_CHAIN" // #nosec
	CredentialKeyUsername                   = "AZURE_USERNAME"                      // #nosec
	CredentialKeyPassword                   = "AZURE_PASSWORD"                      // #nosec

	credentialFile = "credentialsFile"
)

// LoadCredentials gets the credential file from config and loads it into a map
func LoadCredentials(config map[string]string) (map[string]string, error) {
	// the default credential file
	credFile := os.Getenv("AZURE_CREDENTIALS_FILE")

	// use the credential file specified in the BSL spec if provided
	if config != nil && config[credentialFile] != "" {
		credFile = config[credentialFile]
	}

	if len(credFile) == 0 {
		return map[string]string{}, nil
	}

	// put the credential file content into a map
	creds, err := dotenv.Read(credFile)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read credentials from file %s", credFile)
	}
	return creds, nil
}

// GetClientOptions returns the client options based on the BSL/VSL config and credentials
func GetClientOptions(locationCfg, creds map[string]string) (policy.ClientOptions, error) {
	options := policy.ClientOptions{}

	cloudCfg, err := getCloudConfiguration(locationCfg, creds)
	if err != nil {
		return options, err
	}
	options.Cloud = cloudCfg

	if locationCfg["caCert"] != "" {
		certPool, _ := x509.SystemCertPool()
		if certPool == nil {
			certPool = x509.NewCertPool()
		}
		var caCert []byte
		// As this function is used in both repository and plugin, the caCert isn't encoded
		// when passing to the plugin while is encoded when works with repository, use one
		// config item to distinguish these two cases
		if locationCfg["caCertEncoded"] != "" {
			caCert, err = base64.StdEncoding.DecodeString(locationCfg["caCert"])
			if err != nil {
				return options, err
			}
		} else {
			caCert = []byte(locationCfg["caCert"])
		}

		certPool.AppendCertsFromPEM(caCert)

		// https://github.com/Azure/azure-sdk-for-go/blob/sdk/azcore/v1.6.1/sdk/azcore/runtime/transport_default_http_client.go#L19
		transport := &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				RootCAs:    certPool,
			},
		}
		options.Transport = &http.Client{
			Transport: transport,
		}
	}

	return options, nil
}

// getCloudConfiguration based on the BSL/VSL config and credentials
func getCloudConfiguration(locationCfg, creds map[string]string) (cloud.Configuration, error) {
	name := creds[CredentialKeyCloudName]
	activeDirectoryAuthorityURI := locationCfg[BSLConfigActiveDirectoryAuthorityURI]

	var cfg cloud.Configuration
	switch strings.ToUpper(name) {
	case "", "AZURECLOUD", "AZUREPUBLICCLOUD":
		cfg = cloud.AzurePublic
	case "AZURECHINACLOUD":
		cfg = cloud.AzureChina
	case "AZUREUSGOVERNMENT", "AZUREUSGOVERNMENTCLOUD":
		cfg = cloud.AzureGovernment
	default:
		return cloud.Configuration{}, errors.New(fmt.Sprintf("unknown cloud: %s", name))
	}
	if activeDirectoryAuthorityURI != "" {
		cfg.ActiveDirectoryAuthorityHost = activeDirectoryAuthorityURI
	}
	return cfg, nil
}

// GetFromLocationConfigOrCredential returns the value of the specified key from BSL/VSL config or credentials
// as some common configuration items can be set in BSL/VSL config or credential file(such as the subscription ID or resource group)
// Reading from BSL/VSL config takes first.
func GetFromLocationConfigOrCredential(cfg, creds map[string]string, cfgKey, credKey string) string {
	value := cfg[cfgKey]
	if value != "" {
		return value
	}
	return creds[credKey]
}
