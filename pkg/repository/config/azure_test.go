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

package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/velero-io/velero/pkg/util/azure"
)

func TestGetAzureResticEnvVars(t *testing.T) {
	config := map[string]string{}

	// no storage account specified
	_, err := GetAzureResticEnvVars(config)
	require.Error(t, err)

	// specify storage account access key
	name := filepath.Join(os.TempDir(), "credential")
	file, err := os.Create(name)
	require.NoError(t, err)
	defer file.Close()
	defer os.Remove(name)
	_, err = file.WriteString("AccessKey: accesskey")
	require.NoError(t, err)

	config[azure.BSLConfigStorageAccount] = "account01"
	config[azure.BSLConfigStorageAccountAccessKeyName] = "AccessKey"
	config["credentialsFile"] = name
	envs, err := GetAzureResticEnvVars(config)
	require.NoError(t, err)

	assert.Equal(t, "account01", envs["AZURE_ACCOUNT_NAME"])
	assert.Equal(t, "accesskey", envs["AZURE_ACCOUNT_KEY"])
}
