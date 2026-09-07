/*
Copyright 2021 the Velero contributors.

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

package client

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVeleroConfig(t *testing.T) {
	c := VeleroConfig{
		"namespace": "foo",
		"features":  "feature1,feature2",
	}

	assert.Equal(t, "foo", c.Namespace())
	assert.Equal(t, []string{"feature1", "feature2"}, c.Features())
	assert.True(t, c.Colorized())
}

func TestVeleroConfigFeaturesTrimSpaces(t *testing.T) {
	c := VeleroConfig{
		ConfigKeyFeatures: "EnableCSI, EnableAPIGroupVersions, ",
	}
	assert.Equal(t, []string{"EnableCSI", "EnableAPIGroupVersions"}, c.Features())
}

func removeConfigfileName() error {
	// Remove config file if it exist
	configFile := configFileName()
	e := os.Remove(configFile)
	if e != nil {
		if !os.IsNotExist(e) {
			return e
		}
	}
	return nil
}
func TestConfigOperations(t *testing.T) {
	preHomeEnv := ""
	prevEnv := os.Environ()
	for _, entry := range prevEnv {
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) == 2 && parts[0] == "HOME" {
			preHomeEnv = parts[1]
			break
		}
	}
	os.Unsetenv("HOME")
	os.Setenv("HOME", ".")

	// Remove config file if it exists
	err := removeConfigfileName()
	require.NoError(t, err)

	// Test LoadConfig: expect an empty velero config
	expectedConfig := VeleroConfig{}
	config, err := LoadConfig()

	require.NoError(t, err)
	assert.True(t, reflect.DeepEqual(expectedConfig, config))

	// Test savedConfig
	expectedFeature := "EnableCSI"
	expectedColorized := true
	expectedNamespace := "ns-velero"
	expectedCACert := "ca-cert"

	config[ConfigKeyFeatures] = expectedFeature
	config[ConfigKeyColorized] = expectedColorized
	config[ConfigKeyNamespace] = expectedNamespace
	config[ConfigKeyCACert] = expectedCACert

	err = SaveConfig(config)

	require.NoError(t, err)
	savedConfig, err := LoadConfig()
	require.NoError(t, err)

	// Test Features
	feature := savedConfig.Features()
	assert.Len(t, feature, 1)
	assert.Equal(t, expectedFeature, feature[0])

	// Test Colorized
	colorized := savedConfig.Colorized()
	assert.Equal(t, expectedColorized, colorized)

	// Test Namespace
	namespace := savedConfig.Namespace()
	assert.Equal(t, expectedNamespace, namespace)

	// Test Features
	caCertFile := savedConfig.CACertFile()
	assert.Equal(t, expectedCACert, caCertFile)

	t.Cleanup(func() {
		err = removeConfigfileName()
		require.NoError(t, err)
		os.Unsetenv("HOME")
		os.Setenv("HOME", preHomeEnv)
	})
}
