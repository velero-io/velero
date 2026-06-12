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

package restic

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"

	"github.com/vmware-tanzu/velero/internal/credentials"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	repoconfig "github.com/vmware-tanzu/velero/pkg/repository/config"
	"github.com/vmware-tanzu/velero/pkg/util/filesystem"
)

const (

	// DefaultMaintenanceFrequency is the default time interval
	// at which restic prune is run.
	DefaultMaintenanceFrequency = 7 * 24 * time.Hour

	// insecureSkipTLSVerifyKey is the flag in BackupStorageLocation's config
	// to indicate whether to skip TLS verify to setup insecure HTTPS connection.
	insecureSkipTLSVerifyKey = "insecureSkipTLSVerify"

	// resticInsecureTLSFlag is the flag for Restic command line to indicate
	// skip TLS verify on https connection.
	resticInsecureTLSFlag = "--insecure-tls"
)

// TempCACertFile creates a temp file containing a CA bundle
// and returns its path. The caller should generally call os.Remove()
// to remove the file when done with it.
func TempCACertFile(caCert []byte, bsl string, fs filesystem.Interface) (string, error) {
	file, err := fs.TempFile("", fmt.Sprintf("cacert-%s", bsl))
	if err != nil {
		return "", errors.WithStack(err)
	}

	if _, err := file.Write(caCert); err != nil {
		// nothing we can do about an error closing the file here, and we're
		// already returning an error about the write failing.
		file.Close()
		return "", errors.WithStack(err)
	}

	name := file.Name()

	if err := file.Close(); err != nil {
		return "", errors.WithStack(err)
	}

	return name, nil
}

// environ is a slice of strings representing the environment, in the form "key=value".
type environ []string

// Unset a single environment variable.
func (e *environ) Unset(key string) {
	for i := range *e {
		if strings.HasPrefix((*e)[i], key+"=") {
			(*e)[i] = (*e)[len(*e)-1]
			*e = (*e)[:len(*e)-1]
			break
		}
	}
}

// CmdEnv returns a list of environment variables (in the format var=val) that
// should be used when running a restic command for a particular backend provider.
// This list is the current environment, plus any provider-specific variables restic needs.
func CmdEnv(backupLocation *velerov1api.BackupStorageLocation, credentialFileStore credentials.FileStore) ([]string, error) {
	var env environ
	env = os.Environ()
	customEnv := map[string]string{}
	var err error

	config := backupLocation.Spec.Config
	if config == nil {
		config = map[string]string{}
	}

	if backupLocation.Spec.Credential != nil {
		credsFile, err := credentialFileStore.Path(backupLocation.Spec.Credential)
		if err != nil {
			return []string{}, errors.WithStack(err)
		}
		config[repoconfig.CredentialsFileKey] = credsFile
	}

	backendType := repoconfig.GetBackendType(backupLocation.Spec.Provider, backupLocation.Spec.Config)

	switch backendType {
	case repoconfig.AWSBackend:
		customEnv, err = repoconfig.GetS3ResticEnvVars(config)
		if err != nil {
			return []string{}, err
		}
	case repoconfig.AzureBackend:
		customEnv, err = repoconfig.GetAzureResticEnvVars(config)
		if err != nil {
			return []string{}, err
		}
	case repoconfig.GCPBackend:
		customEnv, err = repoconfig.GetGCPResticEnvVars(config)
		if err != nil {
			return []string{}, err
		}
	}

	for k, v := range customEnv {
		env.Unset(k)
		if v == "" {
			continue
		}
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}

	return env, nil
}

// GetInsecureSkipTLSVerifyFromBSL get insecureSkipTLSVerify flag from BSL configuration,
// Then return --insecure-tls flag with boolean value as result.
func GetInsecureSkipTLSVerifyFromBSL(backupLocation *velerov1api.BackupStorageLocation, logger logrus.FieldLogger) string {
	result := ""

	if backupLocation == nil {
		logger.Info("bsl is nil. return empty.")
		return result
	}

	if insecure, _ := strconv.ParseBool(backupLocation.Spec.Config[insecureSkipTLSVerifyKey]); insecure {
		logger.Debugf("set --insecure-tls=true for Restic command according to BSL %s config", backupLocation.Name)
		result = resticInsecureTLSFlag + "=true"
		return result
	}

	return result
}
