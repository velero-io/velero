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

package backend

import (
	"context"
	"strconv"

	"github.com/sirupsen/logrus"

	"github.com/kopia/kopia/repo/blob"
	"github.com/kopia/kopia/repo/blob/sftp"

	"github.com/vmware-tanzu/velero/pkg/repository/udmrepo"
	"github.com/vmware-tanzu/velero/pkg/repository/udmrepo/kopialib/backend/logging"
)

// SFTPBackend implements the backend.Store interface for SFTP storage
// using Kopia's native SFTP blob storage.
type SFTPBackend struct {
	options sftp.Options
}

func (c *SFTPBackend) Setup(ctx context.Context, flags map[string]string, logger logrus.FieldLogger) error {
	host, err := mustHaveString(udmrepo.StoreOptionSFTPHost, flags)
	if err != nil {
		return err
	}

	c.options.Host = host
	c.options.Username = optionalHaveString(udmrepo.StoreOptionSFTPUsername, flags)

	if portStr := optionalHaveString(udmrepo.StoreOptionSFTPPort, flags); portStr != "" {
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return err
		}
		c.options.Port = port
	} else {
		c.options.Port = 22
	}

	sftpPath := optionalHaveString(udmrepo.StoreOptionSFTPPath, flags)
	prefix := optionalHaveString(udmrepo.StoreOptionPrefix, flags)
	if sftpPath != "" && prefix != "" {
		c.options.Path = sftpPath + "/" + prefix
	} else if sftpPath != "" {
		c.options.Path = sftpPath
	} else if prefix != "" {
		c.options.Path = "/" + prefix
	} else {
		c.options.Path = "/"
	}

	c.options.Password = optionalHaveString(udmrepo.StoreOptionSFTPPassword, flags)
	c.options.Keyfile = optionalHaveString(udmrepo.StoreOptionSFTPKeyPath, flags)
	c.options.KeyData = optionalHaveString(udmrepo.StoreOptionSFTPKeyData, flags)
	c.options.KnownHostsData = optionalHaveString(udmrepo.StoreOptionSFTPKnownHostsData, flags)

	ctx = logging.WithLogger(ctx, logger)
	c.options.Limits = setupLimits(ctx, flags)

	return nil
}

func (c *SFTPBackend) Connect(ctx context.Context, isCreate bool, logger logrus.FieldLogger) (blob.Storage, error) {
	ctx = logging.WithLogger(ctx, logger)
	return sftp.New(ctx, &c.options, isCreate)
}
