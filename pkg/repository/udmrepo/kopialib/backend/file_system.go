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
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"

	"github.com/cockroachdb/errors"
	"github.com/kopia/kopia/repo/blob"
	"github.com/kopia/kopia/repo/blob/filesystem"

	"github.com/vmware-tanzu/velero/pkg/repository/udmrepo"
	"github.com/vmware-tanzu/velero/pkg/repository/udmrepo/kopialib/backend/logging"
)

type FsBackend struct {
	options filesystem.Options
}

const (
	defaultFileMode = 0o600
	defaultDirMode  = 0o700
)

func (c *FsBackend) Setup(ctx context.Context, flags map[string]string, logger logrus.FieldLogger) error {
	path, err := mustHaveString(udmrepo.StoreOptionFsPath, flags)
	if err != nil {
		return err
	}

	prefix := optionalHaveString(udmrepo.StoreOptionPrefix, flags)

	c.options.Path = filepath.Join(path, prefix)
	c.options.FileMode = defaultFileMode
	c.options.DirectoryMode = defaultDirMode

	ctx = logging.WithLogger(ctx, logger)

	c.options.Limits = setupLimits(ctx, flags)

	return nil
}

func (c *FsBackend) Connect(ctx context.Context, isCreate bool, logger logrus.FieldLogger) (blob.Storage, error) {
	if !filepath.IsAbs(c.options.Path) {
		return nil, errors.Errorf("filesystem repository path is not absolute, path: %s", c.options.Path)
	}

	if !isCreate {
		if _, err := os.Stat(c.options.Path); err != nil {
			return nil, ErrStoreNotExist
		}
	}

	ctx = logging.WithLogger(ctx, logger)

	return filesystem.New(ctx, &c.options, isCreate)
}
