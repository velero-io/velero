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

	"github.com/sirupsen/logrus"

	"github.com/kopia/kopia/repo/blob"
	"github.com/kopia/kopia/repo/blob/gcs"

	"github.com/velero-io/velero/pkg/repository/udmrepo"
	"github.com/velero-io/velero/pkg/repository/udmrepo/kopialib/backend/logging"
)

type GCSBackend struct {
	options gcs.Options
}

func (c *GCSBackend) Setup(ctx context.Context, flags map[string]string, logger logrus.FieldLogger) error {
	var err error
	c.options.BucketName, err = mustHaveString(udmrepo.StoreOptionOssBucket, flags)
	if err != nil {
		return err
	}

	c.options.ServiceAccountCredentialsFile, err = mustHaveString(udmrepo.StoreOptionCredentialFile, flags)
	if err != nil {
		return err
	}

	c.options.Prefix = optionalHaveString(udmrepo.StoreOptionPrefix, flags)
	c.options.ReadOnly = optionalHaveBool(ctx, udmrepo.StoreOptionGcsReadonly, flags)

	ctx = logging.WithLogger(ctx, logger)

	c.options.Limits = setupLimits(ctx, flags)

	return nil
}

func (c *GCSBackend) Connect(ctx context.Context, isCreate bool, logger logrus.FieldLogger) (blob.Storage, error) {
	ctx = logging.WithLogger(ctx, logger)
	return gcs.New(ctx, &c.options, false)
}
