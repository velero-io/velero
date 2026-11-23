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
	"github.com/kopia/kopia/repo/blob/s3"

	"github.com/velero-io/velero/pkg/repository/udmrepo"
	"github.com/velero-io/velero/pkg/repository/udmrepo/kopialib/backend/logging"
)

type S3Backend struct {
	options s3.Options
}

func (c *S3Backend) Setup(ctx context.Context, flags map[string]string, logger logrus.FieldLogger) error {
	var err error
	c.options.BucketName, err = mustHaveString(udmrepo.StoreOptionOssBucket, flags)
	if err != nil {
		return err
	}

	c.options.AccessKeyID = optionalHaveString(udmrepo.StoreOptionS3KeyID, flags)
	c.options.SecretAccessKey = optionalHaveString(udmrepo.StoreOptionS3SecretKey, flags)
	c.options.Endpoint = optionalHaveString(udmrepo.StoreOptionS3Endpoint, flags)
	c.options.Region = optionalHaveString(udmrepo.StoreOptionOssRegion, flags)
	c.options.Prefix = optionalHaveString(udmrepo.StoreOptionPrefix, flags)
	c.options.DoNotUseTLS = optionalHaveBool(ctx, udmrepo.StoreOptionS3DisableTLS, flags)
	c.options.DoNotVerifyTLS = optionalHaveBool(ctx, udmrepo.StoreOptionS3DisableTLSVerify, flags)
	c.options.SessionToken = optionalHaveString(udmrepo.StoreOptionS3Token, flags)
	c.options.RootCA = optionalHaveBase64(ctx, udmrepo.StoreOptionCACert, flags)

	ctx = logging.WithLogger(ctx, logger)

	c.options.Limits = setupLimits(ctx, flags)

	return nil
}

func (c *S3Backend) Connect(ctx context.Context, isCreate bool, logger logrus.FieldLogger) (blob.Storage, error) {
	ctx = logging.WithLogger(ctx, logger)
	return s3.New(ctx, &c.options, false)
}
