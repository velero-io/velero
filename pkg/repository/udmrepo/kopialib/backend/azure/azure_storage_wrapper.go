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
	"context"

	"github.com/kopia/kopia/repo/blob"
	"github.com/kopia/kopia/repo/blob/azure"
	"github.com/kopia/kopia/repo/blob/throttling"

	"github.com/velero-io/velero/pkg/repository/udmrepo"
	"github.com/velero-io/velero/pkg/repository/udmrepo/kopialib/backend/logging"
	azureutil "github.com/velero-io/velero/pkg/util/azure"
)

const (
	storageType = "azure"
)

func init() {
	blob.AddSupportedStorage(storageType, Option{}, NewStorage)
}

type Option struct {
	Config map[string]string `json:"config"     kopia:"sensitive"`
	Limits throttling.Limits
}

type Storage struct {
	blob.Storage
	Option *Option
}

func (s *Storage) ConnectionInfo() blob.ConnectionInfo {
	return blob.ConnectionInfo{
		Type:   storageType,
		Config: s.Option,
	}
}

func NewStorage(ctx context.Context, option *Option, isCreate bool) (blob.Storage, error) {
	cfg := option.Config

	// Get logger from context
	logger := logging.LoggerFromContext(ctx)

	client, _, err := azureutil.NewStorageClient(logger, cfg)
	if err != nil {
		return nil, err
	}

	opt := &azure.Options{
		Container: cfg[udmrepo.StoreOptionOssBucket],
		Prefix:    cfg[udmrepo.StoreOptionPrefix],
		Limits:    option.Limits,
	}
	azStorage, err := azure.NewWithClient(ctx, opt, client)
	if err != nil {
		return nil, err
	}

	logger.Info("Successfully created Azure storage backend")

	return &Storage{
		Option:  option,
		Storage: azStorage,
	}, nil
}
