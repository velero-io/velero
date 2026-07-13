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
	"testing"
	"time"

	"github.com/kopia/kopia/repo"
	"github.com/kopia/kopia/repo/content"
	"github.com/kopia/kopia/repo/encryption"
	"github.com/kopia/kopia/repo/format"
	"github.com/kopia/kopia/repo/hashing"
	"github.com/kopia/kopia/repo/splitter"
	"github.com/stretchr/testify/assert"

	"github.com/vmware-tanzu/velero/pkg/repository/udmrepo"
)

func TestSetupNewRepositoryOptions(t *testing.T) {
	testCases := []struct {
		name     string
		flags    map[string]string
		expected repo.NewRepositoryOptions
	}{
		{
			name: "with hash algo",
			flags: map[string]string{
				udmrepo.StoreOptionGenHashAlgo: "fake-hash",
			},
			expected: repo.NewRepositoryOptions{
				BlockFormat: format.ContentFormat{
					Hash:       "fake-hash",
					Encryption: encryption.DefaultAlgorithm,
				},
				ObjectFormat: format.ObjectFormat{
					Splitter: splitter.DefaultAlgorithm,
				},
			},
		},
		{
			name: "with encrypt algo",
			flags: map[string]string{
				udmrepo.StoreOptionGenEncryptAlgo: "fake-encrypt",
			},
			expected: repo.NewRepositoryOptions{
				BlockFormat: format.ContentFormat{
					Hash:       hashing.DefaultAlgorithm,
					Encryption: "fake-encrypt",
				},
				ObjectFormat: format.ObjectFormat{
					Splitter: splitter.DefaultAlgorithm,
				},
			},
		},
		{
			name: "with splitter algo",
			flags: map[string]string{
				udmrepo.StoreOptionGenSplitAlgo: "fake-splitter",
			},
			expected: repo.NewRepositoryOptions{
				BlockFormat: format.ContentFormat{
					Hash:       hashing.DefaultAlgorithm,
					Encryption: encryption.DefaultAlgorithm,
				},
				ObjectFormat: format.ObjectFormat{
					Splitter: "fake-splitter",
				},
			},
		},
		{
			name: "with retention algo",
			flags: map[string]string{
				udmrepo.StoreOptionGenRetentionMode: "fake-retention-mode",
			},
			expected: repo.NewRepositoryOptions{
				BlockFormat: format.ContentFormat{
					Hash:       hashing.DefaultAlgorithm,
					Encryption: encryption.DefaultAlgorithm,
				},
				ObjectFormat: format.ObjectFormat{
					Splitter: splitter.DefaultAlgorithm,
				},
				RetentionMode: "fake-retention-mode",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ret := SetupNewRepositoryOptions(context.Background(), tc.flags)
			assert.Equal(t, tc.expected, ret)
		})
	}
}

func TestSetupConnectOptions(t *testing.T) {
	defaultCacheOption := content.CachingOptions{
		ContentCacheSizeBytes:  2000 << 20,
		MetadataCacheSizeBytes: 2000 << 20,
		MaxListCacheDuration:   content.DurationSeconds(time.Duration(30) * time.Second),
	}

	testCases := []struct {
		name        string
		repoOptions udmrepo.RepoOptions
		expected    repo.ConnectOptions
	}{
		{
			name: "with domain",
			repoOptions: udmrepo.RepoOptions{
				GeneralOptions: map[string]string{
					udmrepo.GenOptionOwnerDomain: "fake-domain",
				},
			},
			expected: repo.ConnectOptions{
				CachingOptions: defaultCacheOption,
				ClientOptions: repo.ClientOptions{
					Hostname: "fake-domain",
				},
			},
		},
		{
			name: "with username",
			repoOptions: udmrepo.RepoOptions{
				GeneralOptions: map[string]string{
					udmrepo.GenOptionOwnerName: "fake-user",
				},
			},
			expected: repo.ConnectOptions{
				CachingOptions: defaultCacheOption,
				ClientOptions: repo.ClientOptions{
					Username: "fake-user",
				},
			},
		},
		{
			name: "with wrong readonly",
			repoOptions: udmrepo.RepoOptions{
				GeneralOptions: map[string]string{
					udmrepo.StoreOptionGenReadOnly: "fake-bool",
				},
			},
			expected: repo.ConnectOptions{
				CachingOptions: defaultCacheOption,
				ClientOptions:  repo.ClientOptions{},
			},
		},
		{
			name: "with correct readonly",
			repoOptions: udmrepo.RepoOptions{
				GeneralOptions: map[string]string{
					udmrepo.StoreOptionGenReadOnly: "true",
				},
			},
			expected: repo.ConnectOptions{
				CachingOptions: defaultCacheOption,
				ClientOptions: repo.ClientOptions{
					ReadOnly: true,
				},
			},
		},
		{
			name: "with description",
			repoOptions: udmrepo.RepoOptions{
				Description: "fake-description",
			},
			expected: repo.ConnectOptions{
				CachingOptions: defaultCacheOption,
				ClientOptions: repo.ClientOptions{
					Description: "fake-description",
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ret := SetupConnectOptions(context.Background(), tc.repoOptions)
			assert.Equal(t, tc.expected, ret)
		})
	}
}
