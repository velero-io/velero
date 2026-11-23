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
	"testing"

	velerotest "github.com/velero-io/velero/pkg/test"

	"github.com/kopia/kopia/repo/blob/throttling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/velero-io/velero/pkg/repository/udmrepo"
)

func TestAzureSetup(t *testing.T) {
	backend := AzureBackend{}
	logger := velerotest.NewLogger()

	flags := map[string]string{
		"key":                             "value",
		udmrepo.ThrottleOptionReadOps:     "100",
		udmrepo.ThrottleOptionUploadBytes: "200",
	}
	limits := throttling.Limits{
		ReadsPerSecond:       100,
		UploadBytesPerSecond: 200,
	}

	err := backend.Setup(t.Context(), flags, logger)
	require.NoError(t, err)
	assert.Equal(t, flags, backend.option.Config)
	assert.Equal(t, limits, backend.option.Limits)
}
