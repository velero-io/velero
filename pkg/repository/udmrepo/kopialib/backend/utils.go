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
	"encoding/base64"
	"strconv"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/kopia/kopia/repo/logging"
)

func mustHaveString(key string, flags map[string]string) (string, error) {
	if value, exist := flags[key]; exist {
		return value, nil
	}
	return "", errors.Errorf("key %s not found", key)
}

func optionalHaveString(key string, flags map[string]string) string {
	return optionalHaveStringWithDefault(key, flags, "")
}

func optionalHaveBool(ctx context.Context, key string, flags map[string]string) bool {
	if value, exist := flags[key]; exist {
		if value != "" {
			ret, err := strconv.ParseBool(value)
			if err == nil {
				return ret
			}

			backendLog()(ctx).Errorf("Ignore %s, value [%s] is invalid, err %v", key, value, err)
		}
	}

	return false
}

func optionalHaveFloat64(ctx context.Context, key string, flags map[string]string) float64 {
	if value, exist := flags[key]; exist {
		ret, err := strconv.ParseFloat(value, 64)
		if err == nil {
			return ret
		}

		backendLog()(ctx).Errorf("Ignore %s, value [%s] is invalid, err %v", key, value, err)
	}

	return 0
}

func optionalHaveStringWithDefault(key string, flags map[string]string, defValue string) string {
	if value, exist := flags[key]; exist {
		return value
	}
	return defValue
}

func optionalHaveDuration(ctx context.Context, key string, flags map[string]string) time.Duration {
	if value, exist := flags[key]; exist {
		ret, err := time.ParseDuration(value)
		if err == nil {
			return ret
		}

		backendLog()(ctx).Errorf("Ignore %s, value [%s] is invalid, err %v", key, value, err)
	}

	return 0
}

func optionalHaveBase64(ctx context.Context, key string, flags map[string]string) []byte {
	if value, exist := flags[key]; exist {
		ret, err := base64.StdEncoding.DecodeString(value)
		if err == nil {
			return ret
		}

		backendLog()(ctx).Errorf("Ignore %s, value [%s] is invalid, err %v", key, value, err)
	}

	return nil
}

func optionalHaveIntWithDefault(ctx context.Context, key string, flags map[string]string, defValue int64) int64 {
	if value, exist := flags[key]; exist {
		if value != "" {
			ret, err := strconv.ParseInt(value, 10, 64)
			if err == nil {
				return ret
			}

			backendLog()(ctx).Errorf("Ignore %s, value [%s] is invalid, err %v", key, value, err)
		}
	}

	return defValue
}

func backendLog() func(ctx context.Context) logging.Logger {
	return logging.Module("kopialib-bd")
}
