//go:build windows
// +build windows

/*
Copyright The Velero Contributors.

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

package kopia

import (
	"context"

	"github.com/sirupsen/logrus"

	"github.com/kopia/kopia/fs"
)

// verifyRestoredAttrs is a no-op on Windows: kopia doesn't restore POSIX
// owners there, so there is nothing to verify.
func verifyRestoredAttrs(_ context.Context, _ fs.Entry, _ string, _ logrus.FieldLogger) {
}
