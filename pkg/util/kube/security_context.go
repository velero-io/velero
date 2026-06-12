/*
Copyright 2020 the Velero contributors.

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

package kube

import (
	"strconv"

	"github.com/cockroachdb/errors"
	corev1api "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

func ParseSecurityContext(runAsUser string, runAsGroup string, allowPrivilegeEscalation string, secCtx string) (corev1api.SecurityContext, error) {
	securityContext := corev1api.SecurityContext{}

	if runAsUser != "" {
		parsedRunAsUser, err := strconv.ParseInt(runAsUser, 10, 64)
		if err != nil {
			return securityContext, errors.WithStack(errors.Errorf(`Security context runAsUser "%s" is not a number`, runAsUser))
		}

		securityContext.RunAsUser = &parsedRunAsUser
	}

	if runAsGroup != "" {
		parsedRunAsGroup, err := strconv.ParseInt(runAsGroup, 10, 64)
		if err != nil {
			return securityContext, errors.WithStack(errors.Errorf(`Security context runAsGroup "%s" is not a number`, runAsGroup))
		}

		securityContext.RunAsGroup = &parsedRunAsGroup
	}

	if allowPrivilegeEscalation != "" {
		parsedAllowPrivilegeEscalation, err := strconv.ParseBool(allowPrivilegeEscalation)
		if err != nil {
			return securityContext, errors.WithStack(errors.Errorf(`Security context allowPrivilegeEscalation "%s" is not a boolean`, allowPrivilegeEscalation))
		}

		securityContext.AllowPrivilegeEscalation = &parsedAllowPrivilegeEscalation
	}

	if secCtx != "" {
		err := yaml.UnmarshalStrict([]byte(secCtx), &securityContext)
		if err != nil {
			return securityContext, errors.WithStack(errors.Errorf(`Security context secCtx error: "%s"`, err))
		}
	}

	return securityContext, nil
}
