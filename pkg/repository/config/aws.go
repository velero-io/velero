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

//nolint:gosec // Internal usage. No need to check.
package config

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	s3manager "github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/cockroachdb/errors"
)

// getS3CredentialsFunc is used to make testing more convenient
var getS3CredentialsFunc = GetS3Credentials

const (
	// AWS specific environment variable
	awsProfileEnvVar         = "AWS_PROFILE"
	awsKeyIDEnvVar           = "AWS_ACCESS_KEY_ID"
	awsSecretKeyEnvVar       = "AWS_SECRET_ACCESS_KEY"
	awsSessTokenEnvVar       = "AWS_SESSION_TOKEN"
	awsCredentialsFileEnvVar = "AWS_SHARED_CREDENTIALS_FILE"
	awsConfigFileEnvVar      = "AWS_CONFIG_FILE"

	awsProfileKey     = "profile"
	awsDefaultProfile = "default"
)

// GetS3ResticEnvVars gets the environment variables that restic
// relies on (AWS_PROFILE) based on info in the provided object
// storage location config map.
func GetS3ResticEnvVars(config map[string]string) (map[string]string, error) {
	result := make(map[string]string)

	if credentialsFile, ok := config[CredentialsFileKey]; ok {
		result[awsCredentialsFileEnvVar] = credentialsFile
	}

	if profile, ok := config[awsProfileKey]; ok {
		result[awsProfileEnvVar] = profile
	}

	// GetS3ResticEnvVars reads the AWS config, from files and envs
	// if needed assumes the role and returns the session credentials
	// setting these variables emulates what would happen for example when using kube2iam
	if creds, err := getS3CredentialsFunc(config); err == nil && creds != nil {
		result[awsKeyIDEnvVar] = creds.AccessKeyID
		result[awsSecretKeyEnvVar] = creds.SecretAccessKey
		result[awsSessTokenEnvVar] = creds.SessionToken
		result[awsCredentialsFileEnvVar] = ""
		result[awsProfileEnvVar] = "" // profile is not needed since we have the credentials from profile via GetS3Credentials
		result[awsConfigFileEnvVar] = ""
	}

	return result, nil
}

// GetS3Credentials gets the S3 credential values according to the information
// of the provided config or the system's environment variables. In case BSL
// does not have a credential file configured, it will fall back to using
// the default credential provider chain of AWS and returning no static credentials
func GetS3Credentials(config map[string]string) (*aws.Credentials, error) {
	// If a BSL credential file is specified, we only load this file
	// and return the credentials to the caller
	if credentialsFile, ok := config[CredentialsFileKey]; ok {
		// If we do not find any configuration for an aws profile, we fall back to using
		// the default profile, as otherwise the shared credential file options will be ignored
		profile := awsDefaultProfile
		if _, exists := config[awsProfileKey]; exists {
			profile = config[awsProfileKey]
		}
		cfg, err := awsconfig.LoadSharedConfigProfile(context.Background(), profile, func(options *awsconfig.LoadSharedConfigOptions) {
			// To support the existing use case where a config
			// file is passed as credentials of a BSL
			options.ConfigFiles = []string{credentialsFile}
			options.CredentialsFiles = []string{credentialsFile}
		})
		if err != nil {
			return nil, err
		}

		// TODO: Handle expiring tokens
		if cfg.Credentials.CanExpire {
			return nil, fmt.Errorf("credentials from bsl credential configuration have to be static")
		}

		return &cfg.Credentials, nil
	}

	var opts []func(*awsconfig.LoadOptions) error
	if awsProfile, ok := config[awsProfileKey]; ok {
		opts = append(opts, awsconfig.WithSharedConfigProfile(awsProfile))
	}

	// We want to load the default configuration of the AWS
	// credential chain, which includes environment variables
	// and shared profile configurations
	cfg, err := awsconfig.LoadDefaultConfig(context.Background(), opts...)
	if err != nil {
		return nil, err
	}
	creds, err := cfg.Credentials.Retrieve(context.Background())
	if err != nil {
		return nil, err
	}
	// If the credentials are temporary and therefore can expire,
	// for example, because they are coming from an IAM role, or
	// from a web identity provider, we do not want to return any static
	// credentials. As returning static credentials, would result
	// in any function calling this to have expired credentials.
	// For expiring credentials, we want to fall back to use
	// the default aws provider chain, which is responsible
	// for refreshing the token automatically
	if creds.CanExpire {
		return nil, nil
	}
	return &creds, nil
}

// GetAWSBucketRegion returns the AWS region that a bucket is in, or an error
// if the region cannot be determined.
// It will use us-east-1 as a hinting server and requires config param to use as credentials
func GetAWSBucketRegion(bucket string, config map[string]string) (string, error) {
	cfg, err := awsconfig.LoadDefaultConfig(context.Background(), awsconfig.WithCredentialsProvider(
		aws.CredentialsProviderFunc(
			func(context.Context) (aws.Credentials, error) {
				s3creds, err := GetS3Credentials(config)
				if s3creds == nil {
					return aws.Credentials{}, err
				}
				return *s3creds, err
			},
		),
	))
	if err != nil {
		return "", errors.WithStack(err)
	}
	client := s3.NewFromConfig(cfg)
	region, err := s3manager.GetBucketRegion(context.Background(), client, bucket, func(o *s3.Options) { o.Region = "us-east-1" })
	if err != nil {
		return "", errors.WithStack(err)
	}
	if region == "" {
		return "", errors.New("unable to determine bucket's region")
	}
	return region, nil
}
