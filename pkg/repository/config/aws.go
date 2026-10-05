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
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"

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
	awsProfileKey            = "profile"
	awsCredentialsFileEnvVar = "AWS_SHARED_CREDENTIALS_FILE"
	awsConfigFileEnvVar      = "AWS_CONFIG_FILE"
	awsDefaultProfile        = "default"
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
// of the provided config or the system's environment variables
func GetS3Credentials(config map[string]string) (*aws.Credentials, error) {
	var opts []func(*awsconfig.LoadOptions) error
	credentialsFile := config[CredentialsFileKey]
	if credentialsFile == "" {
		credentialsFile = os.Getenv(awsCredentialsFileEnvVar)
	}
	if credentialsFile != "" {
		opts = append(opts, awsconfig.WithSharedCredentialsFiles([]string{credentialsFile}),
			// To support the existing use case where config file is passed
			// as credentials of a BSL
			awsconfig.WithSharedConfigFiles([]string{credentialsFile}))
	}
	opts = append(opts, awsconfig.WithSharedConfigProfile(config[awsProfileKey]))

	cfg, err := awsconfig.LoadDefaultConfig(context.Background(), opts...)
	if err != nil {
		return nil, err
	}

	if credentialsFile != "" && os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE") != "" && os.Getenv("AWS_ROLE_ARN") != "" {
		// Reset the config to use the credentials from the credentials/config file
		profile := config[awsProfileKey]
		if profile == "" {
			profile = awsDefaultProfile
		}
		sfp, err := awsconfig.LoadSharedConfigProfile(context.Background(), profile, func(o *awsconfig.LoadSharedConfigOptions) {
			o.ConfigFiles = []string{credentialsFile}
			o.CredentialsFiles = []string{credentialsFile}
		})
		if err != nil {
			return nil, fmt.Errorf("error loading config profile '%s': %v", profile, err)
		}
		if err := resolveCredsFromProfile(&cfg, &sfp); err != nil {
			return nil, fmt.Errorf("error resolving creds from profile '%s': %v", profile, err)
		}
	}

	creds, err := cfg.Credentials.Retrieve(context.Background())

	return &creds, err
}

// GetAWSBucketRegion returns the AWS region that a bucket is in, or an error
// if the region cannot be determined.
// It will use us-east-1 as hinting server and requires config param to use as credentials
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

func resolveCredsFromProfile(cfg *aws.Config, sharedConfig *awsconfig.SharedConfig) error {
	var err error
	switch {
	case sharedConfig.Source != nil:
		// Assume IAM role with credentials source from a different profile.
		err = resolveCredsFromProfile(cfg, sharedConfig.Source)
	case sharedConfig.Credentials.HasKeys():
		// Static Credentials from Shared Config/Credentials file.
		cfg.Credentials = credentials.StaticCredentialsProvider{
			Value: sharedConfig.Credentials,
		}
	}
	if err != nil {
		return err
	}
	if len(sharedConfig.RoleARN) > 0 {
		credsFromAssumeRole(cfg, sharedConfig)
	}
	return nil
}

func credsFromAssumeRole(cfg *aws.Config, sharedCfg *awsconfig.SharedConfig) {
	optFns := []func(*stscreds.AssumeRoleOptions){
		func(options *stscreds.AssumeRoleOptions) {
			options.RoleSessionName = sharedCfg.RoleSessionName
			if sharedCfg.RoleDurationSeconds != nil {
				if *sharedCfg.RoleDurationSeconds/time.Minute > 15 {
					options.Duration = *sharedCfg.RoleDurationSeconds
				}
			}
			if len(sharedCfg.ExternalID) > 0 {
				options.ExternalID = aws.String(sharedCfg.ExternalID)
			}
			if len(sharedCfg.MFASerial) != 0 {
				options.SerialNumber = aws.String(sharedCfg.MFASerial)
			}
		},
	}
	cfg.Credentials = stscreds.NewAssumeRoleProvider(sts.NewFromConfig(*cfg), sharedCfg.RoleARN, optFns...)
}
