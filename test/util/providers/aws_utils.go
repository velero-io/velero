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

package providers

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/pkg/errors"
	"golang.org/x/net/context"

	"github.com/vmware-tanzu/velero/pkg/cmd/util/flag"
	"github.com/vmware-tanzu/velero/test"
)

type AWSStorage string

const (
	s3URLKey                     = "s3Url"
	publicURLKey                 = "publicUrl"
	kmsKeyIDKey                  = "kmsKeyId"
	customerKeyEncryptionFileKey = "customerKeyEncryptionFile"
	s3ForcePathStyleKey          = "s3ForcePathStyle"
	bucketKey                    = "bucket"
	signatureVersionKey          = "signatureVersion"
	credentialsFileKey           = "credentialsFile"
	credentialProfileKey         = "profile"
	serverSideEncryptionKey      = "serverSideEncryption"
	insecureSkipTLSVerifyKey     = "insecureSkipTLSVerify"
	caCertKey                    = "caCert"
	enableSharedConfigKey        = "enableSharedConfig"
)

func newSessionOptions(config aws.Config, profile, caCert, credentialsFile, enableSharedConfig string) (session.Options, error) {
	sessionOptions := session.Options{Config: config, Profile: profile}
	if caCert != "" {
		sessionOptions.CustomCABundle = strings.NewReader(caCert)
	}

	if credentialsFile == "" && os.Getenv("AWS_SHARED_CREDENTIALS_FILE") != "" {
		credentialsFile = os.Getenv("AWS_SHARED_CREDENTIALS_FILE")
	}

	if credentialsFile != "" {
		if _, err := os.Stat(credentialsFile); err != nil {
			if os.IsNotExist(err) {
				return session.Options{}, errors.Wrapf(err, "provided credentialsFile does not exist")
			}
			return session.Options{}, errors.Wrapf(err, "could not get credentialsFile info")
		}
		sessionOptions.SharedConfigFiles = append(sessionOptions.SharedConfigFiles, credentialsFile)
		sessionOptions.SharedConfigState = session.SharedConfigEnable
	}

	return sessionOptions, nil
}

// takes AWS session options to create a new session
func getSession(options session.Options) (*session.Session, error) {
	sess, err := session.NewSessionWithOptions(options)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if _, err := sess.Config.Credentials.Get(); err != nil {
		return nil, errors.WithStack(err)
	}

	return sess, nil
}

// GetBucketRegion returns the AWS region that a bucket is in, or an error
// if the region cannot be determined.
func GetBucketRegion(bucket string) (string, error) {
	var region string

	session, err := session.NewSession()
	if err != nil {
		return "", errors.WithStack(err)
	}

	for _, partition := range endpoints.DefaultPartitions() {
		for regionHint := range partition.Regions() {
			region, _ = s3manager.GetBucketRegion(context.Background(), session, bucket, regionHint)

			// we only need to try a single region hint per partition, so break after the first
			break
		}

		if region != "" {
			return region, nil
		}
	}

	return "", errors.New("unable to determine bucket's region")
}

func (s AWSStorage) CreateSession(credentialProfile, credentialsFile, enableSharedConfig, caCert, bucket, bslPrefix, bslConfig string) (*session.Session, error) {
	var err error
	config := flag.NewMap()
	config.Set(bslConfig)
	region := config.Data()["region"]
	objectsInput := s3.ListObjectsV2Input{}
	objectsInput.Bucket = aws.String(bucket)
	objectsInput.Delimiter = aws.String("/")
	s3URL := ""
	s3ForcePathStyleVal := ""
	s3ForcePathStyle := false

	if s3ForcePathStyleVal != "" {
		if s3ForcePathStyle, err = strconv.ParseBool(s3ForcePathStyleVal); err != nil {
			return nil, errors.Wrapf(err, "could not parse %s (expected bool)", s3ForcePathStyleKey)
		}
	}

	// AWS (not an alternate S3-compatible API) and region not
	// explicitly specified: determine the bucket's region
	if s3URL == "" && region == "" {
		var err error

		region, err = GetBucketRegion(bucket)
		if err != nil {
			return nil, err
		}
	}

	serverConfig, err := newAWSConfig(s3URL, region, s3ForcePathStyle)
	if err != nil {
		return nil, err
	}

	sessionOptions, err := newSessionOptions(*serverConfig, credentialProfile, caCert, credentialsFile, enableSharedConfig)
	if err != nil {
		return nil, err
	}

	serverSession, err := getSession(sessionOptions)

	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	return serverSession, nil
}

// IsValidS3URLScheme returns true if the scheme is http:// or https://
// and the url parses correctly, otherwise, return false
func IsValidS3URLScheme(s3URL string) bool {
	u, err := url.Parse(s3URL)
	if err != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	return true
}
func newAWSConfig(url, region string, forcePathStyle bool) (*aws.Config, error) {
	awsConfig := aws.NewConfig().
		WithRegion(region).
		WithS3ForcePathStyle(forcePathStyle)

	if url != "" {
		if !IsValidS3URLScheme(url) {
			return nil, errors.Errorf("Invalid s3 url %s, URL must be valid according to https://golang.org/pkg/net/url/#Parse and start with http:// or https://", url)
		}

		awsConfig = awsConfig.WithEndpointResolver(
			endpoints.ResolverFunc(func(service, region string, optFns ...func(*endpoints.Options)) (endpoints.ResolvedEndpoint, error) {
				if service == s3.EndpointsID {
					return endpoints.ResolvedEndpoint{
						URL: url,
					}, nil
				}

				return endpoints.DefaultResolver().EndpointFor(service, region, optFns...)
			}),
		)
	}

	return awsConfig, nil
}

func (s AWSStorage) ListItems(client *s3.S3, objectsV2Input *s3.ListObjectsV2Input) (*s3.ListObjectsV2Output, error) {
	res, err := client.ListObjectsV2(objectsV2Input)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func (s AWSStorage) DeleteItem(client *s3.S3, deleteObjectV2Input *s3.DeleteObjectInput) (*s3.DeleteObjectOutput, error) {
	res, err := client.DeleteObject(deleteObjectV2Input)
	if err != nil {
		return nil, err
	}
	fmt.Println(res)
	return res, nil
}
func (s AWSStorage) IsObjectsInBucket(cloudCredentialsFile, bslBucket, bslPrefix, bslConfig, backupObject string) (bool, error) {
	config := flag.NewMap()
	config.Set(bslConfig)
	objectsInput := s3.ListObjectsV2Input{}
	objectsInput.Bucket = aws.String(bslBucket)
	objectsInput.Delimiter = aws.String("/")

	if bslPrefix != "" {
		objectsInput.Prefix = aws.String(bslPrefix)
	}

	var err error
	var s3Config *aws.Config
	var sess *session.Session
	region := config.Data()["region"]
	s3url := ""

	if region == "minio" {
		s3url = config.Data()["s3Url"]
		s3Config = &aws.Config{
			Credentials:      credentials.NewSharedCredentials(cloudCredentialsFile, ""),
			Endpoint:         aws.String(s3url),
			Region:           aws.String(region),
			DisableSSL:       aws.Bool(true),
			S3ForcePathStyle: aws.Bool(true),
		}
		sess, err = session.NewSession(s3Config)
	} else {
		sess, err = s.CreateSession("", cloudCredentialsFile, "false", "", "", "", bslConfig)
	}

	if err != nil {
		return false, errors.Wrapf(err, "Failed to create AWS session of region %s", region)
	}
	svc := s3.New(sess)

	bucketObjects, err := s.ListItems(svc, &objectsInput)
	if err != nil {
		fmt.Println("Couldn't retrieve bucket items!")
		return false, errors.Wrapf(err, "Couldn't retrieve bucket items")
	}

	for _, item := range bucketObjects.Contents {
		fmt.Println(*item)
	}
	var backupNameInStorage string
	for _, item := range bucketObjects.CommonPrefixes {
		fmt.Println("item:")
		fmt.Println(item)
		backupNameInStorage = strings.TrimPrefix(*item.Prefix, strings.Trim(bslPrefix, "/")+"/")
		fmt.Println("backupNameInStorage:" + backupNameInStorage + " backupObject:" + backupObject)
		if strings.Contains(backupNameInStorage, backupObject) {
			fmt.Printf("Backup %s was found under prefix %s \n", backupObject, bslPrefix)
			return true, nil
		}
	}
	fmt.Printf("Backup %s was not found under prefix %s \n", backupObject, bslPrefix)
	return false, nil
}

func (s AWSStorage) DeleteObjectsInBucket(cloudCredentialsFile, bslBucket, bslPrefix, bslConfig, backupObject string) error {
	config := flag.NewMap()
	config.Set(bslConfig)

	var err error
	var sess *session.Session
	region := config.Data()["region"]
	s3url := ""

	s3Config := &aws.Config{
		Region:      aws.String(region),
		Credentials: credentials.NewSharedCredentials(cloudCredentialsFile, ""),
	}

	if region == "minio" {
		s3url = config.Data()["s3Url"]
		s3Config = &aws.Config{
			Credentials:      credentials.NewSharedCredentials(cloudCredentialsFile, ""),
			Endpoint:         aws.String(s3url),
			Region:           aws.String(region),
			DisableSSL:       aws.Bool(true),
			S3ForcePathStyle: aws.Bool(true),
		}
		sess, err = session.NewSession(s3Config)
	} else {
		sess, err = s.CreateSession("", cloudCredentialsFile, "false", "", "", "", bslConfig)
	}

	if err != nil {
		return errors.Wrapf(err, "Failed to create AWS session of region %s", region)
	}

	svc := s3.New(sess)

	fullPrefix := strings.Trim(bslPrefix, "/") + "/" + strings.Trim(backupObject, "/") + "/"
	iter := s3manager.NewDeleteListIterator(svc, &s3.ListObjectsInput{
		Bucket: aws.String(bslBucket),
		Prefix: aws.String(fullPrefix),
	})

	if err := s3manager.NewBatchDeleteWithClient(svc).Delete(aws.BackgroundContext(), iter); err != nil {
		return errors.Wrapf(err, "Fail to delete object")
	}
	fmt.Printf("Deleted object(s) from bucket: %s %s \n", bslBucket, fullPrefix)
	return nil
}

func (s AWSStorage) IsSnapshotExisted(cloudCredentialsFile, bslConfig, backupObject string, snapshotCheck test.SnapshotCheckPoint) error {

	config := flag.NewMap()
	config.Set(bslConfig)
	region := config.Data()["region"]

	if region == "minio" {
		return errors.New("No snapshot for Minio provider")
	}
	sess, err := s.CreateSession("", cloudCredentialsFile, "false", "", "", "", bslConfig)

	if err != nil {
		fmt.Printf("Fail to create session with profile %s and config %s", cloudCredentialsFile, bslConfig)
		return errors.Wrapf(err, "Fail to create session with profile %s and config %s", cloudCredentialsFile, bslConfig)
	}

	svc := ec2.New(sess)
	params := &ec2.DescribeSnapshotsInput{
		OwnerIds: []*string{aws.String("self")},
	}

	if !snapshotCheck.EnableCSI {
		params = &ec2.DescribeSnapshotsInput{
			OwnerIds: []*string{aws.String("self")},
			Filters: []*ec2.Filter{
				{
					Name: aws.String("tag:velero.io/backup"),
					Values: []*string{
						aws.String(backupObject),
					},
				},
			},
		}
	}

	result, err := svc.DescribeSnapshots(params)
	if err != nil {
		fmt.Println(err)
	}
	var actualCount int
	if snapshotCheck.EnableCSI {
		for _, snapshotId := range snapshotCheck.SnapshotIDList {
			for _, n := range result.Snapshots {
				if n.SnapshotId != nil && (*n.SnapshotId == snapshotId) {
					actualCount++
					fmt.Printf("SnapshotId: %v, Tags: %v \n", *n.SnapshotId, n.Tags)
					if n.VolumeId != nil {
						fmt.Printf("VolumeId: %v \n", *n.VolumeId)
					}
				}
			}
		}
	} else {
		for _, n := range result.Snapshots {
			if n.SnapshotId != nil {
				fmt.Printf("SnapshotId: %v, Tags: %v \n", *n.SnapshotId, n.Tags)
				if n.VolumeId != nil {
					fmt.Printf("VolumeId: %v \n", *n.VolumeId)
				}
			}
		}
		actualCount = len(result.Snapshots)
	}
	if actualCount != snapshotCheck.ExpectCount {
		return errors.New(fmt.Sprintf("Snapshot count %d is not as expected %d", actualCount, snapshotCheck.ExpectCount))
	} else {
		fmt.Printf("Snapshot count %d is as expected %d\n", actualCount, snapshotCheck.ExpectCount)
		return nil
	}

}

func (s AWSStorage) GetMinioBucketSize(cloudCredentialsFile, bslBucket, bslPrefix, bslConfig string) (int64, error) {
	config := flag.NewMap()
	config.Set(bslConfig)
	region := config.Data()["region"]
	s3url := config.Data()["s3Url"]
	s3Config := &aws.Config{
		Credentials:      credentials.NewSharedCredentials(cloudCredentialsFile, ""),
		Endpoint:         aws.String(s3url),
		Region:           aws.String(region),
		DisableSSL:       aws.Bool(true),
		S3ForcePathStyle: aws.Bool(true),
	}
	if region != "minio" {
		return 0, errors.New("it only supported by minio")
	}
	sess, err := session.NewSession(s3Config)
	if err != nil {
		return 0, errors.Wrapf(err, "Error create config session")
	}

	svc := s3.New(sess)
	var totalSize int64
	var continuationToken *string
	// Paginate through objects in the bucket
	objectsInput := &s3.ListObjectsV2Input{
		Bucket:            aws.String(bslBucket),
		ContinuationToken: continuationToken,
	}
	if bslPrefix != "" {
		objectsInput.Prefix = aws.String(bslPrefix)
	}

	for {
		resp, err := svc.ListObjectsV2(objectsInput)
		if err != nil {
			return 0, errors.Wrapf(err, "Error list objects")
		}

		// Process objects in the current response
		for _, obj := range resp.Contents {
			totalSize += *obj.Size
		}

		// Check if there are more objects to retrieve
		if !*resp.IsTruncated {
			break
		}

		// Set the continuation token for the next page
		continuationToken = resp.NextContinuationToken
	}
	return totalSize, nil
}
