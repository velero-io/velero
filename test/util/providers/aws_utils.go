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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/config"
	s3manager "github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/cockroachdb/errors"

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

func newAWSConfig(region, profile, credentialsFile string, insecureSkipTLSVerify bool, caCert string) (aws.Config, error) {
	empty := aws.Config{}
	client := awshttp.NewBuildableClient().WithTransportOptions(func(tr *http.Transport) {
		if len(caCert) > 0 {
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM([]byte(caCert))
			if tr.TLSClientConfig == nil {
				tr.TLSClientConfig = &tls.Config{
					RootCAs: caCertPool,
				}
			} else {
				tr.TLSClientConfig.RootCAs = caCertPool
			}
		}
		tr.TLSClientConfig.InsecureSkipVerify = insecureSkipTLSVerify
	})
	opts := []func(*config.LoadOptions) error{
		config.WithRegion(region),
		config.WithSharedConfigProfile(profile),
		config.WithHTTPClient(client),
	}

	if credentialsFile == "" && os.Getenv("AWS_SHARED_CREDENTIALS_FILE") != "" {
		credentialsFile = os.Getenv("AWS_SHARED_CREDENTIALS_FILE")
	}

	if credentialsFile != "" {
		if _, err := os.Stat(credentialsFile); err != nil {
			if os.IsNotExist(err) {
				return empty, errors.Wrapf(err, "provided credentialsFile does not exist")
			}
			return empty, errors.Wrapf(err, "could not get credentialsFile info")
		}
		opts = append(opts, config.WithSharedCredentialsFiles([]string{credentialsFile}),
			config.WithSharedConfigFiles([]string{credentialsFile}))
	}

	awsConfig, err := config.LoadDefaultConfig(context.Background(), opts...)
	if err != nil {
		return empty, errors.Wrapf(err, "could not load config")
	}
	if _, err := awsConfig.Credentials.Retrieve(context.Background()); err != nil {
		return empty, errors.WithStack(err)
	}

	return awsConfig, nil
}

func newS3Client(cfg aws.Config, url string, forcePathStyle bool) (*s3.Client, error) {
	opts := []func(*s3.Options){
		func(o *s3.Options) {
			o.UsePathStyle = forcePathStyle
		},
	}
	if url != "" {
		if !IsValidS3URLScheme(url) {
			return nil, errors.Errorf("Invalid s3 url %s, URL must be valid according to https://golang.org/pkg/net/url/#Parse and start with http:// or https://", url)
		}
		opts = append(opts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(url)
		})
	}

	return s3.NewFromConfig(cfg, opts...), nil
}

// GetBucketRegion returns the AWS region that a bucket is in, or an error
// if the region cannot be determined.
func GetBucketRegion(bucket string) (string, error) {
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return "", errors.WithStack(err)
	}
	client := s3.NewFromConfig(cfg)
	region, err := s3manager.GetBucketRegion(context.Background(), client, bucket)
	if err != nil {
		return "", errors.WithStack(err)
	}
	if region == "" {
		return "", errors.New("unable to determine bucket's region")
	}
	return region, nil
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

func (s AWSStorage) ListItems(client *s3.Client, objectsV2Input *s3.ListObjectsV2Input) (*s3.ListObjectsV2Output, error) {
	res, err := client.ListObjectsV2(context.Background(), objectsV2Input)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func (s AWSStorage) DeleteItem(client *s3.Client, deleteObjectV2Input *s3.DeleteObjectInput) (*s3.DeleteObjectOutput, error) {
	res, err := client.DeleteObject(context.Background(), deleteObjectV2Input)
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
	var s3Config aws.Config
	var s3Client *s3.Client
	region := config.Data()["region"]
	s3url := ""
	if region == "" {
		region, err = GetBucketRegion(bslBucket)
		if err != nil {
			return false, errors.Wrapf(err, "failed to get region for bucket %s", bslBucket)
		}
	}
	if region == "minio" {
		s3url = config.Data()["s3Url"]
		s3Config, err = newAWSConfig(region, "", cloudCredentialsFile, true, "")
		if err != nil {
			return false, errors.Wrapf(err, "Failed to create AWS config of region %s", region)
		}
		s3Client, err = newS3Client(s3Config, s3url, true)
	} else {
		s3Config, err = newAWSConfig(region, "", cloudCredentialsFile, false, "")
		if err != nil {
			return false, errors.Wrapf(err, "Failed to create AWS config of region %s", region)
		}
		s3Client, err = newS3Client(s3Config, s3url, true)
	}
	if err != nil {
		return false, errors.Wrapf(err, "failed to create S3 client of region %s", region)
	}

	bucketObjects, err := s.ListItems(s3Client, &objectsInput)
	if err != nil {
		fmt.Println("Couldn't retrieve bucket items!")
		return false, errors.Wrapf(err, "Couldn't retrieve bucket items")
	}

	for _, item := range bucketObjects.Contents {
		fmt.Println(item)
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
	var s3Config aws.Config
	var s3Client *s3.Client
	region := config.Data()["region"]
	s3url := ""
	if region == "" {
		region, err = GetBucketRegion(bslBucket)
		if err != nil {
			return errors.Wrapf(err, "failed to get region for bucket %s", bslBucket)
		}
	}

	if region == "minio" {
		s3url = config.Data()["s3Url"]
		s3Config, err = newAWSConfig(region, "", cloudCredentialsFile, true, "")
		if err != nil {
			return errors.Wrapf(err, "Failed to create AWS config of region %s", region)
		}
		s3Client, err = newS3Client(s3Config, s3url, true)
	} else {
		s3Config, err = newAWSConfig(region, "", cloudCredentialsFile, false, "")
		if err != nil {
			return errors.Wrapf(err, "Failed to create AWS config of region %s", region)
		}
		s3Client, err = newS3Client(s3Config, s3url, false)
	}

	if err != nil {
		return errors.Wrapf(err, "Failed to create S3 client of region %s", region)
	}
	fullPrefix := strings.Trim(bslPrefix, "/") + "/" + strings.Trim(backupObject, "/") + "/"
	listInput := &s3.ListObjectsV2Input{
		Bucket: aws.String(bslBucket),
		Prefix: aws.String(fullPrefix),
	}
	// list all keys
	var objectIds []s3types.ObjectIdentifier
	p := s3.NewListObjectsV2Paginator(s3Client, listInput)
	for p.HasMorePages() {
		page, err := p.NextPage(context.Background())
		if err != nil {
			return errors.Wrapf(err, "failed to list objects in bucket %s", bslBucket)
		}
		for _, obj := range page.Contents {
			objectIds = append(objectIds, s3types.ObjectIdentifier{Key: aws.String(*obj.Key)})
		}
	}
	_, err = s3Client.DeleteObjects(context.Background(), &s3.DeleteObjectsInput{
		Bucket: aws.String(bslBucket),
		Delete: &s3types.Delete{Objects: objectIds},
	})
	if err != nil {
		return errors.Wrapf(err, "failed to delete objects from bucket %s", bslBucket)
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

	cfg, err := newAWSConfig(region, "", cloudCredentialsFile, false, "")
	if err != nil {
		return errors.Wrapf(err, "Failed to create AWS config of region %s", region)
	}

	ec2Client := ec2.NewFromConfig(cfg)
	input := &ec2.DescribeSnapshotsInput{
		OwnerIds: []string{"self"},
	}

	if !snapshotCheck.EnableCSI {
		input = &ec2.DescribeSnapshotsInput{
			OwnerIds: []string{"self"},
			Filters: []ec2types.Filter{
				{
					Name:   aws.String("tag:velero.io/backup"),
					Values: []string{backupObject},
				},
			},
		}
	}

	result, err := ec2Client.DescribeSnapshots(context.Background(), input)
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
	if region != "minio" {
		return 0, errors.New("it only supported by minio")
	}
	s3url := config.Data()["s3Url"]
	s3Config, err := newAWSConfig(region, "", cloudCredentialsFile, true, "")
	if err != nil {
		return 0, errors.Wrapf(err, "failed to create AWS config of region %s", region)
	}
	s3Client, err := newS3Client(s3Config, s3url, true)
	if err != nil {
		return 0, errors.Wrapf(err, "failed to create S3 client of region %s", region)
	}
	/*
		s3Config := &aws.Config{
			Credentials:      credentials.NewSharedCredentials(cloudCredentialsFile, ""),
			Endpoint:         aws.String(s3url),
			Region:           aws.String(region),
			DisableSSL:       aws.Bool(true),
			S3ForcePathStyle: aws.Bool(true),
		}
	*/

	var totalSize int64
	// Paginate through objects in the bucket
	objectsInput := &s3.ListObjectsV2Input{
		Bucket: aws.String(bslBucket),
	}
	if bslPrefix != "" {
		objectsInput.Prefix = aws.String(bslPrefix)
	}

	p := s3.NewListObjectsV2Paginator(s3Client, objectsInput)
	for p.HasMorePages() {
		page, err := p.NextPage(context.Background())
		if err != nil {
			return 0, errors.Wrapf(err, "failed to list objects in bucket %s", bslBucket)
		}
		for _, obj := range page.Contents {
			totalSize += *obj.Size
		}
	}
	return totalSize, nil
}

func (s AWSStorage) GetObject(cloudCredentialsFile, bslBucket, bslPrefix, bslConfig, objectKey string) (io.ReadCloser, error) {
	config := flag.NewMap()
	config.Set(bslConfig)
	objectsInput := s3.ListObjectsV2Input{}
	objectsInput.Bucket = aws.String(bslBucket)
	objectsInput.Delimiter = aws.String("/")

	if bslPrefix != "" {
		objectsInput.Prefix = aws.String(bslPrefix)
	}

	var err error
	var s3Config aws.Config
	var s3Client *s3.Client
	region := config.Data()["region"]
	s3url := ""
	if region == "" {
		region, err = GetBucketRegion(bslBucket)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get region for bucket %s", bslBucket)
		}
	}
	if region == "minio" {
		s3url = config.Data()["s3Url"]
		s3Config, err = newAWSConfig(region, "", cloudCredentialsFile, true, "")
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to create AWS config of region %s", region)
		}
		s3Client, err = newS3Client(s3Config, s3url, true)
	} else {
		s3Config, err = newAWSConfig(region, "", cloudCredentialsFile, false, "")
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to create AWS config of region %s", region)
		}
		s3Client, err = newS3Client(s3Config, s3url, true)
	}
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create S3 client of region %s", region)
	}

	fullObjectKey := strings.Trim(bslPrefix, "/") + "/" + strings.Trim(objectKey, "/")

	result, err := s3Client.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: aws.String(bslBucket),
		Key:    aws.String(fullObjectKey),
	})
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get object %s", fullObjectKey)
	}

	return result.Body, nil
}
