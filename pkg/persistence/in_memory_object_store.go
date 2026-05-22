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

package persistence

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"time"
)

type BucketData map[string][]byte

// inMemoryObjectStore is a simple implementation of the ObjectStore interface
// that stores its data in-memory/in-proc. This is mainly intended to be used
// as a test fake.
type inMemoryObjectStore struct {
	Data   map[string]BucketData
	Config map[string]string
}

func newInMemoryObjectStore(buckets ...string) *inMemoryObjectStore {
	o := &inMemoryObjectStore{
		Data: make(map[string]BucketData),
	}

	for _, bucket := range buckets {
		o.Data[bucket] = make(map[string][]byte)
	}

	return o
}

//
// Interface Implementation
//

func (o *inMemoryObjectStore) Init(config map[string]string) error {
	o.Config = config
	return nil
}

func (o *inMemoryObjectStore) PutObject(bucket, key string, body io.Reader) error {
	bucketData, ok := o.Data[bucket]
	if !ok {
		return errors.New("bucket not found")
	}

	obj, err := io.ReadAll(body)
	if err != nil {
		return err
	}

	bucketData[key] = obj

	return nil
}

func (o *inMemoryObjectStore) ObjectExists(bucket, key string) (bool, error) {
	bucketData, ok := o.Data[bucket]
	if !ok {
		return false, errors.New("bucket not found")
	}

	_, ok = bucketData[key]
	return ok, nil
}

func (o *inMemoryObjectStore) GetObject(bucket, key string) (io.ReadCloser, error) {
	bucketData, ok := o.Data[bucket]
	if !ok {
		return nil, errors.New("bucket not found")
	}

	obj, ok := bucketData[key]
	if !ok {
		return nil, errors.New("key not found")
	}

	return io.NopCloser(bytes.NewReader(obj)), nil
}

func (o *inMemoryObjectStore) ListCommonPrefixes(bucket, prefix, delimiter string) ([]string, error) {
	keys, err := o.ListObjects(bucket, prefix)
	if err != nil {
		return nil, err
	}

	// For each key, check if it has an instance of the delimiter *after* the prefix.
	// If not, skip it; if so, return the prefix of the key up to/including the delimiter.

	var prefixes []string
	for _, key := range keys {
		// everything after 'prefix'
		afterPrefix := key[len(prefix):]

		// index of the *start* of 'delimiter' in 'afterPrefix'
		before, _, ok := strings.Cut(afterPrefix, delimiter)
		if !ok {
			continue
		}

		// return the prefix, plus everything after the prefix and before
		// the delimiter, plus the delimiter
		fullPrefix := prefix + before + delimiter

		prefixes = append(prefixes, fullPrefix)
	}

	return prefixes, nil
}

func (o *inMemoryObjectStore) ListObjects(bucket, prefix string) ([]string, error) {
	bucketData, ok := o.Data[bucket]
	if !ok {
		return nil, errors.New("bucket not found")
	}

	var objs []string
	for key := range bucketData {
		if strings.HasPrefix(key, prefix) {
			objs = append(objs, key)
		}
	}

	return objs, nil
}

func (o *inMemoryObjectStore) DeleteObject(bucket, key string) error {
	bucketData, ok := o.Data[bucket]
	if !ok {
		return errors.New("bucket not found")
	}

	delete(bucketData, key)

	return nil
}

func (o *inMemoryObjectStore) CreateSignedURL(bucket, key string, ttl time.Duration) (string, error) {
	bucketData, ok := o.Data[bucket]
	if !ok {
		return "", errors.New("bucket not found")
	}

	_, ok = bucketData[key]
	if !ok {
		return "", errors.New("key not found")
	}

	return "a-url", nil
}

//
// Test Helper Methods
//

func (o *inMemoryObjectStore) ClearBucket(bucket string) {
	if _, ok := o.Data[bucket]; !ok {
		return
	}

	o.Data[bucket] = make(map[string][]byte)
}
