/*
Copyright 2017 the Velero contributors.

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

package encode

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"

	"github.com/cockroachdb/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"

	v1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/util"
)

// Encode converts the provided object to the specified format
// and returns a byte slice of the encoded data.
func Encode(obj runtime.Object, format string) ([]byte, error) {
	buf := new(bytes.Buffer)

	if err := To(obj, format, buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// To converts the provided object to the specified format and
// writes the encoded data to the provided io.Writer.
func To(obj runtime.Object, format string, w io.Writer) error {
	encoder, err := EncoderFor(format, obj)
	if err != nil {
		return err
	}

	return errors.WithStack(encoder.Encode(obj, w))
}

// EncoderFor gets the appropriate encoder for the specified format.
// Only objects registered in the velero scheme, or objects with their TypeMeta set will have valid encoders.
func EncoderFor(format string, obj runtime.Object) (runtime.Encoder, error) {
	var encoder runtime.Encoder

	codecFactory := serializer.NewCodecFactory(util.VeleroScheme)

	desiredMediaType := fmt.Sprintf("application/%s", format)
	serializerInfo, found := runtime.SerializerInfoForMediaType(codecFactory.SupportedMediaTypes(), desiredMediaType)
	if !found {
		return nil, errors.Errorf("unable to locate an encoder for %q", desiredMediaType)
	}
	if serializerInfo.PrettySerializer != nil {
		encoder = serializerInfo.PrettySerializer
	} else {
		encoder = serializerInfo.Serializer
	}
	if !obj.GetObjectKind().GroupVersionKind().Empty() {
		return encoder, nil
	}
	encoder = codecFactory.EncoderForVersion(encoder, v1.SchemeGroupVersion)
	return encoder, nil
}

// ToJSONGzip takes arbitrary Go data and encodes it to GZip compressed JSON in a buffer, as well as a description of the data to put into an error should encoding fail.
func ToJSONGzip(data any, desc string) (*bytes.Buffer, []error) {
	buf := new(bytes.Buffer)
	gzw := gzip.NewWriter(buf)

	// Since both encoding and closing the gzip writer could fail separately and both errors are useful,
	// collect both errors to report back.
	errs := []error{}

	if err := json.NewEncoder(gzw).Encode(data); err != nil {
		errs = append(errs, errors.Wrapf(err, "error encoding %s", desc))
	}
	if err := gzw.Close(); err != nil {
		errs = append(errs, errors.Wrapf(err, "error closing gzip writer for %s", desc))
	}

	if len(errs) > 0 {
		return nil, errs
	}

	return buf, nil
}
