package resourcemodifiers

import (
	"fmt"
	"net/http"

	"github.com/sirupsen/logrus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/mergepatch"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	"k8s.io/apimachinery/pkg/util/validation/field"
	kubejson "sigs.k8s.io/json"
	"sigs.k8s.io/yaml"
)

type StrategicMergePatch struct {
	PatchData string `json:"patchData,omitempty"`
}

type StrategicMergePatcher struct {
	patches []StrategicMergePatch
	scheme  *runtime.Scheme
}

func (p *StrategicMergePatcher) Patch(u *unstructured.Unstructured, _ logrus.FieldLogger) (*unstructured.Unstructured, error) {
	gvk := u.GetObjectKind().GroupVersionKind()
	schemaReferenceObj, err := p.scheme.New(gvk)
	if err != nil {
		return nil, err
	}

	origin := u.DeepCopy()
	updated := u.DeepCopy()
	for _, patch := range p.patches {
		patchBytes, err := yaml.YAMLToJSON([]byte(patch.PatchData))
		if err != nil {
			return nil, fmt.Errorf("error in converting YAML to JSON %s", err)
		}

		err = strategicPatchObject(origin, patchBytes, updated, schemaReferenceObj)
		if err != nil {
			return nil, fmt.Errorf("error in applying Strategic Patch %s", err.Error())
		}

		origin = updated.DeepCopy()
	}

	return updated, nil
}

// strategicPatchObject applies a strategic merge patch of `patchBytes` to
// `originalObject` and stores the result in `objToUpdate`.
// It additionally returns the map[string]any representation of the
// `originalObject` and `patchBytes`.
// NOTE: Both `originalObject` and `objToUpdate` are supposed to be versioned.
func strategicPatchObject(
	originalObject runtime.Object,
	patchBytes []byte,
	objToUpdate runtime.Object,
	schemaReferenceObj runtime.Object,
) error {
	originalObjMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(originalObject)
	if err != nil {
		return err
	}

	patchMap := make(map[string]any)
	var strictErrs []error
	strictErrs, err = kubejson.UnmarshalStrict(patchBytes, &patchMap)
	if err != nil {
		return apierrors.NewBadRequest(err.Error())
	}

	if err := applyPatchToObject(originalObjMap, patchMap, objToUpdate, schemaReferenceObj, strictErrs); err != nil {
		return err
	}
	return nil
}

// applyPatchToObject applies a strategic merge patch of <patchMap> to
// <originalMap> and stores the result in <objToUpdate>.
// NOTE: <objToUpdate> must be a versioned object.
func applyPatchToObject(
	originalMap map[string]any,
	patchMap map[string]any,
	objToUpdate runtime.Object,
	schemaReferenceObj runtime.Object,
	strictErrs []error,
) error {
	patchedObjMap, err := strategicpatch.StrategicMergeMapPatch(originalMap, patchMap, schemaReferenceObj)
	if err != nil {
		return interpretStrategicMergePatchError(err)
	}

	// Rather than serialize the patched map to JSON, then decode it to an object, we go directly from a map to an object
	converter := runtime.DefaultUnstructuredConverter
	if err := converter.FromUnstructuredWithValidation(patchedObjMap, objToUpdate, true); err != nil {
		strictError, isStrictError := runtime.AsStrictDecodingError(err)
		switch {
		case !isStrictError:
			// disregard any sttrictErrs, because it's an incomplete
			// list of strict errors given that we don't know what fields were
			// unknown because StrategicMergeMapPatch failed.
			// Non-strict errors trump in this case.
			return apierrors.NewInvalid(schema.GroupKind{}, "", field.ErrorList{
				field.Invalid(field.NewPath("patch"), fmt.Sprintf("%+v", patchMap), err.Error()),
			})
		//case validationDirective == metav1.FieldValidationWarn:
		//	addStrictDecodingWarnings(requestContext, append(strictErrs, strictError.Errors()...))
		default:
			strictDecodingError := runtime.NewStrictDecodingError(append(strictErrs, strictError.Errors()...))
			return apierrors.NewInvalid(schema.GroupKind{}, "", field.ErrorList{
				field.Invalid(field.NewPath("patch"), fmt.Sprintf("%+v", patchMap), strictDecodingError.Error()),
			})
		}
	} else if len(strictErrs) > 0 {
		return apierrors.NewInvalid(schema.GroupKind{}, "", field.ErrorList{
			field.Invalid(field.NewPath("patch"), fmt.Sprintf("%+v", patchMap), runtime.NewStrictDecodingError(strictErrs).Error()),
		})
	}

	return nil
}

// interpretStrategicMergePatchError interprets the error type and returns an error with appropriate HTTP code.
func interpretStrategicMergePatchError(err error) error {
	switch err {
	case mergepatch.ErrBadJSONDoc, mergepatch.ErrBadPatchFormatForPrimitiveList, mergepatch.ErrBadPatchFormatForRetainKeys, mergepatch.ErrBadPatchFormatForSetElementOrderList, mergepatch.ErrUnsupportedStrategicMergePatchFormat:
		return apierrors.NewBadRequest(err.Error())
	case mergepatch.ErrNoListOfLists, mergepatch.ErrPatchContentNotMatchRetainKeys:
		return apierrors.NewGenericServerResponse(http.StatusUnprocessableEntity, "", schema.GroupResource{}, "", err.Error(), 0, false)
	default:
		return err
	}
}
