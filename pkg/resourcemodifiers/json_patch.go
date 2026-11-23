package resourcemodifiers

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	jsonpatch "github.com/evanphx/json-patch/v5"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type JSONPatch struct {
	Operation string `json:"operation"`
	From      string `json:"from,omitempty"`
	Path      string `json:"path"`
	Value     string `json:"value,omitempty"`
}

func (p *JSONPatch) ToString() string {
	if addQuotes(&p.Value) {
		return fmt.Sprintf(`{"op": "%s", "from": "%s", "path": "%s", "value": "%s"}`, p.Operation, p.From, p.Path, p.Value)
	}
	return fmt.Sprintf(`{"op": "%s", "from": "%s", "path": "%s", "value": %s}`, p.Operation, p.From, p.Path, p.Value)
}

func addQuotes(value *string) bool {
	if *value == "" {
		return true
	}
	// if value is escaped, remove escape and add quotes
	// this is useful for scenarios where boolean, null and numbers are required to be set as string.
	if strings.HasPrefix(*value, "\"") && strings.HasSuffix(*value, "\"") {
		*value = strings.TrimPrefix(*value, "\"")
		*value = strings.TrimSuffix(*value, "\"")
		return true
	}
	// if value is null, then don't add quotes
	if *value == "null" {
		return false
	}
	// if value is a boolean, then don't add quotes
	if strings.ToLower(*value) == "true" || strings.ToLower(*value) == "false" {
		return false
	}
	// if value is a json object or array, then don't add quotes.
	if strings.HasPrefix(*value, "{") || strings.HasPrefix(*value, "[") {
		return false
	}
	// if value is a number, then don't add quotes
	if _, err := strconv.ParseFloat(*value, 64); err == nil {
		return false
	}
	return true
}

type JSONPatcher struct {
	patches []JSONPatch `yaml:"patches"`
}

func (p *JSONPatcher) Patch(u *unstructured.Unstructured, logger logrus.FieldLogger) (*unstructured.Unstructured, error) {
	modifiedObjBytes, err := p.applyPatch(u)
	if err != nil {
		if errors.Is(err, jsonpatch.ErrTestFailed) {
			logger.Infof("Test operation failed for JSON Patch %s", err.Error())
			return u.DeepCopy(), nil
		}
		return nil, fmt.Errorf("error in applying JSON Patch %s", err.Error())
	}

	updated := &unstructured.Unstructured{}
	err = updated.UnmarshalJSON(modifiedObjBytes)
	if err != nil {
		return nil, fmt.Errorf("error in unmarshalling modified object %s", err.Error())
	}

	return updated, nil
}

func (p *JSONPatcher) applyPatch(u *unstructured.Unstructured) ([]byte, error) {
	patchBytes := p.patchArrayToByteArray()
	jsonPatch, err := jsonpatch.DecodePatch(patchBytes)
	if err != nil {
		return nil, fmt.Errorf("error in decoding json patch %s", err.Error())
	}

	objBytes, err := u.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("error in marshaling object %s", err.Error())
	}

	return jsonPatch.Apply(objBytes)
}

func (p *JSONPatcher) patchArrayToByteArray() []byte {
	var patches []string
	for _, patch := range p.patches {
		patches = append(patches, patch.ToString())
	}
	patchesStr := strings.Join(patches, ",\n\t")
	return []byte(fmt.Sprintf(`[%s]`, patchesStr))
}
