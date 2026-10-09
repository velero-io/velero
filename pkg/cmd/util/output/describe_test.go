package output

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"
	"text/tabwriter"

	"github.com/fatih/color"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestBoolPointerString(t *testing.T) {
	trueStr := "true"
	falseStr := "FALSE"
	nilStr := "nul"
	truee := true
	falsee := false
	testcases := []struct {
		name   string
		input  *bool
		expect string
	}{
		{
			name:   "nil",
			input:  nil,
			expect: nilStr,
		},
		{
			name:   "true",
			input:  &truee,
			expect: trueStr,
		},
		{
			name:   "false",
			input:  &falsee,
			expect: falseStr,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			got := BoolPointerString(tc.input, falseStr, trueStr, nilStr)
			assert.Equal(t, tc.expect, got)
		})
	}
}

func TestDescriber_DescribeMetadata(t *testing.T) {
	input := metav1.ObjectMeta{
		Name:      "test",
		Namespace: "test-ns",
		Labels: map[string]string{
			"test-key2": "v2",
			"test-key0": "v0",
		},
		Annotations: nil,
	}
	expect := new(bytes.Buffer)
	d := &Describer{
		Prefix: "pref-",
		out:    &tabwriter.Writer{},
		buf:    &bytes.Buffer{},
	}
	d.out.Init(d.buf, 0, 8, 0, ' ', 0)
	fmt.Fprintf(expect, "pref-Name:       %s\n", color.New(color.Bold).SprintFunc()("test"))
	fmt.Fprintf(expect, "pref-Namespace:  %s\n", "test-ns")
	fmt.Fprintf(expect, "pref-Labels:     %s\n", "pref-test-key0=v0")
	fmt.Fprintf(expect, "pref-            test-key2=v2\n")
	fmt.Fprintf(expect, "pref-Annotations:%s\n", "pref-<none>")
	d.DescribeMetadata(input)
	d.out.Flush()
	assert.Equal(t, expect.String(), d.buf.String())
}

func TestDescriber_DescribeSlice(t *testing.T) {
	input := []string{"a", "b", "c"}
	expect := new(bytes.Buffer)
	d := &Describer{
		Prefix: "pref-",
		out:    &tabwriter.Writer{},
		buf:    &bytes.Buffer{},
	}
	d.out.Init(d.buf, 0, 8, 0, ' ', 0)
	fmt.Fprintf(expect, "pref-test:pref-a\n")
	fmt.Fprintf(expect, "pref-     b\n")
	fmt.Fprintf(expect, "pref-     c\n")
	d.DescribeSlice(4, "test", input)
	d.out.Flush()
	assert.Equal(t, expect.String(), d.buf.String())
	var input2 []string
	expect2 := new(bytes.Buffer)
	d2 := &Describer{
		Prefix: "pref-",
		out:    &tabwriter.Writer{},
		buf:    &bytes.Buffer{},
	}
	d2.out.Init(d2.buf, 0, 4, 0, ' ', 0)
	fmt.Fprintf(expect2, "pref-test:pref-<none>\n")
	d2.DescribeSlice(4, "test", input2)
	d2.out.Flush()
	assert.Equal(t, expect2.String(), d2.buf.String())
}

func TestStructuredDescriber_JSONEncode(t *testing.T) {
	testcases := []struct {
		name     string
		inputMap map[string]any
		expect   string
	}{
		{
			name:     "invalid json",
			inputMap: map[string]any{},
			expect:   "{}\n",
		},
		{
			name:     "valid json",
			inputMap: map[string]any{"k1": "v1"},
			expect: `{
    "k1": "v1"
}
`,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(tt *testing.T) {
			d := &StructuredDescriber{
				output: tc.inputMap,
			}
			got := d.JSONEncode()
			assert.Equal(tt, tc.expect, got)
		})
	}
}

func TestStructuredDescriber_DescribeMetadata(t *testing.T) {
	d := NewStructuredDescriber("")
	input := metav1.ObjectMeta{
		Name:      "test",
		Namespace: "test-ns",
		Labels: map[string]string{
			"label-1": "v1",
			"label-2": "v2",
		},
		Annotations: map[string]string{
			"annotation-1": "v1",
			"annotation-2": "v2",
		},
	}
	expect := map[string]any{
		"metadata": map[string]any{
			"name":      "test",
			"namespace": "test-ns",
			"labels": map[string]string{
				"label-1": "v1",
				"label-2": "v2",
			},
			"annotations": map[string]string{
				"annotation-1": "v1",
				"annotation-2": "v2",
			},
		},
	}
	d.DescribeMetadata(input)

	assert.True(t, reflect.DeepEqual(expect, d.output))
}

func TestJoinStringWithFallback(t *testing.T) {
	testcases := []struct {
		name     string
		input    []string
		fallback string
		expect   string
	}{
		{
			name:     "empty slice",
			input:    []string{},
			fallback: "fallback-str",
			expect:   "fallback-str",
		},
		{
			name:     "nil slice",
			input:    nil,
			fallback: "fallback-str",
			expect:   "fallback-str",
		},
		{
			name:     "single element",
			input:    []string{"a"},
			fallback: "fallback-str",
			expect:   "a",
		},
		{
			name:     "multiple elements",
			input:    []string{"a", "b", "c"},
			fallback: "fallback-str",
			expect:   "a, b, c",
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			got := JoinStringWithFallback(tc.input, tc.fallback)
			assert.Equal(t, tc.expect, got)
		})
	}
}
