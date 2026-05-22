package framework

import (
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// test that this package do not import cloud provider

// Prevent https://github.com/vmware-tanzu/velero/issues/8207 and https://github.com/vmware-tanzu/velero/issues/8157
func TestPkgImportNoCloudProvider(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("No caller information")
	}
	t.Logf("Current test file path: %s", filename)
	t.Logf("Current test directory: %s", filepath.Dir(filename)) // should be this package name
	// go list -f {{.Deps}} ./<path-to-this-package-dir>
	cmd := exec.CommandContext(
		t.Context(),
		"go",
		"list",
		"-f",
		"{{.Deps}}",
		".",
	)
	// set cmd.Dir to this package even if executed from different dir
	cmd.Dir = filepath.Dir(filename)
	output, err := cmd.Output()
	require.NoError(t, err)
	// split dep by line, replace space with newline
	deps := strings.ReplaceAll(string(output), " ", "\n")
	require.NotEmpty(t, deps)
	// ignore k8s.io
	k8sio, err := regexp.Compile("^k8s.io")
	require.NoError(t, err)
	cloudProvider, err := regexp.Compile("aws|cloud.google.com|azure")
	require.NoError(t, err)
	cloudProviderDeps := []string{}
	for dep := range strings.SplitSeq(deps, "\n") {
		if !k8sio.MatchString(dep) {
			if cloudProvider.MatchString(dep) {
				cloudProviderDeps = append(cloudProviderDeps, dep)
			}
		}
	}
	require.Empty(t, cloudProviderDeps)
}
