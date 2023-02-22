// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build secrets && windows
// +build secrets,windows

package secrets

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	testConfInfo = []byte(`---
instances:
- password: ENC[pass3]
- password: ENC[pass2]
`)
)

func TestGetExecutablePermissionsError(t *testing.T) {
	secretBackendCommand = "some_command"
	defer resetPackageVars()

	res, err := getExecutablePermissions()
	require.NoError(t, err)
	require.IsType(t, permissionsDetails{}, res)
	details := res.(permissionsDetails)
	assert.Equal(t, "Error calling 'get-acl': exit status 1", details.Error)
	assert.Equal(t, "", details.Stdout)
	assert.NotEqual(t, "", details.Stderr)
}

func setupSecretCommmand(t *testing.T) {
	dir := t.TempDir()
	t.Cleanup(resetPackageVars)

	secretBackendCommand = filepath.Join(dir, "an executable with space")
	f, err := os.Create(secretBackendCommand)
	require.NoError(t, err)
	f.Close()

	exec.Command("powershell", "test/setAcl.ps1",
		"-file", fmt.Sprintf("\"%s\"", secretBackendCommand),
		"-removeAllUser", "0",
		"-removeAdmin", "0",
		"-removeLocalSystem", "0",
		"-addDDuser", "1").Run()
}

func TestGetExecutablePermissionsSuccess(t *testing.T) {
	setupSecretCommmand(t)

	res, err := getExecutablePermissions()
	require.NoError(t, err)
	require.IsType(t, permissionsDetails{}, res)
	details := res.(permissionsDetails)
	assert.Equal(t, "", details.Error)
	assert.NotEqual(t, "", details.Stdout)
	assert.Equal(t, "", details.Stderr)
}

func TestDebugInfoError(t *testing.T) {
	secretBackendCommand = "some_command"
	defer resetPackageVars()

	runCommand = func(string) ([]byte, error) {
		res := []byte("{\"pass1\":{\"value\":\"password1\"},")
		res = append(res, []byte("\"pass2\":{\"value\":\"password2\"},")...)
		res = append(res, []byte("\"pass3\":{\"value\":\"password3\"}}")...)
		return res, nil
	}

	_, err := Decrypt(testConf, "test")
	require.NoError(t, err)
	_, err = Decrypt(testConfInfo, "test2")
	require.NoError(t, err)

	var buffer bytes.Buffer
	GetDebugInfo(&buffer)

	expectedResult := `=== Checking executable permissions ===
Executable path: some_command
Executable permissions: error: secretBackendCommand 'some_command' does not exist

Permissions Detail:
Error calling 'get-acl': exit status 1
stdout:

stderr:
get-acl : Cannot find path 'some_command' because it does not exist.
At line:1 char:1
+ get-acl -Path "some_command" | format-list
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (:) [Get-Acl], ItemNotFoundException
    + FullyQualifiedErrorId : GetAcl_PathNotFound_Exception,Microsoft.PowerShell.Commands.GetAclCommand

=== Secrets stats ===
Number of secrets decrypted: 3
Secrets handle decrypted:

- 'pass1':
	used in 'test' configuration in entry 'instances/password'
- 'pass2':
	used in 'test' configuration in entry 'instances/password'
	used in 'test2' configuration in entry 'instances/password'
- 'pass3':
	used in 'test2' configuration in entry 'instances/password'
`

	assert.Equal(t, expectedResult, strings.Replace(buffer.String(), "\r\n", "\n", -1))
}
