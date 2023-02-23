// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package runner

import (
	"fmt"
	"os"
	"strings"

	"github.com/DataDog/datadog-agent/test/new-e2e/runner/parameters"
)

const (
	workspaceFolder = "/tmp/e2e-workspace"
)

type ciProfile struct {
	environments []string
	store        parameters.Store
}

func NewCIProfile() (Profile, error) {
	// Parameter store
	store := parameters.NewAWSStore("ci.datadog-agent.")

	// Create workspace directory
	if err := os.MkdirAll(workspaceFolder, 0o700); err != nil {
		return nil, fmt.Errorf("unable to create temporary folder at: %s, err: %w", workspaceFolder, err)
	}

	// Set Pulumi password
	passVal, err := store.Get(parameters.PulumiPassword)
	if err != nil {
		return nil, fmt.Errorf("unable to get pulumi state password, err: %w", err)
	}
	os.Setenv("PULUMI_CONFIG_PASSPHRASE", passVal)

	return ciProfile{
		environments: []string{"aws/agent-qa"},
		store:        store,
	}, nil
}

func (p ciProfile) EnvironmentNames() string {
	return strings.Join(p.environments, ",")
}

func (p ciProfile) ProjectName() string {
	return "e2eci"
}

func (p ciProfile) RootWorkspacePath() string {
	return workspaceFolder
}

func (p ciProfile) ParameterStore() parameters.Store {
	return p.store
}
