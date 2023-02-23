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

func NewLocalProfile() (Profile, error) {
	if err := os.MkdirAll(workspaceFolder, 0o700); err != nil {
		return nil, fmt.Errorf("unable to create temporary folder at: %s, err: %w", workspaceFolder, err)
	}

	return localProfile{
		environments: []string{"aws/sandbox"},
	}, nil
}

type localProfile struct {
	environments []string
}

func (p localProfile) EnvironmentNames() string {
	return strings.Join(p.environments, ",")
}

func (p localProfile) ProjectName() string {
	return "e2elocal"
}

func (p localProfile) RootWorkspacePath() string {
	return workspaceFolder
}

func (p localProfile) ParameterStore() parameters.Store {
	return parameters.NewEnvStore("DD_")
}
