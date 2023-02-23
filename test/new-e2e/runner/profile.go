// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package runner

import (
	"os"
	"strings"
	"sync"

	"github.com/DataDog/datadog-agent/test/new-e2e/runner/parameters"
)

type CloudProvider string

const (
	AWS   CloudProvider = "aws"
	Azure CloudProvider = "az"
	GCP   CloudProvider = "gcp"
)

type Profile interface {
	// EnvironmentName returns the environment names for cloud providers
	EnvironmentNames() string
	// ProjectName used by Pulumi
	ProjectName() string
	// RootWorkspacePath returns the root directory for local Pulumi workspace
	RootWorkspacePath() string
	// ParameterStore returns the parameter store
	ParameterStore() parameters.Store
}

var (
	runProfile  Profile
	initProfile sync.Once
)

func GetProfile() Profile {
	initProfile.Do(func() {
		var profileFunc func() (Profile, error) = NewLocalProfile
		if strings.ToLower(os.Getenv("CI")) == "true" || strings.ToLower(os.Getenv("E2E_PROFILE")) == "ci" {
			profileFunc = NewCIProfile
		}

		var err error
		runProfile, err = profileFunc()
		if err != nil {
			panic(err)
		}
	})

	return runProfile
}
