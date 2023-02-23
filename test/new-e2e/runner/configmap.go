// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package runner

import (
	"github.com/DataDog/datadog-agent/test/new-e2e/runner/parameters"

	"github.com/pulumi/pulumi/sdk/v3/go/auto"
)

type ConfigMap auto.ConfigMap

func (cm ConfigMap) Set(key, val string, secret bool) {
	cm[key] = auto.ConfigValue{
		Value:  val,
		Secret: secret,
	}
}

func (cm ConfigMap) Merge(in ConfigMap) {
	for key, val := range in {
		cm[key] = val
	}
}

func (cm ConfigMap) ToPulumi() auto.ConfigMap {
	return (auto.ConfigMap)(cm)
}

func SetConfigMapFromParameter(store parameters.Store, cm ConfigMap, paramName, configMapKey string, secret bool) error {
	val, err := store.Get(paramName)
	if err != nil {
		return err
	}

	cm[configMapKey] = auto.ConfigValue{
		Value:  val,
		Secret: secret,
	}
	return nil
}

func BuildConfigMapFromProfile(profile Profile) (ConfigMap, error) {
	cm := ConfigMap{}
	cm.Set("ddinfra:env", profile.EnvironmentNames(), false)

	err := SetConfigMapFromParameter(profile.ParameterStore(), cm, parameters.APIKey, "ddagent:apiKey", true)
	if err != nil {
		return nil, err
	}

	return cm, nil
}
