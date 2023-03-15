// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build kubeapiserver
// +build kubeapiserver

package tests

import (
	"testing"

	"github.com/DataDog/datadog-agent/pkg/compliance/event"

	_ "github.com/DataDog/datadog-agent/pkg/compliance/resources/constants"
	_ "github.com/DataDog/datadog-agent/pkg/compliance/resources/kubeapiserver"

	"github.com/stretchr/testify/assert"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

func TestKubernetesCluster(t *testing.T) {
	kubeClient, err := dynamic.NewForConfig(&rest.Config{
		Host: "localhost:8001",
	})
	if err != nil {
		t.Skipf("could not connect to kubernetes api to start testing: %v", err)
	}

	b := NewTestBench(t).WithKubeClient(kubeClient)
	defer b.Run()

	b.
		AddRule("Context").
		WithScope("kubernetesCluster").
		WithInput(`
- kubeApiserver:
		kind: namespaces
		version: v1
		apiRequest:
			verb: list
	type: array
	tag: namespaces
- constants:
		foo: bar
`).
		WithRego(`
package datadog
import data.datadog as dd

findings[f] {
	input.context.hostname == "{{.Hostname}}"
	input.context.ruleID == "{{.RuleID}}"
	input.context.input.constants.constants.foo == "bar"
	input.context.input.namespaces.kubeApiserver.kind == "namespaces"
	input.context.input.namespaces.kubeApiserver.version == "v1"
	input.context.input.namespaces.kubeApiserver.apiRequest.verb == "list"
	f := dd.passed_finding(
		"my_resource_type",
		"my_resource_id",
		{}
	)
}
`).
		AssertPassedEvent(nil)

	b.
		AddRule("ServiceAccounts").
		WithScope("kubernetesCluster").
		WithInput(`
- kubeApiserver:
		kind: serviceaccounts
		version: v1
		apiRequest:
			verb: list
	type: array
	tag: serviceaccounts
`).
		WithRego(`
package datadog
import data.datadog as dd

has_key(o, k) {
	_ := o[k]
}

valid_resource(r) {
	r.kind == "ServiceAccount"
	has_key(r, "group")
	has_key(r, "version")
	has_key(r, "namespace")
	has_key(r, "name")
	has_key(r, "resource")
}

findings[f] {
	count(input.serviceaccounts) > 0
	valid_resources = [r | r := input.serviceaccounts[_]; valid_resource(r)]
	f := dd.passed_finding(
		"my_resource_type",
		"my_resource_id",
		{"serviceaccounts": input.serviceaccounts}
	)
}
`).
		AssertPassedEvent(func(t *testing.T, evt *event.Event) {
			assert.NotNil(t, evt.Data.(event.Data)["serviceaccounts"])
		})

	b.
		AddRule("Namespaces").
		WithScope("kubernetesCluster").
		WithInput(`
- kubeApiserver:
		kind: namespaces
		version: v1
		apiRequest:
			verb: list
	type: array
	tag: namespaces
`).
		WithRego(`
package datadog
import data.datadog as dd

has_key(o, k) {
	_ := o[k]
}

valid_namespace(n) {
	n.kind == "Namespace"
	has_key(n, "version")
	has_key(n, "group")
	has_key(n, "name")
	has_key(n, "namespace")
	has_key(n, "resource")
	has_key(n.resource, "Object")
}

findings[f] {
	count(input.namespaces) > 0
	valid_namespaces = [r | r := input.namespaces[_]; valid_namespace(r)]
	f := dd.passed_finding(
		"my_resource_type",
		"my_resource_id",
		{"namespaces": input.namespaces}
	)
}
`).
		AssertPassedEvent(nil)
}
