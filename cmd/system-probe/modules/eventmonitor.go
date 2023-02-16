// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.
//go:build linux || windows
// +build linux windows

package modules

import (
	"github.com/DataDog/datadog-agent/cmd/system-probe/api/module"
	"github.com/DataDog/datadog-agent/cmd/system-probe/config"
	"github.com/DataDog/datadog-agent/pkg/eventmonitor"
	emconfig "github.com/DataDog/datadog-agent/pkg/eventmonitor/config"
	"github.com/DataDog/datadog-agent/pkg/eventmonitor/consumers/network"
	cprocess "github.com/DataDog/datadog-agent/pkg/eventmonitor/consumers/process"
	secconfig "github.com/DataDog/datadog-agent/pkg/security/config"
	secmodule "github.com/DataDog/datadog-agent/pkg/security/module"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// EventMonitor - Event monitor Factory
var EventMonitor = module.Factory{
	Name:             config.EventMonitorModule,
	ConfigNamespaces: []string{"event_monitoring_config", "runtime_security_config"},
	Fn: func(sysProbeConfig *config.Config) (module.Module, error) {
		seccfg, err := secconfig.NewConfig()
		if err != nil {
			log.Infof("invalid runtime security configuration: %w", err)
			return nil, module.ErrNotEnabled
		}

		emconfig, err := emconfig.NewConfig(sysProbeConfig, seccfg.CWSConfig)
		if err != nil {
			log.Infof("invalid event monitoring configuration: %w", err)
			return nil, module.ErrNotEnabled
		}

		evm, err := eventmonitor.NewEventMonitor(emconfig)
		if err != nil {
			log.Infof("error initializing event monitoring module: %w", err)
			return nil, module.ErrNotEnabled
		}

		if seccfg.RuntimeEnabled || seccfg.FIMEnabled {
			cws, err := secmodule.NewCWSConsumer(evm)
			if err != nil {
				return nil, err
			}
			evm.RegisterEventConsumer(cws)
		}

		if emconfig.NetworkConsumerEnabled {
			network, err := network.NewNetworkConsumer(evm)
			if err != nil {
				return nil, err
			}
			evm.RegisterEventConsumer(network)
		}

		if emconfig.ProcessConsumerEnabled {
			process, err := cprocess.NewProcessConsumer(evm)
			if err != nil {
				return nil, err
			}
			evm.RegisterEventConsumer(process)
		}

		return evm, err
	},
}
