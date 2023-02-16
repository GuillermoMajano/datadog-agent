// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package config

import (
	"fmt"
	"github.com/DataDog/datadog-agent/pkg/security/utils"
	"os"
	"time"

	coreconfig "github.com/DataDog/datadog-agent/pkg/config"
	logshttp "github.com/DataDog/datadog-agent/pkg/logs/client/http"
	logsconfig "github.com/DataDog/datadog-agent/pkg/logs/config"
	"github.com/DataDog/datadog-agent/pkg/process/util"
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
	"github.com/DataDog/datadog-agent/pkg/security/seclog"
)

const (
	// Minimum value for runtime_security_config.activity_dump.max_dump_size
	MinMaxDumSize = 100
)

// Policy represents a policy file in the configuration file
type Policy struct {
	Name  string   `mapstructure:"name"`
	Files []string `mapstructure:"files"`
	Tags  []string `mapstructure:"tags"`
}

// CWSConfig holds the configuration for the runtime security agent
type CWSConfig struct {
	// RuntimeEnabled defines if the runtime security module should be enabled
	RuntimeEnabled bool
	// PoliciesDir defines the folder in which the policy files are located
	PoliciesDir string
	// WatchPoliciesDir activate policy dir inotify
	WatchPoliciesDir bool
	// PolicyMonitorEnabled enable policy monitoring
	PolicyMonitorEnabled bool
	// EventServerBurst defines the maximum burst of events that can be sent over the grpc server
	EventServerBurst int
	// EventServerRate defines the grpc server rate at which events can be sent
	EventServerRate int
	// EventServerRetention defines an event retention period so that some fields can be resolved
	EventServerRetention int
	// FIMEnabled determines whether fim rules will be loaded
	FIMEnabled bool
	// SelfTestEnabled defines if the self tests should be executed at startup or not
	SelfTestEnabled bool
	// SelfTestSendReport defines if a self test event will be emitted
	SelfTestSendReport bool
	// RemoteConfigurationEnabled defines whether to use remote monitoring
	RemoteConfigurationEnabled bool
	// StatsPollingInterval determines how often metrics should be polled
	StatsPollingInterval time.Duration
	// LogPatterns pattern to be used by the logger for trace level
	LogPatterns []string
	// LogTags tags to be used by the logger for trace level
	LogTags []string
	// NetworkEnabled defines if the network probes should be activated
	NetworkEnabled bool
	// HostServiceName string
	HostServiceName string
	// ActivityDumpEnabled defines if the activity dump manager should be enabled
	ActivityDumpEnabled bool
	// ActivityDumpCleanupPeriod defines the period at which the activity dump manager should perform its cleanup
	// operation.
	ActivityDumpCleanupPeriod time.Duration
	// ActivityDumpTagsResolutionPeriod defines the period at which the activity dump manager should try to resolve
	// missing container tags.
	ActivityDumpTagsResolutionPeriod time.Duration
	// ActivityDumpLoadControlPeriod defines the period at which the activity dump manager should trigger the load controller
	ActivityDumpLoadControlPeriod time.Duration
	// ActivityDumpPathMergeEnabled defines if path merge should be enabled
	ActivityDumpPathMergeEnabled bool
	// ActivityDumpTracedCgroupsCount defines the maximum count of cgroups that should be monitored concurrently. Leave this parameter to 0 to prevent the generation
	// of activity dumps based on cgroups.
	ActivityDumpTracedCgroupsCount int
	// ActivityDumpTracedEventTypes defines the list of events that should be captured in an activity dump. Leave this
	// parameter empty to monitor all event types. If not already present, the `exec` event will automatically be added
	// to this list.
	ActivityDumpTracedEventTypes []model.EventType
	// ActivityDumpCgroupDumpTimeout defines the cgroup activity dumps timeout.
	ActivityDumpCgroupDumpTimeout time.Duration
	// ActivityDumpRateLimiter defines the kernel rate of max events per sec for activity dumps.
	ActivityDumpRateLimiter int
	// ActivityDumpCgroupWaitListTimeout defines the time to wait before a cgroup can be dumped again.
	ActivityDumpCgroupWaitListTimeout time.Duration
	// ActivityDumpCgroupDifferentiateArgs defines if system-probe should differentiate process nodes using process
	// arguments for dumps.
	ActivityDumpCgroupDifferentiateArgs bool
	// ActivityDumpLocalStorageDirectory defines the output directory for the activity dumps and graphs. Leave
	// this field empty to prevent writing any output to disk.
	ActivityDumpLocalStorageDirectory string
	// ActivityDumpLocalStorageFormats defines the formats that should be used to persist the activity dumps locally.
	ActivityDumpLocalStorageFormats []StorageFormat
	// ActivityDumpLocalStorageCompression defines if the local storage should compress the persisted data.
	ActivityDumpLocalStorageCompression bool
	// ActivityDumpLocalStorageMaxDumpsCount defines the maximum count of activity dumps that should be kept locally.
	// When the limit is reached, the oldest dumps will be deleted first.
	ActivityDumpLocalStorageMaxDumpsCount int
	// ActivityDumpRemoteStorageFormats defines the formats that should be used to persist the activity dumps remotely.
	ActivityDumpRemoteStorageFormats []StorageFormat
	// ActivityDumpRemoteStorageCompression defines if the remote storage should compress the persisted data.
	ActivityDumpRemoteStorageCompression bool
	// ActivityDumpSyscallMonitorPeriod defines the minimum amount of time to wait between 2 syscalls event for the same
	// process.
	ActivityDumpSyscallMonitorPeriod time.Duration
	// ActivityDumpMaxDumpCountPerWorkload defines the maximum amount of dumps that the agent should send for a workload
	ActivityDumpMaxDumpCountPerWorkload int
	// # Dynamic configuration fields:
	// ActivityDumpMaxDumpSize defines the maximum size of a dump
	ActivityDumpMaxDumpSize func() int
}

type Config struct {
	CWSConfig
}

// IsRuntimeEnabled returns true if any feature is enabled. Has to be applied in config package too
func (c *Config) IsRuntimeEnabled() bool {
	return c.RuntimeEnabled || c.FIMEnabled
}

func setEnv() {
	if coreconfig.IsContainerized() && util.PathExists("/host") {
		if v := os.Getenv("HOST_PROC"); v == "" {
			os.Setenv("HOST_PROC", "/host/proc")
		}
		if v := os.Getenv("HOST_SYS"); v == "" {
			os.Setenv("HOST_SYS", "/host/sys")
		}
	}
}

// NewConfig returns a new Config object
func NewConfig() (*Config, error) {
	c := &Config{
		CWSConfig{
			RuntimeEnabled: coreconfig.SystemProbe.GetBool("runtime_security_config.enabled"),
			FIMEnabled:     coreconfig.SystemProbe.GetBool("runtime_security_config.fim_enabled"),
			NetworkEnabled: coreconfig.SystemProbe.GetBool("runtime_security_config.network.enabled"),

			SelfTestEnabled:            coreconfig.SystemProbe.GetBool("runtime_security_config.self_test.enabled"),
			SelfTestSendReport:         coreconfig.SystemProbe.GetBool("runtime_security_config.self_test.send_report"),
			RemoteConfigurationEnabled: coreconfig.SystemProbe.GetBool("runtime_security_config.remote_configuration.enabled"),

			StatsPollingInterval: time.Duration(coreconfig.SystemProbe.GetInt("runtime_security_config.events_stats.polling_interval")) * time.Second,

			EventServerBurst:     coreconfig.SystemProbe.GetInt("runtime_security_config.event_server.burst"),
			EventServerRate:      coreconfig.SystemProbe.GetInt("runtime_security_config.event_server.rate"),
			EventServerRetention: coreconfig.SystemProbe.GetInt("runtime_security_config.event_server.retention"),

			// policy & ruleset
			PoliciesDir:          coreconfig.SystemProbe.GetString("runtime_security_config.policies.dir"),
			WatchPoliciesDir:     coreconfig.SystemProbe.GetBool("runtime_security_config.policies.watch_dir"),
			PolicyMonitorEnabled: coreconfig.SystemProbe.GetBool("runtime_security_config.policies.monitor.enabled"),

			// activity dump
			ActivityDumpEnabled:                   coreconfig.SystemProbe.GetBool("runtime_security_config.activity_dump.enabled"),
			ActivityDumpCleanupPeriod:             time.Duration(coreconfig.SystemProbe.GetInt("runtime_security_config.activity_dump.cleanup_period")) * time.Second,
			ActivityDumpTagsResolutionPeriod:      time.Duration(coreconfig.SystemProbe.GetInt("runtime_security_config.activity_dump.tags_resolution_period")) * time.Second,
			ActivityDumpLoadControlPeriod:         time.Duration(coreconfig.SystemProbe.GetInt("runtime_security_config.activity_dump.load_controller_period")) * time.Minute,
			ActivityDumpPathMergeEnabled:          coreconfig.SystemProbe.GetBool("runtime_security_config.activity_dump.path_merge.enabled"),
			ActivityDumpTracedCgroupsCount:        coreconfig.SystemProbe.GetInt("runtime_security_config.activity_dump.traced_cgroups_count"),
			ActivityDumpTracedEventTypes:          model.ParseEventTypeStringSlice(coreconfig.SystemProbe.GetStringSlice("runtime_security_config.activity_dump.traced_event_types")),
			ActivityDumpCgroupDumpTimeout:         time.Duration(coreconfig.SystemProbe.GetInt("runtime_security_config.activity_dump.cgroup_dump_timeout")) * time.Minute,
			ActivityDumpRateLimiter:               coreconfig.SystemProbe.GetInt("runtime_security_config.activity_dump.rate_limiter"),
			ActivityDumpCgroupWaitListTimeout:     time.Duration(coreconfig.SystemProbe.GetInt("runtime_security_config.activity_dump.cgroup_wait_list_timeout")) * time.Minute,
			ActivityDumpCgroupDifferentiateArgs:   coreconfig.SystemProbe.GetBool("runtime_security_config.activity_dump.cgroup_differentiate_args"),
			ActivityDumpLocalStorageDirectory:     coreconfig.SystemProbe.GetString("runtime_security_config.activity_dump.local_storage.output_directory"),
			ActivityDumpLocalStorageMaxDumpsCount: coreconfig.SystemProbe.GetInt("runtime_security_config.activity_dump.local_storage.max_dumps_count"),
			ActivityDumpLocalStorageCompression:   coreconfig.SystemProbe.GetBool("runtime_security_config.activity_dump.local_storage.compression"),
			ActivityDumpRemoteStorageCompression:  coreconfig.SystemProbe.GetBool("runtime_security_config.activity_dump.remote_storage.compression"),
			ActivityDumpSyscallMonitorPeriod:      time.Duration(coreconfig.SystemProbe.GetInt("runtime_security_config.activity_dump.syscall_monitor.period")) * time.Second,
			ActivityDumpMaxDumpCountPerWorkload:   coreconfig.SystemProbe.GetInt("runtime_security_config.activity_dump.max_dump_count_per_workload"),
			// activity dump dynamic fields
			ActivityDumpMaxDumpSize: func() int {
				mds := coreconfig.SystemProbe.GetInt("runtime_security_config.activity_dump.max_dump_size")
				if mds < MinMaxDumSize {
					mds = MinMaxDumSize
				}
				return mds * (1 << 10)
			},

			LogPatterns: coreconfig.SystemProbe.GetStringSlice("runtime_security_config.log_patterns"),
			LogTags:     coreconfig.SystemProbe.GetStringSlice("runtime_security_config.log_tags"),
		},
	}

	if err := c.sanitize(); err != nil {
		return nil, fmt.Errorf("invalid CWS configuration: %w", err)
	}

	setEnv()
	return c, nil
}

// disable all the runtime features
func (c *Config) disableRuntime() {
	c.ActivityDumpEnabled = false
}

// sanitize ensures that the configuration is properly setup
func (c *Config) sanitize() error {
	// the following config params
	if !c.IsRuntimeEnabled() {
		c.disableRuntime()
		return nil
	}

	// if runtime is enabled then we force fim
	if c.RuntimeEnabled {
		c.FIMEnabled = true
	}

	serviceName := utils.GetTagValue("service", coreconfig.GetGlobalConfiguredTags(true))
	if len(serviceName) > 0 {
		c.HostServiceName = fmt.Sprintf("service:%s", serviceName)
	}

	return c.sanitizeRuntimeSecurityConfigActivityDump()
}

// sanitizeNetworkConfiguration ensures that runtime_security_config.activity_dump is properly configured
func (c *Config) sanitizeRuntimeSecurityConfigActivityDump() error {
	var execFound bool
	for _, evtType := range c.ActivityDumpTracedEventTypes {
		if evtType == model.ExecEventType {
			execFound = true
			break
		}
	}
	if !execFound {
		c.ActivityDumpTracedEventTypes = append(c.ActivityDumpTracedEventTypes, model.ExecEventType)
	}

	if formats := coreconfig.SystemProbe.GetStringSlice("runtime_security_config.activity_dump.local_storage.formats"); len(formats) > 0 {
		var err error
		c.ActivityDumpLocalStorageFormats, err = ParseStorageFormats(formats)
		if err != nil {
			return fmt.Errorf("invalid value for runtime_security_config.activity_dump.local_storage.formats: %w", err)
		}
	}
	if formats := coreconfig.SystemProbe.GetStringSlice("runtime_security_config.activity_dump.remote_storage.formats"); len(formats) > 0 {
		var err error
		c.ActivityDumpRemoteStorageFormats, err = ParseStorageFormats(formats)
		if err != nil {
			return fmt.Errorf("invalid value for runtime_security_config.activity_dump.remote_storage.formats: %w", err)
		}
	}

	if c.ActivityDumpTracedCgroupsCount > model.MaxTracedCgroupsCount {
		c.ActivityDumpTracedCgroupsCount = model.MaxTracedCgroupsCount
	}
	return nil
}

// ActivityDumpRemoteStorageEndpoints returns the list of activity dump remote storage endpoints parsed from the agent config
func ActivityDumpRemoteStorageEndpoints(endpointPrefix string, intakeTrackType logsconfig.IntakeTrackType, intakeProtocol logsconfig.IntakeProtocol, intakeOrigin logsconfig.IntakeOrigin) (*logsconfig.Endpoints, error) {
	logsConfig := logsconfig.NewLogsConfigKeys("runtime_security_config.activity_dump.remote_storage.endpoints.", coreconfig.Datadog)
	endpoints, err := logsconfig.BuildHTTPEndpointsWithConfig(logsConfig, endpointPrefix, intakeTrackType, intakeProtocol, intakeOrigin)
	if err != nil {
		endpoints, err = logsconfig.BuildHTTPEndpoints(intakeTrackType, intakeProtocol, intakeOrigin)
		if err == nil {
			httpConnectivity := logshttp.CheckConnectivity(endpoints.Main)
			endpoints, err = logsconfig.BuildEndpoints(httpConnectivity, intakeTrackType, intakeProtocol, intakeOrigin)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("invalid endpoints: %w", err)
	}

	for _, status := range endpoints.GetStatus() {
		seclog.Infof("activity dump remote storage endpoint: %v\n", status)
	}
	return endpoints, nil
}
