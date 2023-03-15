// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build containerd && trivy
// +build containerd,trivy

package containerd

import (
	"context"
	"fmt"
	"time"

	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/sbom"
	cutil "github.com/DataDog/datadog-agent/pkg/util/containerd"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/datadog-agent/pkg/util/trivy"
	"github.com/DataDog/datadog-agent/pkg/workloadmeta"
	"github.com/DataDog/datadog-agent/pkg/workloadmeta/telemetry"
)

func sbomCollectionIsEnabled() bool {
	return imageMetadataCollectionIsEnabled() && config.Datadog.GetBool("container_image_collection.sbom.enabled")
}

func (c *collector) startSBOMCollection(ctx context.Context) error {
	if !sbomCollectionIsEnabled() {
		return nil
	}

	var err error
	enabledAnalyzers := config.Datadog.GetStringSlice("container_image_collection.sbom.analyzers")
	trivyConfiguration := trivy.DefaultCollectorConfig(enabledAnalyzers, config.Datadog.GetString("container_image_collection.sbom.cache_directory"))
	trivyConfiguration.ClearCacheOnClose = config.Datadog.GetBool("container_image_collection.sbom.clear_cache_on_exit")
	trivyConfiguration.ContainerdAccessor = func() (cutil.ContainerdItf, error) {
		return c.containerdClient, nil
	}

	c.trivyClient, err = trivy.NewCollector(trivyConfiguration)
	if err != nil {
		return fmt.Errorf("error initializing trivy client: %w", err)
	}

	imgEventsCh := c.store.Subscribe(
		"SBOM collector",
		workloadmeta.NormalPriority,
		workloadmeta.NewFilter(
			[]workloadmeta.Kind{workloadmeta.KindContainerImageMetadata},
			workloadmeta.SourceAll,
			workloadmeta.EventTypeSet,
		),
	)

	go func() {
		defer func() {
			err := c.trivyClient.Close()
			if err != nil {
				log.Warnf("Unable to close trivy client: %v", err)
			}
		}()

		for {
			select {
			// We don't want to keep scanning if image channel is not empty but context is expired
			case <-ctx.Done():
				return

			case eventBundle := <-imgEventsCh:
				close(eventBundle.Ch)

				for _, event := range eventBundle.Events {
					image := event.Entity.(*workloadmeta.ContainerImageMetadata)

					if image.SBOM != nil {
						// BOM already stored. Can happen when the same image ID
						// is referenced with different names.
						log.Debugf("Image: %s/%s (id %s) SBOM already available", image.Namespace, image.Name, image.ID)
						continue
					}

					scanContext, cancel := context.WithTimeout(ctx, scanningTimeout())
					if err := c.extractBOMWithTrivy(scanContext, image); err != nil {
						log.Warnf("Error extracting SBOM for image: namespace=%s name=%s, err: %s", image.Namespace, image.Name, err)
					}

					cancel()
					time.Sleep(timeBetweenScans())
				}
			}
		}
	}()

	return nil
}

func (c *collector) extractBOMWithTrivy(ctx context.Context, storedImage *workloadmeta.ContainerImageMetadata) error {
	containerdImage, err := c.containerdClient.Image(storedImage.Namespace, storedImage.Name)
	if err != nil {
		return err
	}

	scanFunc := c.trivyScanner.ScanContainerdImage
	if config.Datadog.GetBool("container_image_collection.sbom.use_mount") {
		scanFunc = c.trivyScanner.ScanContainerdImageFromFilesystem
	}

	return scanFunc(storedImage, containerdImage, func(report sbom.Report, at time.Time, duration time.Duration) {
		telemetry.SBOMGenerationDuration.Observe(duration.Seconds())

		bom, err := report.ToCycloneDX()
		if err != nil {
			log.Errorf("Failed to extract SBOM from report")
			return
		}

		sbom := workloadmeta.SBOM{
			CycloneDXBOM:       bom,
			GenerationTime:     at,
			GenerationDuration: duration,
		}

		// Updating workloadmeta entities directly is not thread-safe, that's why we
		// generate an update event here instead.
		if err := c.handleImageCreateOrUpdate(ctx, storedImage.Namespace, storedImage.Name, &sbom); err != nil {
			log.Warnf("Error extracting SBOM for image: namespace=%s name=%s, err: %s", storedImage.Namespace, storedImage.Name, err)
		}
	}, func(err error) {
		log.Error(err)
	}, scanningTimeout(), timeBetweenScans())
}

func scanningTimeout() time.Duration {
	return time.Duration(config.Datadog.GetInt("container_image_collection.sbom.scan_timeout")) * time.Second
}

func timeBetweenScans() time.Duration {
	return time.Duration(config.Datadog.GetInt("container_image_collection.sbom.scan_interval")) * time.Second
}
