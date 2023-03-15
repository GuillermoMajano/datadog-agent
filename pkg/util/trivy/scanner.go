// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build trivy
// +build trivy

package trivy

import (
	"context"
	"errors"
	"time"

	"github.com/containerd/containerd"

	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/sbom"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/datadog-agent/pkg/workloadmeta"
)

// scan buffer needs to be very large as we cannot block containerd collector
const (
	imagesToScanBufferSize = 5000
)

var _scanner *trivyScanner

type scanRequest struct {
	timeout   time.Duration
	interval  time.Duration
	onSuccess sbom.ScanSuccessCallback
	onError   sbom.ScanErrorCallback
}

func (r scanRequest) triggerCallbacks(report sbom.Report, createdAt time.Time, generationDuration time.Duration, err error) {
	if err != nil {
		if r.onError != nil {
			r.onError(err)
		}
	} else {
		if r.onSuccess != nil {
			r.onSuccess(report, createdAt, generationDuration)
		}
	}
}

func (r scanRequest) waitInterval(ctx context.Context) {
	t := time.NewTimer(r.interval)
	select {
	case <-ctx.Done():
	case <-t.C:
	}
	t.Stop()

}

func (r scanRequest) withContext(parent context.Context) (scanContext context.Context, cancel context.CancelFunc) {
	if r.timeout != 0 {
		scanContext, cancel = context.WithTimeout(parent, r.timeout)
	} else {
		scanContext, cancel = context.WithCancel(parent)
	}
	return
}

type imageScanRequest struct {
	scanRequest
	imageMeta      *workloadmeta.ContainerImageMetadata
	img            containerd.Image
	fromFilesystem bool
}

type fsScanRequest struct {
	scanRequest
	path string
}

type trivyScanner struct {
	collector         sbom.Collector
	imagesToScan      chan imageScanRequest
	filesystemsToScan chan fsScanRequest
}

func (s *trivyScanner) scanContainerdImage(imageMeta *workloadmeta.ContainerImageMetadata, image containerd.Image, fromFilesystem bool, onSuccess sbom.ScanSuccessCallback, onError func(err error), timeout, interval time.Duration) error {
	select {
	case s.imagesToScan <- imageScanRequest{
		scanRequest: scanRequest{
			timeout:   timeout,
			interval:  interval,
			onSuccess: onSuccess,
			onError:   onError,
		},
		imageMeta:      imageMeta,
		img:            image,
		fromFilesystem: fromFilesystem,
	}:
		return nil
	default:
		return errors.New("container image queue is full")
	}
}

func (s *trivyScanner) ScanContainerdImage(imageMeta *workloadmeta.ContainerImageMetadata, image containerd.Image, onSuccess sbom.ScanSuccessCallback, onError sbom.ScanErrorCallback, timeout, interval time.Duration) error {
	return s.scanContainerdImage(imageMeta, image, false, onSuccess, onError, timeout, interval)
}

func (s *trivyScanner) ScanContainerdImageFromFilesystem(imageMeta *workloadmeta.ContainerImageMetadata, image containerd.Image, onSuccess sbom.ScanSuccessCallback, onError sbom.ScanErrorCallback, timeout, interval time.Duration) error {
	return s.scanContainerdImage(imageMeta, image, true, onSuccess, onError, timeout, interval)
}

func (s *trivyScanner) ScanFilesystem(path string, onSuccess sbom.ScanSuccessCallback, onError sbom.ScanErrorCallback, timeout, interval time.Duration) error {
	select {
	case s.filesystemsToScan <- fsScanRequest{
		scanRequest: scanRequest{
			onSuccess: onSuccess,
			onError:   onError,
			timeout:   timeout,
			interval:  interval,
		},
	}:
		return nil
	default:
		return errors.New("host fs queue is full")
	}
}

func (s *trivyScanner) Start(ctx context.Context) {
	go func() {
		defer func() {
			err := s.collector.Close()
			if err != nil {
				log.Warnf("Unable to close trivy client: %v", err)
			}
		}()

		for {
			select {
			// We don't want to keep scanning if image channel is not empty but context is expired
			case <-ctx.Done():
				return

			case request, ok := <-s.imagesToScan:
				// Channel has been closed we should exit
				if !ok {
					return
				}

				scanContext, cancel := request.withContext(ctx)
				createdAt := time.Now()

				var report sbom.Report
				var err error
				if request.fromFilesystem {
					report, err = s.collector.ScanContainerdImage(scanContext, request.imageMeta, request.img)
				} else {
					report, err = s.collector.ScanContainerdImageFromFilesystem(scanContext, request.imageMeta, request.img)
				}

				generationDuration := time.Since(createdAt)

				cancel()
				request.triggerCallbacks(report, createdAt, generationDuration, err)
				request.waitInterval(ctx)

			case request, ok := <-s.filesystemsToScan:
				// Channel has been closed we should exit
				if !ok {
					return
				}

				scanContext, cancel := request.withContext(ctx)
				createdAt := time.Now()

				bom, err := s.collector.ScanFilesystem(scanContext, request.path)

				generationDuration := time.Since(createdAt)

				cancel()
				request.triggerCallbacks(bom, createdAt, generationDuration, err)
				request.waitInterval(ctx)
			}
		}
	}()
}

// GetScanner returns the active trivy scanner or creates it if is doesn't exist yet
func GetScanner(cfg config.Config) (*trivyScanner, error) {
	if _scanner == nil {
		collector, err := NewCollector(DefaultCollectorConfig(nil, ""))
		if err != nil {
			return nil, err
		}

		_scanner = &trivyScanner{
			imagesToScan:      make(chan imageScanRequest, imagesToScanBufferSize),
			filesystemsToScan: make(chan fsScanRequest),
			collector:         collector,
		}
		_scanner.Start(context.Background())
	}
	return _scanner, nil
}
