//
// Copyright (C) 2025 TrakRF
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"
)

func TestComputeNetSz(t *testing.T) {
	tests := []struct {
		subnetSz int
		expected uint32
	}{
		{32, 1},
		{31, 1},
		{24, 254},
		{16, 65534},
		{8, 16777214},
	}

	for _, test := range tests {
		result := computeNetSz(test.subnetSz)
		if result != test.expected {
			t.Errorf("computeNetSz(%d) = %d, want %d", test.subnetSz, result, test.expected)
		}
	}
}

func TestLoadConfig(t *testing.T) {
	config := loadConfig()

	if len(config.Subnets) == 0 {
		t.Error("Expected at least one subnet in default config")
	}

	if config.HTTPPort == "" {
		t.Error("Expected HTTP port to be set")
	}

	if config.ScanPort == "" {
		t.Error("Expected scan port to be set")
	}
}
