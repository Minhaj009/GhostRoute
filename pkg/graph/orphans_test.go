package graph

import (
	"testing"

	"github.com/ghostroute/ghostroute/pkg/model"
)

func TestDetectOrphansAWS(t *testing.T) {
	resources := []*model.Resource{
		// 1. Unattached EIP (zombie)
		{
			Address: "aws_eip.idle_eip",
			Type:    "aws_eip",
			Name:    "idle_eip",
			Attributes: map[string]interface{}{
				"id":                "eipalloc-1111",
				"public_ip":         "52.1.2.3",
				"instance":          "",
				"network_interface": "",
			},
		},
		// 2. Attached EIP (healthy)
		{
			Address: "aws_eip.attached_eip",
			Type:    "aws_eip",
			Name:    "attached_eip",
			Attributes: map[string]interface{}{
				"id":        "eipalloc-2222",
				"public_ip": "52.1.2.4",
				"instance":  "i-active01",
			},
		},
		// 3. Detached EBS volume (zombie)
		{
			Address: "aws_ebs_volume.detached_vol",
			Type:    "aws_ebs_volume",
			Name:    "detached_vol",
			Attributes: map[string]interface{}{
				"id":   "vol-9999",
				"size": 100,
				"type": "gp3",
			},
		},
		// 4. Orphaned ALB (no listeners, zombie)
		{
			Address: "aws_lb.lonely_alb",
			Type:    "aws_lb",
			Name:    "lonely_alb",
			Attributes: map[string]interface{}{
				"arn":  "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/lonely-alb/123",
				"name": "lonely-alb",
			},
		},
		// 5. Unrouted NAT Gateway (zombie)
		{
			Address: "aws_nat_gateway.idle_nat",
			Type:    "aws_nat_gateway",
			Name:    "idle_nat",
			Attributes: map[string]interface{}{
				"id": "nat-0123456789",
			},
		},
	}

	dag := BuildDAG(resources)
	detector := NewOrphanDetector(dag)
	findings := detector.DetectOrphans()

	// We expect 4 findings: idle_eip, detached_vol, lonely_alb, idle_nat
	if len(findings) != 4 {
		t.Fatalf("Expected 4 orphan findings, got %d", len(findings))
	}

	foundMap := make(map[string]bool)
	for _, f := range findings {
		foundMap[f.ResourceAddress] = true
	}

	expected := []string{
		"aws_eip.idle_eip",
		"aws_ebs_volume.detached_vol",
		"aws_lb.lonely_alb",
		"aws_nat_gateway.idle_nat",
	}

	for _, exp := range expected {
		if !foundMap[exp] {
			t.Errorf("Expected finding for %s, but was not detected", exp)
		}
	}

	// Attached EIP must not be flagged
	if foundMap["aws_eip.attached_eip"] {
		t.Errorf("Attached EIP aws_eip.attached_eip was erroneously flagged as an orphan")
	}
}

func TestDetectOrphansMultiCloud(t *testing.T) {
	resources := []*model.Resource{
		// GCP Unused IP
		{
			Address: "google_compute_address.unused_ip",
			Type:    "google_compute_address",
			Name:    "unused_ip",
			Attributes: map[string]interface{}{
				"address": "34.100.1.2",
			},
		},
		// GCP Detached Disk
		{
			Address: "google_compute_disk.detached_disk",
			Type:    "google_compute_disk",
			Name:    "detached_disk",
			Attributes: map[string]interface{}{
				"size": 200,
			},
		},
		// Azure Unattached Public IP
		{
			Address: "azurerm_public_ip.idle_pip",
			Type:    "azurerm_public_ip",
			Name:    "idle_pip",
			Attributes: map[string]interface{}{
				"ip_address": "20.50.1.2",
			},
		},
		// Azure Detached Managed Disk
		{
			Address: "azurerm_managed_disk.detached_md",
			Type:    "azurerm_managed_disk",
			Name:    "detached_md",
			Attributes: map[string]interface{}{
				"disk_size_gb": 64,
			},
		},
	}

	dag := BuildDAG(resources)
	detector := NewOrphanDetector(dag)
	findings := detector.DetectOrphans()

	if len(findings) != 4 {
		t.Fatalf("Expected 4 multi-cloud orphan findings, got %d", len(findings))
	}
}
