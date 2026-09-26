package finops

import (
	"math"
	"testing"

	"github.com/ghostroute/ghostroute/pkg/model"
)

func TestCalculateWaste(t *testing.T) {
	tests := []struct {
		name         string
		finding      model.Finding
		resource     model.Resource
		wantMonthly  float64
		wantAnnual   float64
	}{
		{
			name: "AWS EIP unattached",
			finding: model.Finding{
				Category:     model.CategoryZombie,
				ResourceType: "aws_eip",
			},
			resource:    model.Resource{},
			wantMonthly: 3.65,
			wantAnnual:  43.80,
		},
		{
			name: "AWS EBS gp3 100GB",
			finding: model.Finding{
				Category:     model.CategoryZombie,
				ResourceType: "aws_ebs_volume",
			},
			resource: model.Resource{
				Attributes: map[string]interface{}{
					"size": 100,
					"type": "gp3",
				},
			},
			wantMonthly: 8.00,
			wantAnnual:  96.00,
		},
		{
			name: "AWS EBS gp2 50GB",
			finding: model.Finding{
				Category:     model.CategoryZombie,
				ResourceType: "aws_ebs_volume",
			},
			resource: model.Resource{
				Attributes: map[string]interface{}{
					"size": 50,
					"type": "gp2",
				},
			},
			wantMonthly: 5.00,
			wantAnnual:  60.00,
		},
		{
			name: "AWS ALB Orphaned",
			finding: model.Finding{
				Category:     model.CategoryZombie,
				ResourceType: "aws_lb",
			},
			resource:    model.Resource{},
			wantMonthly: 16.43,
			wantAnnual:  197.16,
		},
		{
			name: "AWS NAT Gateway Orphaned",
			finding: model.Finding{
				Category:     model.CategoryZombie,
				ResourceType: "aws_nat_gateway",
			},
			resource:    model.Resource{},
			wantMonthly: 32.85,
			wantAnnual:  394.20,
		},
		{
			name: "GCP Static IP",
			finding: model.Finding{
				Category:     model.CategoryZombie,
				ResourceType: "google_compute_address",
			},
			resource:    model.Resource{},
			wantMonthly: 7.30,
			wantAnnual:  87.60,
		},
		{
			name: "GCP SSD Disk 100GB",
			finding: model.Finding{
				Category:     model.CategoryZombie,
				ResourceType: "google_compute_disk",
			},
			resource: model.Resource{
				Attributes: map[string]interface{}{
					"size": 100,
					"type": "pd-ssd",
				},
			},
			wantMonthly: 17.00,
			wantAnnual:  204.00,
		},
		{
			name: "Dangling DNS (Zero Waste, Security Risk)",
			finding: model.Finding{
				Category:     model.CategoryDanglingDNS,
				ResourceType: "aws_route53_record",
			},
			resource:    model.Resource{},
			wantMonthly: 0.0,
			wantAnnual:  0.0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, a := CalculateWaste(&tc.finding, &tc.resource)
			if math.Abs(m-tc.wantMonthly) > 0.001 {
				t.Errorf("Monthly waste = %f, want %f", m, tc.wantMonthly)
			}
			if math.Abs(a-tc.wantAnnual) > 0.001 {
				t.Errorf("Annual waste = %f, want %f", a, tc.wantAnnual)
			}
		})
	}
}

func TestGetCatalogEntries(t *testing.T) {
	entries := GetCatalogEntries()
	if len(entries) < 8 {
		t.Errorf("Expected at least 8 catalog entries, got %d", len(entries))
	}
	for _, entry := range entries {
		if entry.CloudProvider == "" || entry.ResourceType == "" || entry.MonthlyRateUSD <= 0 {
			t.Errorf("Invalid catalog entry: %+v", entry)
		}
	}
}
