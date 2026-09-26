package finops

import (
	"strings"

	"github.com/ghostroute/ghostroute/pkg/model"
)

// HoursPerMonth represents standard FinOps cloud billing calculation constant (365 days / 12 months * 24 hours).
const HoursPerMonth = 730.0

// CatalogEntry represents a reference pricing benchmark for unattached assets.
type CatalogEntry struct {
	CloudProvider string  `json:"cloud_provider"`
	ResourceType  string  `json:"resource_type"`
	Description   string  `json:"description"`
	HourlyRateUSD float64 `json:"hourly_rate_usd"`
	MonthlyRateUSD float64 `json:"monthly_rate_usd"`
	Unit          string  `json:"unit"`
}

// GetCatalogEntries returns the complete static pricing matrix for unattached cloud resources.
func GetCatalogEntries() []CatalogEntry {
	return []CatalogEntry{
		// AWS
		{
			CloudProvider: "AWS",
			ResourceType:  "aws_eip",
			Description:   "Unattached / Idle Public IPv4 Address",
			HourlyRateUSD: 0.005,
			MonthlyRateUSD: 3.65,
			Unit:          "per IP/month",
		},
		{
			CloudProvider: "AWS",
			ResourceType:  "aws_ebs_volume (gp3)",
			Description:   "Detached General Purpose SSD Volume (gp3)",
			HourlyRateUSD: 0.00011,
			MonthlyRateUSD: 0.08,
			Unit:          "per GB/month",
		},
		{
			CloudProvider: "AWS",
			ResourceType:  "aws_ebs_volume (gp2)",
			Description:   "Detached General Purpose SSD Volume (gp2)",
			HourlyRateUSD: 0.000137,
			MonthlyRateUSD: 0.10,
			Unit:          "per GB/month",
		},
		{
			CloudProvider: "AWS",
			ResourceType:  "aws_ebs_volume (io2)",
			Description:   "Detached Provisioned IOPS SSD Volume (io2)",
			HourlyRateUSD: 0.000171,
			MonthlyRateUSD: 0.125,
			Unit:          "per GB/month",
		},
		{
			CloudProvider: "AWS",
			ResourceType:  "aws_lb / aws_alb",
			Description:   "Orphaned Application / Network Load Balancer (Base Fee)",
			HourlyRateUSD: 0.0225,
			MonthlyRateUSD: 16.43,
			Unit:          "per LB/month",
		},
		{
			CloudProvider: "AWS",
			ResourceType:  "aws_nat_gateway",
			Description:   "Unrouted / Idle VPC NAT Gateway (Base Fee)",
			HourlyRateUSD: 0.045,
			MonthlyRateUSD: 32.85,
			Unit:          "per Gateway/month",
		},
		// GCP
		{
			CloudProvider: "GCP",
			ResourceType:  "google_compute_address",
			Description:   "Unused Static External IP Address",
			HourlyRateUSD: 0.010,
			MonthlyRateUSD: 7.30,
			Unit:          "per IP/month",
		},
		{
			CloudProvider: "GCP",
			ResourceType:  "google_compute_disk (standard)",
			Description:   "Detached Standard Persistent Disk",
			HourlyRateUSD: 0.000055,
			MonthlyRateUSD: 0.040,
			Unit:          "per GB/month",
		},
		{
			CloudProvider: "GCP",
			ResourceType:  "google_compute_disk (ssd)",
			Description:   "Detached SSD Persistent Disk",
			HourlyRateUSD: 0.000233,
			MonthlyRateUSD: 0.170,
			Unit:          "per GB/month",
		},
		// Azure
		{
			CloudProvider: "Azure",
			ResourceType:  "azurerm_public_ip",
			Description:   "Unassociated Static/Dynamic Public IP",
			HourlyRateUSD: 0.005,
			MonthlyRateUSD: 3.65,
			Unit:          "per IP/month",
		},
		{
			CloudProvider: "Azure",
			ResourceType:  "azurerm_managed_disk",
			Description:   "Detached Premium/Standard Managed Disk",
			HourlyRateUSD: 0.000103,
			MonthlyRateUSD: 0.075,
			Unit:          "per GB/month",
		},
	}
}

// CalculateWaste calculates the estimated monthly and annual financial loss for a zombie resource.
func CalculateWaste(f *model.Finding, res *model.Resource) (float64, float64) {
	if f.Category != model.CategoryZombie {
		return 0.0, 0.0
	}

	var monthly float64

	switch f.ResourceType {
	// AWS Elastic IP: $0.005/hr * 730 = $3.65/mo
	case "aws_eip":
		monthly = 3.65

	// AWS EBS Volume: sizeGB * ratePerGB
	case "aws_ebs_volume":
		sizeGB := float64(res.GetIntAttr("size"))
		if sizeGB <= 0 {
			sizeGB = 50.0
		}
		volType := strings.ToLower(res.GetStringAttr("type"))
		ratePerGB := 0.08 // default gp3
		switch volType {
		case "gp2":
			ratePerGB = 0.10
		case "gp3":
			ratePerGB = 0.08
		case "io1", "io2":
			ratePerGB = 0.125
		case "st1":
			ratePerGB = 0.045
		case "sc1":
			ratePerGB = 0.015
		}
		monthly = sizeGB * ratePerGB

	// AWS ALB / NLB: $0.0225/hr * 730 = $16.425 (~$16.43)
	case "aws_lb", "aws_alb":
		monthly = 16.43

	// AWS NAT Gateway: $0.045/hr * 730 = $32.85
	case "aws_nat_gateway":
		monthly = 32.85

	// GCP Static External IP: $0.010/hr * 730 = $7.30
	case "google_compute_address":
		monthly = 7.30

	// GCP Persistent Disk: sizeGB * rate
	case "google_compute_disk":
		sizeGB := float64(res.GetIntAttr("size"))
		if sizeGB <= 0 {
			sizeGB = 50.0
		}
		diskType := strings.ToLower(res.GetStringAttr("type"))
		ratePerGB := 0.040
		if strings.Contains(diskType, "ssd") {
			ratePerGB = 0.170
		} else if strings.Contains(diskType, "balanced") {
			ratePerGB = 0.100
		}
		monthly = sizeGB * ratePerGB

	// Azure Public IP: $3.65/mo
	case "azurerm_public_ip":
		monthly = 3.65

	// Azure Managed Disk: sizeGB * rate
	case "azurerm_managed_disk":
		sizeGB := float64(res.GetIntAttr("disk_size_gb"))
		if sizeGB <= 0 {
			sizeGB = 32.0
		}
		monthly = sizeGB * 0.075

	default:
		monthly = 0.0
	}

	annual := monthly * 12.0
	return monthly, annual
}
