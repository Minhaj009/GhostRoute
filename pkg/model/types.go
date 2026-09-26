package model

import (
	"fmt"
	"time"
)

// Severity represents the criticality level of an identified finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// FindingCategory distinguishes FinOps zombies from dangling DNS takeovers.
type FindingCategory string

const (
	CategoryZombie      FindingCategory = "ZOMBIE_RESOURCE"
	CategoryDanglingDNS FindingCategory = "DANGLING_DNS"
)

// Resource represents a cloud resource parsed from Terraform/OpenTofu state or HCL.
type Resource struct {
	Address      string                 `json:"address"`
	Type         string                 `json:"type"`
	Name         string                 `json:"name"`
	Provider     string                 `json:"provider"`
	Mode         string                 `json:"mode"`
	Attributes   map[string]interface{} `json:"attributes"`
	Dependencies []string               `json:"dependencies"`
}

// GetStringAttr safely retrieves a string attribute from resource attributes map.
func (r *Resource) GetStringAttr(key string) string {
	if r.Attributes == nil {
		return ""
	}
	val, ok := r.Attributes[key]
	if !ok || val == nil {
		return ""
	}
	str, ok := val.(string)
	if !ok {
		return fmt.Sprintf("%v", val)
	}
	return str
}

// GetIntAttr safely retrieves an int/float attribute from resource attributes map.
func (r *Resource) GetIntAttr(key string) int {
	if r.Attributes == nil {
		return 0
	}
	val, ok := r.Attributes[key]
	if !ok || val == nil {
		return 0
	}
	switch v := val.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	default:
		return 0
	}
}

// GetSliceAttr safely retrieves a slice of strings or interface items.
func (r *Resource) GetSliceAttr(key string) []string {
	if r.Attributes == nil {
		return nil
	}
	val, ok := r.Attributes[key]
	if !ok || val == nil {
		return nil
	}
	switch v := val.(type) {
	case []string:
		return v
	case []interface{}:
		res := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				res = append(res, s)
			} else {
				res = append(res, fmt.Sprintf("%v", item))
			}
		}
		return res
	default:
		return nil
	}
}

// Finding represents a single security vulnerability or zombie FinOps asset.
type Finding struct {
	ID                 string          `json:"id"`
	RuleID             string          `json:"rule_id"`
	Title              string          `json:"title"`
	Category           FindingCategory `json:"category"`
	Severity           Severity        `json:"severity"`
	ResourceAddress    string          `json:"resource_address"`
	ResourceType       string          `json:"resource_type"`
	CloudProvider      string          `json:"cloud_provider"`
	Description        string          `json:"description"`
	Impact             string          `json:"impact"`
	MonthlyWasteUSD    float64         `json:"monthly_waste_usd"`
	AnnualWasteUSD     float64         `json:"annual_waste_usd"`
	RemediationCommand string          `json:"remediation_command"`
	RemediationHCL     string          `json:"remediation_hcl"`

	// DNS specific attributes
	DNSDomain        string `json:"dns_domain,omitempty"`
	DNSTarget        string `json:"dns_target,omitempty"`
	TakeoverProvider string `json:"takeover_provider,omitempty"`
}

// ScanResult aggregates all findings and cost analytics from an offline scan.
type ScanResult struct {
	ScanTarget          string             `json:"scan_target"`
	Timestamp           time.Time          `json:"timestamp"`
	Duration            time.Duration      `json:"duration"`
	TotalResources      int                `json:"total_resources"`
	TotalZombies        int                `json:"total_zombies"`
	TotalDanglingDNS    int                `json:"total_dangling_dns"`
	TotalMonthlyWasteUSD float64           `json:"total_monthly_waste_usd"`
	TotalAnnualWasteUSD  float64           `json:"total_annual_waste_usd"`
	Findings            []Finding          `json:"findings"`
	CostByProvider      map[string]float64 `json:"cost_by_provider"`
	SeverityCounts      map[Severity]int   `json:"severity_counts"`
}

// NewScanResult creates an initialized ScanResult.
func NewScanResult(target string) *ScanResult {
	return &ScanResult{
		ScanTarget:     target,
		Timestamp:      time.Now(),
		Findings:       make([]Finding, 0),
		CostByProvider: make(map[string]float64),
		SeverityCounts: map[Severity]int{
			SeverityCritical: 0,
			SeverityHigh:     0,
			SeverityMedium:   0,
			SeverityLow:      0,
			SeverityInfo:     0,
		},
	}
}

// AddFinding adds a finding and recalculates summary statistics.
func (sr *ScanResult) AddFinding(f Finding) {
	sr.Findings = append(sr.Findings, f)
	if f.Category == CategoryZombie {
		sr.TotalZombies++
	} else if f.Category == CategoryDanglingDNS {
		sr.TotalDanglingDNS++
	}

	sr.TotalMonthlyWasteUSD += f.MonthlyWasteUSD
	sr.TotalAnnualWasteUSD += f.AnnualWasteUSD

	if f.CloudProvider != "" {
		sr.CostByProvider[f.CloudProvider] += f.MonthlyWasteUSD
	}
	sr.SeverityCounts[f.Severity]++
}
