package model

import (
	"testing"
)

func TestResourceHelpers(t *testing.T) {
	attrs := map[string]interface{}{
		"volume_id": "vol-12345",
		"size":      100,
		"float_sz":  45.5,
		"records":   []interface{}{"example.com", "test.org"},
		"str_slice": []string{"sub1.com", "sub2.com"},
		"nil_val":   nil,
	}

	res := &Resource{
		Address:    "aws_ebs_volume.test",
		Type:       "aws_ebs_volume",
		Name:       "test",
		Attributes: attrs,
	}

	if got := res.GetStringAttr("volume_id"); got != "vol-12345" {
		t.Errorf("GetStringAttr(volume_id) = %v, want vol-12345", got)
	}
	if got := res.GetStringAttr("missing"); got != "" {
		t.Errorf("GetStringAttr(missing) = %v, want empty", got)
	}
	if got := res.GetStringAttr("nil_val"); got != "" {
		t.Errorf("GetStringAttr(nil_val) = %v, want empty", got)
	}

	if got := res.GetIntAttr("size"); got != 100 {
		t.Errorf("GetIntAttr(size) = %v, want 100", got)
	}
	if got := res.GetIntAttr("float_sz"); got != 45 {
		t.Errorf("GetIntAttr(float_sz) = %v, want 45", got)
	}
	if got := res.GetIntAttr("missing"); got != 0 {
		t.Errorf("GetIntAttr(missing) = %v, want 0", got)
	}

	recs := res.GetSliceAttr("records")
	if len(recs) != 2 || recs[0] != "example.com" || recs[1] != "test.org" {
		t.Errorf("GetSliceAttr(records) = %v, want [example.com test.org]", recs)
	}

	strSlice := res.GetSliceAttr("str_slice")
	if len(strSlice) != 2 || strSlice[0] != "sub1.com" {
		t.Errorf("GetSliceAttr(str_slice) = %v", strSlice)
	}

	if got := res.GetSliceAttr("missing"); got != nil {
		t.Errorf("GetSliceAttr(missing) = %v, want nil", got)
	}
}

func TestScanResultAggregation(t *testing.T) {
	sr := NewScanResult("test.tfstate")
	if sr.TotalResources != 0 || sr.TotalZombies != 0 || sr.TotalDanglingDNS != 0 {
		t.Errorf("Expected initial counts to be 0")
	}

	sr.AddFinding(Finding{
		ID:              "GHOST-001",
		Title:           "Unattached EIP",
		Category:        CategoryZombie,
		Severity:        SeverityHigh,
		CloudProvider:   "aws",
		MonthlyWasteUSD: 3.65,
		AnnualWasteUSD:  43.80,
	})

	sr.AddFinding(Finding{
		ID:               "GHOST-002",
		Title:            "Dangling DNS to S3",
		Category:         CategoryDanglingDNS,
		Severity:         SeverityCritical,
		CloudProvider:    "aws",
		MonthlyWasteUSD:  0,
		AnnualWasteUSD:   0,
		TakeoverProvider: "Amazon S3",
	})

	if sr.TotalZombies != 1 {
		t.Errorf("Expected 1 zombie, got %d", sr.TotalZombies)
	}
	if sr.TotalDanglingDNS != 1 {
		t.Errorf("Expected 1 dangling DNS, got %d", sr.TotalDanglingDNS)
	}
	if sr.TotalMonthlyWasteUSD != 3.65 {
		t.Errorf("Expected $3.65 monthly waste, got %f", sr.TotalMonthlyWasteUSD)
	}
	if sr.TotalAnnualWasteUSD != 43.80 {
		t.Errorf("Expected $43.80 annual waste, got %f", sr.TotalAnnualWasteUSD)
	}
	if sr.SeverityCounts[SeverityHigh] != 1 || sr.SeverityCounts[SeverityCritical] != 1 {
		t.Errorf("Severity counts mismatch: %+v", sr.SeverityCounts)
	}
	if sr.CostByProvider["aws"] != 3.65 {
		t.Errorf("CostByProvider[aws] = %f, want 3.65", sr.CostByProvider["aws"])
	}
}
