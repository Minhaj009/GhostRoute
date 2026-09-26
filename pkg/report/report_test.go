package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ghostroute/ghostroute/pkg/model"
)

func makeSampleScanResult() *model.ScanResult {
	sr := model.NewScanResult("terraform.tfstate")
	sr.Duration = 150 * time.Millisecond
	sr.TotalResources = 15

	sr.AddFinding(model.Finding{
		ID:                 "GHOST-001",
		RuleID:             "aws-unattached-eip",
		Title:              "Unattached Elastic IP Address",
		Category:           model.CategoryZombie,
		Severity:           model.SeverityHigh,
		ResourceAddress:    "aws_eip.unattached",
		ResourceType:       "aws_eip",
		CloudProvider:      "aws",
		Description:        "Elastic IP is unattached",
		MonthlyWasteUSD:    3.65,
		AnnualWasteUSD:     43.80,
		RemediationCommand: "terraform state rm aws_eip.unattached",
	})

	sr.AddFinding(model.Finding{
		ID:                 "GHOST-DNS-02",
		RuleID:             "dangling-subdomain-takeover-fingerprint",
		Title:              "Critical Subdomain Takeover: Amazon S3",
		Category:           model.CategoryDanglingDNS,
		Severity:           model.SeverityCritical,
		ResourceAddress:    "aws_route53_record.cdn",
		ResourceType:       "dns_record",
		CloudProvider:      "aws_route53",
		DNSDomain:          "cdn.example.com",
		DNSTarget:          "mybucket.s3.amazonaws.com",
		TakeoverProvider:   "Amazon S3",
		Description:        "Bucket does not exist",
		RemediationCommand: "terraform state rm aws_route53_record.cdn",
	})

	return sr
}

func TestRenderTUI(t *testing.T) {
	sr := makeSampleScanResult()
	var buf bytes.Buffer
	RenderTUI(&buf, sr)
	output := buf.String()

	if !strings.Contains(output, "GHOSTROUTE") {
		t.Error("TUI output missing banner")
	}
	if !strings.Contains(output, "aws_eip.unattached") {
		t.Error("TUI output missing resource address")
	}
	if !strings.Contains(output, "$3.65/mo") {
		t.Error("TUI output missing monthly waste")
	}
	if !strings.Contains(output, "CRITICAL") {
		t.Error("TUI output missing CRITICAL alert")
	}
}

func TestGenerateSARIF(t *testing.T) {
	sr := makeSampleScanResult()
	var buf bytes.Buffer
	err := GenerateSARIF(&buf, sr)
	if err != nil {
		t.Fatalf("GenerateSARIF failed: %v", err)
	}

	var sarifObj SARIFReport
	if err := json.Unmarshal(buf.Bytes(), &sarifObj); err != nil {
		t.Fatalf("Generated SARIF is not valid JSON: %v", err)
	}

	if sarifObj.Version != "2.1.0" {
		t.Errorf("SARIF version = %s, want 2.1.0", sarifObj.Version)
	}

	if len(sarifObj.Runs) == 0 {
		t.Fatal("Expected at least one run in SARIF")
	}

	run := sarifObj.Runs[0]
	if run.Tool.Driver.Name != "GhostRoute" {
		t.Errorf("Tool driver name = %s, want GhostRoute", run.Tool.Driver.Name)
	}

	if len(run.Results) != 2 {
		t.Errorf("Expected 2 results in SARIF, got %d", len(run.Results))
	}

	if len(run.Tool.Driver.Rules) != 2 {
		t.Errorf("Expected 2 rules registered, got %d", len(run.Tool.Driver.Rules))
	}
}

func TestGenerateJSON(t *testing.T) {
	sr := makeSampleScanResult()
	var buf bytes.Buffer
	err := GenerateJSON(&buf, sr)
	if err != nil {
		t.Fatalf("GenerateJSON failed: %v", err)
	}

	var decoded model.ScanResult
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("Generated JSON is not valid model.ScanResult: %v", err)
	}

	if decoded.TotalZombies != 1 {
		t.Errorf("Decoded total zombies = %d, want 1", decoded.TotalZombies)
	}
	if decoded.TotalDanglingDNS != 1 {
		t.Errorf("Decoded total dangling DNS = %d, want 1", decoded.TotalDanglingDNS)
	}
}

func TestGeneratePruneScript(t *testing.T) {
	sr := makeSampleScanResult()
	var buf bytes.Buffer
	err := GeneratePruneScript(&buf, sr)
	if err != nil {
		t.Fatalf("GeneratePruneScript failed: %v", err)
	}

	script := buf.String()
	if !strings.Contains(script, "#!/usr/bin/env bash") {
		t.Error("Missing bash shebang")
	}
	if !strings.Contains(script, "terraform state rm 'aws_eip.unattached'") {
		t.Error("Missing terraform state rm command for zombie EIP")
	}
}
