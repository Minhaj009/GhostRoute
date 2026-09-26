package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghostroute/ghostroute/pkg/model"
)

func TestRootCommand(t *testing.T) {
	cmd := newRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"version"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("version command failed: %v", err)
	}

	if !strings.Contains(buf.String(), "GhostRoute v") {
		t.Errorf("version output missing expected string: %s", buf.String())
	}
}

func TestCatalogCommand(t *testing.T) {
	cmd := newRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"catalog"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("catalog command failed: %v", err)
	}
}

func TestScanDemoTUI(t *testing.T) {
	cmd := newRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"scan", "--demo", "--format", "tui"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("scan --demo failed: %v", err)
	}

	out := buf.String()
	// Should identify zombies and takeovers
	if !strings.Contains(out, "GHOSTROUTE") {
		t.Error("TUI output missing banner")
	}
}

func TestScanDemoJSON(t *testing.T) {
	cmd := newRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"scan", "--demo", "--format", "json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("scan --demo --format json failed: %v", err)
	}

	var sr model.ScanResult
	if err := json.Unmarshal(buf.Bytes(), &sr); err != nil {
		t.Fatalf("Failed to parse JSON output: %v, body: %s", err, buf.String())
	}

	if sr.TotalZombies < 4 {
		t.Errorf("Expected at least 4 zombies in demo, got %d", sr.TotalZombies)
	}
	if sr.TotalDanglingDNS < 2 {
		t.Errorf("Expected at least 2 dangling DNS in demo, got %d", sr.TotalDanglingDNS)
	}
	if sr.TotalMonthlyWasteUSD <= 0 {
		t.Errorf("Expected positive monthly waste, got %f", sr.TotalMonthlyWasteUSD)
	}
}

func TestScanDemoSARIF(t *testing.T) {
	tempFile := filepath.Join(t.TempDir(), "report.sarif")
	cmd := newRootCmd()
	cmd.SetArgs([]string{"scan", "--demo", "--format", "sarif", "--output", tempFile})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("scan --demo --format sarif failed: %v", err)
	}

	data, err := os.ReadFile(tempFile)
	if err != nil {
		t.Fatalf("Failed to read generated SARIF file: %v", err)
	}

	var sarifObj map[string]interface{}
	if err := json.Unmarshal(data, &sarifObj); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v", err)
	}

	if sarifObj["version"] != "2.1.0" {
		t.Errorf("SARIF version = %v, want 2.1.0", sarifObj["version"])
	}
}

func TestScanCleanAWS(t *testing.T) {
	statePath := filepath.Join("..", "..", "tests", "fixtures", "clean_aws.tfstate")
	if _, err := os.Stat(statePath); err != nil {
		statePath = filepath.Join("tests", "fixtures", "clean_aws.tfstate")
	}

	cmd := newRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"scan", "--state", statePath, "--format", "json", "--skip-dns"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("scan clean state failed: %v", err)
	}

	var sr model.ScanResult
	if err := json.Unmarshal(buf.Bytes(), &sr); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	if sr.TotalZombies != 0 {
		t.Errorf("Expected 0 zombies on clean state, got %d", sr.TotalZombies)
	}
	if sr.TotalMonthlyWasteUSD != 0 {
		t.Errorf("Expected $0 monthly waste on clean state, got %f", sr.TotalMonthlyWasteUSD)
	}
}

func TestScanPruneScriptGeneration(t *testing.T) {
	pruneFile := filepath.Join(t.TempDir(), "prune.sh")
	cmd := newRootCmd()
	cmd.SetArgs([]string{"scan", "--demo", "--prune-file", pruneFile, "--format", "tui"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("scan with prune-file failed: %v", err)
	}

	content, err := os.ReadFile(pruneFile)
	if err != nil {
		t.Fatalf("Failed to read prune file: %v", err)
	}

	script := string(content)
	if !strings.Contains(script, "terraform state rm") {
		t.Error("Prune script missing terraform state rm commands")
	}
}

func TestScanFailOnCritical(t *testing.T) {
	cmd := newRootCmd()
	cmd.SetArgs([]string{"scan", "--demo", "--fail-on-critical"})

	err := cmd.Execute()
	if err == nil {
		t.Error("Expected error from --fail-on-critical on demo state with vulnerabilities, got nil")
	}
}
