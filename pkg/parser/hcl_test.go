package parser

import (
	"strings"
	"testing"
)

func TestParseHCL(t *testing.T) {
	hclContent := `
# Sample main.tf
terraform {
  required_version = ">= 1.5.0"
}

resource "aws_ebs_volume" "orphaned" {
  availability_zone = "us-east-1a"
  size              = 50
  type              = "gp3"
}

resource "aws_eip" "idle" {
  domain = "vpc"
}
`

	resources, err := ParseHCL(strings.NewReader(hclContent))
	if err != nil {
		t.Fatalf("ParseHCL failed: %v", err)
	}

	if len(resources) != 2 {
		t.Fatalf("Expected 2 resources, got %d", len(resources))
	}

	r1 := resources[0]
	if r1.Address != "aws_ebs_volume.orphaned" {
		t.Errorf("Expected address 'aws_ebs_volume.orphaned', got '%s'", r1.Address)
	}
	if r1.Attributes["size"] != "50" {
		t.Errorf("Expected size '50', got '%v'", r1.Attributes["size"])
	}
	if r1.Attributes["type"] != "gp3" {
		t.Errorf("Expected type 'gp3', got '%v'", r1.Attributes["type"])
	}

	r2 := resources[1]
	if r2.Address != "aws_eip.idle" {
		t.Errorf("Expected address 'aws_eip.idle', got '%s'", r2.Address)
	}
	if r2.Attributes["domain"] != "vpc" {
		t.Errorf("Expected domain 'vpc', got '%v'", r2.Attributes["domain"])
	}
}
