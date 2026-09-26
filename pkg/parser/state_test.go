package parser

import (
	"strings"
	"testing"
)

func TestParseStateValid(t *testing.T) {
	rawJSON := `{
		"version": 4,
		"terraform_version": "1.5.7",
		"serial": 12,
		"lineage": "c84f8842-8941-4560-a2b1-6a2d1d0c4eb5",
		"resources": [
			{
				"mode": "managed",
				"type": "aws_eip",
				"name": "unattached",
				"provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
				"instances": [
					{
						"schema_version": 0,
						"attributes": {
							"id": "eipalloc-0a1b2c3d",
							"public_ip": "54.210.10.15",
							"instance": "",
							"network_interface": ""
						}
					}
				]
			},
			{
				"module": "module.backend",
				"mode": "managed",
				"type": "aws_ebs_volume",
				"name": "data",
				"provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
				"instances": [
					{
						"index_key": 0,
						"schema_version": 0,
						"attributes": {
							"id": "vol-0123456789abcdef0",
							"size": 100,
							"type": "gp3"
						}
					}
				]
			},
			{
				"mode": "data",
				"type": "aws_ami",
				"name": "ubuntu",
				"provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
				"instances": [
					{
						"attributes": {
							"id": "ami-0c55b159cbfafe1f0"
						}
					}
				]
			}
		]
	}`

	resources, err := ParseState(strings.NewReader(rawJSON))
	if err != nil {
		t.Fatalf("ParseState failed: %v", err)
	}

	// Data source should be ignored; only 2 managed resources
	if len(resources) != 2 {
		t.Fatalf("Expected 2 managed resources, got %d", len(resources))
	}

	// Test first resource
	eip := resources[0]
	if eip.Address != "aws_eip.unattached" {
		t.Errorf("Expected address 'aws_eip.unattached', got '%s'", eip.Address)
	}
	if eip.Provider != "aws" {
		t.Errorf("Expected provider 'aws', got '%s'", eip.Provider)
	}
	if eip.GetStringAttr("public_ip") != "54.210.10.15" {
		t.Errorf("Expected public_ip '54.210.10.15', got '%s'", eip.GetStringAttr("public_ip"))
	}

	// Test module resource with index
	ebs := resources[1]
	if ebs.Address != "module.backend.aws_ebs_volume.data[0]" {
		t.Errorf("Expected address 'module.backend.aws_ebs_volume.data[0]', got '%s'", ebs.Address)
	}
	if ebs.GetIntAttr("size") != 100 {
		t.Errorf("Expected size 100, got %d", ebs.GetIntAttr("size"))
	}
	if ebs.GetStringAttr("type") != "gp3" {
		t.Errorf("Expected type 'gp3', got '%s'", ebs.GetStringAttr("type"))
	}
}

func TestParseStateInvalid(t *testing.T) {
	// Malformed JSON
	_, err := ParseState(strings.NewReader(`{ not json }`))
	if err == nil {
		t.Error("Expected error for malformed JSON, got nil")
	}

	// Version too low
	lowVer := `{"version": 2, "resources": []}`
	_, err = ParseState(strings.NewReader(lowVer))
	if err == nil {
		t.Error("Expected error for version 2, got nil")
	}
}
