package parser

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ghostroute/ghostroute/pkg/model"
)

// TFStateRaw models the top-level Terraform/OpenTofu state JSON schema.
type TFStateRaw struct {
	Version          int                `json:"version"`
	TerraformVersion string             `json:"terraform_version"`
	Serial           int                `json:"serial"`
	Lineage          string             `json:"lineage"`
	Resources        []TFResourceRecord `json:"resources"`
}

// TFResourceRecord models a resource entry in the state file.
type TFResourceRecord struct {
	Module    string               `json:"module,omitempty"`
	Mode      string               `json:"mode"` // "managed" or "data"
	Type      string               `json:"type"`
	Name      string               `json:"name"`
	Provider  string               `json:"provider"`
	Instances []TFInstanceRecord   `json:"instances"`
}

// TFInstanceRecord models a single instance of a resource.
type TFInstanceRecord struct {
	IndexKey       interface{}            `json:"index_key,omitempty"`
	SchemaVersion  int                    `json:"schema_version"`
	Attributes     map[string]interface{} `json:"attributes"`
	Dependencies   []string               `json:"dependencies,omitempty"`
}

// ParseStateFile reads and parses a Terraform state file from disk.
func ParseStateFile(filePath string) ([]*model.Resource, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open state file %s: %w", filePath, err)
	}
	defer f.Close()

	return ParseState(f)
}

// ParseState reads and parses Terraform state JSON from an io.Reader.
func ParseState(r io.Reader) ([]*model.Resource, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read state data: %w", err)
	}

	var rawState TFStateRaw
	if err := json.Unmarshal(data, &rawState); err != nil {
		return nil, fmt.Errorf("invalid terraform state JSON: %w", err)
	}

	if rawState.Version < 3 {
		return nil, fmt.Errorf("unsupported state version %d (minimum supported is 3, recommended 4)", rawState.Version)
	}

	var resources []*model.Resource

	for _, resRecord := range rawState.Resources {
		// We only analyze managed infrastructure (not data sources)
		if resRecord.Mode != "managed" {
			continue
		}

		provider := cleanProviderName(resRecord.Provider)

		for _, instance := range resRecord.Instances {
			address := buildAddress(resRecord.Module, resRecord.Type, resRecord.Name, instance.IndexKey)

			res := &model.Resource{
				Address:      address,
				Type:         resRecord.Type,
				Name:         resRecord.Name,
				Provider:     provider,
				Mode:         resRecord.Mode,
				Attributes:   instance.Attributes,
				Dependencies: instance.Dependencies,
			}

			if res.Attributes == nil {
				res.Attributes = make(map[string]interface{})
			}

			resources = append(resources, res)
		}
	}

	return resources, nil
}

// cleanProviderName extracts clean provider name (e.g., 'aws' from 'provider["registry.terraform.io/hashicorp/aws"]')
func cleanProviderName(raw string) string {
	if raw == "" {
		return "unknown"
	}
	lower := strings.ToLower(raw)
	if strings.Contains(lower, "aws") {
		return "aws"
	}
	if strings.Contains(lower, "google") || strings.Contains(lower, "gcp") {
		return "gcp"
	}
	if strings.Contains(lower, "azurerm") || strings.Contains(lower, "azure") {
		return "azure"
	}
	if strings.Contains(lower, "cloudflare") {
		return "cloudflare"
	}
	if strings.Contains(lower, "digitalocean") {
		return "digitalocean"
	}
	// Fallback: strip quotes and brackets
	trimmed := strings.Trim(raw, "[]\"'")
	parts := strings.Split(trimmed, "/")
	return parts[len(parts)-1]
}

// buildAddress constructs normalized Terraform address
func buildAddress(module, resType, name string, indexKey interface{}) string {
	var base string
	if module != "" {
		base = fmt.Sprintf("%s.%s.%s", module, resType, name)
	} else {
		base = fmt.Sprintf("%s.%s", resType, name)
	}

	if indexKey != nil {
		switch v := indexKey.(type) {
		case string:
			return fmt.Sprintf("%s[\"%s\"]", base, v)
		case float64:
			return fmt.Sprintf("%s[%d]", base, int(v))
		case int:
			return fmt.Sprintf("%s[%d]", base, v)
		default:
			return fmt.Sprintf("%s[%v]", base, v)
		}
	}

	return base
}
