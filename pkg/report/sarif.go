package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/ghostroute/ghostroute/pkg/model"
)

// SARIFReport models the top-level SARIF v2.1.0 JSON format for GitHub Security Code Scanning.
type SARIFReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []SARIFRule `json:"rules"`
}

type SARIFRule struct {
	ID                   string             `json:"id"`
	Name                 string             `json:"name"`
	ShortDescription     SARIFMessage       `json:"shortDescription"`
	FullDescription      SARIFMessage       `json:"fullDescription"`
	DefaultConfiguration SARIFConfiguration `json:"defaultConfiguration"`
	Help                 SARIFMessage       `json:"help"`
}

type SARIFConfiguration struct {
	Level string `json:"level"` // "error", "warning", "note"
}

type SARIFResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   SARIFMessage    `json:"message"`
	Locations []SARIFLocation `json:"locations"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           SARIFRegion           `json:"region"`
}

type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

type SARIFRegion struct {
	StartLine int `json:"startLine"`
}

type SARIFMessage struct {
	Text string `json:"text"`
}

// GenerateSARIF builds a SARIF v2.1.0 document from a ScanResult and writes to io.Writer.
func GenerateSARIF(w io.Writer, sr *model.ScanResult) error {
	rulesMap := make(map[string]SARIFRule)
	var results []SARIFResult

	for _, f := range sr.Findings {
		level := "warning"
		if f.Severity == model.SeverityCritical || f.Severity == model.SeverityHigh {
			level = "error"
		} else if f.Severity == model.SeverityLow || f.Severity == model.SeverityInfo {
			level = "note"
		}

		if _, exists := rulesMap[f.ID]; !exists {
			rulesMap[f.ID] = SARIFRule{
				ID:   f.ID,
				Name: f.RuleID,
				ShortDescription: SARIFMessage{
					Text: f.Title,
				},
				FullDescription: SARIFMessage{
					Text: f.Description,
				},
				DefaultConfiguration: SARIFConfiguration{
					Level: level,
				},
				Help: SARIFMessage{
					Text: fmt.Sprintf("%s\n\nImpact: %s\nRemediation: %s", f.Description, f.Impact, f.RemediationHCL),
				},
			}
		}

		msg := fmt.Sprintf("[%s] %s: %s", f.Severity, f.Title, f.Description)
		if f.MonthlyWasteUSD > 0 {
			msg += fmt.Sprintf(" (Est. FinOps Waste: $%.2f/mo)", f.MonthlyWasteUSD)
		}

		results = append(results, SARIFResult{
			RuleID: f.ID,
			Level:  level,
			Message: SARIFMessage{
				Text: msg,
			},
			Locations: []SARIFLocation{
				{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{
							URI: sr.ScanTarget,
						},
						Region: SARIFRegion{
							StartLine: 1,
						},
					},
				},
			},
		})
	}

	var rules []SARIFRule
	for _, rule := range rulesMap {
		rules = append(rules, rule)
	}

	report := SARIFReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           "GhostRoute",
						Version:        "1.0.0",
						InformationURI: "https://github.com/ghostroute/ghostroute",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}
