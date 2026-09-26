package parser

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ghostroute/ghostroute/pkg/model"
)

var (
	// Regex pattern to extract resource declarations: resource "aws_instance" "web" {
	resourceDeclRegex = regexp.MustCompile(`^\s*resource\s+"([^"]+)"\s+"([^"]+)"\s*\{`)
	// Regex pattern to find attribute assignments: key = "value"
	attrAssignRegex = regexp.MustCompile(`^\s*([a-zA-Z0-9_-]+)\s*=\s*(.+)`)
)

// ParseHCLDirectory recursively parses .tf files in a directory to extract statically defined resources.
func ParseHCLDirectory(dirPath string) ([]*model.Resource, error) {
	var resources []*model.Resource

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// Skip .git and .terraform directories
			if info.Name() == ".git" || info.Name() == ".terraform" {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) == ".tf" {
			fileRes, err := ParseHCLFile(path)
			if err != nil {
				return err
			}
			resources = append(resources, fileRes...)
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed walking directory %s: %w", dirPath, err)
	}

	return resources, nil
}

// ParseHCLFile parses a single .tf file into basic model.Resource structures.
func ParseHCLFile(filePath string) ([]*model.Resource, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open .tf file %s: %w", filePath, err)
	}
	defer f.Close()

	return ParseHCL(f)
}

// ParseHCL parses HCL content from an io.Reader.
func ParseHCL(r io.Reader) ([]*model.Resource, error) {
	var resources []*model.Resource
	scanner := bufio.NewScanner(r)

	var currentRes *model.Resource
	braceDepth := 0

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Skip empty lines and full line comments
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}

		if currentRes == nil {
			matches := resourceDeclRegex.FindStringSubmatch(line)
			if len(matches) == 3 {
				resType := matches[1]
				resName := matches[2]
				currentRes = &model.Resource{
					Address:    fmt.Sprintf("%s.%s", resType, resName),
					Type:       resType,
					Name:       resName,
					Provider:   cleanProviderName(resType),
					Mode:       "managed",
					Attributes: make(map[string]interface{}),
				}
				braceDepth = 1
			}
		} else {
			// Count braces
			openCount := strings.Count(line, "{")
			closeCount := strings.Count(line, "}")
			braceDepth += openCount - closeCount

			if braceDepth <= 0 {
				resources = append(resources, currentRes)
				currentRes = nil
				braceDepth = 0
				continue
			}

			// Extract attributes
			attrMatches := attrAssignRegex.FindStringSubmatch(line)
			if len(attrMatches) == 3 {
				key := strings.TrimSpace(attrMatches[1])
				rawVal := strings.TrimSpace(attrMatches[2])
				val := strings.Trim(rawVal, `"'`)
				currentRes.Attributes[key] = val
			}
		}
	}

	if currentRes != nil {
		resources = append(resources, currentRes)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading HCL lines: %w", err)
	}

	return resources, nil
}

// LocateStateFile attempts to find a terraform.tfstate file in the given path or directory.
func LocateStateFile(path string) (string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("path not found: %s", path)
	}

	if !fi.IsDir() {
		return path, nil
	}

	// Try standard candidate state file names in directory
	candidates := []string{
		"terraform.tfstate",
		"terraform.tfstate.backup",
		".terraform/terraform.tfstate",
	}

	for _, cand := range candidates {
		candPath := filepath.Join(path, cand)
		if _, err := os.Stat(candPath); err == nil {
			return candPath, nil
		}
	}

	return "", fmt.Errorf("no terraform.tfstate found in %s", path)
}
