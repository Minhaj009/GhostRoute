package report

import (
	"fmt"
	"io"
	"time"

	"github.com/ghostroute/ghostroute/pkg/model"
)

// GeneratePruneScript creates a runnable script to safely remove orphaned resources from state.
func GeneratePruneScript(w io.Writer, sr *model.ScanResult) error {
	fmt.Fprintf(w, "#!/usr/bin/env bash\n")
	fmt.Fprintf(w, "# =============================================================================\n")
	fmt.Fprintf(w, "# GhostRoute Safe Prune Script\n")
	fmt.Fprintf(w, "# Generated at: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(w, "# Target: %s\n", sr.ScanTarget)
	fmt.Fprintf(w, "# Estimated Monthly Savings: $%.2f USD/month ($%.2f USD/year)\n", sr.TotalMonthlyWasteUSD, sr.TotalAnnualWasteUSD)
	fmt.Fprintf(w, "# =============================================================================\n")
	fmt.Fprintf(w, "# IMPORTANT: Review each command before executing in production.\n")
	fmt.Fprintf(w, "# 'terraform state rm' removes resources from state management without deleting\n")
	fmt.Fprintf(w, "# actual cloud assets. To destroy actual zombie assets, destroy them via IaC or cloud console.\n\n")

	fmt.Fprintf(w, "set -e\n\n")

	hasZombies := false
	for _, f := range sr.Findings {
		if f.Category == model.CategoryZombie {
			hasZombies = true
			fmt.Fprintf(w, "# [%s] %s (Est. waste: $%.2f/mo)\n", f.Severity, f.Title, f.MonthlyWasteUSD)
			fmt.Fprintf(w, "# Address: %s\n", f.ResourceAddress)
			if f.RemediationHCL != "" {
				fmt.Fprintf(w, "%s\n", f.RemediationHCL)
			}
			fmt.Fprintf(w, "echo \"[GhostRoute] Pruning %s from state...\"\n", f.ResourceAddress)
			fmt.Fprintf(w, "terraform state rm '%s'\n\n", f.ResourceAddress)
		}
	}

	if !hasZombies {
		fmt.Fprintf(w, "echo \"[GhostRoute] No zombie resources to prune.\"\n")
	} else {
		fmt.Fprintf(w, "echo \"[GhostRoute] State prune completed successfully. Remember to commit changes and clean .tf definitions!\"\n")
	}

	return nil
}
