package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/fatih/color"
	"github.com/ghostroute/ghostroute/pkg/model"
)

// RenderTUI prints an ANSI dashboard of the scan result to the provided writer.
func RenderTUI(w io.Writer, sr *model.ScanResult) {
	cyan := color.New(color.FgCyan, color.Bold).SprintFunc()
	yellow := color.New(color.FgYellow, color.Bold).SprintFunc()
	red := color.New(color.FgRed, color.Bold).SprintFunc()
	green := color.New(color.FgGreen, color.Bold).SprintFunc()
	magenta := color.New(color.FgMagenta, color.Bold).SprintFunc()
	bold := color.New(color.Bold).SprintFunc()

	banner := `
   ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗██████╗  ██████╗ ██╗   ██╗████████╗███████╗
  ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝██╔══██╗██╔═══██╗██║   ██║╚══██╔══╝██╔════╝
  ██║  ███╗███████║██║   ██║███████╗   ██║   ██████╔╝██║   ██║██║   ██║   ██║   █████╗  
  ██║   ██║██╔══██║██║   ██║╚════██║   ██║   ██╔══██╗██║   ██║██║   ██║   ██║   ██╔══╝  
  ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ██║  ██║╚██████╔╝╚██████╔╝   ██║   ███████╗
   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝   ╚══════╝
`
	fmt.Fprintln(w, cyan(banner))
	fmt.Fprintln(w, bold("  GHOSTROUTE - Offline Cloud Zombie & Dangling DNS Hunter"))
	fmt.Fprintf(w, "  %s %s | %s %s\n",
		bold("Target:"), sr.ScanTarget,
		bold("Scan Time:"), sr.Duration.Round(1e6).String(),
	)
	fmt.Fprintln(w, strings.Repeat("─", 88))

	// Executive Summary Cards
	fmt.Fprintf(w, "  %s: %-5d | %s: %-5s | %s: %-5s | %s: %-10s\n",
		bold("Total Resources"), sr.TotalResources,
		yellow("Zombie Assets"), fmt.Sprintf("%d", sr.TotalZombies),
		red("Dangling DNS"), fmt.Sprintf("%d", sr.TotalDanglingDNS),
		green("Monthly Waste"), fmt.Sprintf("$%.2f/mo", sr.TotalMonthlyWasteUSD),
	)
	fmt.Fprintf(w, "  %s: %s\n",
		bold("Annualized FinOps Waste"),
		green(fmt.Sprintf("$%.2f USD/year", sr.TotalAnnualWasteUSD)),
	)
	fmt.Fprintln(w, strings.Repeat("─", 88))

	if len(sr.Findings) == 0 {
		fmt.Fprintf(w, "\n  %s No zombie infrastructure or dangling DNS records detected. Clean state!\n\n", green("[✓] PASS:"))
		return
	}

	fmt.Fprintf(w, "\n  %s\n", bold("FINDINGS & ACTIONABLE REMEDIATION:"))
	fmt.Fprintln(w, strings.Repeat("─", 88))
	fmt.Fprintf(w, "  %-12s %-10s %-32s %-18s\n", "SEVERITY", "ID", "RESOURCE ADDRESS", "IMPACT / WASTE")
	fmt.Fprintln(w, strings.Repeat("─", 88))

	for _, f := range sr.Findings {
		var sevStr string
		switch f.Severity {
		case model.SeverityCritical:
			sevStr = red("[CRITICAL]")
		case model.SeverityHigh:
			sevStr = red("[HIGH]")
		case model.SeverityMedium:
			sevStr = yellow("[MEDIUM]")
		case model.SeverityLow:
			sevStr = magenta("[LOW]")
		default:
			sevStr = green("[INFO]")
		}

		var impactStr string
		if f.Category == model.CategoryDanglingDNS {
			impactStr = red("Subdomain Takeover")
		} else {
			impactStr = green(fmt.Sprintf("$%.2f/mo", f.MonthlyWasteUSD))
		}

		addr := f.ResourceAddress
		if len(addr) > 30 {
			addr = addr[:27] + "..."
		}

		fmt.Fprintf(w, "  %-20s %-10s %-32s %-18s\n", sevStr, f.ID, addr, impactStr)
		fmt.Fprintf(w, "    ↳ %s: %s\n", bold("Detail"), f.Description)
		if f.DNSTarget != "" {
			fmt.Fprintf(w, "    ↳ %s: %s -> %s (%s)\n", red("DNS Route"), f.DNSDomain, f.DNSTarget, f.TakeoverProvider)
		}
		if f.RemediationCommand != "" {
			fmt.Fprintf(w, "    ↳ %s: %s\n", cyan("Quick Prune"), f.RemediationCommand)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, strings.Repeat("─", 88))
	fmt.Fprintf(w, "  %s Run with '--format sarif' for GitHub Actions CI/CD gates, or '--prune-file prune.sh' to generate cleanup script.\n\n", bold("Tip:"))
}
