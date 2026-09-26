package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/ghostroute/ghostroute/pkg/dns"
	"github.com/ghostroute/ghostroute/pkg/finops"
	"github.com/ghostroute/ghostroute/pkg/graph"
	"github.com/ghostroute/ghostroute/pkg/model"
	"github.com/ghostroute/ghostroute/pkg/parser"
	"github.com/ghostroute/ghostroute/pkg/report"
	"github.com/ghostroute/ghostroute/tests/fixtures"
)

var (
	version = "1.0.0"
	commit  = "dev"
	date    = "2026-09-26"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "ghostroute",
		Short: "GhostRoute: Offline Cloud Zombie & Dangling DNS Hunter",
		Long: `GhostRoute is a sub-second, zero-cost CLI tool and CI/CD security gate.
It parses local Terraform/OpenTofu state graphs and HCL definitions to detect
unattached cloud resources (orphaned load balancers, idle Elastic IPs, detached EBS volumes)
and dangling DNS records vulnerable to subdomain takeover with ZERO cloud API queries.`,
		SilenceUsage:  true,
		SilenceErrors: false,
	}

	rootCmd.AddCommand(newScanCmd())
	rootCmd.AddCommand(newDNSAuditCmd())
	rootCmd.AddCommand(newCatalogCmd())
	rootCmd.AddCommand(newVersionCmd())

	return rootCmd
}

func newScanCmd() *cobra.Command {
	var stateFile string
	var format string
	var outputFile string
	var pruneFile string
	var demoMode bool
	var failOnCritical bool
	var skipDNS bool

	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan a Terraform/OpenTofu state file or directory for zombies and dangling DNS",
		RunE: func(cmd *cobra.Command, args []string) error {
			startTime := time.Now()
			targetName := "terraform.tfstate"

			var resources []*model.Resource
			var err error

			if demoMode {
				targetName = "[BUILT-IN DEMO VULNERABLE CLOUD INFRASTRUCTURE]"
				resources, err = parser.ParseState(strings.NewReader(fixtures.VulnerableAWSStateJSON))
				if err != nil {
					return fmt.Errorf("failed parsing demo state: %w", err)
				}
			} else {
				path := "."
				if len(args) > 0 {
					path = args[0]
				}

				resolvedStatePath := stateFile
				if resolvedStatePath == "" {
					resolvedStatePath, err = parser.LocateStateFile(path)
					if err != nil {
						return fmt.Errorf("no state file found: %w (try passing --state <file> or --demo)", err)
					}
				}
				targetName = resolvedStatePath
				resources, err = parser.ParseStateFile(resolvedStatePath)
				if err != nil {
					return fmt.Errorf("failed to parse state file %s: %w", resolvedStatePath, err)
				}
			}

			sr := model.NewScanResult(targetName)
			sr.TotalResources = len(resources)

			// Step 1: Build Resource Dependency DAG
			dag := graph.BuildDAG(resources)

			// Step 2: Detect Zombie Infrastructure
			detector := graph.NewOrphanDetector(dag)
			zombieFindings := detector.DetectOrphans()

			// Step 3: Compute FinOps Cost Waste
			for i := range zombieFindings {
				f := &zombieFindings[i]
				node := dag.Nodes[f.ResourceAddress]
				if node != nil {
					m, a := finops.CalculateWaste(f, node.Resource)
					f.MonthlyWasteUSD = m
					f.AnnualWasteUSD = a
				}
				sr.AddFinding(*f)
			}

			// Step 4: Extract and Audit DNS records
			dnsCandidates := dns.ExtractDNSRecords(resources)
			if len(dnsCandidates) > 0 {
				if demoMode {
					// In demo mode, inject realistic simulated takeover findings for instant preview
					sr.AddFinding(model.Finding{
						ID:                 "GHOST-DNS-02",
						RuleID:             "dangling-subdomain-takeover-fingerprint",
						Title:              "Critical Subdomain Takeover: Amazon S3 (Unclaimed)",
						Category:           model.CategoryDanglingDNS,
						Severity:           model.SeverityCritical,
						ResourceAddress:    "aws_route53_record.dangling_s3_cname",
						ResourceType:       "aws_route53_record",
						CloudProvider:      "aws_route53",
						DNSDomain:          "assets.production-corp.com",
						DNSTarget:          "abandoned-corp-assets-2023.s3.amazonaws.com",
						TakeoverProvider:   "Amazon S3",
						Description:        "Route53 CNAME points to deleted S3 bucket 'abandoned-corp-assets-2023'. S3 returned NoSuchBucket.",
						Impact:             "Attackers can register this S3 bucket name and serve arbitrary malicious content under assets.production-corp.com.",
						RemediationCommand: "terraform state rm aws_route53_record.dangling_s3_cname",
						RemediationHCL:     "# Remove or repoint aws_route53_record.dangling_s3_cname in main.tf",
					})
					sr.AddFinding(model.Finding{
						ID:                 "GHOST-DNS-02",
						RuleID:             "dangling-subdomain-takeover-fingerprint",
						Title:              "Critical Subdomain Takeover: GitHub Pages (Unclaimed)",
						Category:           model.CategoryDanglingDNS,
						Severity:           model.SeverityCritical,
						ResourceAddress:    "aws_route53_record.dangling_github_pages",
						ResourceType:       "aws_route53_record",
						CloudProvider:      "aws_route53",
						DNSDomain:          "docs.production-corp.com",
						DNSTarget:          "old-project-docs.github.io",
						TakeoverProvider:   "GitHub Pages",
						Description:        "Route53 CNAME points to abandoned GitHub Pages site 'old-project-docs.github.io'.",
						Impact:             "Attackers can claim the repository name on GitHub and take over docs.production-corp.com.",
						RemediationCommand: "terraform state rm aws_route53_record.dangling_github_pages",
						RemediationHCL:     "# Remove or repoint aws_route53_record.dangling_github_pages in main.tf",
					})
				} else if !skipDNS {
					resolver := dns.NewResolverEngine(3 * time.Second)
					dnsFindings := resolver.AuditDNSRecords(dnsCandidates)
					for _, df := range dnsFindings {
						sr.AddFinding(df)
					}
				}
			}

			sr.Duration = time.Since(startTime)

			// Step 5: Format Output
			var outWriter io.Writer = cmd.OutOrStdout()
			if outputFile != "" {
				f, err := os.Create(outputFile)
				if err != nil {
					return fmt.Errorf("failed to create output file %s: %w", outputFile, err)
				}
				defer f.Close()
				outWriter = f
			}

			switch strings.ToLower(format) {
			case "sarif":
				if err := report.GenerateSARIF(outWriter, sr); err != nil {
					return fmt.Errorf("failed to generate SARIF: %w", err)
				}
				if outputFile != "" {
					fmt.Printf("[GhostRoute] SARIF report successfully written to %s\n", outputFile)
				}
			case "json":
				if err := report.GenerateJSON(outWriter, sr); err != nil {
					return fmt.Errorf("failed to generate JSON: %w", err)
				}
				if outputFile != "" {
					fmt.Printf("[GhostRoute] JSON report successfully written to %s\n", outputFile)
				}
			default: // "tui"
				report.RenderTUI(outWriter, sr)
			}

			// Step 6: Generate Prune Script if requested
			if pruneFile != "" {
				pf, err := os.Create(pruneFile)
				if err != nil {
					return fmt.Errorf("failed to create prune script %s: %w", pruneFile, err)
				}
				defer pf.Close()
				if err := report.GeneratePruneScript(pf, sr); err != nil {
					return fmt.Errorf("failed to generate prune script: %w", err)
				}
				fmt.Printf("[GhostRoute] Safe prune script generated at %s\n", pruneFile)
			}

			// Step 7: Evaluate CI/CD Exit Code
			if failOnCritical {
				criticalCount := sr.SeverityCounts[model.SeverityCritical] + sr.SeverityCounts[model.SeverityHigh]
				if criticalCount > 0 {
					return fmt.Errorf("scan failed: found %d high/critical severity security or FinOps issues", criticalCount)
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&stateFile, "state", "s", "", "Path to terraform.tfstate file")
	cmd.Flags().StringVarP(&format, "format", "f", "tui", "Output format: tui, sarif, json")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Write report output to specified file path")
	cmd.Flags().StringVarP(&pruneFile, "prune-file", "p", "", "Generate safe terraform state rm prune script")
	cmd.Flags().BoolVar(&demoMode, "demo", false, "Run instant scan against built-in vulnerable cloud fixture")
	cmd.Flags().BoolVar(&failOnCritical, "fail-on-critical", false, "Exit with code 1 if critical or high issues are found (CI/CD gate)")
	cmd.Flags().BoolVar(&skipDNS, "skip-dns", false, "Skip local socket DNS resolution queries")

	return cmd
}

func newDNSAuditCmd() *cobra.Command {
	var zone string
	var target string

	cmd := &cobra.Command{
		Use:   "dns-audit",
		Short: "Audit a specific zone or CNAME target for dangling subdomain takeover",
		RunE: func(cmd *cobra.Command, args []string) error {
			if zone == "" && target == "" {
				return fmt.Errorf("must specify either --zone or --target")
			}

			bold := color.New(color.Bold).SprintFunc()
			cyan := color.New(color.FgCyan).SprintFunc()
			red := color.New(color.FgRed, color.Bold).SprintFunc()
			green := color.New(color.FgGreen, color.Bold).SprintFunc()

			fmt.Printf("\n%s\n", bold("GhostRoute Standalone DNS Takeover Audit"))
			fmt.Println(strings.Repeat("─", 60))

			var candidate dns.RecordCandidate
			if target != "" {
				candidate = dns.RecordCandidate{
					Domain:   zone,
					Target:   target,
					Provider: "manual-audit",
				}
			} else {
				candidate = dns.RecordCandidate{
					Domain:   zone,
					Target:   zone,
					Provider: "manual-audit",
				}
			}

			sig := dns.MatchSignature(candidate.Target)
			if sig == nil {
				fmt.Printf("  Target '%s' does not match any monitored cloud/SaaS provider signatures.\n\n", cyan(candidate.Target))
				return nil
			}

			fmt.Printf("  %s: Matched cloud signature %s\n", bold("Provider"), cyan(sig.Provider))
			fmt.Printf("  %s: Probing target via local sockets...\n", bold("Status"))

			resolver := dns.NewResolverEngine(3 * time.Second)
			findings := resolver.AuditDNSRecords([]dns.RecordCandidate{candidate})

			if len(findings) > 0 {
				f := findings[0]
				fmt.Printf("\n  %s %s!\n", red("[CRITICAL VULNERABILITY]"), f.Title)
				fmt.Printf("  %s: %s\n", bold("Impact"), f.Impact)
				fmt.Printf("  %s: %s\n\n", bold("Remediation"), f.RemediationHCL)
			} else {
				fmt.Printf("\n  %s Target is healthy or properly claimed. No takeover detected.\n\n", green("[✓] PASS:"))
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&zone, "zone", "z", "", "Domain or zone to check (e.g. assets.example.com)")
	cmd.Flags().StringVarP(&target, "target", "t", "", "CNAME target domain (e.g. mybucket.s3.amazonaws.com)")

	return cmd
}

func newCatalogCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "catalog",
		Short: "Display the static cloud pricing matrix for unattached resources",
		Run: func(cmd *cobra.Command, args []string) {
			w := cmd.OutOrStdout()
			bold := color.New(color.Bold).SprintFunc()
			cyan := color.New(color.FgCyan, color.Bold).SprintFunc()
			green := color.New(color.FgGreen).SprintFunc()

			fmt.Fprintf(w, "\n%s\n", cyan("GhostRoute Static FinOps Pricing Catalog"))
			fmt.Fprintln(w, "Zero API calls. Calibrated against official AWS, GCP, and Azure rate cards.")
			fmt.Fprintln(w, strings.Repeat("─", 88))
			fmt.Fprintf(w, "  %-8s %-32s %-12s %-12s %-20s\n", "CLOUD", "RESOURCE TYPE", "HOURLY RATE", "MONTHLY RATE", "BILLING UNIT")
			fmt.Fprintln(w, strings.Repeat("─", 88))

			entries := finops.GetCatalogEntries()
			for _, e := range entries {
				fmt.Fprintf(w, "  %-8s %-32s $%-11.5f %-12s %-20s\n",
					bold(e.CloudProvider),
					e.ResourceType,
					e.HourlyRateUSD,
					green(fmt.Sprintf("$%.2f/mo", e.MonthlyRateUSD)),
					e.Unit,
				)
			}
			fmt.Fprintln(w, strings.Repeat("─", 88))
			fmt.Fprintln(w)
		},
	}
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Display GhostRoute version and build information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "GhostRoute v%s (commit: %s, built: %s)\n", version, commit, date)
		},
	}
}
