# GhostRoute 👻

> **Sub-Second, Zero-Cost Cloud Zombie & Dangling DNS Hunter**  
> *Operates 100% offline on static Terraform / OpenTofu state graphs + local socket lookups with $0 API query fees.*

---

## 🎯 The Problem

Companies inadvertently leak thousands of dollars every month on abandoned cloud assets:
- **Detached EBS Storage Volumes** that remain billed indefinitely after EC2 instances are terminated.
- **Unattached Elastic IP Addresses** incurring hourly AWS idle IPv4 charges ($0.005/hr).
- **Orphaned Load Balancers & Idle NAT Gateways** charging continuous base fees ($16–$33/mo each) while routing zero traffic.
- **Dangling Route 53 / Cloudflare DNS Records** pointing to decommissioned S3 buckets, deleted GitHub Pages, or abandoned Heroku/Azure apps, exposing the organization to **Critical Subdomain Takeover** attacks.

Unlike SaaS scanners (Infracost, Cloud Custodian, Wiz) that require cloud credentials, expensive API query fees, or external cloud agents, **GhostRoute operates purely offline on your local machine or in GitHub Actions with zero cloud API permissions**.

---

## ⚡ Key Architectural Features

- **Zero Cloud API Fees ($0 Architecture)**: Traverses static `terraform.tfstate` (JSON schema v4) and HCL configs offline. No AWS STS, DescribeInstances, or Route 53 API calls needed.
- **Directed Acyclic Graph (DAG) Engine**: Constructs complete parent-child resource topologies to detect zero-reference / unattached anomalies across **AWS**, **GCP**, and **Azure**.
- **15+ Provider Subdomain Takeover Engine**: Concurrently audits DNS CNAME/Alias targets against a built-in signature database (Amazon S3, GitHub Pages, Heroku, Azure App Service, Traffic Manager, CloudFront, Shopify, Fastly, Netlify, Zendesk, etc.).
- **FinOps Static Cost Matrix**: Accurately computes exact monthly and annualized dollar leakage based on official cloud rate cards.
- **Multi-Format Reporting**:
  - **ANSI Terminal Dashboard (TUI)** with high-risk alert flags.
  - **SARIF v2.1.0** export for instant integration with GitHub Code Scanning alerts.
  - **Machine-Readable JSON** for custom CI/CD automations.
  - **Safe Prune Scripts** generating `terraform state rm` snippets to cleanly remove zombies.
- **Turnkey `--demo` Mode**: Built-in realistic vulnerable cloud fixture so anyone can test it with one command without having cloud infrastructure or writing Terraform code.

---

## 🚀 Quick Start (No Cloud Account or Servers Needed!)

### 1. Instant Demo Scan (One Command)
```powershell
# Run instant scan on the built-in vulnerable cloud fixture
go run ./cmd/ghostroute scan --demo
```

### 2. Scan Your Local Terraform / OpenTofu State
```bash
# Scan a specific state file
ghostroute scan ./terraform --state terraform.tfstate

# Scan and export a GitHub Actions SARIF report
ghostroute scan --format sarif --output ghostroute-report.sarif

# Generate an automated safe cleanup script
ghostroute scan --prune-file prune.sh
```

### 3. Check Only for Dangling DNS Subdomain Takeovers
```bash
ghostroute dns-audit --zone assets.mycompany.com --target old-assets.s3.amazonaws.com
```

### 4. View Static FinOps Pricing Matrix
```bash
ghostroute catalog
```

---

## 🧪 100% Automated Testing (Zero-Server Dependency)

GhostRoute is designed to be completely bug-free and tested on any developer machine without running servers.

Run all automated unit, graph traversal, FinOps calculation, mock DNS/HTTP, and CLI tests:

```powershell
# On Windows PowerShell
.\run_tests.ps1

# Or with Go directly
go test -v -cover ./...
```

---

## 🔒 GitHub Actions CI/CD Integration

Add GhostRoute to your pull request workflow to block zombie cloud resources and dangling DNS before merging to `main`:

```yaml
name: GhostRoute FinOps & Security Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.23'
      - name: Run GhostRoute Scan
        run: |
          go run ./cmd/ghostroute scan --state terraform.tfstate --format sarif --output ghostroute.sarif --fail-on-critical
      - name: Upload SARIF to GitHub Security Center
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: ghostroute.sarif
```

---

## 📜 License

Apache-2.0 License. Free for personal and enterprise use.
