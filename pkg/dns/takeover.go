package dns

import (
	"strings"
)

// ProviderSignature defines the detection criteria for a cloud/SaaS subdomain takeover.
type ProviderSignature struct {
	Provider           string   `json:"provider"`
	CNAMEDomains       []string `json:"cname_domains"`
	ResponsePatterns   []string `json:"response_patterns"`
	NXDOMAINVulnerable bool     `json:"nxdomain_vulnerable"`
	Severity           string   `json:"severity"`
	Remediation        string   `json:"remediation"`
}

// Signatures is the curated list of 15+ high-risk cloud provider takeover fingerprints.
var Signatures = []ProviderSignature{
	{
		Provider: "Amazon S3",
		CNAMEDomains: []string{
			"s3.amazonaws.com",
			"s3-website",
			"s3-website-us-east-1.amazonaws.com",
			"s3-website-us-west-1.amazonaws.com",
			"s3-website-us-west-2.amazonaws.com",
			"s3-website-eu-west-1.amazonaws.com",
		},
		ResponsePatterns: []string{
			"NoSuchBucket",
			"The specified bucket does not exist",
		},
		NXDOMAINVulnerable: false,
		Severity:           "CRITICAL",
		Remediation:        "Recreate the S3 bucket in your account or remove the dangling Route53 CNAME/Alias record.",
	},
	{
		Provider: "GitHub Pages",
		CNAMEDomains: []string{
			"github.io",
		},
		ResponsePatterns: []string{
			"There isn't a GitHub Pages site here",
			"For root URLs (like http://example.com/) you must provide an index.html file",
		},
		NXDOMAINVulnerable: false,
		Severity:           "CRITICAL",
		Remediation:        "Claim the repository name with CNAME file in your GitHub account or delete the DNS record.",
	},
	{
		Provider: "Heroku",
		CNAMEDomains: []string{
			"herokuapp.com",
			"herokudns.com",
		},
		ResponsePatterns: []string{
			"No such app",
			"There's nothing here, yet.",
			"herokucdn.com/error-pages/no-such-app.html",
		},
		NXDOMAINVulnerable: false,
		Severity:           "CRITICAL",
		Remediation:        "Claim the Heroku application name or delete the dangling DNS record.",
	},
	{
		Provider: "Azure App Service",
		CNAMEDomains: []string{
			"azurewebsites.net",
			"cloudapp.net",
			"azurefd.net",
		},
		ResponsePatterns: []string{
			"404 Web Site not found",
			"The resource you are looking for has been removed, had its name changed, or is temporarily unavailable.",
		},
		NXDOMAINVulnerable: false,
		Severity:           "CRITICAL",
		Remediation:        "Re-register the Azure Web App or delete the dangling DNS record.",
	},
	{
		Provider: "Azure Traffic Manager",
		CNAMEDomains: []string{
			"trafficmanager.net",
		},
		ResponsePatterns:   nil,
		NXDOMAINVulnerable: true,
		Severity:           "CRITICAL",
		Remediation:        "Create the Azure Traffic Manager profile or delete the Route53/Cloudflare record.",
	},
	{
		Provider: "AWS CloudFront",
		CNAMEDomains: []string{
			"cloudfront.net",
		},
		ResponsePatterns: []string{
			"The request could not be satisfied",
			"Bad request",
			"ERROR: The request could not be satisfied",
		},
		NXDOMAINVulnerable: false,
		Severity:           "HIGH",
		Remediation:        "Attach the custom alternate domain (CNAME) to an active CloudFront distribution or remove the record.",
	},
	{
		Provider: "Shopify",
		CNAMEDomains: []string{
			"myshopify.com",
		},
		ResponsePatterns: []string{
			"Sorry, this shop is currently unavailable",
			"Only one step left!",
		},
		NXDOMAINVulnerable: false,
		Severity:           "CRITICAL",
		Remediation:        "Claim the shop domain in your Shopify admin panel or remove the DNS record.",
	},
	{
		Provider: "Fastly",
		CNAMEDomains: []string{
			"fastly.net",
			"fastlylb.net",
		},
		ResponsePatterns: []string{
			"Fastly error: unknown domain",
		},
		NXDOMAINVulnerable: false,
		Severity:           "CRITICAL",
		Remediation:        "Add the domain to your Fastly service or delete the DNS record.",
	},
	{
		Provider: "Netlify",
		CNAMEDomains: []string{
			"netlify.app",
			"netlify.com",
		},
		ResponsePatterns: []string{
			"Not Found - Request ID:",
			"page not found",
		},
		NXDOMAINVulnerable: false,
		Severity:           "CRITICAL",
		Remediation:        "Claim the site on Netlify or remove the DNS record.",
	},
	{
		Provider: "Zendesk",
		CNAMEDomains: []string{
			"zendesk.com",
		},
		ResponsePatterns: []string{
			"Help Center Closed",
			"No such help center",
		},
		NXDOMAINVulnerable: false,
		Severity:           "CRITICAL",
		Remediation:        "Reactivate the Zendesk help center or remove the host record.",
	},
	{
		Provider: "Surge.sh",
		CNAMEDomains: []string{
			"surge.sh",
		},
		ResponsePatterns: []string{
			"project not found",
		},
		NXDOMAINVulnerable: false,
		Severity:           "CRITICAL",
		Remediation:        "Deploy project to surge.sh with CNAME file or remove DNS record.",
	},
	{
		Provider: "Ghost",
		CNAMEDomains: []string{
			"ghost.io",
		},
		ResponsePatterns: []string{
			"The thing you were looking for is no longer here",
		},
		NXDOMAINVulnerable: false,
		Severity:           "HIGH",
		Remediation:        "Reconfigure Ghost blog or delete the DNS record.",
	},
	{
		Provider: "Readme.io",
		CNAMEDomains: []string{
			"readme.io",
		},
		ResponsePatterns: []string{
			"Project doesnt exist... yet!",
		},
		NXDOMAINVulnerable: false,
		Severity:           "CRITICAL",
		Remediation:        "Claim the Readme.io project or remove the DNS record.",
	},
}

// MatchSignature checks if a CNAME target domain points to a known cloud provider.
func MatchSignature(cnameTarget string) *ProviderSignature {
	targetLower := strings.ToLower(strings.TrimSuffix(cnameTarget, "."))
	for i := range Signatures {
		sig := &Signatures[i]
		for _, domain := range sig.CNAMEDomains {
			if strings.HasSuffix(targetLower, domain) || strings.Contains(targetLower, domain) {
				return sig
			}
		}
	}
	return nil
}

// MatchesBodyFingerprint checks if response body matches any known provider error message.
func MatchesBodyFingerprint(sig *ProviderSignature, body string) bool {
	if sig == nil || len(sig.ResponsePatterns) == 0 {
		return false
	}
	for _, pattern := range sig.ResponsePatterns {
		if strings.Contains(body, pattern) {
			return true
		}
	}
	return false
}
