package dns

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ghostroute/ghostroute/pkg/model"
)

// RecordCandidate holds normalized DNS record info for analysis.
type RecordCandidate struct {
	ResourceAddress string
	Domain          string
	RecordType      string
	Target          string
	Provider        string
}

// ResolverEngine handles concurrent local DNS resolution and fingerprint analysis.
type ResolverEngine struct {
	timeout         time.Duration
	client          *http.Client
	LookupCNAMEFn   func(ctx context.Context, host string) (string, error)
	HTTPGetFn       func(url string) (int, string, error)
	SkipNetwork     bool
}

// NewResolverEngine initializes a ResolverEngine with local socket resolver.
func NewResolverEngine(timeout time.Duration) *ResolverEngine {
	if timeout <= 0 {
		timeout = 4 * time.Second
	}

	netResolver := &net.Resolver{
		PreferGo: true,
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Allow inspection of expired certs on abandoned subdomains
		DialContext: (&net.Dialer{
			Timeout: timeout,
		}).DialContext,
		ResponseHeaderTimeout: timeout,
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	engine := &ResolverEngine{
		timeout: timeout,
		client:  httpClient,
	}

	engine.LookupCNAMEFn = func(ctx context.Context, host string) (string, error) {
		return netResolver.LookupCNAME(ctx, host)
	}

	engine.HTTPGetFn = func(targetURL string) (int, string, error) {
		req, err := http.NewRequestWithContext(context.Background(), "GET", targetURL, nil)
		if err != nil {
			return 0, "", err
		}
		req.Header.Set("User-Agent", "GhostRoute-Security-Audit/1.0")

		resp, err := httpClient.Do(req)
		if err != nil {
			return 0, "", err
		}
		defer resp.Body.Close()

		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024)) // limit to 64KB
		if err != nil {
			return resp.StatusCode, "", err
		}

		return resp.StatusCode, string(bodyBytes), nil
	}

	return engine
}

// ExtractDNSRecords extracts all CNAME/Alias DNS records from state resources.
func ExtractDNSRecords(resources []*model.Resource) []RecordCandidate {
	var candidates []RecordCandidate

	for _, res := range resources {
		switch res.Type {
		// AWS Route 53 Record
		case "aws_route53_record":
			recType := strings.ToUpper(res.GetStringAttr("type"))
			domain := res.GetStringAttr("name")
			records := res.GetSliceAttr("records")

			// Direct CNAME records
			if recType == "CNAME" {
				for _, target := range records {
					candidates = append(candidates, RecordCandidate{
						ResourceAddress: res.Address,
						Domain:          domain,
						RecordType:      recType,
						Target:          target,
						Provider:        "aws_route53",
					})
				}
			}

			// Alias records (e.g. S3 website endpoint or CloudFront)
			extractAlias := func(val interface{}) string {
				switch av := val.(type) {
				case string:
					return av
				case map[string]interface{}:
					if name, ok := av["name"].(string); ok {
						return name
					}
				case []interface{}:
					for _, item := range av {
						if m, ok := item.(map[string]interface{}); ok {
							if name, ok := m["name"].(string); ok && name != "" {
								return name
							}
						}
					}
				}
				return ""
			}

			if aliasVal, ok := res.Attributes["alias"]; ok {
				if target := extractAlias(aliasVal); target != "" {
					candidates = append(candidates, RecordCandidate{
						ResourceAddress: res.Address,
						Domain:          domain,
						RecordType:      "ALIAS",
						Target:          target,
						Provider:        "aws_route53",
					})
				}
			}

			for k, v := range res.Attributes {
				if k != "alias" && strings.Contains(k, "alias") {
					if target := extractAlias(v); target != "" {
						candidates = append(candidates, RecordCandidate{
							ResourceAddress: res.Address,
							Domain:          domain,
							RecordType:      "ALIAS",
							Target:          target,
							Provider:        "aws_route53",
						})
					}
				}
			}

		// Cloudflare Record
		case "cloudflare_record":
			recType := strings.ToUpper(res.GetStringAttr("type"))
			if recType == "CNAME" {
				domain := res.GetStringAttr("name")
				target := res.GetStringAttr("value")
				if target == "" {
					target = res.GetStringAttr("content")
				}
				candidates = append(candidates, RecordCandidate{
					ResourceAddress: res.Address,
					Domain:          domain,
					RecordType:      recType,
					Target:          target,
					Provider:        "cloudflare",
				})
			}

		// Google Cloud DNS Record
		case "google_dns_record_set":
			recType := strings.ToUpper(res.GetStringAttr("type"))
			if recType == "CNAME" {
				domain := res.GetStringAttr("name")
				targets := res.GetSliceAttr("rrdatas")
				for _, target := range targets {
					candidates = append(candidates, RecordCandidate{
						ResourceAddress: res.Address,
						Domain:          domain,
						RecordType:      recType,
						Target:          target,
						Provider:        "gcp_dns",
					})
				}
			}
		}
	}

	return candidates
}

// AuditDNSRecords concurrently checks DNS records for dangling takeover vulnerabilities.
func (re *ResolverEngine) AuditDNSRecords(candidates []RecordCandidate) []model.Finding {
	var findings []model.Finding
	var mu sync.Mutex
	var wg sync.WaitGroup

	semaphore := make(chan struct{}, 10) // Concurrency limit of 10 concurrent lookups

	for _, cand := range candidates {
		sig := MatchSignature(cand.Target)
		if sig == nil {
			continue // target does not point to a monitored cloud provider
		}

		wg.Add(1)
		go func(c RecordCandidate, s *ProviderSignature) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			finding := re.inspectCandidate(c, s)
			if finding != nil {
				mu.Lock()
				findings = append(findings, *finding)
				mu.Unlock()
			}
		}(cand, sig)
	}

	wg.Wait()
	return findings
}

// inspectCandidate checks a single record candidate against its matched signature
func (re *ResolverEngine) inspectCandidate(c RecordCandidate, sig *ProviderSignature) *model.Finding {
	if re.SkipNetwork {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), re.timeout)
	defer cancel()

	// 1. Resolve CNAME destination
	cnameResolved, err := re.LookupCNAMEFn(ctx, c.Domain)
	isNXDOMAIN := false
	if err != nil {
		errStr := strings.ToLower(err.Error())
		if strings.Contains(errStr, "no such host") || strings.Contains(errStr, "nxdomain") {
			isNXDOMAIN = true
		}
	}

	// 2. Check if NXDOMAIN confirms takeover (e.g. Azure Traffic Manager)
	if isNXDOMAIN && sig.NXDOMAINVulnerable {
		return &model.Finding{
			ID:                 "GHOST-DNS-01",
			RuleID:             "dangling-subdomain-takeover-nxdomain",
			Title:              fmt.Sprintf("Critical Subdomain Takeover: %s (NXDOMAIN)", sig.Provider),
			Category:           model.CategoryDanglingDNS,
			Severity:           model.SeverityCritical,
			ResourceAddress:    c.ResourceAddress,
			ResourceType:       "dns_record",
			CloudProvider:      c.Provider,
			DNSDomain:          c.Domain,
			DNSTarget:          c.Target,
			TakeoverProvider:   sig.Provider,
			Description:        fmt.Sprintf("DNS record '%s' points to '%s' which returned NXDOMAIN on %s.", c.Domain, c.Target, sig.Provider),
			Impact:             "Attackers can register this orphaned resource name and take over the subdomain to execute phishing, cookie theft, or malware distribution.",
			RemediationCommand: fmt.Sprintf("terraform state rm %s", c.ResourceAddress),
			RemediationHCL:     sig.Remediation,
		}
	}

	// 3. HTTP Probe to inspect body fingerprint
	probeTarget := c.Target
	if cnameResolved != "" {
		probeTarget = cnameResolved
	}
	probeTarget = strings.TrimSuffix(probeTarget, ".")

	urls := []string{
		fmt.Sprintf("http://%s", probeTarget),
		fmt.Sprintf("https://%s", probeTarget),
	}

	for _, u := range urls {
		statusCode, body, err := re.HTTPGetFn(u)
		if err == nil {
			if MatchesBodyFingerprint(sig, body) || (statusCode == 404 && MatchesBodyFingerprint(sig, body)) {
				return &model.Finding{
					ID:                 "GHOST-DNS-02",
					RuleID:             "dangling-subdomain-takeover-fingerprint",
					Title:              fmt.Sprintf("Critical Subdomain Takeover: %s (Unclaimed)", sig.Provider),
					Category:           model.CategoryDanglingDNS,
					Severity:           model.SeverityCritical,
					ResourceAddress:    c.ResourceAddress,
					ResourceType:       "dns_record",
					CloudProvider:      c.Provider,
					DNSDomain:          c.Domain,
					DNSTarget:          c.Target,
					TakeoverProvider:   sig.Provider,
					Description:        fmt.Sprintf("DNS record '%s' points to unclaimed %s resource '%s'. Fingerprint detected.", c.Domain, sig.Provider, c.Target),
					Impact:             "High risk of full subdomain takeover. Anyone can claim this cloud resource and serve arbitrary content under your organization's domain.",
					RemediationCommand: fmt.Sprintf("terraform state rm %s", c.ResourceAddress),
					RemediationHCL:     sig.Remediation,
				}
			}
		}
	}

	return nil
}
