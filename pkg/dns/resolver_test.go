package dns

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ghostroute/ghostroute/pkg/model"
)

func TestExtractDNSRecords(t *testing.T) {
	resources := []*model.Resource{
		{
			Address: "aws_route53_record.cname_test",
			Type:    "aws_route53_record",
			Name:    "cname_test",
			Attributes: map[string]interface{}{
				"name":    "assets.example.com",
				"type":    "CNAME",
				"records": []interface{}{"my-unclaimed-bucket.s3.amazonaws.com"},
			},
		},
		{
			Address: "aws_route53_record.alias_test",
			Type:    "aws_route53_record",
			Name:    "alias_test",
			Attributes: map[string]interface{}{
				"name": "blog.example.com",
				"type": "A",
				"alias": map[string]interface{}{
					"name": "company.github.io",
				},
			},
		},
		{
			Address: "cloudflare_record.cf_test",
			Type:    "cloudflare_record",
			Name:    "cf_test",
			Attributes: map[string]interface{}{
				"name":    "status.example.com",
				"type":    "CNAME",
				"content": "app.herokuapp.com",
			},
		},
	}

	records := ExtractDNSRecords(resources)
	if len(records) != 3 {
		t.Fatalf("Expected 3 DNS records extracted, got %d", len(records))
	}

	r0 := records[0]
	if r0.Domain != "assets.example.com" || r0.Target != "my-unclaimed-bucket.s3.amazonaws.com" {
		t.Errorf("Record 0 mismatch: %+v", r0)
	}

	r1 := records[1]
	if r1.Domain != "blog.example.com" || r1.Target != "company.github.io" {
		t.Errorf("Record 1 mismatch: %+v", r1)
	}

	r2 := records[2]
	if r2.Domain != "status.example.com" || r2.Target != "app.herokuapp.com" {
		t.Errorf("Record 2 mismatch: %+v", r2)
	}
}

func TestAuditDNSRecordsWithMockServer(t *testing.T) {
	// Spin up in-process mock server simulating an abandoned S3 bucket
	mockS3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>`))
	}))
	defer mockS3.Close()

	engine := NewResolverEngine(2 * time.Second)

	// Mock HTTP GET to return mockS3 response
	engine.HTTPGetFn = func(targetURL string) (int, string, error) {
		return 404, `<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>`, nil
	}

	engine.LookupCNAMEFn = func(ctx context.Context, host string) (string, error) {
		return "my-dead-bucket.s3.amazonaws.com", nil
	}

	candidates := []RecordCandidate{
		{
			ResourceAddress: "aws_route53_record.dead_s3",
			Domain:          "cdn.example.com",
			RecordType:      "CNAME",
			Target:          "my-dead-bucket.s3.amazonaws.com",
			Provider:        "aws_route53",
		},
	}

	findings := engine.AuditDNSRecords(candidates)
	if len(findings) != 1 {
		t.Fatalf("Expected 1 critical takeover finding, got %d", len(findings))
	}

	f := findings[0]
	if f.Severity != model.SeverityCritical {
		t.Errorf("Expected CRITICAL severity, got %v", f.Severity)
	}
	if f.Category != model.CategoryDanglingDNS {
		t.Errorf("Expected DANGLING_DNS category, got %v", f.Category)
	}
	if f.TakeoverProvider != "Amazon S3" {
		t.Errorf("Expected TakeoverProvider Amazon S3, got %s", f.TakeoverProvider)
	}
}

func TestAuditDNSRecordsNXDOMAIN(t *testing.T) {
	engine := NewResolverEngine(2 * time.Second)

	// Simulate NXDOMAIN
	engine.LookupCNAMEFn = func(ctx context.Context, host string) (string, error) {
		return "", errors.New("no such host (NXDOMAIN)")
	}

	candidates := []RecordCandidate{
		{
			ResourceAddress: "aws_route53_record.traffic_mgr",
			Domain:          "traffic.example.com",
			RecordType:      "CNAME",
			Target:          "myprofile.trafficmanager.net",
			Provider:        "aws_route53",
		},
	}

	findings := engine.AuditDNSRecords(candidates)
	if len(findings) != 1 {
		t.Fatalf("Expected 1 NXDOMAIN takeover finding for Azure Traffic Manager, got %d", len(findings))
	}

	f := findings[0]
	if f.Severity != model.SeverityCritical {
		t.Errorf("Expected CRITICAL severity, got %v", f.Severity)
	}
	if f.TakeoverProvider != "Azure Traffic Manager" {
		t.Errorf("Expected Azure Traffic Manager, got %s", f.TakeoverProvider)
	}
}
