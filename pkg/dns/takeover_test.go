package dns

import (
	"testing"
)

func TestMatchSignature(t *testing.T) {
	tests := []struct {
		target       string
		wantProvider string
	}{
		{"my-bucket.s3.amazonaws.com", "Amazon S3"},
		{"blog.s3-website-us-east-1.amazonaws.com", "Amazon S3"},
		{"docs.github.io", "GitHub Pages"},
		{"api-stg.herokuapp.com", "Heroku"},
		{"portal.azurewebsites.net", "Azure App Service"},
		{"traffic.trafficmanager.net", "Azure Traffic Manager"},
		{"cdn.cloudfront.net", "AWS CloudFront"},
		{"store.myshopify.com", "Shopify"},
		{"edge.fastly.net", "Fastly"},
		{"help.zendesk.com", "Zendesk"},
		{"internal.corp.local", ""}, // Not a known cloud provider
	}

	for _, tc := range tests {
		t.Run(tc.target, func(t *testing.T) {
			sig := MatchSignature(tc.target)
			if tc.wantProvider == "" {
				if sig != nil {
					t.Errorf("Expected nil signature for %s, got %v", tc.target, sig.Provider)
				}
			} else {
				if sig == nil {
					t.Fatalf("Expected signature %s for %s, got nil", tc.wantProvider, tc.target)
				}
				if sig.Provider != tc.wantProvider {
					t.Errorf("Got provider %s, want %s", sig.Provider, tc.wantProvider)
				}
			}
		})
	}
}

func TestMatchesBodyFingerprint(t *testing.T) {
	s3Sig := MatchSignature("mybucket.s3.amazonaws.com")
	if s3Sig == nil {
		t.Fatal("Failed to get S3 signature")
	}

	vulnerableS3Body := `<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>`

	if !MatchesBodyFingerprint(s3Sig, vulnerableS3Body) {
		t.Error("Expected vulnerable S3 body to match fingerprint, but it didn't")
	}

	healthyS3Body := `<html><body>Welcome to our website</body></html>`
	if MatchesBodyFingerprint(s3Sig, healthyS3Body) {
		t.Error("Healthy body erroneously matched S3 fingerprint")
	}

	ghSig := MatchSignature("docs.github.io")
	vulnerableGHBody := `<html><body>There isn't a GitHub Pages site here.</body></html>`
	if !MatchesBodyFingerprint(ghSig, vulnerableGHBody) {
		t.Error("Expected vulnerable GitHub Pages body to match fingerprint")
	}
}
