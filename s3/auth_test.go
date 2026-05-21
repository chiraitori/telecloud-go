package s3

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestVerifySigV2HeaderWithXAmzDateAndSkew(t *testing.T) {
	secret := "test-secret"
	requestTime := time.Now().UTC()
	req := signedSigV2Request(t, requestTime, secret)

	if err := verifySigV2Header(req, req.Header.Get("Authorization"), secret); err != nil {
		t.Fatalf("valid sigv2 request failed: %v", err)
	}

	oldReq := signedSigV2Request(t, requestTime.Add(-s3AuthSkewLimit-time.Minute), secret)
	if err := verifySigV2Header(oldReq, oldReq.Header.Get("Authorization"), secret); err == nil || !strings.Contains(err.Error(), "skew") {
		t.Fatalf("expected skew error for old sigv2 request, got %v", err)
	}
}

func TestApplyCORSHeadersUsesAllowlistAndAppendsVary(t *testing.T) {
	t.Setenv("S3_CORS_ALLOWED_ORIGINS", "http://127.0.0.1:3000, https://app.example.com")

	req := httptest.NewRequest(http.MethodOptions, "/s3/telecloud/video.mp4", nil)
	req.Header.Set("Origin", "http://127.0.0.1:3000")
	req.Header.Set("Access-Control-Request-Headers", "authorization,range")
	rec := httptest.NewRecorder()
	rec.Header().Set("Vary", "Accept-Encoding")

	if !applyCORSHeaders(rec, req) {
		t.Fatal("expected allowed CORS origin")
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://127.0.0.1:3000" {
		t.Fatalf("unexpected allowed origin %q", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Headers"); got != "authorization,range" {
		t.Fatalf("unexpected allowed headers %q", got)
	}
	if got := rec.Header().Get("Vary"); got != "Accept-Encoding, Origin, Access-Control-Request-Headers" {
		t.Fatalf("unexpected Vary %q", got)
	}

	deniedReq := httptest.NewRequest(http.MethodOptions, "/s3/telecloud/video.mp4", nil)
	deniedReq.Header.Set("Origin", "http://evil.test")
	deniedRec := httptest.NewRecorder()
	if applyCORSHeaders(deniedRec, deniedReq) {
		t.Fatal("expected denied CORS origin")
	}
	if got := deniedRec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("denied origin should not receive allow-origin, got %q", got)
	}
}

func signedSigV2Request(t *testing.T, requestTime time.Time, secret string) *http.Request {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "http://example.test/s3/telecloud?list-type=2&max-keys=1", nil)
	date := requestTime.Format("20060102T150405Z")
	req.Header.Set("X-Amz-Date", date)

	stringToSign := strings.Join([]string{
		http.MethodGet,
		"",
		"",
		"",
		"x-amz-date:" + date + "\n/s3/telecloud",
	}, "\n")

	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write([]byte(stringToSign))
	req.Header.Set("Authorization", "AWS test-access:"+base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	return req
}
