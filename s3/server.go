package s3

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"telecloud/config"
	"telecloud/database"
	"time"

	"github.com/johannesboyne/gofakes3"
)

const s3AuthSkewLimit = 15 * time.Minute
const s3MaxPresignExpiry = 7 * 24 * time.Hour

func NewHandler(cfg *config.Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		applyCORSHeaders(w, r)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if database.GetSetting("s3_enabled") != "true" {
			http.Error(w, "S3 API is disabled", http.StatusForbidden)
			return
		}

		// Pre-authentication to identify the user.
		// Two auth methods:
		// 1. Authorization header (normal SDK requests)
		// 2. Query parameters (presigned URLs — no Authorization header)
		var accessKey string

		authHeader := r.Header.Get("Authorization")
		accessKey, err := extractAccessKey(r, authHeader)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		var username string
		var isAdmin bool
		var secretKey string

		if accessKey != "" {
			dbAccessKey := database.GetSetting("s3_access_key")
			if accessKey == dbAccessKey && dbAccessKey != "" {
				username = database.GetSetting("admin_username")
				if username == "" {
					username = "admin"
				}
				isAdmin = true
				secretKey = database.GetSetting("s3_secret_key")
			} else {
				var child struct {
					Username  string  `db:"username"`
					Enabled   int     `db:"s3_enabled"`
					SecretKey *string `db:"s3_secret_key"`
				}
				err := database.RODB.Get(&child, "SELECT username, s3_enabled, s3_secret_key FROM child_accounts WHERE s3_access_key = ?", accessKey)
				if err == nil && child.Username != "" {
					if child.Enabled == 0 {
						http.Error(w, "S3 API disabled", http.StatusForbidden)
						return
					}
					username = child.Username
					isAdmin = false
					if child.SecretKey != nil {
						secretKey = *child.SecretKey
					}
				}
			}
		}

		if username == "" || secretKey == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if err := verifyS3Signature(r, authHeader, accessKey, secretKey); err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Normalize path for "Fixed Bucket" mode.
		// We want to force all requests to be treated as if they are against the "telecloud" bucket.
		path := strings.TrimPrefix(r.URL.Path, "/s3")
		path = strings.TrimPrefix(path, "/")

		if path != "" {
			parts := strings.Split(path, "/")
			if len(parts) > 0 {
				// If the first part is a known bucket name or just any bucket name,
				// we strip it to treat the rest as the object key.
				// For Telecloud, we only ever "really" have one bucket called "telecloud".
				if parts[0] == "telecloud" || parts[0] == username || parts[0] == "admin" {
					path = strings.Join(parts[1:], "/")
				}
			}
		}

		// Reconstruct the path to always be /telecloud/<key>
		r.URL.Path = "/" + "telecloud/" + strings.TrimPrefix(path, "/")

		backend := NewBackend(cfg, username, isAdmin)
		faker := gofakes3.New(backend)
		if r.Header.Get("Range") != "" {
			faker.Server().ServeHTTP(&rangeStatusWriter{ResponseWriter: w}, r)
			return
		}
		faker.Server().ServeHTTP(w, r)
	})
}

type rangeStatusWriter struct {
	http.ResponseWriter
	wroteHeader bool
}

func (w *rangeStatusWriter) WriteHeader(statusCode int) {
	if statusCode == http.StatusOK && w.Header().Get("Content-Range") != "" {
		statusCode = http.StatusPartialContent
	}
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *rangeStatusWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader && w.Header().Get("Content-Range") != "" {
		w.WriteHeader(http.StatusPartialContent)
	}
	return w.ResponseWriter.Write(b)
}

func applyCORSHeaders(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = "*"
	}

	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Vary", "Origin, Access-Control-Request-Headers")
	w.Header().Set("Access-Control-Allow-Methods", "GET, HEAD, PUT, POST, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Max-Age", "86400")
	w.Header().Set("Access-Control-Expose-Headers", "Accept-Ranges, Content-Length, Content-Range, Content-Type, ETag, Last-Modified, x-amz-request-id, x-amz-version-id")

	requestedHeaders := r.Header.Get("Access-Control-Request-Headers")
	if requestedHeaders != "" {
		w.Header().Set("Access-Control-Allow-Headers", requestedHeaders)
		return
	}
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Content-MD5, Range, X-Amz-Content-Sha256, X-Amz-Date, X-Amz-Security-Token, X-Amz-User-Agent, X-Amz-Copy-Source, X-Amz-Metadata-Directive, X-Amz-Acl, X-Amz-Meta-*")
}

func extractAccessKey(r *http.Request, authHeader string) (string, error) {
	if strings.HasPrefix(authHeader, "AWS4-HMAC-SHA256") {
		parts := parseAuthorizationParams(strings.TrimPrefix(authHeader, "AWS4-HMAC-SHA256"))
		credential := parts["Credential"]
		if credential == "" {
			return "", errors.New("missing credential")
		}
		return strings.Split(credential, "/")[0], nil
	}

	if strings.HasPrefix(authHeader, "AWS ") {
		credential := strings.TrimSpace(strings.TrimPrefix(authHeader, "AWS "))
		if credential == "" || !strings.Contains(credential, ":") {
			return "", errors.New("invalid sigv2 credential")
		}
		return strings.SplitN(credential, ":", 2)[0], nil
	}

	if r.URL.Query().Get("X-Amz-Algorithm") != "" {
		credential := r.URL.Query().Get("X-Amz-Credential")
		if credential == "" {
			return "", errors.New("missing presigned credential")
		}
		return strings.Split(credential, "/")[0], nil
	}

	return "", nil
}

func verifyS3Signature(r *http.Request, authHeader, accessKey, secretKey string) error {
	switch {
	case strings.HasPrefix(authHeader, "AWS4-HMAC-SHA256"):
		return verifySigV4Header(r, authHeader, secretKey)
	case strings.HasPrefix(authHeader, "AWS "):
		return verifySigV2Header(r, authHeader, secretKey)
	case r.URL.Query().Get("X-Amz-Algorithm") == "AWS4-HMAC-SHA256":
		return verifySigV4Presigned(r, accessKey, secretKey)
	default:
		return errors.New("missing supported s3 signature")
	}
}

func verifySigV4Header(r *http.Request, authHeader, secretKey string) error {
	params := parseAuthorizationParams(strings.TrimPrefix(authHeader, "AWS4-HMAC-SHA256"))
	credential := params["Credential"]
	signedHeaders := strings.ToLower(params["SignedHeaders"])
	signature := params["Signature"]
	if credential == "" || signedHeaders == "" || signature == "" {
		return errors.New("missing sigv4 authorization fields")
	}

	requestTime, err := parseAmzTime(r.Header.Get("X-Amz-Date"))
	if err != nil {
		return err
	}
	if time.Since(requestTime) > s3AuthSkewLimit || time.Until(requestTime) > s3AuthSkewLimit {
		return errors.New("sigv4 request time skew")
	}

	payloadHash := r.Header.Get("X-Amz-Content-Sha256")
	if payloadHash == "" {
		payloadHash = emptySHA256Hex()
	}

	canonicalRequest, err := canonicalSigV4Request(r, signedHeaders, payloadHash, nil)
	if err != nil {
		return err
	}

	return compareSigV4(signature, credential, requestTime, canonicalRequest, secretKey)
}

func verifySigV4Presigned(r *http.Request, accessKey, secretKey string) error {
	query := r.URL.Query()
	if query.Get("X-Amz-Credential") == "" || query.Get("X-Amz-SignedHeaders") == "" || query.Get("X-Amz-Signature") == "" {
		return errors.New("missing presigned sigv4 fields")
	}
	if query.Get("X-Amz-Algorithm") != "AWS4-HMAC-SHA256" {
		return errors.New("unsupported presigned algorithm")
	}

	credential := query.Get("X-Amz-Credential")
	if strings.Split(credential, "/")[0] != accessKey {
		return errors.New("presigned credential mismatch")
	}

	requestTime, err := parseAmzTime(query.Get("X-Amz-Date"))
	if err != nil {
		return err
	}

	expirySeconds, err := strconv.ParseInt(query.Get("X-Amz-Expires"), 10, 64)
	if err != nil || expirySeconds < 0 {
		return errors.New("invalid presigned expiry")
	}
	expiry := time.Duration(expirySeconds) * time.Second
	if expiry > s3MaxPresignExpiry {
		return errors.New("presigned expiry too long")
	}
	now := time.Now().UTC()
	if now.Before(requestTime.Add(-s3AuthSkewLimit)) || now.After(requestTime.Add(expiry)) {
		return errors.New("presigned url expired")
	}

	payloadHash := query.Get("X-Amz-Content-Sha256")
	if payloadHash == "" {
		payloadHash = "UNSIGNED-PAYLOAD"
	}

	canonicalRequest, err := canonicalSigV4Request(r, strings.ToLower(query.Get("X-Amz-SignedHeaders")), payloadHash, map[string]bool{"X-Amz-Signature": true})
	if err != nil {
		return err
	}

	return compareSigV4(query.Get("X-Amz-Signature"), credential, requestTime, canonicalRequest, secretKey)
}

func verifySigV2Header(r *http.Request, authHeader, secretKey string) error {
	credential := strings.TrimSpace(strings.TrimPrefix(authHeader, "AWS "))
	parts := strings.SplitN(credential, ":", 2)
	if len(parts) != 2 || parts[1] == "" {
		return errors.New("invalid sigv2 authorization")
	}

	date := r.Header.Get("Date")
	if date == "" {
		date = r.Header.Get("X-Amz-Date")
	}
	if date == "" {
		return errors.New("missing sigv2 date")
	}

	stringToSign := strings.Join([]string{
		r.Method,
		r.Header.Get("Content-MD5"),
		r.Header.Get("Content-Type"),
		date,
		canonicalAmzHeaders(r.Header) + canonicalSigV2Resource(r),
	}, "\n")

	mac := hmac.New(sha1.New, []byte(secretKey))
	mac.Write([]byte(stringToSign))
	expected := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(parts[1])) {
		return errors.New("sigv2 signature mismatch")
	}
	return nil
}

func parseAuthorizationParams(value string) map[string]string {
	result := make(map[string]string)
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		key, val, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		result[key] = val
	}
	return result
}

func canonicalSigV4Request(r *http.Request, signedHeaders, payloadHash string, ignoredQuery map[string]bool) (string, error) {
	headers, err := canonicalSigV4Headers(r, signedHeaders)
	if err != nil {
		return "", err
	}

	return strings.Join([]string{
		r.Method,
		canonicalURI(r),
		canonicalQueryString(r.URL.Query(), ignoredQuery),
		headers,
		signedHeaders,
		payloadHash,
	}, "\n"), nil
}

func canonicalSigV4Headers(r *http.Request, signedHeaders string) (string, error) {
	var b strings.Builder
	for _, header := range strings.Split(signedHeaders, ";") {
		header = strings.ToLower(strings.TrimSpace(header))
		if header == "" {
			continue
		}

		var values []string
		if header == "host" {
			values = []string{r.Host}
		} else {
			values = r.Header.Values(header)
			if len(values) == 0 {
				values = r.Header.Values(http.CanonicalHeaderKey(header))
			}
		}
		if len(values) == 0 {
			return "", fmt.Errorf("missing signed header %s", header)
		}

		for i, value := range values {
			values[i] = canonicalHeaderValue(value)
		}
		b.WriteString(header)
		b.WriteByte(':')
		b.WriteString(strings.Join(values, ","))
		b.WriteByte('\n')
	}
	return b.String(), nil
}

func compareSigV4(signature, credential string, requestTime time.Time, canonicalRequest, secretKey string) error {
	scope, err := sigV4Scope(credential, requestTime)
	if err != nil {
		return err
	}

	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		requestTime.Format("20060102T150405Z"),
		scope,
		hex.EncodeToString(sha256Bytes([]byte(canonicalRequest))),
	}, "\n")

	expected := hex.EncodeToString(sigV4SigningHMAC(secretKey, scope, stringToSign))
	provided, err := hex.DecodeString(signature)
	if err != nil {
		return err
	}
	expectedBytes, err := hex.DecodeString(expected)
	if err != nil {
		return err
	}
	if !hmac.Equal(expectedBytes, provided) {
		return errors.New("sigv4 signature mismatch")
	}
	return nil
}

func sigV4Scope(credential string, requestTime time.Time) (string, error) {
	parts := strings.Split(credential, "/")
	if len(parts) != 5 || parts[3] != "s3" || parts[4] != "aws4_request" {
		return "", errors.New("invalid sigv4 credential scope")
	}
	if parts[1] != requestTime.Format("20060102") {
		return "", errors.New("sigv4 credential date mismatch")
	}
	return strings.Join(parts[1:], "/"), nil
}

func sigV4SigningHMAC(secretKey, scope, stringToSign string) []byte {
	parts := strings.Split(scope, "/")
	dateKey := hmacSHA256([]byte("AWS4"+secretKey), parts[0])
	regionKey := hmacSHA256(dateKey, parts[1])
	serviceKey := hmacSHA256(regionKey, parts[2])
	signingKey := hmacSHA256(serviceKey, parts[3])
	return hmacSHA256(signingKey, stringToSign)
}

func parseAmzTime(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, errors.New("missing x-amz-date")
	}

	for _, layout := range []string{"20060102T150405Z", "20060102T150405-0700", time.RFC1123} {
		t, err := time.Parse(layout, value)
		if err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, errors.New("invalid x-amz-date")
}

func canonicalURI(r *http.Request) string {
	path := r.URL.EscapedPath()
	if path == "" {
		return "/"
	}
	return path
}

func canonicalQueryString(values url.Values, ignored map[string]bool) string {
	type pair struct {
		key string
		val string
	}

	var pairs []pair
	for key, vals := range values {
		if ignored != nil && ignored[key] {
			continue
		}
		if len(vals) == 0 {
			pairs = append(pairs, pair{key: awsURLEncode(key), val: ""})
			continue
		}
		for _, val := range vals {
			pairs = append(pairs, pair{key: awsURLEncode(key), val: awsURLEncode(val)})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].key == pairs[j].key {
			return pairs[i].val < pairs[j].val
		}
		return pairs[i].key < pairs[j].key
	})

	encoded := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		encoded = append(encoded, pair.key+"="+pair.val)
	}
	return strings.Join(encoded, "&")
}

func canonicalHeaderValue(value string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(value)), " ")
}

func canonicalAmzHeaders(header http.Header) string {
	keys := make([]string, 0)
	for key := range header {
		lower := strings.ToLower(key)
		if strings.HasPrefix(lower, "x-amz-") {
			keys = append(keys, lower)
		}
	}
	sort.Strings(keys)

	var b strings.Builder
	for _, key := range keys {
		values := header.Values(key)
		if len(values) == 0 {
			values = header.Values(http.CanonicalHeaderKey(key))
		}
		for i, value := range values {
			values[i] = canonicalHeaderValue(value)
		}
		b.WriteString(key)
		b.WriteByte(':')
		b.WriteString(strings.Join(values, ","))
		b.WriteByte('\n')
	}
	return b.String()
}

func canonicalSigV2Resource(r *http.Request) string {
	resource := canonicalURI(r)
	subresources := []string{
		"acl", "cors", "delete", "lifecycle", "location", "logging", "notification",
		"partNumber", "policy", "requestPayment", "response-cache-control",
		"response-content-disposition", "response-content-encoding",
		"response-content-language", "response-content-type", "response-expires",
		"tagging", "torrent", "uploadId", "uploads", "versionId", "versioning",
		"versions", "website",
	}

	query := r.URL.Query()
	var parts []string
	for _, key := range subresources {
		if vals, ok := query[key]; ok {
			if len(vals) == 0 || vals[0] == "" {
				parts = append(parts, key)
			} else {
				parts = append(parts, key+"="+vals[0])
			}
		}
	}
	if len(parts) == 0 {
		return resource
	}
	sort.Strings(parts)
	return resource + "?" + strings.Join(parts, "&")
}

func awsURLEncode(value string) string {
	encoded := url.QueryEscape(value)
	encoded = strings.ReplaceAll(encoded, "+", "%20")
	encoded = strings.ReplaceAll(encoded, "%7E", "~")
	return encoded
}

func hmacSHA256(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(value))
	return mac.Sum(nil)
}

func sha256Bytes(value []byte) []byte {
	sum := sha256.Sum256(value)
	return sum[:]
}

func emptySHA256Hex() string {
	return hex.EncodeToString(sha256Bytes(nil))
}
