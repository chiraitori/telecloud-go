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
	"time"
)

const s3AuthSkewLimit = 15 * time.Minute
const s3MaxPresignExpiry = 7 * 24 * time.Hour

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
		return errors.New("missing x-amz-content-sha256")
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
	amzDate := r.Header.Get("X-Amz-Date")
	if date == "" && amzDate == "" {
		return errors.New("missing sigv2 date")
	}

	effectiveDate := date
	if amzDate != "" {
		effectiveDate = amzDate
	}
	requestTime, err := parseAmzTime(effectiveDate)
	if err != nil {
		return err
	}
	if time.Since(requestTime) > s3AuthSkewLimit || time.Until(requestTime) > s3AuthSkewLimit {
		return errors.New("sigv2 request time skew")
	}

	dateLine := date
	if amzDate != "" {
		dateLine = ""
	}

	stringToSign := strings.Join([]string{
		r.Method,
		r.Header.Get("Content-MD5"),
		r.Header.Get("Content-Type"),
		dateLine,
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
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	segments := strings.Split(path, "/")
	for i, segment := range segments {
		unescaped, err := url.PathUnescape(segment)
		if err != nil {
			unescaped = segment
		}
		segments[i] = sigV4URLEncode(unescaped, true)
	}
	return strings.Join(segments, "/")
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
	resource := r.URL.EscapedPath()
	if resource == "" {
		resource = "/"
	}
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
	return sigV4URLEncode(value, true)
}

func sigV4URLEncode(value string, encodeSlash bool) string {
	var b strings.Builder
	for _, c := range []byte(value) {
		if isSigV4Unreserved(c) {
			b.WriteByte(c)
			continue
		}
		if c == '/' && !encodeSlash {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}

func isSigV4Unreserved(c byte) bool {
	return (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '.' || c == '_' || c == '~'
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
