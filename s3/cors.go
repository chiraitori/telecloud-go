package s3

import (
	"net/http"
	"os"
	"strings"
	"telecloud/database"
)

const defaultS3CORSAllowedHeaders = "Authorization, Content-Type, Content-MD5, Range, X-Amz-Content-Sha256, X-Amz-Date, X-Amz-Security-Token, X-Amz-User-Agent, X-Amz-Copy-Source, X-Amz-Metadata-Directive, X-Amz-Acl, X-Amz-Meta-*"

func applyCORSHeaders(w http.ResponseWriter, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}

	appendVaryHeader(w, "Origin", "Access-Control-Request-Headers")

	allowed, allowedOrigin := corsAllowedOrigin(origin)
	if !allowed {
		return false
	}

	w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
	w.Header().Set("Access-Control-Allow-Methods", "GET, HEAD, PUT, POST, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Max-Age", "86400")
	w.Header().Set("Access-Control-Expose-Headers", "Accept-Ranges, Content-Length, Content-Range, Content-Type, ETag, Last-Modified, x-amz-request-id, x-amz-version-id")

	requestedHeaders := r.Header.Get("Access-Control-Request-Headers")
	if requestedHeaders != "" {
		w.Header().Set("Access-Control-Allow-Headers", requestedHeaders)
		return true
	}
	w.Header().Set("Access-Control-Allow-Headers", defaultS3CORSAllowedHeaders)
	return true
}

func corsAllowedOrigin(origin string) (bool, string) {
	allowedOrigins := strings.TrimSpace(os.Getenv("S3_CORS_ALLOWED_ORIGINS"))
	if database.RODB != nil {
		if dbAllowedOrigins := strings.TrimSpace(database.GetSetting("s3_cors_allowed_origins")); dbAllowedOrigins != "" {
			allowedOrigins = dbAllowedOrigins
		}
	}
	if allowedOrigins == "" {
		return true, "*"
	}

	for _, item := range strings.Split(allowedOrigins, ",") {
		allowed := strings.TrimSpace(item)
		switch allowed {
		case "":
			continue
		case "*", "0.0.0.0":
			return true, "*"
		case origin:
			return true, origin
		}
	}
	return false, ""
}

func appendVaryHeader(w http.ResponseWriter, values ...string) {
	seen := make(map[string]bool)
	merged := make([]string, 0, len(values))

	for _, existing := range w.Header().Values("Vary") {
		for _, part := range strings.Split(existing, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			key := strings.ToLower(part)
			if seen[key] {
				continue
			}
			seen[key] = true
			merged = append(merged, part)
		}
	}

	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if seen[key] {
			continue
		}
		seen[key] = true
		merged = append(merged, value)
	}

	w.Header().Set("Vary", strings.Join(merged, ", "))
}
