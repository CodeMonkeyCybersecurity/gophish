package middleware

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"

	log "github.com/gophish/gophish/logger"
)

// CORSConfig holds CORS configuration
type CORSConfig struct {
	AllowedOrigins []string
	AllowedMethods []string
	AllowedHeaders []string
	MaxAge         int
	AllowedPattern []*regexp.Regexp // Compiled patterns for wildcards
}

// originCache caches origin validation results for performance
var originCache = struct {
	sync.RWMutex
	cache map[string]bool
}{
	cache: make(map[string]bool),
}

// DefaultCORSConfig returns secure default CORS configuration
func DefaultCORSConfig() CORSConfig {
	return CORSConfig{
		AllowedOrigins: []string{}, // Empty = no CORS, same-origin only
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"Authorization", "Content-Type", "X-Requested-With"},
		MaxAge:         3600,
		AllowedPattern: []*regexp.Regexp{},
	}
}

// CompileCORSConfig compiles wildcard patterns in CORS configuration
// Call this once during initialization
func CompileCORSConfig(config *CORSConfig) error {
	for _, origin := range config.AllowedOrigins {
		if strings.Contains(origin, "*") {
			pattern, err := compileOriginPattern(origin)
			if err != nil {
				return fmt.Errorf("invalid origin pattern %q: %v", origin, err)
			}
			config.AllowedPattern = append(config.AllowedPattern, pattern)
		}
	}
	return nil
}

// compileOriginPattern converts wildcard pattern to regex
// Supports patterns like: https://*.example.com
func compileOriginPattern(pattern string) (*regexp.Regexp, error) {
	// Escape special regex characters except *
	escaped := regexp.QuoteMeta(pattern)

	// Replace escaped \* with regex pattern for subdomain
	// [a-zA-Z0-9-]+ matches subdomains
	escaped = strings.ReplaceAll(escaped, "\\*", "[a-zA-Z0-9-]+")

	// Anchor the pattern
	regexPattern := "^" + escaped + "$"

	return regexp.Compile(regexPattern)
}

// CORS returns a middleware that handles CORS with allowlist
func CORS(config CORSConfig) func(http.Handler) http.Handler {
	// Compile patterns once during middleware setup
	if err := CompileCORSConfig(&config); err != nil {
		log.Errorf("Failed to compile CORS config: %v", err)
		// Return middleware that blocks all CORS
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				next.ServeHTTP(w, r)
			})
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// If no allowed origins configured, don't set CORS headers
			// This allows same-origin requests to work
			if len(config.AllowedOrigins) == 0 {
				if origin != "" {
					log.Debugf("CORS: No allowed origins configured, rejecting cross-origin request from: %s", origin)
				}
				next.ServeHTTP(w, r)
				return
			}

			// Check if origin is allowed
			allowed := isOriginAllowed(origin, config)

			if !allowed {
				// Origin not allowed
				if origin != "" {
					log.Warnf("CORS: Request from non-allowed origin rejected: %s (IP: %s)", origin, r.RemoteAddr)
					// Optionally count failed CORS attempts for rate limiting
				}
				// Don't set CORS headers for non-allowed origins
				// This allows same-origin requests to work
				next.ServeHTTP(w, r)
				return
			}

			// Set CORS headers for allowed origin
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", strings.Join(config.AllowedMethods, ", "))
			w.Header().Set("Access-Control-Allow-Headers", strings.Join(config.AllowedHeaders, ", "))
			w.Header().Set("Access-Control-Max-Age", fmt.Sprintf("%d", config.MaxAge))
			w.Header().Set("Access-Control-Allow-Credentials", "true")

			// Expose headers that JavaScript can read
			w.Header().Set("Access-Control-Expose-Headers", "Content-Length, Content-Type")

			// Handle preflight requests
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusNoContent) // 204 is more appropriate than 200
				return
			}

			log.Debugf("CORS: Allowed request from origin: %s", origin)
			next.ServeHTTP(w, r)
		})
	}
}

// isOriginAllowed checks if an origin is in the allowed list (with caching)
func isOriginAllowed(origin string, config CORSConfig) bool {
	if origin == "" {
		return false
	}

	// Check cache first
	originCache.RLock()
	cached, found := originCache.cache[origin]
	originCache.RUnlock()

	if found {
		return cached
	}

	// Check exact matches
	allowed := false
	for _, allowedOrigin := range config.AllowedOrigins {
		if !strings.Contains(allowedOrigin, "*") {
			// Exact match
			if origin == allowedOrigin {
				allowed = true
				break
			}
		}
	}

	// Check pattern matches if no exact match found
	if !allowed && len(config.AllowedPattern) > 0 {
		for _, pattern := range config.AllowedPattern {
			if pattern.MatchString(origin) {
				allowed = true
				break
			}
		}
	}

	// Cache the result (with limit to prevent memory exhaustion)
	originCache.Lock()
	if len(originCache.cache) < 1000 {  // Limit cache size
		originCache.cache[origin] = allowed
	}
	originCache.Unlock()

	return allowed
}

// ClearOriginCache clears the origin validation cache
// Useful after updating CORS configuration
func ClearOriginCache() {
	originCache.Lock()
	originCache.cache = make(map[string]bool)
	originCache.Unlock()
}

// ValidateOrigin checks if an origin is in the allowed list (exported for testing)
func ValidateOrigin(origin string, allowedOrigins []string, allowedPatterns []*regexp.Regexp) bool {
	if origin == "" {
		return false
	}

	// Check exact matches
	for _, allowed := range allowedOrigins {
		if !strings.Contains(allowed, "*") && origin == allowed {
			return true
		}
	}

	// Check pattern matches
	for _, pattern := range allowedPatterns {
		if pattern.MatchString(origin) {
			return true
		}
	}

	return false
}

// ValidateCORSConfig validates CORS configuration
func ValidateCORSConfig(config CORSConfig) error {
	if len(config.AllowedOrigins) == 0 {
		// Empty config is valid (no CORS)
		return nil
	}

	// Validate each origin
	for _, origin := range config.AllowedOrigins {
		// Check for wildcard in middle of domain (security risk)
		if strings.Count(origin, "*") > 1 {
			return fmt.Errorf("origin pattern cannot contain multiple wildcards: %s", origin)
		}

		// Wildcard should only be at subdomain level
		if strings.Contains(origin, "*") {
			if !strings.HasPrefix(origin, "https://*.") && !strings.HasPrefix(origin, "http://*.") {
				return fmt.Errorf("wildcard must be at subdomain level: %s", origin)
			}
		}

		// Warn about non-HTTPS origins
		if strings.HasPrefix(origin, "http://") && !strings.Contains(origin, "localhost") {
			log.Warnf("CORS: Non-HTTPS origin configured: %s (security risk)", origin)
		}
	}

	// Validate methods
	if len(config.AllowedMethods) == 0 {
		return fmt.Errorf("at least one HTTP method must be allowed")
	}

	// Validate headers
	if len(config.AllowedHeaders) == 0 {
		return fmt.Errorf("at least one header must be allowed")
	}

	// Validate max age
	if config.MaxAge < 0 {
		return fmt.Errorf("max age cannot be negative")
	}

	return nil
}
