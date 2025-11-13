package middleware

import (
	"container/list"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	log "github.com/gophish/gophish/logger"
)

// CORSConfigV3 holds CORS configuration with V3 enhancements
type CORSConfigV3 struct {
	AllowedOrigins []string
	AllowedMethods []string
	AllowedHeaders []string
	MaxAge         int
	AllowedPattern []*regexp.Regexp // Compiled patterns for wildcards
	CacheTTL       time.Duration    // Cache entry TTL
	MaxCacheSize   int              // Maximum cache entries
}

// cacheEntryV3 represents a cached origin validation result
type cacheEntryV3 struct {
	origin    string
	allowed   bool
	timestamp time.Time
}

// originCacheV3 is an LRU cache with TTL for origin validation
type originCacheV3 struct {
	sync.RWMutex
	cache    map[string]*list.Element
	lruList  *list.List
	maxSize  int
	ttl      time.Duration
	hits     int64
	misses   int64
}

var globalOriginCache *originCacheV3

// initOriginCache initializes the global origin cache
func initOriginCache(maxSize int, ttl time.Duration) {
	globalOriginCache = &originCacheV3{
		cache:   make(map[string]*list.Element),
		lruList: list.New(),
		maxSize: maxSize,
		ttl:     ttl,
	}
}

// get retrieves an origin from cache, checking TTL
func (oc *originCacheV3) get(origin string) (bool, bool) {
	oc.Lock()
	defer oc.Unlock()

	elem, found := oc.cache[origin]
	if !found {
		oc.misses++
		return false, false
	}

	entry := elem.Value.(*cacheEntryV3)

	// Check TTL
	if time.Since(entry.timestamp) >= oc.ttl {
		// Expired, remove
		oc.lruList.Remove(elem)
		delete(oc.cache, origin)
		oc.misses++
		return false, false
	}

	// Move to front (LRU)
	oc.lruList.MoveToFront(elem)
	oc.hits++
	return entry.allowed, true
}

// set adds an origin to cache with LRU eviction
func (oc *originCacheV3) set(origin string, allowed bool) {
	oc.Lock()
	defer oc.Unlock()

	// Check if already exists
	if elem, found := oc.cache[origin]; found {
		// Update existing entry
		entry := elem.Value.(*cacheEntryV3)
		entry.allowed = allowed
		entry.timestamp = time.Now()
		oc.lruList.MoveToFront(elem)
		return
	}

	// Evict oldest if at capacity
	if oc.lruList.Len() >= oc.maxSize {
		oldest := oc.lruList.Back()
		if oldest != nil {
			oldEntry := oldest.Value.(*cacheEntryV3)
			delete(oc.cache, oldEntry.origin)
			oc.lruList.Remove(oldest)
			log.Debugf("CORS cache: Evicted LRU entry for origin: %s", oldEntry.origin)
		}
	}

	// Add new entry
	entry := &cacheEntryV3{
		origin:    origin,
		allowed:   allowed,
		timestamp: time.Now(),
	}
	elem := oc.lruList.PushFront(entry)
	oc.cache[origin] = elem
}

// clear removes all entries from cache
func (oc *originCacheV3) clear() {
	oc.Lock()
	defer oc.Unlock()

	oc.cache = make(map[string]*list.Element)
	oc.lruList = list.New()
	log.Info("CORS cache: Cleared all entries")
}

// stats returns cache statistics
func (oc *originCacheV3) stats() map[string]interface{} {
	oc.RLock()
	defer oc.RUnlock()

	total := oc.hits + oc.misses
	hitRate := 0.0
	if total > 0 {
		hitRate = float64(oc.hits) / float64(total) * 100
	}

	return map[string]interface{}{
		"size":     oc.lruList.Len(),
		"max_size": oc.maxSize,
		"hits":     oc.hits,
		"misses":   oc.misses,
		"hit_rate": fmt.Sprintf("%.2f%%", hitRate),
		"ttl":      oc.ttl.String(),
	}
}

// DefaultCORSConfigV3 returns secure default CORS configuration for V3
func DefaultCORSConfigV3() CORSConfigV3 {
	return CORSConfigV3{
		AllowedOrigins: []string{}, // Empty = no CORS, same-origin only
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"Authorization", "Content-Type", "X-Requested-With"},
		MaxAge:         3600,
		AllowedPattern: []*regexp.Regexp{},
		CacheTTL:       5 * time.Minute,
		MaxCacheSize:   1000,
	}
}

// compileOriginPatternV3 converts wildcard pattern to regex with V3 enhancements
// Supports:
//   - Multi-level subdomains: *.example.com matches api.v2.example.com
//   - Underscores: *.example.com matches admin_console.example.com
//   - Ports: *.example.com matches admin.example.com:8443
func compileOriginPatternV3(pattern string) (*regexp.Regexp, error) {
	// Escape special regex characters except *
	escaped := regexp.QuoteMeta(pattern)

	// V3 ENHANCEMENT: Support multi-level subdomains, underscores, and ports
	// Pattern: https://*.example.com
	// Matches:
	//   - https://admin.example.com
	//   - https://api.v2.example.com (multi-level with dots)
	//   - https://admin_console.example.com (underscores)
	//   - https://admin.example.com:8443 (with port)

	// Subdomain pattern: letters, digits, dots, underscores, hyphens
	subdomainPattern := "[a-zA-Z0-9._-]+"

	// Port pattern: optional colon followed by 1-5 digits
	portPattern := "(:[0-9]{1,5})?"

	// Replace escaped \* with subdomain pattern
	escaped = strings.ReplaceAll(escaped, "\\*", subdomainPattern)

	// Add optional port support before end anchor
	// Need to handle both with and without trailing path
	if strings.HasSuffix(escaped, "$") {
		escaped = strings.TrimSuffix(escaped, "$") + portPattern + "$"
	} else {
		escaped = escaped + portPattern
	}

	// Anchor the pattern
	if !strings.HasPrefix(escaped, "^") {
		escaped = "^" + escaped
	}
	if !strings.HasSuffix(escaped, "$") {
		escaped = escaped + "$"
	}

	regex, err := regexp.Compile(escaped)
	if err != nil {
		return nil, fmt.Errorf("failed to compile pattern %q: %v", pattern, err)
	}

	return regex, nil
}

// CompileCORSConfigV3 compiles wildcard patterns in CORS configuration
// Call this once during initialization
func CompileCORSConfigV3(config *CORSConfigV3) error {
	for _, origin := range config.AllowedOrigins {
		if strings.Contains(origin, "*") {
			pattern, err := compileOriginPatternV3(origin)
			if err != nil {
				return fmt.Errorf("invalid origin pattern %q: %v", origin, err)
			}
			config.AllowedPattern = append(config.AllowedPattern, pattern)
			log.Infof("CORS: Compiled wildcard pattern: %s", origin)
		}
	}

	// Initialize global cache
	if globalOriginCache == nil {
		initOriginCache(config.MaxCacheSize, config.CacheTTL)
		log.Infof("CORS: Initialized origin cache (size: %d, TTL: %v)", config.MaxCacheSize, config.CacheTTL)
	}

	return nil
}

// CORSV3 returns a middleware that handles CORS with V3 enhancements
func CORSV3(config CORSConfigV3) func(http.Handler) http.Handler {
	// Compile patterns once during middleware setup
	if err := CompileCORSConfigV3(&config); err != nil {
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

			// Check if origin is allowed (with caching)
			allowed := isOriginAllowedV3(origin, config)

			if !allowed {
				// Origin not allowed
				if origin != "" {
					log.Warnf("CORS: Request from non-allowed origin rejected: %s (IP: %s)", origin, r.RemoteAddr)
					// Increment metrics counter if available
					if corsMetrics != nil {
						corsMetrics.rejectedRequests++
					}
				}
				// Don't set CORS headers for non-allowed origins
				next.ServeHTTP(w, r)
				return
			}

			// Set CORS headers for allowed origin
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", strings.Join(config.AllowedMethods, ", "))
			w.Header().Set("Access-Control-Allow-Headers", strings.Join(config.AllowedHeaders, ", "))
			w.Header().Set("Access-Control-Max-Age", fmt.Sprintf("%d", config.MaxAge))
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Expose-Headers", "Content-Length, Content-Type")

			// Increment metrics counter if available
			if corsMetrics != nil {
				corsMetrics.allowedRequests++
			}

			// Handle preflight requests
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusNoContent) // 204 is appropriate for preflight
				return
			}

			log.Debugf("CORS: Allowed request from origin: %s", origin)
			next.ServeHTTP(w, r)
		})
	}
}

// isOriginAllowedV3 checks if an origin is allowed with LRU caching
func isOriginAllowedV3(origin string, config CORSConfigV3) bool {
	if origin == "" {
		return false
	}

	// Check cache first
	if globalOriginCache != nil {
		if allowed, found := globalOriginCache.get(origin); found {
			return allowed
		}
	}

	// Not in cache, calculate
	allowed := calculateOriginAllowed(origin, config)

	// Cache the result
	if globalOriginCache != nil {
		globalOriginCache.set(origin, allowed)
	}

	return allowed
}

// calculateOriginAllowed performs the actual origin validation
func calculateOriginAllowed(origin string, config CORSConfigV3) bool {
	// Check exact matches first (faster)
	for _, allowedOrigin := range config.AllowedOrigins {
		if !strings.Contains(allowedOrigin, "*") {
			if origin == allowedOrigin {
				return true
			}
		}
	}

	// Check pattern matches
	for _, pattern := range config.AllowedPattern {
		if pattern.MatchString(origin) {
			return true
		}
	}

	return false
}

// ClearOriginCacheV3 clears the V3 origin validation cache
// Call this after updating CORS configuration
func ClearOriginCacheV3() {
	if globalOriginCache != nil {
		globalOriginCache.clear()
	}
}

// GetOriginCacheStats returns cache statistics for monitoring
func GetOriginCacheStats() map[string]interface{} {
	if globalOriginCache != nil {
		return globalOriginCache.stats()
	}
	return map[string]interface{}{
		"error": "cache not initialized",
	}
}

// ValidateCORSConfigV3 validates CORS configuration
func ValidateCORSConfigV3(config CORSConfigV3) error {
	if len(config.AllowedOrigins) == 0 {
		// Empty config is valid (no CORS)
		return nil
	}

	// Validate each origin
	for _, origin := range config.AllowedOrigins {
		// Check for multiple wildcards (security risk)
		if strings.Count(origin, "*") > 1 {
			return fmt.Errorf("origin pattern cannot contain multiple wildcards: %s", origin)
		}

		// Wildcard should only be at subdomain level
		if strings.Contains(origin, "*") {
			if !strings.HasPrefix(origin, "https://*.") && !strings.HasPrefix(origin, "http://*.") {
				return fmt.Errorf("wildcard must be at subdomain level (https://*. or http://*.): %s", origin)
			}
		}

		// Warn about non-HTTPS origins (except localhost)
		if strings.HasPrefix(origin, "http://") && !strings.Contains(origin, "localhost") && !strings.Contains(origin, "127.0.0.1") {
			log.Warnf("CORS: Non-HTTPS origin configured: %s (security risk in production)", origin)
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

	// Validate cache settings
	if config.MaxCacheSize < 10 {
		return fmt.Errorf("max cache size must be at least 10")
	}

	if config.CacheTTL < 1*time.Minute {
		return fmt.Errorf("cache TTL must be at least 1 minute")
	}

	return nil
}

// Simple metrics tracking (can be replaced with Prometheus)
var corsMetrics *struct {
	allowedRequests  int64
	rejectedRequests int64
}

func init() {
	corsMetrics = &struct {
		allowedRequests  int64
		rejectedRequests int64
	}{}
}

// GetCORSMetrics returns CORS request metrics
func GetCORSMetrics() map[string]int64 {
	if corsMetrics == nil {
		return map[string]int64{}
	}
	return map[string]int64{
		"allowed":  corsMetrics.allowedRequests,
		"rejected": corsMetrics.rejectedRequests,
	}
}
