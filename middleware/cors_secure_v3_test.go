package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCompileOriginPatternV3(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		origins []string
		want    map[string]bool
	}{
		{
			name:    "simple wildcard",
			pattern: "https://*.example.com",
			origins: []string{
				"https://admin.example.com",
				"https://api.example.com",
				"https://evil.com",
			},
			want: map[string]bool{
				"https://admin.example.com": true,
				"https://api.example.com":   true,
				"https://evil.com":          false,
			},
		},
		{
			name:    "multi-level subdomain",
			pattern: "https://*.example.com",
			origins: []string{
				"https://api.v2.example.com",
				"https://admin.staging.example.com",
				"https://a.b.c.example.com",
			},
			want: map[string]bool{
				"https://api.v2.example.com":           true,
				"https://admin.staging.example.com":    true,
				"https://a.b.c.example.com":            true,
			},
		},
		{
			name:    "with port",
			pattern: "https://*.example.com",
			origins: []string{
				"https://admin.example.com:8443",
				"https://api.example.com:3000",
			},
			want: map[string]bool{
				"https://admin.example.com:8443": true,
				"https://api.example.com:3000":   true,
			},
		},
		{
			name:    "with underscore",
			pattern: "https://*.example.com",
			origins: []string{
				"https://admin_console.example.com",
				"https://api_v2.example.com",
			},
			want: map[string]bool{
				"https://admin_console.example.com": true,
				"https://api_v2.example.com":        true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			regex, err := compileOriginPatternV3(tt.pattern)
			if err != nil {
				t.Fatalf("compileOriginPatternV3() error = %v", err)
			}

			for origin, want := range tt.want {
				got := regex.MatchString(origin)
				if got != want {
					t.Errorf("pattern %q matching %q: got %v, want %v", tt.pattern, origin, got, want)
				}
			}
		})
	}
}

func TestCORSV3Middleware(t *testing.T) {
	config := CORSConfigV3{
		AllowedOrigins: []string{"https://admin.example.com", "https://*.api.example.com"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE"},
		AllowedHeaders: []string{"Authorization", "Content-Type"},
		MaxAge:         3600,
		CacheTTL:       5 * time.Minute,
		MaxCacheSize:   100,
	}

	handler := CORSV3(config)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	tests := []struct {
		name         string
		origin       string
		method       string
		wantAllowed  bool
		wantStatus   int
	}{
		{
			name:        "exact match allowed",
			origin:      "https://admin.example.com",
			method:      "GET",
			wantAllowed: true,
			wantStatus:  http.StatusOK,
		},
		{
			name:        "wildcard match allowed",
			origin:      "https://v2.api.example.com",
			method:      "POST",
			wantAllowed: true,
			wantStatus:  http.StatusOK,
		},
		{
			name:        "not allowed",
			origin:      "https://evil.com",
			method:      "GET",
			wantAllowed: false,
			wantStatus:  http.StatusOK,
		},
		{
			name:        "preflight allowed",
			origin:      "https://admin.example.com",
			method:      "OPTIONS",
			wantAllowed: true,
			wantStatus:  http.StatusNoContent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/test", nil)
			req.Header.Set("Origin", tt.origin)
			if tt.method == "OPTIONS" {
				req.Header.Set("Access-Control-Request-Method", "POST")
			}

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("status code = %v, want %v", w.Code, tt.wantStatus)
			}

			allowOrigin := w.Header().Get("Access-Control-Allow-Origin")
			hasAllowOrigin := allowOrigin != ""

			if tt.wantAllowed && !hasAllowOrigin {
				t.Errorf("expected Access-Control-Allow-Origin header, got none")
			}
			if !tt.wantAllowed && hasAllowOrigin {
				t.Errorf("unexpected Access-Control-Allow-Origin header: %v", allowOrigin)
			}
		})
	}
}

func TestOriginCacheV3(t *testing.T) {
	// Initialize cache
	initOriginCache(10, 100*time.Millisecond)

	// Test set and get
	globalOriginCache.set("https://test.com", true)
	allowed, found := globalOriginCache.get("https://test.com")
	if !found {
		t.Error("expected to find cached origin")
	}
	if !allowed {
		t.Error("expected origin to be allowed")
	}

	// Test TTL expiration
	time.Sleep(150 * time.Millisecond)
	_, found = globalOriginCache.get("https://test.com")
	if found {
		t.Error("expected cache entry to be expired")
	}

	// Test LRU eviction
	for i := 0; i < 15; i++ {
		globalOriginCache.set(fmt.Sprintf("https://test%d.com", i), true)
	}

	stats := globalOriginCache.stats()
	size := stats["size"].(int)
	if size > 10 {
		t.Errorf("cache size %d exceeds max size 10", size)
	}
}

func TestValidateCORSConfigV3(t *testing.T) {
	tests := []struct {
		name    string
		config  CORSConfigV3
		wantErr bool
	}{
		{
			name: "valid config",
			config: CORSConfigV3{
				AllowedOrigins: []string{"https://example.com"},
				AllowedMethods: []string{"GET", "POST"},
				AllowedHeaders: []string{"Authorization"},
				MaxAge:         3600,
				MaxCacheSize:   100,
				CacheTTL:       5 * time.Minute,
			},
			wantErr: false,
		},
		{
			name: "multiple wildcards",
			config: CORSConfigV3{
				AllowedOrigins: []string{"https://*.*.example.com"},
				AllowedMethods: []string{"GET"},
				AllowedHeaders: []string{"Authorization"},
				MaxAge:         3600,
				MaxCacheSize:   100,
				CacheTTL:       5 * time.Minute,
			},
			wantErr: true,
		},
		{
			name: "no methods",
			config: CORSConfigV3{
				AllowedOrigins: []string{"https://example.com"},
				AllowedMethods: []string{},
				AllowedHeaders: []string{"Authorization"},
				MaxAge:         3600,
				MaxCacheSize:   100,
				CacheTTL:       5 * time.Minute,
			},
			wantErr: true,
		},
		{
			name: "cache size too small",
			config: CORSConfigV3{
				AllowedOrigins: []string{"https://example.com"},
				AllowedMethods: []string{"GET"},
				AllowedHeaders: []string{"Authorization"},
				MaxAge:         3600,
				MaxCacheSize:   5,
				CacheTTL:       5 * time.Minute,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCORSConfigV3(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCORSConfigV3() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func BenchmarkCORSV3MiddlewareCacheHit(b *testing.B) {
	config := CORSConfigV3{
		AllowedOrigins: []string{"https://admin.example.com"},
		AllowedMethods: []string{"GET"},
		AllowedHeaders: []string{"Authorization"},
		MaxAge:         3600,
		CacheTTL:       5 * time.Minute,
		MaxCacheSize:   1000,
	}

	handler := CORSV3(config)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Pre-populate cache
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "https://admin.example.com")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "https://admin.example.com")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}
}
