package middleware

import (
	"fmt"
	"net/http"
	"strings"

	log "github.com/gophish/gophish/logger"
)

// CORSConfig holds CORS configuration
type CORSConfig struct {
	AllowedOrigins []string
	AllowedMethods []string
	AllowedHeaders []string
	MaxAge         int
}

// DefaultCORSConfig returns secure default CORS configuration
func DefaultCORSConfig() CORSConfig {
	return CORSConfig{
		AllowedOrigins: []string{}, // Empty = no CORS, same-origin only
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"Authorization", "Content-Type", "X-Requested-With"},
		MaxAge:         3600,
	}
}

// CORS returns a middleware that handles CORS with allowlist
func CORS(config CORSConfig) func(http.Handler) http.Handler {
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
			allowed := false
			for _, allowedOrigin := range config.AllowedOrigins {
				if origin == allowedOrigin {
					allowed = true
					break
				}
			}

			if !allowed {
				// Origin not allowed
				if origin != "" {
					log.Warnf("CORS: Request from non-allowed origin rejected: %s (IP: %s)", origin, r.RemoteAddr)
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

			// Handle preflight requests
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}

			log.Debugf("CORS: Allowed request from origin: %s", origin)
			next.ServeHTTP(w, r)
		})
	}
}

// ValidateOrigin checks if an origin is in the allowed list
func ValidateOrigin(origin string, allowedOrigins []string) bool {
	for _, allowed := range allowedOrigins {
		if origin == allowed {
			return true
		}
	}
	return false
}
