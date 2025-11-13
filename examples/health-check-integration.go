// Health Check Integration Example for HERA V3
//
// This file demonstrates how to integrate the V3 health check and metrics
// endpoints into your existing Gophish application.
//
// To use this code:
// 1. Copy the relevant sections to your controllers/route.go
// 2. Adjust imports and variable names as needed
// 3. Test the endpoints after integration

package examples

import (
	"encoding/json"
	"fmt"
	"net/http"

	log "github.com/gophish/gophish/logger"
	"github.com/gophish/gophish/middleware"
	"github.com/gophish/gophish/models"
	"github.com/gophish/gophish/monitoring"
	"github.com/gorilla/mux"
	"gorm.io/gorm"
)

// Example 1: Basic health check setup
func SetupHealthCheckBasic(router *mux.Router, db *gorm.DB) {
	// Create health check with database connectivity test
	healthCheck := &monitoring.HealthCheck{
		DatabaseCheck: func() error {
			sqlDB, err := db.DB()
			if err != nil {
				return fmt.Errorf("database connection error: %w", err)
			}
			return sqlDB.Ping()
		},
		SessionStoreCheck: func() error {
			if middleware.Store == nil {
				return fmt.Errorf("session store not initialized")
			}
			return nil
		},
		MaxGoroutines: 5000, // Alert if goroutines exceed 5000
		MaxMemoryMB:   1024, // Alert if memory exceeds 1GB
	}

	// Register health check endpoint
	router.HandleFunc("/health", monitoring.HealthHandler(healthCheck)).Methods("GET")
}

// Example 2: Advanced health check with custom checks
func SetupHealthCheckAdvanced(router *mux.Router, db *gorm.DB) {
	healthCheck := &monitoring.HealthCheck{
		// Check database connectivity
		DatabaseCheck: func() error {
			// Test write access
			var count int64
			if err := db.Model(&models.User{}).Count(&count).Error; err != nil {
				return fmt.Errorf("database query failed: %v", err)
			}
			return nil
		},

		// Check session store
		SessionStoreCheck: func() error {
			if middleware.Store == nil {
				return fmt.Errorf("session store not initialized")
			}

			// Verify session options are configured correctly
			opts := middleware.GetStoreOptions()
			if opts == nil {
				return fmt.Errorf("session options not available")
			}

			if !opts.HttpOnly {
				return fmt.Errorf("HttpOnly not enabled")
			}

			return nil
		},

		// Thresholds
		MaxGoroutines: 5000,
		MaxMemoryMB:   1024,
	}

	router.HandleFunc("/health", monitoring.HealthHandler(healthCheck)).Methods("GET")
}

// Example 3: Setup all monitoring endpoints
func SetupMonitoring(router *mux.Router, db *gorm.DB) {
	// Health check (for load balancers)
	healthCheck := &monitoring.HealthCheck{
		DatabaseCheck: func() error {
			sqlDB, err := db.DB()
			if err != nil {
				return fmt.Errorf("database connection error: %w", err)
			}
			return sqlDB.Ping()
		},
		SessionStoreCheck: func() error {
			if middleware.Store == nil {
				return fmt.Errorf("session store not initialized")
			}
			return nil
		},
		MaxGoroutines: 5000,
		MaxMemoryMB:   1024,
	}

	// Public endpoints (no authentication required)
	router.HandleFunc("/health", monitoring.HealthHandler(healthCheck)).Methods("GET")

	// Metrics endpoints (should be protected or internal only)
	// Option 1: Separate internal router/port
	internalRouter := mux.NewRouter()
	internalRouter.HandleFunc("/metrics", monitoring.MetricsHandler()).Methods("GET")
	internalRouter.HandleFunc("/metrics/prometheus", monitoring.PrometheusHandler()).Methods("GET")

	// Option 2: Same router with authentication
	// router.Handle("/metrics", middleware.RequireAPIKey(monitoring.MetricsHandler())).Methods("GET")
	// router.Handle("/metrics/prometheus", middleware.RequireAPIKey(monitoring.PrometheusHandler())).Methods("GET")

	// Start internal metrics server on different port (recommended for security)
	go func() {
		http.ListenAndServe(":9090", internalRouter)
	}()
}

// Example 4: Complete integration into existing Gophish AdminServer
type AdminServerExample struct {
	router *mux.Router
	db     *gorm.DB
}

func (as *AdminServerExample) SetupRoutes() {
	// Existing routes...
	// as.router.HandleFunc("/api/campaigns", as.Campaigns).Methods("GET", "POST")
	// ...

	// Add V3 monitoring endpoints
	healthCheck := &monitoring.HealthCheck{
		DatabaseCheck: func() error {
			sqlDB, err := as.db.DB()
			if err != nil {
				return fmt.Errorf("database connection error: %w", err)
			}
			return sqlDB.Ping()
		},
		SessionStoreCheck: func() error {
			if middleware.Store == nil {
				return fmt.Errorf("session store not initialized")
			}
			return nil
		},
		MaxGoroutines: 5000,
		MaxMemoryMB:   1024,
	}

	// Health check - public, for load balancer
	as.router.HandleFunc("/health", monitoring.HealthHandler(healthCheck)).Methods("GET")

	// Metrics - internal only
	// Create separate router for metrics on different port
	metricsRouter := mux.NewRouter()
	metricsRouter.HandleFunc("/metrics", monitoring.MetricsHandler()).Methods("GET")
	metricsRouter.HandleFunc("/metrics/prometheus", monitoring.PrometheusHandler()).Methods("GET")

	// Add CORS cache stats endpoint
	metricsRouter.HandleFunc("/metrics/cors-cache", func(w http.ResponseWriter, r *http.Request) {
		stats := middleware.GetOriginCacheStats()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(stats)
	}).Methods("GET")

	// Start metrics server on port 9090
	go func() {
		log.Info("Starting metrics server on :9090")
		if err := http.ListenAndServe(":9090", metricsRouter); err != nil {
			log.Errorf("Metrics server failed: %v", err)
		}
	}()
}

// Example 5: Testing health check locally
func ExampleHealthCheckTest() {
	// You can test the health check like this:
	//
	// curl http://localhost:3333/health
	//
	// Expected response:
	// {
	//   "status": "healthy",
	//   "timestamp": "2025-11-12T...",
	//   "uptime_seconds": 3600,
	//   "checks": {
	//     "database": "ok",
	//     "session_store": "ok",
	//     "goroutines": "ok",
	//     "memory": "ok",
	//     "template_goroutines": "ok",
	//     "template_timeouts": "ok"
	//   },
	//   "goroutine_count": 42,
	//   "memory_mb": 128
	// }
	//
	// If any check fails, status will be "degraded" or "unhealthy"
	// and HTTP status will be 503 instead of 200
}

// Example 6: Kubernetes readiness/liveness probe configuration
/*
apiVersion: apps/v1
kind: Deployment
metadata:
  name: gophish
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: gophish
        image: gophish:latest
        ports:
        - containerPort: 3333
          name: http
        - containerPort: 9090
          name: metrics
        livenessProbe:
          httpGet:
            path: /health
            port: 3333
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /health
            port: 3333
          initialDelaySeconds: 10
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 3
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
*/

// Example 7: Load balancer health check configuration (HAProxy)
/*
backend gophish_backend
    balance roundrobin
    option httpchk GET /health
    http-check expect status 200
    server gophish1 192.168.1.10:3333 check inter 5s fall 3 rise 2
    server gophish2 192.168.1.11:3333 check inter 5s fall 3 rise 2
    server gophish3 192.168.1.12:3333 check inter 5s fall 3 rise 2
*/

// Example 8: Nginx upstream health check
/*
upstream gophish {
    server 192.168.1.10:3333 max_fails=3 fail_timeout=30s;
    server 192.168.1.11:3333 max_fails=3 fail_timeout=30s;
    server 192.168.1.12:3333 max_fails=3 fail_timeout=30s;

    # Nginx Plus has built-in health checks
    # health_check uri=/health interval=5s fails=3 passes=2;
}
*/

// Example 9: Integration into existing main.go
/*
package main

import (
    "github.com/gophish/gophish/middleware"
    "github.com/gophish/gophish/models"
    "github.com/gophish/gophish/monitoring"
)

func main() {
    // ... existing initialization ...

    // Initialize V3 session store
    if err := middleware.InitSessionStore(
        config.SessionSigningKey,
        config.SessionEncryptionKey,
    ); err != nil {
        log.Fatal(err)
    }

    // Update session options based on TLS config
    middleware.UpdateStoreOptions(config.AdminServer.UseTLS)

    // Load common passwords
    if err := models.LoadCommonPasswords(config.CommonPasswordsFile); err != nil {
        log.Warnf("Failed to load common passwords: %v", err)
    }

    // Setup admin server
    adminServer := controllers.NewAdminServer(config, db)

    // Add health check
    healthCheck := &monitoring.HealthCheck{
        DatabaseCheck: func() error {
            sqlDB, err := db.DB()
            if err != nil {
                return fmt.Errorf("database connection error: %w", err)
            }
            return sqlDB.Ping()
        },
        SessionStoreCheck: func() error {
            if middleware.Store == nil {
                return fmt.Errorf("session store not initialized")
            }
            return nil
        },
        MaxGoroutines: 5000,
        MaxMemoryMB:   1024,
    }
    adminServer.Router.HandleFunc("/health", monitoring.HealthHandler(healthCheck)).Methods("GET")

    // Start metrics server on separate port
    go func() {
        metricsRouter := mux.NewRouter()
        metricsRouter.HandleFunc("/metrics", monitoring.MetricsHandler()).Methods("GET")
        metricsRouter.HandleFunc("/metrics/prometheus", monitoring.PrometheusHandler()).Methods("GET")
        http.ListenAndServe(":9090", metricsRouter)
    }()

    // ... rest of main ...
}
*/
