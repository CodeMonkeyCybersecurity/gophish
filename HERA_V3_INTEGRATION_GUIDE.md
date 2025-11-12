# HERA V3 Integration Guide - Production-Ready Security Implementation

## Executive Summary

This guide provides step-by-step instructions for integrating HERA V3 security enhancements into Gophish. V3 includes all V2 fixes plus production hardening, monitoring, and operational tools.

**Version:** 3.0 (Production-Ready)
**Date:** 2025-11-12
**Estimated Integration Time:** 2-3 weeks
**Skill Level Required:** Intermediate Go, DevOps experience

---

## What's New in V3

### V3 Enhancements Over V2
1. **Enhanced CORS** - LRU cache with TTL, multi-level subdomain support, port support
2. **Thread-Safe Sessions** - sync.Once initialization, race condition fixes
3. **Template Monitoring** - Goroutine tracking, rate limiting, metrics
4. **Prometheus Metrics** - Complete observability and monitoring
5. **Automated Testing** - Comprehensive test suite
6. **Zero-Downtime Deployment** - Rolling deployment scripts
7. **Production Checklist** - Complete operational procedures
8. **File-Based Passwords** - External common password lists

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Phase 1: Preparation](#phase-1-preparation)
3. [Phase 2: Core Integration](#phase-2-core-integration)
4. [Phase 3: Monitoring Setup](#phase-3-monitoring-setup)
5. [Phase 4: Testing](#phase-4-testing)
6. [Phase 5: Deployment](#phase-5-deployment)
7. [Phase 6: Post-Deployment](#phase-6-post-deployment)
8. [Troubleshooting](#troubleshooting)
9. [Performance Tuning](#performance-tuning)
10. [Security Hardening](#security-hardening)

---

## Prerequisites

### System Requirements
- Go 1.18+ (V3 uses modern Go features)
- Linux/Unix system (tested on Ubuntu 20.04+)
- MySQL 5.7+ or PostgreSQL 12+ (SQLite for development only)
- 2+ GB RAM (4+ GB recommended for production)
- 2+ CPU cores

### Required Tools
```bash
# Go tools
go install github.com/securego/gosec/v2/cmd/gosec@latest
go install golang.org/x/vuln/cmd/govulncheck@latest

# Testing tools (optional but recommended)
go install golang.org/x/lint/golint@latest
```

### Knowledge Requirements
- Familiarity with Gophish codebase
- Basic Go programming
- Understanding of HTTP/TLS
- Basic DevOps (deployment, monitoring)

---

## Phase 1: Preparation

### Step 1.1: Backup Current System

Create complete backup before making any changes:

```bash
# Backup database
mysqldump -u gophish -p gophish > backup-$(date +%Y%m%d).sql

# Or for SQLite
cp gophish.db gophish.db.backup-$(date +%Y%m%d)

# Backup binary
cp gophish gophish.backup-$(date +%Y%m%d)

# Backup configuration
cp config.json config.json.backup-$(date +%Y%m%d)
```

### Step 1.2: Review V3 Files

Ensure all V3 files are present:

```bash
# Check V3 implementation files
ls -la middleware/cors_secure_v3.go
ls -la middleware/session_secure_v3.go
ls -la models/template_secure_v3.go
ls -la monitoring/metrics.go

# Check scripts and tools
ls -la scripts/test-hera-v3.sh
ls -la deployments/zero-downtime-deploy.sh
ls -la deployments/PRODUCTION_CHECKLIST.md

# Check documentation
ls -la HERA_V3_FINAL_ANALYSIS.md
ls -la HERA_V3_INTEGRATION_GUIDE.md
```

### Step 1.3: Set Up Development Environment

```bash
# Create development branch
git checkout -b hera-v3-integration

# Install dependencies
go mod download
go mod tidy

# Run initial build test
go build -o /tmp/gophish-test ./cmd/gophish
```

---

## Phase 2: Core Integration

### Step 2.1: Session Management Integration

#### A. Generate Session Keys

Create a script to generate session keys (if not already present):

```bash
# Create scripts/generate-session-keys.go
cat > scripts/generate-session-keys.go <<'EOF'
package main

import (
    "fmt"
    "github.com/gophish/gophish/middleware"
)

func main() {
    signing, encryption, err := middleware.GenerateSessionKeysV3()
    if err != nil {
        panic(err)
    }

    fmt.Println("==============================================")
    fmt.Println("HERA V3 Session Keys")
    fmt.Println("==============================================")
    fmt.Println("")
    fmt.Println("Add these to your config.json:")
    fmt.Println("")
    fmt.Println("\"session_signing_key\": \"" + signing + "\",")
    fmt.Println("\"session_encryption_key\": \"" + encryption + "\"")
    fmt.Println("")
    fmt.Println("IMPORTANT: Store these securely!")
    fmt.Println("==============================================")
}
EOF

# Generate keys
go run scripts/generate-session-keys.go > session-keys.txt

# Display keys
cat session-keys.txt
```

#### B. Update config.json

Add session keys to your configuration:

```json
{
  "admin_server": {
    "listen_url": "0.0.0.0:3333",
    "use_tls": true,
    "cert_path": "gophish_admin.crt",
    "key_path": "gophish_admin.key"
  },
  "phish_server": {
    "listen_url": "0.0.0.0:80"
  },
  "db_name": "mysql",
  "db_path": "user:password@tcp(localhost:3306)/gophish?charset=utf8&parseTime=True",
  "session_signing_key": "YOUR_GENERATED_SIGNING_KEY_HERE",
  "session_encryption_key": "YOUR_GENERATED_ENCRYPTION_KEY_HERE",
  "cors_origins": [
    "https://admin.example.com",
    "https://*.api.example.com"
  ],
  "cors_cache_ttl": "5m",
  "cors_cache_size": 1000,
  "common_passwords_file": "data/common-passwords.txt"
}
```

#### C. Update main.go

Integrate V3 session management:

```go
// In cmd/gophish/main.go

import (
    "github.com/gophish/gophish/middleware"
    // ... other imports
)

func main() {
    // ... existing code ...

    // Initialize V3 session store
    signingKey := conf.SessionSigningKey
    encryptionKey := conf.SessionEncryptionKey

    if os.Getenv("ENV") == "production" {
        // Production: Require keys
        if err := middleware.InitSessionStoreV3(signingKey, encryptionKey); err != nil {
            log.Fatal(err)
        }
    } else {
        // Development: Allow generation with warning
        if err := middleware.InitSessionStoreWithWarningV3(signingKey, encryptionKey); err != nil {
            log.Fatal(err)
        }
    }

    // Update session options based on TLS configuration
    if err := middleware.UpdateStoreOptionsV3(conf.AdminServer.UseTLS); err != nil {
        log.Error(err)
    }

    // ... rest of initialization ...
}
```

### Step 2.2: CORS Integration

#### A. Update Configuration Structure

Add CORS configuration to config struct:

```go
// In config/config.go

type Config struct {
    // ... existing fields ...
    CORSOrigins    []string `json:"cors_origins"`
    CORSCacheTTL   string   `json:"cors_cache_ttl"`
    CORSCacheSize  int      `json:"cors_cache_size"`
}
```

#### B. Initialize CORS Middleware

```go
// In controllers/route.go or main initialization

import (
    "github.com/gophish/gophish/middleware"
    "time"
)

func CreateAdminRouter() *mux.Router {
    router := mux.NewRouter()

    // Parse cache TTL
    cacheTTL, err := time.ParseDuration(conf.CORSCacheTTL)
    if err != nil {
        cacheTTL = 5 * time.Minute
    }

    // Configure CORS
    corsConfig := middleware.CORSConfigV3{
        AllowedOrigins: conf.CORSOrigins,
        AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
        AllowedHeaders: []string{"Authorization", "Content-Type", "X-Requested-With"},
        MaxAge:         3600,
        CacheTTL:       cacheTTL,
        MaxCacheSize:   conf.CORSCacheSize,
    }

    // Validate CORS configuration
    if err := middleware.ValidateCORSConfigV3(corsConfig); err != nil {
        log.Fatalf("Invalid CORS configuration: %v", err)
    }

    // Apply CORS middleware
    router.Use(middleware.CORSV3(corsConfig))

    // ... rest of router setup ...

    return router
}
```

### Step 2.3: Template Security Integration

#### A. Create Common Password File

```bash
# Create data directory
mkdir -p data

# Download or create common password list
# Example: Top 10,000 common passwords
cat > data/common-passwords.txt <<EOF
# Common passwords database for HERA V3
# One password per line
# Lines starting with # are comments

password
password123
123456
12345678
admin
administrator
welcome
letmein
qwerty
monkey
dragon
master
# ... add more passwords ...
EOF

# Or download a larger list:
# wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt -O data/common-passwords.txt
```

#### B. Load Common Passwords at Startup

```go
// In main.go after session initialization

import (
    "github.com/gophish/gophish/models"
)

func main() {
    // ... session initialization ...

    // Load common password list
    passwordFile := conf.CommonPasswordsFile
    if passwordFile == "" {
        passwordFile = "data/common-passwords.txt"
    }

    if err := models.LoadCommonPasswords(passwordFile); err != nil {
        log.Warnf("Failed to load common passwords: %v (using hardcoded list)", err)
    }

    // ... rest of initialization ...
}
```

#### C. Update Template Execution

Replace existing template execution with V3 version:

```go
// In models/template.go or wherever templates are executed

import (
    "context"
)

// Replace ExecuteTemplate calls with ExecuteTemplateWithRateLimitV3
func (t *Template) Render(data interface{}, userID int64) (string, error) {
    ctx := context.Background()

    // Use V3 with rate limiting
    output, err := ExecuteTemplateWithRateLimitV3(ctx, t.Text, data, userID)
    if err != nil {
        return "", err
    }

    return output, nil
}

// For validation (no rate limit needed)
func (t *Template) Validate() error {
    return ValidateTemplateSafeV3(t.Text)
}
```

### Step 2.4: Monitoring Integration

#### A. Register Metrics Endpoints

```go
// In controllers/route.go

import (
    "github.com/gophish/gophish/monitoring"
)

func CreateAdminRouter() *mux.Router {
    router := mux.NewRouter()

    // ... CORS and other middleware ...

    // Register health check endpoint
    healthCheck := &monitoring.HealthCheck{
        DatabaseCheck: func() error {
            return db.DB().Ping()
        },
        SessionStoreCheck: func() error {
            if middleware.StoreV3 == nil {
                return fmt.Errorf("session store not initialized")
            }
            return nil
        },
        MaxGoroutines: 5000,
        MaxMemoryMB:   1024,
    }

    router.HandleFunc("/health", monitoring.HealthHandler(healthCheck)).Methods("GET")

    // Register metrics endpoints
    router.HandleFunc("/metrics", monitoring.MetricsHandler()).Methods("GET")
    router.HandleFunc("/metrics/prometheus", monitoring.PrometheusHandler()).Methods("GET")

    // ... rest of routes ...

    return router
}
```

#### B. Instrument Code with Metrics

```go
// Example: In CORS middleware (already done in cors_secure_v3.go)
// But you can add more instrumentation in your application code

import "github.com/gophish/gophish/monitoring"

// In login handler
func Login(w http.ResponseWriter, r *http.Request) {
    // ... authentication logic ...

    if authenticated {
        monitoring.IncrementSessionCreated()
    } else {
        monitoring.IncrementSessionValidationError()
    }

    // ... rest of handler ...
}

// In template execution
func ExecuteTemplate(template string, data interface{}) {
    monitoring.IncrementTemplateExecution()

    // ... execution logic ...

    if err != nil {
        monitoring.IncrementTemplateError()
    }
}
```

---

## Phase 3: Monitoring Setup

### Step 3.1: Prometheus Configuration

Create Prometheus configuration:

```yaml
# prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'gophish-hera-v3'
    static_configs:
      - targets: ['localhost:3333']
    metrics_path: '/metrics/prometheus'
```

### Step 3.2: Grafana Dashboard

Import the provided Grafana dashboard JSON:

```json
{
  "dashboard": {
    "title": "Gophish HERA V3 Security Metrics",
    "timezone": "browser",
    "panels": [
      {
        "title": "CORS Rejection Rate",
        "targets": [
          {
            "expr": "rate(gophish_cors_requests_total{allowed=\"false\"}[5m])"
          }
        ],
        "type": "graph"
      },
      {
        "title": "Template Execution Duration (p99)",
        "targets": [
          {
            "expr": "histogram_quantile(0.99, rate(gophish_template_executions_total[5m]))"
          }
        ],
        "type": "graph"
      },
      {
        "title": "Active Template Goroutines",
        "targets": [
          {
            "expr": "gophish_template_goroutines"
          }
        ],
        "type": "graph",
        "alert": {
          "conditions": [
            {
              "evaluator": {
                "params": [100],
                "type": "gt"
              }
            }
          ]
        }
      },
      {
        "title": "System Goroutines",
        "targets": [
          {
            "expr": "gophish_goroutines"
          }
        ],
        "type": "graph"
      },
      {
        "title": "Memory Usage (MB)",
        "targets": [
          {
            "expr": "gophish_memory_mb"
          }
        ],
        "type": "graph"
      },
      {
        "title": "Session Validation Errors",
        "targets": [
          {
            "expr": "rate(gophish_session_validation_errors_total[5m])"
          }
        ],
        "type": "graph"
      }
    ]
  }
}
```

### Step 3.3: Alert Rules

Create Prometheus alert rules:

```yaml
# prometheus-alerts.yml
groups:
  - name: gophish-hera-v3-alerts
    rules:
      - alert: HighCORSRejectionRate
        expr: rate(gophish_cors_requests_total{allowed="false"}[5m]) > 10
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High CORS rejection rate"
          description: "CORS is rejecting {{ $value }} requests/sec for 5 minutes"

      - alert: TemplateGoroutineLeak
        expr: gophish_template_goroutines > 100
        for: 10m
        labels:
          severity: critical
        annotations:
          summary: "Template goroutine leak detected"
          description: "{{ $value }} template goroutines active (threshold: 100)"

      - alert: HighTemplateTimeouts
        expr: rate(gophish_template_timeouts_total[5m]) > 1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High template timeout rate"
          description: "{{ $value }} template timeouts/sec for 5 minutes"

      - alert: SystemGoroutineLeak
        expr: gophish_goroutines > 5000
        for: 10m
        labels:
          severity: critical
        annotations:
          summary: "System goroutine count very high"
          description: "{{ $value }} goroutines (threshold: 5000)"

      - alert: HighMemoryUsage
        expr: gophish_memory_mb > 1024
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "High memory usage"
          description: "Memory usage is {{ $value }} MB (threshold: 1024 MB)"

      - alert: HighSessionErrors
        expr: rate(gophish_session_validation_errors_total[5m]) > 5
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High session validation error rate"
          description: "{{ $value }} session errors/sec for 5 minutes"
```

---

## Phase 4: Testing

### Step 4.1: Run Automated Test Suite

```bash
# Run the complete V3 test suite
./scripts/test-hera-v3.sh

# Review test output
cat /tmp/cors-test.log
cat /tmp/session-test.log
cat /tmp/template-test.log
```

### Step 4.2: Manual Testing

#### Test Session Management
```bash
# Start application
./gophish --config config.json

# Test login
curl -X POST http://localhost:3333/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"password"}' \
  -c cookies.txt

# Test session persistence
curl http://localhost:3333/api/campaigns \
  -b cookies.txt

# Verify session in logs (should NOT see keys logged!)
grep -i "session" gophish.log | grep -v "key"
```

#### Test CORS
```bash
# Test allowed origin
curl -H "Origin: https://admin.example.com" \
  -H "Access-Control-Request-Method: POST" \
  -X OPTIONS \
  http://localhost:3333/api/campaigns

# Should return Access-Control-Allow-Origin header

# Test rejected origin
curl -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: POST" \
  -X OPTIONS \
  http://localhost:3333/api/campaigns

# Should NOT return Access-Control-Allow-Origin header
```

#### Test Template Security
```bash
# Test template with malicious patterns
curl -X POST http://localhost:3333/api/templates/validate \
  -H "Content-Type: application/json" \
  -d '{"text":"{{.Call \"os.Exec\" \"rm -rf /\"}}"}'

# Should return validation error

# Test legitimate template
curl -X POST http://localhost:3333/api/templates/validate \
  -H "Content-Type: application/json" \
  -d '{"text":"Hello {{.FirstName}}"}'

# Should return success
```

#### Test Monitoring
```bash
# Test health endpoint
curl http://localhost:3333/health | jq

# Test metrics endpoint
curl http://localhost:3333/metrics | jq

# Test Prometheus metrics
curl http://localhost:3333/metrics/prometheus
```

### Step 4.3: Load Testing

```bash
# Install Apache Bench if not present
sudo apt-get install apache2-utils

# Run load test
ab -n 10000 -c 100 http://localhost:3333/health

# Monitor goroutines during load
watch -n 1 'curl -s http://localhost:3333/metrics | jq .system_goroutines'

# Monitor memory during load
watch -n 1 'curl -s http://localhost:3333/metrics | jq .system_memory_mb'
```

---

## Phase 5: Deployment

### Step 5.1: Staging Deployment

```bash
# Deploy to staging
scp gophish staging-server:/opt/gophish/
scp config.json staging-server:/opt/gophish/
scp -r data/ staging-server:/opt/gophish/

# SSH to staging
ssh staging-server

# Stop old instance
sudo systemctl stop gophish

# Start new instance
sudo systemctl start gophish

# Monitor logs
sudo journalctl -u gophish -f
```

### Step 5.2: Production Deployment

Use the production checklist and zero-downtime deployment script:

```bash
# Review production checklist
cat deployments/PRODUCTION_CHECKLIST.md

# Run deployment script
./deployments/zero-downtime-deploy.sh \
  --binary ./gophish \
  --config ./config.json \
  --port 3334 \
  --old-port 3333 \
  --wait 30
```

---

## Phase 6: Post-Deployment

### Step 6.1: Immediate Checks (T+0 to T+1 hour)

```bash
# Check application status
curl http://localhost:3333/health | jq .status

# Check metrics
curl http://localhost:3333/metrics | jq

# Check logs for errors
tail -f gophish.log | grep -i error

# Monitor goroutines
watch -n 5 'curl -s http://localhost:3333/metrics | jq .system_goroutines'
```

### Step 6.2: Daily Monitoring (Week 1)

- Check Grafana dashboards daily
- Review error logs
- Monitor goroutine count trends
- Check memory usage trends
- Verify alert rules are working

### Step 6.3: Performance Baseline

Establish baseline metrics after 1 week:

```bash
# Export metrics for baseline
curl http://localhost:3333/metrics > baseline-week1.json

# Compare against future metrics
```

---

## Troubleshooting

### Issue: "session key required" Error

**Cause:** Session keys not configured or invalid format

**Solution:**
```bash
# Regenerate keys
go run scripts/generate-session-keys.go

# Verify keys in config.json
jq '.session_signing_key, .session_encryption_key' config.json

# Verify key format (should be base64)
echo "YOUR_SIGNING_KEY" | base64 -d | wc -c  # Should be 64
echo "YOUR_ENCRYPTION_KEY" | base64 -d | wc -c  # Should be 32
```

### Issue: CORS Blocking Legitimate Origins

**Cause:** Misconfigured CORS origins or cache issue

**Solution:**
```bash
# Check CORS configuration
jq '.cors_origins' config.json

# Test specific origin
curl -v -H "Origin: https://your-origin.com" \
  -H "Access-Control-Request-Method: POST" \
  -X OPTIONS http://localhost:3333/api/campaigns

# Check CORS cache stats
curl http://localhost:3333/metrics | jq | grep cors

# Clear cache (restart application)
sudo systemctl restart gophish
```

### Issue: High Goroutine Count

**Cause:** Template goroutine leak or other goroutine leak

**Solution:**
```bash
# Check template-specific goroutines
curl http://localhost:3333/metrics | jq .active_template_goroutines

# Check template timeouts
curl http://localhost:3333/metrics | jq .total_timeouts

# Generate goroutine profile
curl http://localhost:3333/debug/pprof/goroutine > goroutine.prof

# Analyze with pprof
go tool pprof goroutine.prof

# If leak confirmed, restart application
sudo systemctl restart gophish
```

### Issue: Memory Leak

**Cause:** CORS cache, template rate limiters, or other memory issue

**Solution:**
```bash
# Generate heap profile
curl http://localhost:3333/debug/pprof/heap > heap.prof

# Analyze with pprof
go tool pprof -http=:8080 heap.prof

# Check CORS cache size
curl http://localhost:3333/metrics | jq | grep cache

# Check rate limiter count
curl http://localhost:3333/metrics | jq .rate_limiters_count

# If leak confirmed, restart application
sudo systemctl restart gophish
```

---

## Performance Tuning

### CORS Cache Tuning

```json
// In config.json

// Default: 1000 entries, 5 minutes TTL
"cors_cache_size": 1000,
"cors_cache_ttl": "5m",

// High-traffic sites:
"cors_cache_size": 5000,
"cors_cache_ttl": "10m",

// Low-traffic sites:
"cors_cache_size": 500,
"cors_cache_ttl": "2m"
```

### Template Rate Limiting

Adjust rate limits in code:

```go
// In models/template_secure_v3.go:334

// Default: 10 templates per minute, burst of 5
limiter = rate.NewLimiter(rate.Limit(10.0/60.0), 5)

// For high-volume users:
limiter = rate.NewLimiter(rate.Limit(30.0/60.0), 10)

// For strict rate limiting:
limiter = rate.NewLimiter(rate.Limit(5.0/60.0), 2)
```

### Database Connection Pooling

```go
// In database initialization

db.DB().SetMaxOpenConns(100)       // Default: unlimited
db.DB().SetMaxIdleConns(10)        // Default: 2
db.DB().SetConnMaxLifetime(time.Hour) // Default: unlimited
```

---

## Security Hardening

### Step 1: TLS Configuration

Ensure strong TLS configuration:

```json
// config.json
{
  "admin_server": {
    "use_tls": true,
    "cert_path": "gophish_admin.crt",
    "key_path": "gophish_admin.key",
    "tls_min_version": "1.2"
  }
}
```

### Step 2: CORS Restrictions

Use exact origins in production (avoid wildcards):

```json
// Development
"cors_origins": ["https://*.dev.example.com"]

// Production (preferred)
"cors_origins": [
  "https://admin.example.com",
  "https://api.example.com"
]
```

### Step 3: Common Password List

Use a comprehensive password list:

```bash
# Download RockYou passwords (common breach database)
wget https://github.com/danielmiessler/SecLists/raw/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt \
  -O data/common-passwords.txt
```

### Step 4: Session Security

```json
// config.json - rotate keys quarterly
"session_signing_key": "ROTATE_EVERY_3_MONTHS",
"session_encryption_key": "ROTATE_EVERY_3_MONTHS"
```

### Step 5: Monitoring & Alerting

- Set up PagerDuty/OpsGenie for critical alerts
- Configure Slack/email for warning alerts
- Enable audit logging for security events

---

## Summary

You have successfully integrated HERA V3! Your Gophish instance now has:

✅ Secure session management with persistent keys
✅ Advanced CORS with wildcard patterns and caching
✅ Template security with monitoring and rate limiting
✅ Comprehensive metrics and monitoring
✅ Automated testing suite
✅ Production-ready deployment scripts
✅ Complete operational procedures

**Next Steps:**
1. Monitor metrics daily for the first week
2. Review and adjust rate limits based on usage
3. Set up quarterly security reviews
4. Schedule key rotation
5. Implement disaster recovery procedures

**Support:**
- Review HERA_V3_FINAL_ANALYSIS.md for technical details
- Use deployments/PRODUCTION_CHECKLIST.md for deployments
- Run scripts/test-hera-v3.sh before each deployment

**Version:** HERA V3.0
**Last Updated:** 2025-11-12
**Status:** Production Ready ✅
