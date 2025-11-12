# Migrating from HERA V2 to V3

This guide provides step-by-step instructions for migrating from HERA V2 to V3.

## Overview

**Migration Complexity:** Low to Medium
**Estimated Time:** 2-4 hours
**Downtime Required:** No (with zero-downtime deployment)
**Risk Level:** Low (V3 files are separate, V2 remains functional)

## What Changed from V2 to V3

### Critical Fixes in V3

| Issue | V2 Behavior | V3 Fix |
|-------|-------------|--------|
| **CORS Subdomain Pattern** | `*.example.com` only matched `admin.example.com` | Now matches `api.v2.example.com`, ports `:8443` |
| **Origin Cache** | Fixed 1000 limit, no eviction | LRU cache with TTL, automatic eviction |
| **Goroutine Monitoring** | No visibility | Metrics tracking with alerting |
| **Rate Limiting** | None | Per-user template rate limiting (10/min) |
| **Session Initialization** | Potential race condition | Thread-safe with `sync.Once` |
| **Common Passwords** | Hardcoded list (~30) | File-based (supports 1M+) |

### New Features in V3

- Complete monitoring stack (Prometheus + Grafana)
- Automated test suite
- Zero-downtime deployment tools
- Production checklist
- Integration examples

## Pre-Migration Checklist

- [ ] **Backup everything**
  - Database (full backup)
  - Configuration files
  - Current binary
  - Application data

- [ ] **Test V3 in development**
  - Set up dev environment
  - Run automated tests
  - Verify functionality

- [ ] **Review V3 documentation**
  - [HERA_V3_FINAL_ANALYSIS.md](HERA_V3_FINAL_ANALYSIS.md)
  - [HERA_V3_INTEGRATION_GUIDE.md](HERA_V3_INTEGRATION_GUIDE.md)
  - [HERA_V3_README.md](HERA_V3_README.md)

- [ ] **Plan monitoring**
  - Prometheus setup
  - Grafana dashboard
  - Alert configuration

## Migration Strategy

### Option A: Gradual Migration (Recommended)

Migrate one component at a time, testing at each step.

### Option B: Full Migration

Migrate all components in one deployment (faster but riskier).

### Option C: Parallel Running

Run V2 and V3 side-by-side temporarily (most cautious).

---

## Step-by-Step Migration (Option A: Gradual)

### Phase 1: Preparation (Week 1)

#### 1.1 Verify V3 Files Exist

```bash
# Check V3 implementations
ls -la middleware/cors_secure_v3.go
ls -la middleware/session_secure_v3.go
ls -la models/template_secure_v3.go
ls -la monitoring/metrics.go

# Check tests
ls -la middleware/*_v3_test.go
ls -la models/*_v3_test.go

# Check tools
ls -la scripts/test-hera-v3.sh
ls -la scripts/generate-session-keys.go
ls -la deployments/zero-downtime-deploy.sh
```

#### 1.2 Run V3 Tests

```bash
# Run full test suite
./scripts/test-hera-v3.sh

# Expected: All tests pass
```

#### 1.3 Create Staging Environment

```bash
# Copy production config to staging
cp config.json config-staging.json

# Update staging-specific values
vim config-staging.json
```

### Phase 2: Session Management (Week 2)

#### 2.1 Generate New Session Keys

```bash
# Generate keys
go run scripts/generate-session-keys.go > session-keys-v3.txt

# Review keys
cat session-keys-v3.txt
```

#### 2.2 Update Configuration

Add to your `config.json`:

```json
{
  "session_signing_key": "YOUR_NEW_SIGNING_KEY",
  "session_encryption_key": "YOUR_NEW_ENCRYPTION_KEY"
}
```

**IMPORTANT:** Store keys securely (environment variables, vault, etc.)

#### 2.3 Update Code to Use V3 Sessions

Find your session initialization code:

```go
// OLD (V2):
if err := middleware.InitSessionStore(signingKey, encryptionKey); err != nil {
    log.Fatal(err)
}

// NEW (V3):
if err := middleware.InitSessionStoreV3(signingKey, encryptionKey); err != nil {
    log.Fatal(err)
}

middleware.UpdateStoreOptionsV3(config.AdminServer.UseTLS)
```

#### 2.4 Update Session Usage

Find references to `middleware.Store`:

```go
// OLD (V2):
session, _ := middleware.Store.Get(r, "gophish")

// NEW (V3):
session, _ := middleware.StoreV3.Get(r, "gophish")
```

**Find all references:**
```bash
grep -r "middleware\.Store\." --include="*.go"
```

#### 2.5 Test Session Management

```bash
# Build
go build -o gophish-v3-test

# Run
./gophish-v3-test --config config-staging.json

# Test login/logout
curl -X POST http://localhost:3333/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"password"}' \
  -c cookies.txt

# Verify session persists
curl http://localhost:3333/api/campaigns -b cookies.txt
```

### Phase 3: CORS Enhancement (Week 2)

#### 3.1 Update Configuration

Add CORS settings to `config.json`:

```json
{
  "cors_origins": [
    "https://admin.example.com",
    "https://*.api.example.com"
  ],
  "cors_cache_ttl": "5m",
  "cors_cache_size": 1000
}
```

#### 3.2 Update CORS Middleware

Find your CORS middleware setup:

```go
// OLD (V2):
corsConfig := middleware.CORSConfig{
    AllowedOrigins: config.CORSOrigins,
    // ...
}
router.Use(middleware.CORS(corsConfig))

// NEW (V3):
corsConfig := middleware.CORSConfigV3{
    AllowedOrigins: config.CORSOrigins,
    AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
    AllowedHeaders: []string{"Authorization", "Content-Type"},
    MaxAge:         3600,
    CacheTTL:       5 * time.Minute,
    MaxCacheSize:   1000,
}

// Validate config
if err := middleware.ValidateCORSConfigV3(corsConfig); err != nil {
    log.Fatalf("Invalid CORS config: %v", err)
}

router.Use(middleware.CORSV3(corsConfig))
```

#### 3.3 Test CORS

```bash
# Test allowed origin
curl -H "Origin: https://admin.example.com" \
  -H "Access-Control-Request-Method: POST" \
  -X OPTIONS \
  http://localhost:3333/api/campaigns

# Should return Access-Control-Allow-Origin header

# Test multi-level subdomain (V3 feature)
curl -H "Origin: https://api.v2.example.com" \
  -H "Access-Control-Request-Method: POST" \
  -X OPTIONS \
  http://localhost:3333/api/campaigns

# Should return Access-Control-Allow-Origin header (NEW IN V3!)

# Test rejected origin
curl -H "Origin: https://evil.com" \
  -X OPTIONS \
  http://localhost:3333/api/campaigns

# Should NOT return Access-Control-Allow-Origin header
```

### Phase 4: Template Security (Week 3)

#### 4.1 Load Common Password List

```bash
# Use provided sample
cp data/common-passwords.txt /etc/gophish/data/

# OR download comprehensive list
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-100000.txt \
  -O /etc/gophish/data/common-passwords.txt
```

#### 4.2 Update Configuration

```json
{
  "common_passwords_file": "/etc/gophish/data/common-passwords.txt"
}
```

#### 4.3 Load Passwords at Startup

```go
// In main.go after session initialization
if err := models.LoadCommonPasswords(config.CommonPasswordsFile); err != nil {
    log.Warnf("Failed to load common passwords: %v (using hardcoded list)", err)
}
```

#### 4.4 Update Template Execution

Find template execution code:

```go
// OLD (V2):
output, err := models.ExecuteTemplateSafe(text, data)

// NEW (V3) - with rate limiting:
ctx := context.Background()
output, err := models.ExecuteTemplateWithRateLimitV3(ctx, text, data, userID)

// NEW (V3) - without rate limiting (for system templates):
ctx := context.Background()
output, err := models.ExecuteTemplateWithContextV3(ctx, text, data)
```

#### 4.5 Update Password Validation

```go
// OLD (V2):
strength := models.CheckPasswordStrength(password)

// NEW (V3):
strength := models.CheckPasswordStrengthV3(password)

if strength.Score < 3 {
    return fmt.Errorf("password too weak: %s", strings.Join(strength.Feedback, ", "))
}
```

### Phase 5: Monitoring Setup (Week 3)

#### 5.1 Add Health Check Endpoint

```go
// In your router setup
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
```

#### 5.2 Add Metrics Endpoints

```go
// Create separate metrics router on port 9090
metricsRouter := mux.NewRouter()
metricsRouter.HandleFunc("/metrics", monitoring.MetricsHandler()).Methods("GET")
metricsRouter.HandleFunc("/metrics/prometheus", monitoring.PrometheusHandler()).Methods("GET")

go func() {
    log.Info("Starting metrics server on :9090")
    http.ListenAndServe(":9090", metricsRouter)
}()
```

#### 5.3 Configure Prometheus

```bash
# Copy alert rules
sudo cp monitoring/prometheus/alert-rules.yml /etc/prometheus/

# Update prometheus.yml
sudo vim /etc/prometheus/prometheus.yml
```

Add to `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'gophish-v3'
    static_configs:
      - targets: ['localhost:9090']
    metrics_path: '/metrics/prometheus'

rule_files:
  - "alert-rules.yml"
```

#### 5.4 Import Grafana Dashboard

```bash
curl -X POST http://grafana:3000/api/dashboards/db \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d @monitoring/grafana/hera-v3-dashboard.json
```

### Phase 6: Testing (Week 4)

#### 6.1 Run Full Test Suite

```bash
./scripts/test-hera-v3.sh
```

#### 6.2 Manual Testing

```bash
# Test all critical paths
./deployments/manual-test-checklist.sh
```

#### 6.3 Load Testing

```bash
# Install Apache Bench
sudo apt-get install apache2-utils

# Run load test
ab -n 10000 -c 100 http://localhost:3333/health

# Monitor metrics during load
watch -n 1 'curl -s http://localhost:9090/metrics | jq .system_goroutines'
```

### Phase 7: Production Deployment (Week 5)

#### 7.1 Review Production Checklist

```bash
cat deployments/PRODUCTION_CHECKLIST.md
```

#### 7.2 Final Backups

```bash
# Database
mysqldump -u gophish -p gophish > backup-$(date +%Y%m%d-%H%M%S).sql

# Config
cp config.json config.json.backup-$(date +%Y%m%d-%H%M%S)

# Binary
cp gophish gophish.backup-$(date +%Y%m%d-%H%M%S)
```

#### 7.3 Zero-Downtime Deployment

```bash
./deployments/zero-downtime-deploy.sh \
  --binary ./gophish-v3 \
  --config ./config.json \
  --port 3334 \
  --old-port 3333 \
  --wait 30
```

#### 7.4 Post-Deployment Verification

```bash
# Check health
curl http://localhost:3333/health | jq

# Expected:
# {
#   "status": "healthy",
#   "checks": {
#     "database": "ok",
#     "session_store": "ok",
#     "goroutines": "ok",
#     "memory": "ok"
#   }
# }

# Check metrics
curl http://localhost:9090/metrics | jq

# Test critical paths
curl -X POST http://localhost:3333/api/login -d '{"username":"admin","password":"password"}'
```

---

## Rollback Procedure

If issues occur, follow these steps:

### 1. Stop New Version

```bash
kill $(cat gophish.pid)
```

### 2. Restore Old Binary

```bash
cp gophish.backup-TIMESTAMP gophish
chmod +x gophish
```

### 3. Restore Old Config

```bash
cp config.json.backup-TIMESTAMP config.json
```

### 4. Restore Database (if migrations ran)

```bash
mysql -u gophish -p gophish < backup-TIMESTAMP.sql
```

### 5. Start Old Version

```bash
./gophish --config config.json &
```

### 6. Verify

```bash
curl http://localhost:3333/health
```

---

## Common Migration Issues

### Issue: Session Keys Don't Work

**Symptoms:** "session key required" error

**Solution:**
```bash
# Verify keys are base64 encoded
echo "YOUR_KEY" | base64 -d | wc -c

# Signing key should be 64 bytes
# Encryption key should be 32 bytes

# Regenerate if needed
go run scripts/generate-session-keys.go
```

### Issue: CORS Still Blocking Multi-Level Subdomains

**Symptoms:** `api.v2.example.com` blocked

**Solution:**
```bash
# Verify using V3 middleware
grep "CORSV3" your-code.go

# Check cache is being used
curl http://localhost:9090/metrics | jq | grep cors_cache

# Clear cache if needed (restart application)
```

### Issue: Template Rate Limiting Too Aggressive

**Symptoms:** "rate limit exceeded" errors

**Solution:**
```go
// In models/template_secure_v3.go:334
// Adjust rate limit:
// Default: 10 templates per minute, burst of 5
limiter = rate.NewLimiter(rate.Limit(10.0/60.0), 5)

// Increase to 30/min:
limiter = rate.NewLimiter(rate.Limit(30.0/60.0), 10)
```

### Issue: Monitoring Endpoints Not Accessible

**Symptoms:** 404 on `/health` or `/metrics`

**Solution:**
```go
// Verify endpoints registered
router.HandleFunc("/health", monitoring.HealthHandler(healthCheck)).Methods("GET")

// Check metrics on separate port
curl http://localhost:9090/metrics
```

---

## V2 to V3 Code Mapping

| V2 Function/Type | V3 Equivalent | Notes |
|------------------|---------------|-------|
| `middleware.InitSessionStore` | `middleware.InitSessionStoreV3` | Thread-safe with sync.Once |
| `middleware.Store` | `middleware.StoreV3` | Update all references |
| `middleware.CORS` | `middleware.CORSV3` | Enhanced pattern matching |
| `middleware.CORSConfig` | `middleware.CORSConfigV3` | Added cache settings |
| `models.ExecuteTemplateSafe` | `models.ExecuteTemplateSafeV3` | Same API |
| `models.ExecuteTemplateWithContext` | `models.ExecuteTemplateWithContextV3` | Added monitoring |
| - | `models.ExecuteTemplateWithRateLimitV3` | **NEW:** With rate limiting |
| `models.CheckPasswordStrength` | `models.CheckPasswordStrengthV3` | Enhanced entropy |
| - | `models.LoadCommonPasswords` | **NEW:** File-based passwords |

---

## Testing Migration Success

Run this checklist after migration:

```bash
# 1. All tests pass
./scripts/test-hera-v3.sh

# 2. Health check healthy
curl http://localhost:3333/health | jq .status
# Expected: "healthy"

# 3. Metrics available
curl http://localhost:9090/metrics | jq keys

# 4. CORS working (test your origins)
curl -H "Origin: https://YOUR_ORIGIN" \
  -X OPTIONS http://localhost:3333/api/campaigns

# 5. Multi-level subdomains work (V3 feature)
curl -H "Origin: https://api.v2.YOUR_DOMAIN" \
  -X OPTIONS http://localhost:3333/api/campaigns

# 6. Sessions persist
curl -X POST http://localhost:3333/api/login -c cookies.txt -d '...'
curl http://localhost:3333/api/campaigns -b cookies.txt
# Should work without re-authenticating

# 7. Template rate limiting works
# Submit 6 templates rapidly - 6th should fail

# 8. Goroutine count stable
watch -n 5 'curl -s http://localhost:9090/metrics | jq .system_goroutines'
# Should stay < 100 under normal load

# 9. Grafana dashboard shows data
# Open http://grafana:3000/d/hera-v3

# 10. Alerts configured
# Check Prometheus: http://prometheus:9090/alerts
```

---

## Post-Migration Monitoring

Monitor these metrics for first 7 days:

- **Goroutine count** - Should stay < 1000
- **Memory usage** - Should stay < 1GB
- **CORS rejection rate** - Should match baseline
- **Template timeout rate** - Should be < 1/min
- **Session validation errors** - Should be low
- **Cache hit rate** - Should be > 80%

---

## Getting Help

If you encounter issues:

1. **Check logs:** `tail -f gophish.log | grep ERROR`
2. **Review documentation:** [HERA_V3_INTEGRATION_GUIDE.md](HERA_V3_INTEGRATION_GUIDE.md)
3. **Run diagnostics:** `./scripts/test-hera-v3.sh`
4. **Check metrics:** `curl http://localhost:9090/metrics | jq`
5. **Open issue:** Include logs, config (redact keys), metrics

---

**Migration Version:** 2.0 → 3.0
**Last Updated:** 2025-11-12
**Estimated Time:** 2-4 weeks
**Risk Level:** Low
**Recommended Approach:** Gradual (Option A)
