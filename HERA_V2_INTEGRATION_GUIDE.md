# HERA V2 Integration Guide - Corrected Security Implementations

## Overview

This guide provides step-by-step instructions for integrating the corrected (V2) security implementations into the Gophish codebase.

**Version:** 2.0 (Corrected)
**Date:** 2025-11-12

---

## What's New in V2

### Critical Bugs Fixed
1. ✅ **Session keys no longer logged** - Removed critical security vulnerability
2. ✅ **Error handling added** - crypto operations now checked for errors
3. ✅ **text/template used** - Maintains phishing email functionality
4. ✅ **Deprecated API removed** - strings.Title replaced
5. ✅ **Race condition fixed** - Mutex added to session store updates
6. ✅ **CORS wildcard support** - Pattern matching for subdomains
7. ✅ **Goroutine leak documented** - Known limitation explained
8. ✅ **Password entropy corrected** - Proper calculation

### New Features
- Wildcard CORS origin support (e.g., `https://*.example.com`)
- Session key validation function
- CORS configuration caching for performance
- Separate production vs development initialization
- Comprehensive error messages

---

## Prerequisites

Before starting integration:
- [ ] Backup current Gophish installation
- [ ] Review HERA_META_ANALYSIS.md for context
- [ ] Test in development environment first
- [ ] Have database backup ready
- [ ] Understand rollback plan

---

## Step 1: Configuration Updates

### 1.1 Update Config Structure

**File:** `config/config.go`

**Change:**
```go
// AdminServer represents the Admin server configuration details
type AdminServer struct {
	ListenURL            string   `json:"listen_url"`
	UseTLS               bool     `json:"use_tls"`
	CertPath             string   `json:"cert_path"`
	KeyPath              string   `json:"key_path"`
	CSRFKey              string   `json:"csrf_key"`
	AllowedInternalHosts []string `json:"allowed_internal_hosts"`
	TrustedOrigins       []string `json:"trusted_origins"`

	// ADD THESE NEW FIELDS:
	SessionSigningKey    string   `json:"session_signing_key"`
	SessionEncryptionKey string   `json:"session_encryption_key"`
	CustomCACertPath     string   `json:"custom_ca_cert_path"`
}
```

### 1.2 Generate Session Keys

**Create:** `scripts/generate-session-keys.go`

```go
package main

import (
	"fmt"
	"os"

	"github.com/gophish/gophish/middleware"
)

func main() {
	signing, encryption, err := middleware.GenerateSessionKeys()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating keys: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Add these to your config.json admin_server section:")
	fmt.Println()
	fmt.Printf("  \"session_signing_key\": \"%s\",\n", signing)
	fmt.Printf("  \"session_encryption_key\": \"%s\"\n", encryption)
	fmt.Println()
	fmt.Println("IMPORTANT: Keep these keys secret and backed up!")
	fmt.Println("If you lose these keys, all user sessions will be invalidated.")
}
```

**Run:**
```bash
go run scripts/generate-session-keys.go
```

**Update:** `config.json`
```json
{
  "admin_server": {
    "listen_url": "127.0.0.1:3333",
    "use_tls": true,
    "cert_path": "gophish_admin.crt",
    "key_path": "gophish_admin.key",
    "trusted_origins": [
      "https://admin.yourdomain.com"
    ],
    "session_signing_key": "<generated-key-here>",
    "session_encryption_key": "<generated-key-here>"
  }
}
```

---

## Step 2: Replace Session Management

### 2.1 Backup Original

```bash
cp middleware/session.go middleware/session.go.backup
```

### 2.2 Replace Implementation

```bash
cp middleware/session_secure_v2.go middleware/session.go
```

### 2.3 Update Main Initialization

**File:** `gophish.go`

**Find:**
```go
// After loading config, before creating servers
```

**Add:**
```go
// Initialize session store with persistent keys
err = middleware.InitSessionStore(
    conf.AdminConf.SessionSigningKey,
    conf.AdminConf.SessionEncryptionKey,
)
if err != nil {
    log.Fatal(err)
}

// Update session cookie secure flag based on TLS
middleware.UpdateStoreOptions(conf.AdminConf.UseTLS)
```

**For Development Only:**
```go
// Development: Allow generating temporary keys
err = middleware.InitSessionStoreWithWarning(
    conf.AdminConf.SessionSigningKey,
    conf.AdminConf.SessionEncryptionKey,
)
```

---

## Step 3: Update CORS Implementation

### 3.1 Backup Original

```bash
cp middleware/middleware.go middleware/middleware.go.backup
```

### 3.2 Add CORS Module

```bash
cp middleware/cors_secure_v2.go middleware/cors.go
```

### 3.3 Update RequireAPIKey Middleware

**File:** `middleware/middleware.go`

**Remove:**
```go
// REMOVE these lines from RequireAPIKey:
w.Header().Set("Access-Control-Allow-Origin", "*")
if r.Method == "OPTIONS" {
    w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
    w.Header().Set("Access-Control-Max-Age", "1000")
    w.Header().Set("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept")
    return
}
```

### 3.4 Apply CORS Middleware

**File:** `controllers/api/server.go`

**In registerRoutes():**
```go
// Apply CORS middleware
corsConfig := middleware.DefaultCORSConfig()
corsConfig.AllowedOrigins = conf.AdminConf.TrustedOrigins

// Validate configuration
if err := middleware.ValidateCORSConfig(corsConfig); err != nil {
    log.Fatalf("Invalid CORS configuration: %v", err)
}

// Compile patterns
if err := middleware.CompileCORSConfig(&corsConfig); err != nil {
    log.Fatalf("Failed to compile CORS config: %v", err)
}

// Apply to API routes
apiHandler = middleware.CORS(corsConfig)(apiHandler)
```

---

## Step 4: Update Template Security

### 4.1 Backup Original

```bash
cp models/template_context.go models/template_context.go.backup
```

### 4.2 Add Secure Template Module

```bash
cp models/template_secure_v2.go models/template_secure_additions.go
```

### 4.3 Update ExecuteTemplate Function

**File:** `models/template_context.go`

**Replace:**
```go
func ExecuteTemplate(text string, data interface{}) (string, error) {
    buff := bytes.Buffer{}
    tmpl, err := template.New("template").Parse(text)
    if err != nil {
        return buff.String(), err
    }
    err = tmpl.Execute(&buff, data)
    return buff.String(), err
}
```

**With:**
```go
// ExecuteTemplate is now in template_secure_additions.go
// Uses ExecuteTemplateSafe with timeout protection
func ExecuteTemplate(text string, data interface{}) (string, error) {
    // For backward compatibility, use safe version with default context
    ctx := context.Background()
    return ExecuteTemplateWithContext(ctx, text, data)
}
```

---

## Step 5: Fix TLS Verification

### 5.1 Update Import.go

**File:** `controllers/api/import.go`

**Find:**
```go
tr := &http.Transport{
    DialContext: restrictedDialer.DialContext,
    TLSClientConfig: &tls.Config{
        InsecureSkipVerify: true,  // REMOVE THIS
    },
}
```

**Replace with:**
```go
// Load custom CA if configured
var tlsConfig *tls.Config
if conf.AdminConf.CustomCACertPath != "" {
    caCert, err := ioutil.ReadFile(conf.AdminConf.CustomCACertPath)
    if err != nil {
        log.Warnf("Failed to load custom CA certificate: %v", err)
        tlsConfig = &tls.Config{
            MinVersion: tls.VersionTLS12,
        }
    } else {
        caCertPool := x509.NewCertPool()
        if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
            log.Warnf("Failed to parse custom CA certificate")
        }
        tlsConfig = &tls.Config{
            RootCAs:    caCertPool,
            MinVersion: tls.VersionTLS12,
        }
        log.Debugf("Using custom CA certificate for site imports")
    }
} else {
    tlsConfig = &tls.Config{
        MinVersion: tls.VersionTLS12,
        // Uses system CA pool by default
    }
}

tr := &http.Transport{
    DialContext: restrictedDialer.DialContext,
    TLSClientConfig: tlsConfig,
}
```

**Add import:**
```go
import (
    // ... existing imports ...
    "crypto/x509"
    "io/ioutil"
)
```

---

## Step 6: Database Migrations

### 6.1 Create Migration for Password History

**File:** `db/db_sqlite3/migrations/20251112000000_password_history.sql`

```sql
-- +goose Up
CREATE TABLE IF NOT EXISTS password_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    hash TEXT NOT NULL,
    changed_at DATETIME NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_password_history_user_id ON password_history(user_id);
CREATE INDEX idx_password_history_changed_at ON password_history(changed_at);

-- +goose Down
DROP INDEX IF EXISTS idx_password_history_changed_at;
DROP INDEX IF EXISTS idx_password_history_user_id;
DROP TABLE IF EXISTS password_history;
```

**For MySQL:**
**File:** `db/db_mysql/migrations/20251112000000_password_history.sql`

```sql
-- +goose Up
CREATE TABLE IF NOT EXISTS password_history (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    user_id BIGINT NOT NULL,
    hash VARCHAR(255) NOT NULL,
    changed_at DATETIME NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE INDEX idx_password_history_user_id ON password_history(user_id);
CREATE INDEX idx_password_history_changed_at ON password_history(changed_at);

-- +goose Down
DROP TABLE IF EXISTS password_history;
```

### 6.2 Run Migration

```bash
# Backup database first!
cp gophish.db gophish.db.backup

# Run Gophish - migrations run automatically on startup
./gophish
```

---

## Step 7: Update Security Headers

**File:** `middleware/middleware.go`

**Update ApplySecurityHeaders:**
```go
func ApplySecurityHeaders(next http.Handler) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Content Security Policy
        csp := "default-src 'self'; " +
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
            "style-src 'self' 'unsafe-inline'; " +
            "img-src 'self' data: https:; " +
            "font-src 'self' data:; " +
            "connect-src 'self'; " +
            "frame-ancestors 'none';"
        w.Header().Set("Content-Security-Policy", csp)

        // Clickjacking protection
        w.Header().Set("X-Frame-Options", "DENY")

        // Prevent MIME sniffing
        w.Header().Set("X-Content-Type-Options", "nosniff")

        // XSS Protection (legacy browsers)
        w.Header().Set("X-XSS-Protection", "1; mode=block")

        // Referrer policy
        w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

        // Permissions policy
        w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

        next.ServeHTTP(w, r)
    }
}
```

---

## Step 8: Testing

### 8.1 Unit Tests

Create test files:

**File:** `middleware/session_test.go`
```go
package middleware

import (
    "testing"
)

func TestSessionKeyGeneration(t *testing.T) {
    signing, encryption, err := GenerateSessionKeys()
    if err != nil {
        t.Fatalf("Failed to generate keys: %v", err)
    }

    if signing == "" || encryption == "" {
        t.Fatal("Generated empty keys")
    }

    // Test validation
    err = ValidateSessionKeys(signing, encryption)
    if err != nil {
        t.Fatalf("Generated keys failed validation: %v", err)
    }
}

func TestSessionKeyValidation(t *testing.T) {
    tests := []struct {
        name        string
        signing     string
        encryption  string
        shouldError bool
    }{
        {"empty keys", "", "", true},
        {"invalid base64", "not-base64!", "not-base64!", true},
        {"wrong length", "AAAA", "BBBB", true},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := ValidateSessionKeys(tt.signing, tt.encryption)
            if tt.shouldError && err == nil {
                t.Error("Expected error but got none")
            }
            if !tt.shouldError && err != nil {
                t.Errorf("Unexpected error: %v", err)
            }
        })
    }
}
```

**Run tests:**
```bash
go test ./middleware/... -v
go test ./models/... -v
```

### 8.2 Integration Tests

**Test checklist:**
- [ ] Session persistence across restarts
- [ ] CORS with allowed origins
- [ ] CORS with wildcard patterns
- [ ] CORS rejection of non-allowed origins
- [ ] Template execution with timeout
- [ ] Template validation blocks dangerous patterns
- [ ] Password strength validation
- [ ] TLS certificate verification (try invalid cert)

### 8.3 Security Tests

```bash
# Test CORS
curl -H "Origin: https://evil.com" http://localhost:3333/api/campaigns/

# Test template timeout (create campaign with slow template)

# Test certificate verification
# (try to import site with self-signed cert)
```

---

## Step 9: Deployment

### 9.1 Staging Deployment

1. Deploy to staging environment
2. Run automated tests
3. Manual testing of critical flows:
   - Login/logout
   - Campaign creation
   - Template rendering
   - API access
4. Monitor for errors
5. Performance testing

### 9.2 Production Deployment

```bash
# 1. Backup
./backup-gophish.sh

# 2. Stop service
systemctl stop gophish

# 3. Deploy new version
cp gophish gophish.backup
cp gophish-new gophish

# 4. Update config
cp config.json config.json.backup
# Edit config.json with new fields

# 5. Start service
systemctl start gophish

# 6. Monitor logs
tail -f /var/log/gophish/gophish.log

# 7. Verify
curl https://localhost:3333/
```

### 9.3 Rollback Plan

If issues occur:
```bash
# 1. Stop service
systemctl stop gophish

# 2. Restore backup
cp gophish.backup gophish
cp config.json.backup config.json
cp gophish.db.backup gophish.db

# 3. Start service
systemctl start gophish
```

---

## Step 10: Monitoring

### 10.1 Metrics to Track

Add to monitoring:
- Session validation failures
- CORS rejection rate
- Template execution timeouts
- Template validation failures
- API authentication failures
- TLS certificate validation failures

### 10.2 Alerts

Configure alerts for:
- High rate of session failures (>100/min)
- Multiple CORS rejections from same IP
- Template timeouts (>10/hour)
- TLS verification failures

### 10.3 Logging

Ensure logging captures:
```go
log.SetLevel(log.InfoLevel) // Production
log.SetLevel(log.DebugLevel) // Troubleshooting
```

---

## Common Issues and Solutions

### Issue: Sessions Invalidated on Restart

**Cause:** Session keys not in config or changing
**Solution:** Ensure session_signing_key and session_encryption_key are in config.json

### Issue: CORS Errors After Update

**Cause:** trusted_origins not configured
**Solution:** Add trusted origins to config.json:
```json
"trusted_origins": ["https://admin.yourdomain.com"]
```

### Issue: Templates Not Rendering

**Cause:** Template validation too strict
**Solution:** Check logs for validation errors, adjust dangerousPatterns if needed

### Issue: Database Lock Errors (SQLite)

**Cause:** Connection pool too large for SQLite
**Solution:** Use MySQL/PostgreSQL for production or reduce max_open_connections

---

## Performance Considerations

### Expected Performance Impact

- **Session validation:** Negligible (<1ms)
- **CORS checking:** ~0.1ms per request (cached)
- **Template execution:** +1-5ms for timeout wrapper
- **Template validation:** +10-50ms on template creation only

### Optimization Tips

1. **CORS cache:** Already implemented, grows to 1000 entries
2. **Template pre-validation:** Validate templates on creation, not execution
3. **Database connection pool:** Tune based on workload

---

## Security Checklist

After integration, verify:
- [ ] Session keys are in config and not logged
- [ ] TLS certificate verification enabled
- [ ] CORS configured with trusted origins only
- [ ] Templates validated before use
- [ ] Security headers present in responses
- [ ] API keys only in Authorization header
- [ ] Database connection pool appropriately sized
- [ ] All tests passing
- [ ] No deprecation warnings
- [ ] Monitoring and alerting configured

---

## Additional Resources

- **HERA_SECURITY_ANALYSIS.md** - Original findings
- **HERA_META_ANALYSIS.md** - Critical review and bug fixes
- **HERA_IMPLEMENTATION_PLAN.md** - Original implementation guide
- **Go Security Best Practices** - https://go.dev/doc/security/best-practices
- **OWASP Top 10** - https://owasp.org/www-project-top-ten/

---

## Support and Troubleshooting

### Debug Mode

Enable debug logging:
```go
log.SetLevel(log.DebugLevel)
```

### Verify Configuration

```go
// Add to gophish.go main() for startup verification
log.Info("Configuration verification:")
log.Infof("- Session signing key configured: %v", conf.AdminConf.SessionSigningKey != "")
log.Infof("- Session encryption key configured: %v", conf.AdminConf.SessionEncryptionKey != "")
log.Infof("- Trusted origins: %v", conf.AdminConf.TrustedOrigins)
log.Infof("- Custom CA configured: %v", conf.AdminConf.CustomCACertPath != "")
```

### Test Each Component

```bash
# Test session management
go test -v ./middleware -run TestSession

# Test CORS
go test -v ./middleware -run TestCORS

# Test templates
go test -v ./models -run TestTemplate
```

---

## Migration Timeline

**Recommended schedule:**

- **Week 1:** Development environment integration and testing
- **Week 2:** Staging deployment and validation
- **Week 3:** Production deployment (off-hours)
- **Week 4:** Monitoring and optimization

**Estimated effort:** 40-60 hours for complete integration and testing

---

**Guide Version:** 2.0
**Last Updated:** 2025-11-12
**Next Review:** After successful production deployment

