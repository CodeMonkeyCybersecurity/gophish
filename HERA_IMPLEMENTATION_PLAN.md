# HERA Implementation Plan - Security Improvements

## Overview
This document provides specific, actionable implementation details for addressing the security vulnerabilities identified in the HERA Security Analysis.

---

## CRITICAL PRIORITY IMPLEMENTATIONS

### C-1: Fix TLS Certificate Verification

**File:** `controllers/api/import.go`
**Lines:** 118-124

**Current Code:**
```go
restrictedDialer := dialer.Dialer()
tr := &http.Transport{
    DialContext: restrictedDialer.DialContext,
    TLSClientConfig: &tls.Config{
        InsecureSkipVerify: true,  // REMOVE THIS
    },
}
```

**Fixed Code:**
```go
restrictedDialer := dialer.Dialer()
tr := &http.Transport{
    DialContext: restrictedDialer.DialContext,
    TLSClientConfig: &tls.Config{
        MinVersion: tls.VersionTLS12,
        // If custom CA is needed, add RootCAs here
        // RootCAs: customCAPool,
    },
}
```

**Additional Changes:**
1. Add optional custom CA certificate support in config:
```go
// config/config.go - add to AdminServer struct
CustomCACertPath string `json:"custom_ca_cert_path"`
```

2. Load custom CA if provided:
```go
// In import.go, add before creating transport
var tlsConfig *tls.Config
if conf.AdminConf.CustomCACertPath != "" {
    caCert, err := ioutil.ReadFile(conf.AdminConf.CustomCACertPath)
    if err != nil {
        return err
    }
    caCertPool := x509.NewCertPool()
    caCertPool.AppendCertsFromPEM(caCert)
    tlsConfig = &tls.Config{
        RootCAs:    caCertPool,
        MinVersion: tls.VersionTLS12,
    }
} else {
    tlsConfig = &tls.Config{
        MinVersion: tls.VersionTLS12,
    }
}
```

**Testing:**
```bash
# Test that HTTPS sites with valid certs work
# Test that invalid certs are rejected
# Test that custom CA works if configured
```

---

### C-2: Persistent Session Keys

**File:** `middleware/session.go`
**Lines:** 21-23

**Current Code:**
```go
var Store = sessions.NewCookieStore(
    []byte(securecookie.GenerateRandomKey(64)),
    []byte(securecookie.GenerateRandomKey(32)))
```

**New Implementation:**

**Step 1:** Add to config structure
```go
// config/config.go - add to AdminServer struct
SessionSigningKey    string `json:"session_signing_key"`
SessionEncryptionKey string `json:"session_encryption_key"`
```

**Step 2:** Create key management helper
```go
// middleware/session.go - new file structure

package middleware

import (
    "crypto/rand"
    "encoding/base64"
    "encoding/gob"
    "fmt"
    "io"

    "github.com/gophish/gophish/models"
    "github.com/gorilla/securecookie"
    "github.com/gorilla/sessions"
)

var Store *sessions.CookieStore

// init registers the necessary models
func init() {
    gob.Register(&models.User{})
    gob.Register(&models.Flash{})
}

// InitSessionStore initializes the session store with provided keys
// If keys are empty, generates new ones (should only happen on first install)
func InitSessionStore(signingKey, encryptionKey string) error {
    var signingKeyBytes, encryptionKeyBytes []byte
    var err error

    if signingKey == "" {
        signingKeyBytes = securecookie.GenerateRandomKey(64)
        log.Warn("No signing key provided, generated new key. Add to config.json for persistence.")
        log.Infof("session_signing_key: %s", base64.StdEncoding.EncodeToString(signingKeyBytes))
    } else {
        signingKeyBytes, err = base64.StdEncoding.DecodeString(signingKey)
        if err != nil {
            return fmt.Errorf("invalid signing key: %v", err)
        }
        if len(signingKeyBytes) != 64 {
            return fmt.Errorf("signing key must be 64 bytes (base64 encoded)")
        }
    }

    if encryptionKey == "" {
        encryptionKeyBytes = securecookie.GenerateRandomKey(32)
        log.Warn("No encryption key provided, generated new key. Add to config.json for persistence.")
        log.Infof("session_encryption_key: %s", base64.StdEncoding.EncodeToString(encryptionKeyBytes))
    } else {
        encryptionKeyBytes, err = base64.StdEncoding.DecodeString(encryptionKey)
        if err != nil {
            return fmt.Errorf("invalid encryption key: %v", err)
        }
        if len(encryptionKeyBytes) != 32 {
            return fmt.Errorf("encryption key must be 32 bytes (base64 encoded)")
        }
    }

    Store = sessions.NewCookieStore(signingKeyBytes, encryptionKeyBytes)
    Store.Options.HttpOnly = true
    Store.Options.SameSite = http.SameSiteStrictMode
    Store.MaxAge(86400 * 5) // 5 days

    return nil
}

// GenerateSessionKeys generates new session keys for initial setup
func GenerateSessionKeys() (signing, encryption string) {
    signingKey := make([]byte, 64)
    encryptionKey := make([]byte, 32)

    io.ReadFull(rand.Reader, signingKey)
    io.ReadFull(rand.Reader, encryptionKey)

    return base64.StdEncoding.EncodeToString(signingKey),
           base64.StdEncoding.EncodeToString(encryptionKey)
}
```

**Step 3:** Update main initialization
```go
// gophish.go - in main() after loading config

// Initialize session store with persistent keys
err = middleware.InitSessionStore(
    conf.AdminConf.SessionSigningKey,
    conf.AdminConf.SessionEncryptionKey,
)
if err != nil {
    log.Fatal(err)
}
```

**Step 4:** Create migration script
```go
// scripts/generate-session-keys.go
package main

import (
    "fmt"
    "github.com/gophish/gophish/middleware"
)

func main() {
    signing, encryption := middleware.GenerateSessionKeys()
    fmt.Println("Add these to your config.json admin_server section:")
    fmt.Printf("  \"session_signing_key\": \"%s\",\n", signing)
    fmt.Printf("  \"session_encryption_key\": \"%s\"\n", encryption)
}
```

**Testing:**
```bash
# Generate keys
go run scripts/generate-session-keys.go

# Add to config.json
# Restart server
# Verify sessions persist across restarts
# Verify old sessions are invalidated when keys change
```

---

### C-3: Fix CORS Policy

**File:** `middleware/middleware.go`
**Lines:** 76-110

**Current Code:**
```go
func RequireAPIKey(handler http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Access-Control-Allow-Origin", "*")  // BAD!
        // ...
    })
}
```

**Fixed Implementation:**

**Step 1:** Create CORS middleware
```go
// middleware/cors.go - new file
package middleware

import (
    "net/http"
    "strings"

    "github.com/gophish/gophish/config"
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
        AllowedOrigins: []string{}, // Empty = no CORS
        AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
        AllowedHeaders: []string{"Authorization", "Content-Type"},
        MaxAge:         3600,
    }
}

// CORS returns a middleware that handles CORS with allowlist
func CORS(config CORSConfig) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            origin := r.Header.Get("Origin")

            // If no allowed origins configured, don't set CORS headers
            if len(config.AllowedOrigins) == 0 {
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
                // Origin not allowed, but don't error - just don't set CORS headers
                // This allows same-origin requests to work
                if origin != "" {
                    log.Warnf("CORS request from non-allowed origin: %s", origin)
                }
                next.ServeHTTP(w, r)
                return
            }

            // Set CORS headers for allowed origin
            w.Header().Set("Access-Control-Allow-Origin", origin)
            w.Header().Set("Access-Control-Allow-Methods", strings.Join(config.AllowedMethods, ", "))
            w.Header().Set("Access-Control-Allow-Headers", strings.Join(config.AllowedHeaders, ", "))
            w.Header().Set("Access-Control-Max-Age", fmt.Sprintf("%d", config.MaxAge))
            w.Header().Set("Access-Control-Allow-Credentials", "true")

            // Handle preflight
            if r.Method == "OPTIONS" {
                w.WriteHeader(http.StatusOK)
                return
            }

            next.ServeHTTP(w, r)
        })
    }
}
```

**Step 2:** Update API server to use new CORS
```go
// controllers/api/server.go - update registerRoutes

func (as *Server) registerRoutes() {
    // ... existing code ...

    // Apply CORS middleware
    corsConfig := middleware.DefaultCORSConfig()
    corsConfig.AllowedOrigins = conf.AdminConf.TrustedOrigins

    handler = middleware.CORS(corsConfig)(handler)

    // ... rest of middleware chain ...
}
```

**Step 3:** Remove old CORS code
```go
// middleware/middleware.go - in RequireAPIKey
// REMOVE these lines:
// w.Header().Set("Access-Control-Allow-Origin", "*")
// if r.Method == "OPTIONS" { ... }
```

**Step 4:** Update config documentation
```json
// config.json example
{
  "admin_server": {
    "trusted_origins": [
      "https://admin.example.com",
      "https://dashboard.example.com"
    ]
  }
}
```

**Testing:**
```bash
# Test that requests from non-allowed origins are blocked
# Test that trusted origins work
# Test that same-origin requests work
# Test OPTIONS preflight requests
```

---

### C-4: Template Injection Protection

**File:** `models/template_context.go`
**Lines:** 77-84

**Current Code:**
```go
func ExecuteTemplate(text string, data interface{}) (string, error) {
    buff := bytes.Buffer{}
    tmpl, err := template.New("template").Parse(text)
    // Uses text/template - unsafe!
    err = tmpl.Execute(&buff, data)
    return buff.String(), err
}
```

**Fixed Implementation:**

**Step 1:** Create safe template executor
```go
// models/template_context.go - replace ExecuteTemplate

import (
    "bytes"
    "html/template"  // Changed from text/template
    "fmt"
)

// AllowedTemplateFuncs returns the safe set of functions available in templates
func AllowedTemplateFuncs() template.FuncMap {
    return template.FuncMap{
        // String functions
        "lower":    strings.ToLower,
        "upper":    strings.ToUpper,
        "title":    strings.Title,
        "trim":     strings.TrimSpace,

        // Safe utility functions
        "now":      time.Now,
        "dateFormat": func(format string, t time.Time) string {
            return t.Format(format)
        },
    }
}

// ExecuteTemplate creates a templated string with safe functions
func ExecuteTemplate(text string, data interface{}) (string, error) {
    buff := bytes.Buffer{}

    // Use html/template for automatic escaping
    tmpl, err := template.New("template").
        Funcs(AllowedTemplateFuncs()).
        Parse(text)
    if err != nil {
        return buff.String(), fmt.Errorf("template parse error: %v", err)
    }

    err = tmpl.Execute(&buff, data)
    if err != nil {
        return buff.String(), fmt.Errorf("template execution error: %v", err)
    }

    return buff.String(), nil
}

// ExecuteTemplateWithContext adds timeout and safety
func ExecuteTemplateWithContext(ctx context.Context, text string, data interface{}) (string, error) {
    // Add timeout protection
    ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
    defer cancel()

    // Channel for result
    resultChan := make(chan struct {
        result string
        err    error
    }, 1)

    go func() {
        result, err := ExecuteTemplate(text, data)
        resultChan <- struct {
            result string
            err    error
        }{result, err}
    }()

    select {
    case res := <-resultChan:
        return res.result, res.err
    case <-ctx.Done():
        return "", fmt.Errorf("template execution timeout")
    }
}
```

**Step 2:** Create template validator with stricter rules
```go
// models/template_context.go - enhance ValidateTemplate

// TemplateSandbox wraps template data to prevent unsafe access
type TemplateSandbox struct {
    Data interface{}
}

// ValidateTemplate ensures templates are safe
func ValidateTemplate(text string) error {
    // Check for dangerous patterns
    dangerousPatterns := []string{
        "{{call",
        "{{define",
        "{{template",
        "{{block",
        ".Call",
        ".Method",
    }

    for _, pattern := range dangerousPatterns {
        if strings.Contains(text, pattern) {
            return fmt.Errorf("template contains disallowed pattern: %s", pattern)
        }
    }

    // Try to parse and execute with test data
    vc := ValidationContext{
        FromAddress: "test@example.com",
        BaseURL:     "http://example.com",
    }
    td := Result{
        BaseRecipient: BaseRecipient{
            Email:     "test@example.com",
            FirstName: "Test",
            LastName:  "User",
            Position:  "Tester",
        },
        RId: "test123",
    }

    ptx, err := NewPhishingTemplateContext(vc, td.BaseRecipient, td.RId)
    if err != nil {
        return err
    }

    // Use timeout-protected execution
    ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
    defer cancel()

    _, err = ExecuteTemplateWithContext(ctx, text, ptx)
    if err != nil {
        return fmt.Errorf("template validation failed: %v", err)
    }

    return nil
}
```

**Step 3:** Add template complexity limits
```go
// models/template_context.go - add limits

const (
    MaxTemplateSize       = 1024 * 1024 // 1MB
    MaxTemplateDepth      = 10
    MaxTemplateExecutions = 100
)

func checkTemplateComplexity(text string) error {
    if len(text) > MaxTemplateSize {
        return fmt.Errorf("template exceeds maximum size of %d bytes", MaxTemplateSize)
    }

    // Count nested template depth
    depth := 0
    maxDepth := 0
    for _, char := range text {
        if char == '{' {
            depth++
            if depth > maxDepth {
                maxDepth = depth
            }
        } else if char == '}' {
            depth--
        }
    }

    if maxDepth > MaxTemplateDepth {
        return fmt.Errorf("template nesting exceeds maximum depth of %d", MaxTemplateDepth)
    }

    return nil
}
```

**Testing:**
```go
// models/template_context_test.go - add security tests

func TestTemplateInjection(t *testing.T) {
    maliciousTemplates := []string{
        "{{.}}",  // Expose all data
        "{{call .SomeFunction}}",
        "{{define \"evil\"}}...",
        "{{template \"evil\"}}",
    }

    for _, tmpl := range maliciousTemplates {
        err := ValidateTemplate(tmpl)
        if err == nil {
            t.Errorf("Malicious template was not rejected: %s", tmpl)
        }
    }
}

func TestTemplateTimeout(t *testing.T) {
    // Template with infinite loop
    infiniteTemplate := "{{range .}}{{.}}{{end}}"

    ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
    defer cancel()

    _, err := ExecuteTemplateWithContext(ctx, infiniteTemplate, []string{"a", "b", "c"})
    if err == nil || !strings.Contains(err.Error(), "timeout") {
        t.Error("Template timeout did not trigger")
    }
}
```

---

## HIGH PRIORITY IMPLEMENTATIONS

### H-1: Strengthen Password Policy

**File:** `auth/auth.go`

**New Implementation:**
```go
// auth/auth.go - update constants and add new validation

const (
    MinPasswordLength     = 12  // Increased from 8
    MaxPasswordLength     = 128
    MinPasswordEntropy    = 40.0 // bits
    PasswordHistorySize   = 5
)

// PasswordStrength represents password strength metrics
type PasswordStrength struct {
    Length       int
    HasUpper     bool
    HasLower     bool
    HasDigit     bool
    HasSpecial   bool
    Entropy      float64
    IsCommon     bool
    Score        int // 0-4
}

// CheckPasswordStrength analyzes password strength
func CheckPasswordStrength(password string) PasswordStrength {
    strength := PasswordStrength{
        Length: len(password),
    }

    charSets := 0
    for _, char := range password {
        switch {
        case unicode.IsUpper(char):
            strength.HasUpper = true
        case unicode.IsLower(char):
            strength.HasLower = true
        case unicode.IsDigit(char):
            strength.HasDigit = true
        case unicode.IsPunct(char) || unicode.IsSymbol(char):
            strength.HasSpecial = true
        }
    }

    if strength.HasUpper {
        charSets++
    }
    if strength.HasLower {
        charSets++
    }
    if strength.HasDigit {
        charSets++
    }
    if strength.HasSpecial {
        charSets++
    }

    // Calculate entropy (simplified)
    var charsetSize int
    switch charSets {
    case 1:
        charsetSize = 26
    case 2:
        charsetSize = 52
    case 3:
        charsetSize = 62
    case 4:
        charsetSize = 94
    }

    strength.Entropy = float64(strength.Length) * math.Log2(float64(charsetSize))

    // Check against common passwords
    strength.IsCommon = isCommonPassword(password)

    // Calculate score (0-4)
    strength.Score = calculatePasswordScore(strength)

    return strength
}

// CheckPasswordPolicy with enhanced validation
func CheckPasswordPolicy(password string) error {
    switch {
    case password == "":
        return ErrEmptyPassword
    case len(password) < MinPasswordLength:
        return ErrPasswordTooShort
    case len(password) > MaxPasswordLength:
        return fmt.Errorf("password must be less than %d characters", MaxPasswordLength)
    }

    strength := CheckPasswordStrength(password)

    if strength.IsCommon {
        return errors.New("password is too common, please choose a more unique password")
    }

    if strength.Entropy < MinPasswordEntropy {
        return errors.New("password is not complex enough, please use a mix of uppercase, lowercase, numbers, and symbols")
    }

    if strength.Score < 2 {
        return errors.New("password is too weak, please choose a stronger password")
    }

    return nil
}

// isCommonPassword checks against list of common passwords
func isCommonPassword(password string) bool {
    // This should load from a file, using slice for example
    commonPasswords := []string{
        "password", "password123", "123456", "12345678",
        "admin", "administrator", "welcome", "welcome123",
        "letmein", "monkey", "dragon", "master",
        "qwerty", "abc123", "111111", "password1",
        // ... load from rockyou.txt or similar
    }

    lowerPass := strings.ToLower(password)
    for _, common := range commonPasswords {
        if lowerPass == common {
            return true
        }
    }
    return false
}

// calculatePasswordScore returns 0-4 score
func calculatePasswordScore(strength PasswordStrength) int {
    score := 0

    // Length points
    if strength.Length >= 12 {
        score++
    }
    if strength.Length >= 16 {
        score++
    }

    // Complexity points
    complexityPoints := 0
    if strength.HasUpper {
        complexityPoints++
    }
    if strength.HasLower {
        complexityPoints++
    }
    if strength.HasDigit {
        complexityPoints++
    }
    if strength.HasSpecial {
        complexityPoints++
    }

    if complexityPoints >= 3 {
        score++
    }
    if complexityPoints == 4 {
        score++
    }

    // Entropy points
    if strength.Entropy >= 50 {
        score++
    }

    // Cap at 4
    if score > 4 {
        score = 4
    }

    return score
}
```

**Add password history:**
```go
// models/user.go - add password history

type PasswordHistory struct {
    ID        int64     `json:"id"`
    UserID    int64     `json:"user_id"`
    Hash      string    `json:"-"`
    ChangedAt time.Time `json:"changed_at"`
}

// CheckPasswordHistory verifies password hasn't been used recently
func CheckPasswordHistory(userID int64, newPassword string) error {
    var history []PasswordHistory
    err := db.Where("user_id = ?", userID).
        Order("changed_at DESC").
        Limit(auth.PasswordHistorySize).
        Find(&history).Error

    if err != nil {
        return err
    }

    for _, oldHash := range history {
        err := auth.ValidatePassword(newPassword, oldHash.Hash)
        if err == nil {
            return fmt.Errorf("password has been used recently, please choose a different password")
        }
    }

    return nil
}

// SavePasswordHistory saves old password to history
func SavePasswordHistory(userID int64, hash string) error {
    ph := PasswordHistory{
        UserID:    userID,
        Hash:      hash,
        ChangedAt: time.Now(),
    }

    err := db.Save(&ph).Error
    if err != nil {
        return err
    }

    // Clean up old history beyond limit
    var count int
    db.Model(&PasswordHistory{}).Where("user_id = ?", userID).Count(&count)

    if count > auth.PasswordHistorySize {
        // Delete oldest entries
        db.Where("user_id = ?", userID).
            Order("changed_at ASC").
            Limit(count - auth.PasswordHistorySize).
            Delete(&PasswordHistory{})
    }

    return nil
}
```

**Update password change logic:**
```go
// controllers/api/user.go - in User() PUT handler

// Before setting new password:
err = models.CheckPasswordHistory(existingUser.Id, ur.Password)
if err != nil {
    JSONResponse(w, models.Response{Success: false, Message: err.Error()}, http.StatusBadRequest)
    return
}

// After generating new hash, save old one to history:
if existingUser.Hash != "" {
    err = models.SavePasswordHistory(existingUser.Id, existingUser.Hash)
    if err != nil {
        log.Error(err) // Log but don't fail
    }
}
```

---

### H-2: Remove API Keys from URL

**File:** `middleware/middleware.go`
**Lines:** 86-95

**Implementation:**
```go
// middleware/middleware.go - update RequireAPIKey

func RequireAPIKey(handler http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Only support Authorization header - no query params
        authHeader := r.Header.Get("Authorization")

        if authHeader == "" {
            JSONError(w, http.StatusUnauthorized, "Missing Authorization header")
            return
        }

        // Support both "Bearer TOKEN" and just "TOKEN"
        ak := strings.TrimPrefix(authHeader, "Bearer ")
        ak = strings.TrimSpace(ak)

        if ak == "" {
            JSONError(w, http.StatusUnauthorized, "Invalid Authorization header format")
            return
        }

        u, err := models.GetUserByAPIKey(ak)
        if err != nil {
            // Log the attempt
            log.Warnf("Invalid API key attempt from %s", r.RemoteAddr)
            JSONError(w, http.StatusUnauthorized, "Invalid API Key")
            return
        }

        // Check if account is locked
        if u.AccountLocked {
            JSONError(w, http.StatusForbidden, "Account is locked")
            return
        }

        // Update last activity timestamp
        go func() {
            u.LastLogin = time.Now()
            models.PutUser(&u)
        }()

        r = ctx.Set(r, "user", u)
        r = ctx.Set(r, "user_id", u.Id)
        r = ctx.Set(r, "api_key", ak)
        handler.ServeHTTP(w, r)
    })
}
```

**Add API key rotation:**
```go
// controllers/api/user.go - add new endpoint

func (as *Server) RotateAPIKey(w http.ResponseWriter, r *http.Request) {
    if r.Method != "POST" {
        JSONResponse(w, models.Response{Success: false, Message: "Method not allowed"}, http.StatusMethodNotAllowed)
        return
    }

    currentUser := ctx.Get(r, "user").(models.User)
    vars := mux.Vars(r)
    id, _ := strconv.ParseInt(vars["id"], 0, 64)

    // Can only rotate own key unless admin
    hasSystem, _ := currentUser.HasPermission(models.PermissionModifySystem)
    if !hasSystem && currentUser.Id != id {
        JSONResponse(w, models.Response{Success: false, Message: "Permission denied"}, http.StatusForbidden)
        return
    }

    user, err := models.GetUser(id)
    if err != nil {
        JSONResponse(w, models.Response{Success: false, Message: "User not found"}, http.StatusNotFound)
        return
    }

    // Save old key to history for audit
    log.Infof("API key rotation for user %d by user %d", user.Id, currentUser.Id)

    // Generate new key
    newKey := auth.GenerateSecureKey(auth.APIKeyLength)
    user.ApiKey = newKey

    err = models.PutUser(&user)
    if err != nil {
        JSONResponse(w, models.Response{Success: false, Message: err.Error()}, http.StatusInternalServerError)
        return
    }

    JSONResponse(w, struct {
        Success bool   `json:"success"`
        Message string `json:"message"`
        ApiKey  string `json:"api_key"`
    }{
        Success: true,
        Message: "API key rotated successfully",
        ApiKey:  newKey,
    }, http.StatusOK)
}
```

---

### H-3: Fix Database Connection Pool

**File:** `models/models.go`
**Line:** 189

**Current:**
```go
db.DB().SetMaxOpenConns(1)
```

**Fixed Implementation:**
```go
// config/config.go - add database pool config
type DatabaseConfig struct {
    MaxOpenConnections int `json:"max_open_connections"`
    MaxIdleConnections int `json:"max_idle_connections"`
    ConnMaxLifetime    int `json:"conn_max_lifetime_seconds"`
}

type Config struct {
    // ... existing fields ...
    Database DatabaseConfig `json:"database"`
}
```

**Update models/models.go:**
```go
// models/models.go - in Setup()

// Configure connection pool
maxOpen := conf.Database.MaxOpenConnections
if maxOpen == 0 {
    maxOpen = 25 // Default
}
maxIdle := conf.Database.MaxIdleConnections
if maxIdle == 0 {
    maxIdle = 5 // Default
}
maxLifetime := conf.Database.ConnMaxLifetime
if maxLifetime == 0 {
    maxLifetime = 300 // 5 minutes default
}

db.DB().SetMaxOpenConns(maxOpen)
db.DB().SetMaxIdleConns(maxIdle)
db.DB().SetConnMaxLifetime(time.Duration(maxLifetime) * time.Second)

log.Infof("Database pool configured: max_open=%d max_idle=%d max_lifetime=%ds",
    maxOpen, maxIdle, maxLifetime)
```

**Update config.json:**
```json
{
  "database": {
    "max_open_connections": 50,
    "max_idle_connections": 10,
    "conn_max_lifetime_seconds": 300
  }
}
```

---

## Continued in next file due to length...

### Summary of Remaining High Priority Items

**H-4: Rate Limiting** - Implement progressive delay on login
**H-5: Dependency Updates** - Staged update plan
**H-6: Security Headers** - Complete header implementation
**H-7: Impersonation Logging** - Enhanced audit trail
**H-8: Secure Defaults** - Configuration templates

See HERA_IMPLEMENTATION_PART2.md for detailed implementations of remaining items.

---

## Testing Strategy

### Unit Tests
```bash
# Run security-focused tests
go test -v ./auth/... -run Security
go test -v ./middleware/... -run CORS
go test -v ./models/... -run Template
```

### Integration Tests
```bash
# Test full authentication flow
go test -v ./controllers/... -run Auth

# Test API security
go test -v ./controllers/api/... -run Security
```

### Security Tests
```bash
# Run gosec
gosec -fmt=json -out=gosec-report.json ./...

# Run govulncheck
govulncheck ./...

# Run OWASP ZAP
zap-cli quick-scan http://localhost:3333
```

---

## Deployment Checklist

- [ ] All critical fixes tested in development
- [ ] Database migrations created and tested
- [ ] Configuration updated with new fields
- [ ] Session keys generated and stored securely
- [ ] Documentation updated
- [ ] Security headers verified
- [ ] CORS configuration tested
- [ ] API endpoints tested with new authentication
- [ ] Backup of current system created
- [ ] Rollback plan prepared
- [ ] Team trained on new security features

---

## Monitoring & Alerting

### Metrics to Track
- Failed authentication attempts per IP
- API key usage patterns
- Template execution failures
- Session invalidations
- CORS violations
- Rate limit triggers

### Alerts to Configure
- Multiple failed logins from same IP (>5/min)
- API key used from new IP address
- Admin impersonation events
- Suspicious template submissions
- Database connection pool exhaustion
- TLS certificate validation failures

---

**Document Version:** 1.0
**Last Updated:** 2025-11-12
**Next Review:** After implementation of critical fixes
