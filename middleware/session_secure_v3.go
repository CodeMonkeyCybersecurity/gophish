package middleware

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	log "github.com/gophish/gophish/logger"
	"github.com/gophish/gophish/models"
	"github.com/gorilla/sessions"
)

// Store contains the session information for the request
// This will be initialized by InitSessionStore()
var (
	Store      *sessions.CookieStore
	storeMutex sync.RWMutex
	initOnce   sync.Once
	initErr    error
)

func init() {
	// Register necessary models for session storage
	gob.Register(&models.User{})
	gob.Register(&models.Flash{})
}

// InitSessionStore initializes the session store with provided keys
// Uses sync.Once to ensure thread-safe single initialization
// Keys must be provided in base64-encoded format
func InitSessionStore(signingKey, encryptionKey string) error {
	initOnce.Do(func() {
		initErr = doInitSessionStore(signingKey, encryptionKey)
	})
	return initErr
}

// doInitSessionStore performs the actual session store initialization
// This is called exactly once by sync.Once
func doInitSessionStore(signingKey, encryptionKey string) error {
	var signingKeyBytes, encryptionKeyBytes []byte
	var err error

	// SECURITY: Never generate keys at runtime in production
	// Keys must be provided via configuration
	if signingKey == "" {
		return fmt.Errorf("session signing key is required - run 'go run scripts/generate-session-keys.go' to generate keys")
	}

	if encryptionKey == "" {
		return fmt.Errorf("session encryption key is required - run 'go run scripts/generate-session-keys.go' to generate keys")
	}

	// Decode and validate signing key
	signingKeyBytes, err = base64.StdEncoding.DecodeString(signingKey)
	if err != nil {
		return fmt.Errorf("invalid signing key encoding: %v", err)
	}
	if len(signingKeyBytes) != 64 {
		return fmt.Errorf("signing key must be 64 bytes (base64 encoded), got %d bytes", len(signingKeyBytes))
	}

	// Decode and validate encryption key
	encryptionKeyBytes, err = base64.StdEncoding.DecodeString(encryptionKey)
	if err != nil {
		return fmt.Errorf("invalid encryption key encoding: %v", err)
	}
	if len(encryptionKeyBytes) != 32 {
		return fmt.Errorf("encryption key must be 32 bytes (base64 encoded), got %d bytes", len(encryptionKeyBytes))
	}

	// No mutex needed here - sync.Once guarantees single execution
	Store = sessions.NewCookieStore(signingKeyBytes, encryptionKeyBytes)

	// Secure cookie configuration
	Store.Options.HttpOnly = true
	Store.Options.Secure = true // Will be updated based on TLS config
	Store.Options.SameSite = http.SameSiteStrictMode
	Store.Options.Path = "/"
	Store.MaxAge(86400 * 5) // 5 days

	log.Info("Session store initialized with secure configuration")
	return nil
}

// InitSessionStoreWithWarning initializes session store but allows generating keys
// This should only be used for development/testing, never in production
func InitSessionStoreWithWarning(signingKey, encryptionKey string) error {
	if signingKey == "" || encryptionKey == "" {
		log.Error("=" + strings.Repeat("=", 70))
		log.Error("CRITICAL SECURITY WARNING: Session keys not configured!")
		log.Error("=" + strings.Repeat("=", 70))
		log.Error("")
		log.Error("Session keys are being generated randomly. This means:")
		log.Error("  - All user sessions will be invalidated on restart")
		log.Error("  - Multi-instance deployments will not work")
		log.Error("  - This configuration is NOT suitable for production")
		log.Error("")
		log.Error("To fix this:")
		log.Error("  1. Run: go run scripts/generate-session-keys.go")
		log.Error("  2. Add the generated keys to your config.json")
		log.Error("  3. Restart the application")
		log.Error("")
		log.Error("=" + strings.Repeat("=", 70))

		// Generate temporary keys
		sig, enc, err := GenerateSessionKeysBytes()
		if err != nil {
			return fmt.Errorf("failed to generate temporary session keys: %v", err)
		}
		signingKey = base64.StdEncoding.EncodeToString(sig)
		encryptionKey = base64.StdEncoding.EncodeToString(enc)
	}

	return InitSessionStore(signingKey, encryptionKey)
}

// GenerateSessionKeys generates new session keys for configuration
// Returns base64-encoded keys suitable for config.json
func GenerateSessionKeys() (signing, encryption string, err error) {
	signingBytes, encryptionBytes, err := GenerateSessionKeysBytes()
	if err != nil {
		return "", "", err
	}

	return base64.StdEncoding.EncodeToString(signingBytes),
		base64.StdEncoding.EncodeToString(encryptionBytes),
		nil
}

// GenerateSessionKeysBytes generates raw session key bytes
func GenerateSessionKeysBytes() (signing, encryption []byte, err error) {
	signingKey := make([]byte, 64)
	encryptionKey := make([]byte, 32)

	// V2 FIX: Check error from ReadFull (was missing in V1)
	if _, err := io.ReadFull(rand.Reader, signingKey); err != nil {
		return nil, nil, fmt.Errorf("failed to generate signing key: %v", err)
	}
	if _, err := io.ReadFull(rand.Reader, encryptionKey); err != nil {
		return nil, nil, fmt.Errorf("failed to generate encryption key: %v", err)
	}

	return signingKey, encryptionKey, nil
}

// UpdateStoreOptions updates Store options based on TLS configuration
// This should be called after TLS configuration is determined
func UpdateStoreOptions(useTLS bool) error {
	storeMutex.Lock()
	defer storeMutex.Unlock()

	if Store == nil {
		return fmt.Errorf("session store not initialized")
	}

	Store.Options.Secure = useTLS
	log.Infof("Updated session cookie Secure flag to: %v", useTLS)

	return nil
}

// GetStoreOptions returns current store options (for testing/debugging)
func GetStoreOptions() *sessions.Options {
	storeMutex.RLock()
	defer storeMutex.RUnlock()

	if Store == nil {
		return nil
	}

	return Store.Options
}

// ValidateSessionKeys validates that keys are properly formatted
// Returns error if keys are invalid
func ValidateSessionKeys(signingKey, encryptionKey string) error {
	if signingKey == "" {
		return fmt.Errorf("signing key cannot be empty")
	}
	if encryptionKey == "" {
		return fmt.Errorf("encryption key cannot be empty")
	}

	// Validate signing key
	sigBytes, err := base64.StdEncoding.DecodeString(signingKey)
	if err != nil {
		return fmt.Errorf("signing key is not valid base64: %v", err)
	}
	if len(sigBytes) != 64 {
		return fmt.Errorf("signing key must be 64 bytes, got %d", len(sigBytes))
	}

	// Validate encryption key
	encBytes, err := base64.StdEncoding.DecodeString(encryptionKey)
	if err != nil {
		return fmt.Errorf("encryption key is not valid base64: %v", err)
	}
	if len(encBytes) != 32 {
		return fmt.Errorf("encryption key must be 32 bytes, got %d", len(encBytes))
	}

	return nil
}

// GetSessionMetrics returns session-related metrics
func GetSessionMetrics() map[string]interface{} {
	storeMutex.RLock()
	defer storeMutex.RUnlock()

	return map[string]interface{}{
		"initialized": Store != nil,
		"max_age":     86400 * 5, // 5 days
		"http_only":   true,
		"secure":      Store != nil && Store.Options.Secure,
		"same_site":   "Strict",
	}
}

// ResetInitOnce resets the initialization guard (for testing only)
// WARNING: This is NOT thread-safe and should only be used in tests
func ResetInitOnce() {
	initOnce = sync.Once{}
	initErr = nil
	Store = nil
}
