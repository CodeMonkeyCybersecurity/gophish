package middleware

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"io"
	"net/http"

	"github.com/gophish/gophish/models"
	log "github.com/gophish/gophish/logger"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

// Store contains the session information for the request
// This will be initialized by InitSessionStore()
var Store *sessions.CookieStore

// init registers the necessary models to be saved in the session later
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

	// Secure cookie configuration
	Store.Options.HttpOnly = true
	Store.Options.Secure = true // Should be true in production with TLS
	Store.Options.SameSite = http.SameSiteStrictMode
	Store.MaxAge(86400 * 5) // 5 days

	log.Info("Session store initialized with secure configuration")
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

// UpdateStoreOptions updates Store options based on TLS configuration
func UpdateStoreOptions(useTLS bool) {
	if Store != nil {
		Store.Options.Secure = useTLS
		log.Infof("Updated session cookie Secure flag to: %v", useTLS)
	}
}
