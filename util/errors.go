package util

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	log "github.com/gophish/gophish/logger"
	"github.com/sirupsen/logrus"
)

// SafeJSONError returns a sanitized error message to the client
// while logging the detailed error internally for debugging
func SafeJSONError(w http.ResponseWriter, r *http.Request, statusCode int, publicMsg string, internalErr error) {
	// Log detailed error internally with context
	if internalErr != nil {
		log.WithFields(logrus.Fields{
			"status":     statusCode,
			"error":      internalErr.Error(),
			"endpoint":   r.URL.Path,
			"method":     r.Method,
			"remote_ip":  r.RemoteAddr,
			"user_agent": r.Header.Get("User-Agent"),
		}).Error(publicMsg)
	} else {
		// Still log even if no internal error
		log.WithFields(logrus.Fields{
			"status":     statusCode,
			"endpoint":   r.URL.Path,
			"method":     r.Method,
			"remote_ip":  r.RemoteAddr,
			"user_agent": r.Header.Get("User-Agent"),
		}).Warn(publicMsg)
	}

	// Determine if we should show detailed errors (dev mode only)
	showDetailedErrors := os.Getenv("GOPHISH_DEV_MODE") == "true"

	// Build response message
	responseMsg := publicMsg
	if showDetailedErrors && internalErr != nil {
		// In dev mode, include the error for debugging
		responseMsg = fmt.Sprintf("%s: %v", publicMsg, internalErr)
	}

	// Send JSON response
	response := map[string]interface{}{
		"success": false,
		"message": responseMsg,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)
}

// SafeError returns a sanitized error message for text/html responses
func SafeError(w http.ResponseWriter, r *http.Request, statusCode int, publicMsg string, internalErr error) {
	// Log detailed error internally
	if internalErr != nil {
		log.WithFields(logrus.Fields{
			"status":    statusCode,
			"error":     internalErr.Error(),
			"endpoint":  r.URL.Path,
			"method":    r.Method,
			"remote_ip": r.RemoteAddr,
		}).Error(publicMsg)
	}

	// Determine if we should show detailed errors (dev mode only)
	showDetailedErrors := os.Getenv("GOPHISH_DEV_MODE") == "true"

	// Build error message
	errorMsg := publicMsg
	if showDetailedErrors && internalErr != nil {
		errorMsg = fmt.Sprintf("%s: %v", publicMsg, internalErr)
	}

	// Send simple error response
	http.Error(w, errorMsg, statusCode)
}

// SafeLogError logs an error with context without sending HTTP response
// Useful for middleware or background operations
func SafeLogError(r *http.Request, operation string, internalErr error) {
	if internalErr != nil {
		log.WithFields(logrus.Fields{
			"operation":  operation,
			"error":      internalErr.Error(),
			"endpoint":   r.URL.Path,
			"method":     r.Method,
			"remote_ip":  r.RemoteAddr,
			"user_agent": r.Header.Get("User-Agent"),
		}).Error("Operation failed")
	}
}
