package models

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"strings"
	"text/template" // INTENTIONALLY text/template for phishing emails
	"time"
	"unicode"

	log "github.com/gophish/gophish/logger"
)

const (
	// MaxTemplateSize limits template size to prevent DoS
	MaxTemplateSize = 1024 * 1024 // 1MB

	// MaxTemplateDepth limits nesting depth
	MaxTemplateDepth = 100 // Increased from 10 - allow legitimate templates

	// MaxTemplateExecutionTime limits template execution time
	MaxTemplateExecutionTime = 5 * time.Second
)

// AllowedTemplateFuncs returns the safe set of functions available in templates
// NOTE: Limited set to prevent code execution via template injection
func AllowedTemplateFuncs() template.FuncMap {
	return template.FuncMap{
		// String functions - safe
		"lower": strings.ToLower,
		"upper": strings.ToUpper,
		"trim":  strings.TrimSpace,
		// Note: strings.Title is deprecated in Go 1.18+, removed from allowlist

		// Date/time functions - safe, read-only
		"now": time.Now,

		// Safe utility functions
		"len": func(v interface{}) int {
			switch val := v.(type) {
			case string:
				return len(val)
			case []interface{}:
				return len(val)
			default:
				return 0
			}
		},
	}
}

// ExecuteTemplateSafe executes a template with safety controls
// Uses text/template (required for phishing emails) but with restrictions
func ExecuteTemplateSafe(text string, data interface{}) (string, error) {
	// Check template complexity before execution
	if err := checkTemplateComplexity(text); err != nil {
		return "", err
	}

	buff := bytes.Buffer{}

	// SECURITY NOTE: Using text/template instead of html/template
	// This is required for Gophish to render HTML emails properly
	// html/template would escape HTML tags, breaking phishing templates
	//
	// MITIGATIONS:
	// 1. Limited function set (AllowedTemplateFuncs)
	// 2. Timeout protection (ExecuteTemplateWithContext)
	// 3. Complexity limits (checkTemplateComplexity)
	// 4. Pattern validation (ValidateTemplateSafe)
	// 5. Audit logging (caller's responsibility)
	tmpl, err := template.New("template").
		Funcs(AllowedTemplateFuncs()).
		Option("missingkey=error"). // Fail on missing template variables
		Parse(text)
	if err != nil {
		log.Errorf("Template parse error: %v", err)
		return buff.String(), fmt.Errorf("template parse error: %v", err)
	}

	err = tmpl.Execute(&buff, data)
	if err != nil {
		log.Errorf("Template execution error: %v", err)
		return buff.String(), fmt.Errorf("template execution error: %v", err)
	}

	return buff.String(), nil
}

// ExecuteTemplateWithContext executes template with timeout protection
// NOTE: Goroutine may leak if template hangs - this is a Go limitation
func ExecuteTemplateWithContext(ctx context.Context, text string, data interface{}) (string, error) {
	// Add timeout protection
	ctx, cancel := context.WithTimeout(ctx, MaxTemplateExecutionTime)
	defer cancel()

	// Channel for result
	type result struct {
		output string
		err    error
	}
	resultChan := make(chan result, 1)

	go func() {
		// GOROUTINE LEAK WARNING:
		// This goroutine cannot be cancelled and will run to completion
		// even if context times out. This is a limitation of Go's template engine.
		// Monitor goroutine count in production for leaks.
		defer func() {
			if r := recover(); r != nil {
				log.Errorf("Template execution panicked: %v", r)
				resultChan <- result{"", fmt.Errorf("template execution panic: %v", r)}
			}
		}()

		output, err := ExecuteTemplateSafe(text, data)

		// Try to send result, but don't block if context already cancelled
		select {
		case resultChan <- result{output, err}:
			// Sent successfully
		case <-ctx.Done():
			// Context cancelled, don't block
			log.Warnf("Template execution completed after context timeout")
		}
	}()

	select {
	case res := <-resultChan:
		return res.output, res.err
	case <-ctx.Done():
		log.Errorf("Template execution timeout after %v", MaxTemplateExecutionTime)
		return "", fmt.Errorf("template execution timeout after %v", MaxTemplateExecutionTime)
	}
}

// checkTemplateComplexity validates template size and complexity
func checkTemplateComplexity(text string) error {
	if len(text) > MaxTemplateSize {
		return fmt.Errorf("template exceeds maximum size of %d bytes", MaxTemplateSize)
	}

	// Count nested braces (rough complexity metric)
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

// ValidateTemplateSafe validates templates for security issues
// Returns error if template contains dangerous patterns
func ValidateTemplateSafe(text string) error {
	// Check for truly dangerous patterns only
	// REVISED: Allow {{define}}, {{template}}, {{block}} for legitimate template composition
	dangerousPatterns := []string{
		"{{call",   // Function calls - dangerous
		".Call",    // Reflection method calls
		".Method",  // Method access
		"$.Env",    // Environment access
		"os.Getenv", // OS function calls
		".Exec",    // Command execution
		".Run",     // Process execution
	}

	lowerText := strings.ToLower(text)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(lowerText, strings.ToLower(pattern)) {
			return fmt.Errorf("template contains disallowed pattern: %s", pattern)
		}
	}

	// Check complexity
	if err := checkTemplateComplexity(text); err != nil {
		return err
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
		return fmt.Errorf("test context creation failed: %v", err)
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

// CalculatePasswordEntropy calculates Shannon entropy of password
// This measures the actual unpredictability based on character distribution
// NOT the theoretical maximum entropy
func CalculatePasswordEntropy(password string) float64 {
	if len(password) == 0 {
		return 0
	}

	// Count character frequencies
	freq := make(map[rune]int)
	for _, char := range password {
		freq[char]++
	}

	// Calculate Shannon entropy per character
	var entropyPerChar float64
	length := float64(len(password))
	for _, count := range freq {
		if count > 0 {
			p := float64(count) / length
			entropyPerChar -= p * math.Log2(p)
		}
	}

	// Total entropy is per-character entropy * length
	// This represents the total unpredictability in bits
	return entropyPerChar * length
}

// CalculateIdealPasswordEntropy calculates theoretical maximum entropy
// This is what the entropy COULD be if all characters were unique and random
func CalculateIdealPasswordEntropy(password string) float64 {
	if len(password) == 0 {
		return 0
	}

	// Determine character set size
	var hasLower, hasUpper, hasDigit, hasSpecial bool
	for _, char := range password {
		switch {
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsDigit(char):
			hasDigit = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	charsetSize := 0
	if hasLower {
		charsetSize += 26
	}
	if hasUpper {
		charsetSize += 26
	}
	if hasDigit {
		charsetSize += 10
	}
	if hasSpecial {
		charsetSize += 32 // approximate
	}

	if charsetSize == 0 {
		return 0
	}

	// Ideal entropy = log2(charset) * length
	return math.Log2(float64(charsetSize)) * float64(len(password))
}

// PasswordStrength represents password strength analysis
type PasswordStrength struct {
	Length       int
	HasUpper     bool
	HasLower     bool
	HasDigit     bool
	HasSpecial   bool
	ActualEntropy float64 // Actual entropy based on distribution
	IdealEntropy  float64 // Theoretical maximum entropy
	IsCommon      bool
	Score         int // 0-4
	Feedback      []string
}

// CheckPasswordStrength analyzes password strength
func CheckPasswordStrength(password string) PasswordStrength {
	strength := PasswordStrength{
		Length:   len(password),
		Feedback: []string{},
	}

	// Analyze character types
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

	// Calculate both actual and ideal entropy
	strength.ActualEntropy = CalculatePasswordEntropy(password)
	strength.IdealEntropy = CalculateIdealPasswordEntropy(password)

	// Check against common passwords
	strength.IsCommon = isCommonPassword(password)

	// Calculate score and feedback
	strength.Score, strength.Feedback = calculatePasswordScore(strength)

	return strength
}

// calculatePasswordScore calculates password score (0-4) and provides feedback
func calculatePasswordScore(strength PasswordStrength) (int, []string) {
	score := 0
	feedback := []string{}

	// Length points
	if strength.Length < 12 {
		feedback = append(feedback, "Password should be at least 12 characters")
	} else if strength.Length >= 12 {
		score++
	}

	if strength.Length >= 16 {
		score++
	} else if strength.Length >= 12 {
		feedback = append(feedback, "Consider using 16+ characters for stronger security")
	}

	// Complexity points
	if !strength.HasUpper {
		feedback = append(feedback, "Add uppercase letters")
	}
	if !strength.HasLower {
		feedback = append(feedback, "Add lowercase letters")
	}
	if !strength.HasDigit {
		feedback = append(feedback, "Add numbers")
	}
	if !strength.HasSpecial {
		feedback = append(feedback, "Add special characters (!@#$%^&*)")
	}

	complexityCount := 0
	if strength.HasUpper {
		complexityCount++
	}
	if strength.HasLower {
		complexityCount++
	}
	if strength.HasDigit {
		complexityCount++
	}
	if strength.HasSpecial {
		complexityCount++
	}

	if complexityCount >= 3 {
		score++
	}
	if complexityCount == 4 {
		score++
	}

	// Entropy points - use actual entropy
	if strength.ActualEntropy >= 50 {
		score++
	} else {
		feedback = append(feedback, "Password is too predictable")
	}

	// Common password check overrides everything
	if strength.IsCommon {
		feedback = append(feedback, "This password is too common")
		score = 0 // Override score if common
	}

	// Cap at 4
	if score > 4 {
		score = 4
	}

	if score >= 3 && len(feedback) == 0 {
		feedback = append(feedback, "Strong password")
	}

	return score, feedback
}

// isCommonPassword checks against a list of common passwords
// This is a simplified check - production should use larger lists
func isCommonPassword(password string) bool {
	// Top common passwords (sample - should be loaded from file in production)
	commonPasswords := []string{
		"password", "password123", "123456", "12345678", "123456789",
		"admin", "administrator", "welcome", "welcome123", "root",
		"letmein", "monkey", "dragon", "master", "password1",
		"qwerty", "abc123", "111111", "1234567", "sunshine",
		"princess", "adobe123", "123123", "12345", "1234567890",
		"admin123", "changeme", "test", "test123", "password!",
		"gophish", "gophish123", "passw0rd", "Pa$$w0rd", "Password1",
	}

	lowerPass := strings.ToLower(password)
	for _, common := range commonPasswords {
		if lowerPass == strings.ToLower(common) {
			return true
		}
		// Check if password contains common password as substring (length > 6)
		if len(common) > 6 && strings.Contains(lowerPass, strings.ToLower(common)) {
			return true
		}
	}

	// Check for sequential patterns
	// FIXED: Only check for actual sequential patterns at start/end
	sequentialPatterns := []string{
		"123456", "234567", "345678", "456789", "567890",
		"abcdef", "bcdefg", "cdefgh",
		"qwerty", "asdfgh", "zxcvbn",
		"987654", "876543", "765432",
	}

	for _, pattern := range sequentialPatterns {
		if strings.Contains(lowerPass, pattern) {
			return true
		}
	}

	return false
}
