package models

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"math"
	"strings"
	"time"
	"unicode"

	log "github.com/gophish/gophish/logger"
)

const (
	// MaxTemplateSize limits template size to prevent DoS
	MaxTemplateSize = 1024 * 1024 // 1MB

	// MaxTemplateDepth limits nesting depth
	MaxTemplateDepth = 10

	// MaxTemplateExecutionTime limits template execution time
	MaxTemplateExecutionTime = 5 * time.Second
)

// AllowedTemplateFuncs returns the safe set of functions available in templates
func AllowedTemplateFuncs() template.FuncMap {
	return template.FuncMap{
		// String functions - safe
		"lower": strings.ToLower,
		"upper": strings.ToUpper,
		"title": strings.Title,
		"trim":  strings.TrimSpace,

		// Date/time functions - safe
		"now": time.Now,
		"dateFormat": func(format string, t time.Time) string {
			return t.Format(format)
		},

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
// Uses html/template for automatic escaping
func ExecuteTemplateSafe(text string, data interface{}) (string, error) {
	// Check template complexity before execution
	if err := checkTemplateComplexity(text); err != nil {
		return "", err
	}

	buff := bytes.Buffer{}

	// Use html/template for automatic escaping
	tmpl, err := template.New("template").
		Funcs(AllowedTemplateFuncs()).
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
		output, err := ExecuteTemplateSafe(text, data)
		resultChan <- result{output, err}
	}()

	select {
	case res := <-resultChan:
		return res.output, res.err
	case <-ctx.Done():
		return "", fmt.Errorf("template execution timeout after %v", MaxTemplateExecutionTime)
	}
}

// checkTemplateComplexity validates template size and complexity
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

// ValidateTemplateSafe validates templates for security issues
func ValidateTemplateSafe(text string) error {
	// Check for dangerous patterns
	dangerousPatterns := []string{
		"{{call",
		"{{define",
		"{{template",
		"{{block",
		".Call",
		".Method",
		"printf",  // Can be used for format string attacks
		"println", // Information disclosure
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

// CalculatePasswordEntropy calculates Shannon entropy of password
func CalculatePasswordEntropy(password string) float64 {
	if len(password) == 0 {
		return 0
	}

	// Count character frequencies
	freq := make(map[rune]int)
	for _, char := range password {
		freq[char]++
	}

	// Calculate entropy
	var entropy float64
	length := float64(len(password))
	for _, count := range freq {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}

	// Multiply by length to get total entropy
	return entropy * length
}

// PasswordStrength represents password strength analysis
type PasswordStrength struct {
	Length       int
	HasUpper     bool
	HasLower     bool
	HasDigit     bool
	HasSpecial   bool
	Entropy      float64
	IsCommon     bool
	Score        int // 0-4
	Feedback     []string
}

// CheckPasswordStrength analyzes password strength
func CheckPasswordStrength(password string) PasswordStrength {
	strength := PasswordStrength{
		Length:   len(password),
		Feedback: []string{},
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

	// Calculate entropy
	strength.Entropy = CalculatePasswordEntropy(password)

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

	// Entropy points
	if strength.Entropy >= 50 {
		score++
	} else {
		feedback = append(feedback, "Password is too predictable")
	}

	// Common password check
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
func isCommonPassword(password string) bool {
	// Top 100 most common passwords (sample)
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
		// Check if password contains common password
		if strings.Contains(lowerPass, strings.ToLower(common)) && len(common) > 6 {
			return true
		}
	}

	// Check for sequential numbers or letters
	if strings.Contains(password, "123456") ||
		strings.Contains(password, "abcdef") ||
		strings.Contains(password, "qwerty") {
		return true
	}

	return false
}
