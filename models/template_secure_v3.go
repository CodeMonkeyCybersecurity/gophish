package models

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"math"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"text/template" // INTENTIONALLY text/template for phishing emails
	"time"
	"unicode"

	log "github.com/gophish/gophish/logger"
	"golang.org/x/time/rate"
)

const (
	// MaxTemplateSize limits template size to prevent DoS
	MaxTemplateSize = 1024 * 1024 // 1MB

	// MaxTemplateDepth limits nesting depth
	MaxTemplateDepth = 100

	// MaxTemplateExecutionTime limits template execution time
	MaxTemplateExecutionTime = 5 * time.Second

	// DefaultCommonPasswordsPath is the default path to common passwords file
	DefaultCommonPasswordsPath = "data/common-passwords.txt"
)

// V3 ENHANCEMENT: Goroutine monitoring
var (
	activeTemplateGoroutines int64
	totalTemplateTimeouts    int64
	totalTemplateExecutions  int64
	totalTemplateErrors      int64
)

// V3 ENHANCEMENT: Per-user rate limiting
var (
	templateLimiters = struct {
		sync.RWMutex
		limiters map[int64]*rate.Limiter
	}{
		limiters: make(map[int64]*rate.Limiter),
	}
)

// V3 ENHANCEMENT: File-based common password list
var (
	commonPasswordSet = struct {
		sync.RWMutex
		passwords map[string]bool
		loaded    bool
	}{
		passwords: make(map[string]bool),
	}
)

// AllowedTemplateFuncsV3 returns the safe set of functions available in templates
// NOTE: Limited set to prevent code execution via template injection
func AllowedTemplateFuncsV3() template.FuncMap {
	return template.FuncMap{
		// String functions - safe
		"lower": strings.ToLower,
		"upper": strings.ToUpper,
		"trim":  strings.TrimSpace,
		// V2 FIX: Removed deprecated strings.Title

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

// ExecuteTemplateSafeV3 executes a template with safety controls
// Uses text/template (required for phishing emails) but with restrictions
func ExecuteTemplateSafeV3(text string, data interface{}) (string, error) {
	// Check template complexity before execution
	if err := checkTemplateComplexityV3(text); err != nil {
		return "", err
	}

	buff := bytes.Buffer{}

	// SECURITY NOTE: Using text/template instead of html/template
	// This is required for Gophish to render HTML emails properly
	// html/template would escape HTML tags, breaking phishing templates
	//
	// MITIGATIONS:
	// 1. Limited function set (AllowedTemplateFuncsV3)
	// 2. Timeout protection (ExecuteTemplateWithContextV3)
	// 3. Complexity limits (checkTemplateComplexityV3)
	// 4. Pattern validation (ValidateTemplateSafeV3)
	// 5. Rate limiting (ExecuteTemplateWithRateLimitV3)
	// 6. Goroutine monitoring (V3 enhancement)
	tmpl, err := template.New("template").
		Funcs(AllowedTemplateFuncsV3()).
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

// ExecuteTemplateWithContextV3 executes template with timeout protection and monitoring
// V3 ENHANCEMENT: Goroutine monitoring and leak detection
func ExecuteTemplateWithContextV3(ctx context.Context, text string, data interface{}) (string, error) {
	// Increment total executions counter
	atomic.AddInt64(&totalTemplateExecutions, 1)

	// Add timeout protection
	ctx, cancel := context.WithTimeout(ctx, MaxTemplateExecutionTime)
	defer cancel()

	// Channel for result
	type result struct {
		output string
		err    error
	}
	resultChan := make(chan result, 1)

	// V3 ENHANCEMENT: Track active goroutines
	atomic.AddInt64(&activeTemplateGoroutines, 1)

	go func() {
		// V3 ENHANCEMENT: Decrement counter when goroutine completes
		defer atomic.AddInt64(&activeTemplateGoroutines, -1)

		// GOROUTINE LEAK WARNING:
		// This goroutine cannot be cancelled and will run to completion
		// even if context times out. This is a limitation of Go's template engine.
		// V3 monitors goroutine count to detect leaks.
		defer func() {
			if r := recover(); r != nil {
				log.Errorf("Template execution panicked: %v", r)
				atomic.AddInt64(&totalTemplateErrors, 1)
				resultChan <- result{"", fmt.Errorf("template execution panic: %v", r)}
			}
		}()

		output, err := ExecuteTemplateSafeV3(text, data)

		// Try to send result, but don't block if context already cancelled
		select {
		case resultChan <- result{output, err}:
			// Sent successfully
		case <-ctx.Done():
			// Context cancelled, don't block
			// V3 ENHANCEMENT: This goroutine leaked - increment counter
			atomic.AddInt64(&totalTemplateTimeouts, 1)
			log.Warnf("Template execution completed after context timeout (goroutine leak detected)")
		}
	}()

	select {
	case res := <-resultChan:
		if res.err != nil {
			atomic.AddInt64(&totalTemplateErrors, 1)
		}
		return res.output, res.err
	case <-ctx.Done():
		atomic.AddInt64(&totalTemplateTimeouts, 1)
		log.Errorf("Template execution timeout after %v", MaxTemplateExecutionTime)

		// V3 ENHANCEMENT: Alert if leak count is high
		totalTimeouts := atomic.LoadInt64(&totalTemplateTimeouts)
		if totalTimeouts > 100 {
			log.Errorf("CRITICAL: %d template timeouts detected - potential goroutine leak", totalTimeouts)
		}

		// V3 ENHANCEMENT: Alert if active goroutine count is high
		activeCount := atomic.LoadInt64(&activeTemplateGoroutines)
		if activeCount > 1000 {
			log.Errorf("CRITICAL: %d active template goroutines - goroutine leak confirmed", activeCount)
		}

		return "", fmt.Errorf("template execution timeout after %v", MaxTemplateExecutionTime)
	}
}

// V3 ENHANCEMENT: GetTemplateLimiter gets or creates rate limiter for user
func GetTemplateLimiter(userID int64) *rate.Limiter {
	templateLimiters.RLock()
	limiter, exists := templateLimiters.limiters[userID]
	templateLimiters.RUnlock()

	if exists {
		return limiter
	}

	templateLimiters.Lock()
	defer templateLimiters.Unlock()

	// Double-check after acquiring write lock
	if limiter, exists := templateLimiters.limiters[userID]; exists {
		return limiter
	}

	// Create new limiter: 10 templates per minute, burst of 5
	limiter = rate.NewLimiter(rate.Limit(10.0/60.0), 5)
	templateLimiters.limiters[userID] = limiter
	log.Debugf("Created rate limiter for user %d: 10 templates/minute, burst 5", userID)
	return limiter
}

// V3 ENHANCEMENT: ExecuteTemplateWithRateLimitV3 adds rate limiting
func ExecuteTemplateWithRateLimitV3(ctx context.Context, text string, data interface{}, userID int64) (string, error) {
	limiter := GetTemplateLimiter(userID)

	if !limiter.Allow() {
		log.Warnf("Template execution rate limit exceeded for user %d", userID)
		return "", fmt.Errorf("template execution rate limit exceeded (max 10 per minute)")
	}

	return ExecuteTemplateWithContextV3(ctx, text, data)
}

// checkTemplateComplexityV3 validates template size and complexity
func checkTemplateComplexityV3(text string) error {
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

// ValidateTemplateSafeV3 validates templates for security issues
// Returns error if template contains dangerous patterns
func ValidateTemplateSafeV3(text string) error {
	// Check for truly dangerous patterns only
	// V2 FIX: Allow {{define}}, {{template}}, {{block}} for legitimate template composition
	dangerousPatterns := []string{
		"{{call",    // Function calls - dangerous
		".Call",     // Reflection method calls
		".Method",   // Method access
		"$.Env",     // Environment access
		"os.Getenv", // OS function calls
		".Exec",     // Command execution
		".Run",      // Process execution
	}

	lowerText := strings.ToLower(text)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(lowerText, strings.ToLower(pattern)) {
			return fmt.Errorf("template contains disallowed pattern: %s", pattern)
		}
	}

	// Check complexity
	if err := checkTemplateComplexityV3(text); err != nil {
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

	_, err = ExecuteTemplateWithContextV3(ctx, text, ptx)
	if err != nil {
		return fmt.Errorf("template validation failed: %v", err)
	}

	return nil
}

// V3 ENHANCEMENT: GetTemplateMetrics returns template execution metrics
func GetTemplateMetrics() map[string]interface{} {
	return map[string]interface{}{
		"active_goroutines":   atomic.LoadInt64(&activeTemplateGoroutines),
		"total_timeouts":      atomic.LoadInt64(&totalTemplateTimeouts),
		"total_executions":    atomic.LoadInt64(&totalTemplateExecutions),
		"total_errors":        atomic.LoadInt64(&totalTemplateErrors),
		"system_goroutines":   runtime.NumGoroutine(),
		"rate_limiters_count": len(templateLimiters.limiters),
	}
}

// V3 ENHANCEMENT: LoadCommonPasswords loads common passwords from file
func LoadCommonPasswords(filepath string) error {
	file, err := os.Open(filepath)
	if err != nil {
		log.Warnf("Failed to open password list %s: %v (using hardcoded list)", filepath, err)
		return fmt.Errorf("failed to open password list: %v", err)
	}
	defer file.Close()

	commonPasswordSet.Lock()
	defer commonPasswordSet.Unlock()

	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() {
		password := strings.TrimSpace(strings.ToLower(scanner.Text()))
		if password != "" && !strings.HasPrefix(password, "#") { // Allow comments
			commonPasswordSet.passwords[password] = true
			count++
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading password list: %v", err)
	}

	commonPasswordSet.loaded = true
	log.Infof("Loaded %d common passwords from %s", count, filepath)
	return nil
}

// CalculatePasswordEntropyV3 calculates Shannon entropy of password
// This measures the actual unpredictability based on character distribution
func CalculatePasswordEntropyV3(password string) float64 {
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
	return entropyPerChar * length
}

// CalculateIdealPasswordEntropyV3 calculates theoretical maximum entropy
func CalculateIdealPasswordEntropyV3(password string) float64 {
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

// PasswordStrengthV3 represents password strength analysis
type PasswordStrengthV3 struct {
	Length        int
	HasUpper      bool
	HasLower      bool
	HasDigit      bool
	HasSpecial    bool
	ActualEntropy float64
	IdealEntropy  float64
	IsCommon      bool
	Score         int // 0-4
	Feedback      []string
}

// CheckPasswordStrengthV3 analyzes password strength
func CheckPasswordStrengthV3(password string) PasswordStrengthV3 {
	strength := PasswordStrengthV3{
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
	strength.ActualEntropy = CalculatePasswordEntropyV3(password)
	strength.IdealEntropy = CalculateIdealPasswordEntropyV3(password)

	// Check against common passwords
	strength.IsCommon = isCommonPasswordV3(password)

	// Calculate score and feedback
	strength.Score, strength.Feedback = calculatePasswordScoreV3(strength)

	return strength
}

// calculatePasswordScoreV3 calculates password score (0-4) and provides feedback
func calculatePasswordScoreV3(strength PasswordStrengthV3) (int, []string) {
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

// V3 ENHANCEMENT: isCommonPasswordV3 checks against loaded password list
func isCommonPasswordV3(password string) bool {
	lowerPass := strings.ToLower(password)

	// Check loaded password list first
	commonPasswordSet.RLock()
	if commonPasswordSet.loaded {
		_, isCommon := commonPasswordSet.passwords[lowerPass]
		commonPasswordSet.RUnlock()
		if isCommon {
			return true
		}
	} else {
		commonPasswordSet.RUnlock()
	}

	// Fallback to hardcoded list if file not loaded
	hardcodedCommon := []string{
		"password", "password123", "123456", "12345678", "123456789",
		"admin", "administrator", "welcome", "welcome123", "root",
		"letmein", "monkey", "dragon", "master", "password1",
		"qwerty", "abc123", "111111", "1234567", "sunshine",
		"princess", "adobe123", "123123", "12345", "1234567890",
		"admin123", "changeme", "test", "test123", "password!",
		"gophish", "gophish123", "passw0rd", "Pa$$w0rd", "Password1",
	}

	for _, common := range hardcodedCommon {
		if lowerPass == strings.ToLower(common) {
			return true
		}
		// Check if password contains common password as substring (length > 6)
		if len(common) > 6 && strings.Contains(lowerPass, strings.ToLower(common)) {
			return true
		}
	}

	// Check for sequential patterns
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

// V3 ENHANCEMENT: GetCommonPasswordStats returns stats about loaded password list
func GetCommonPasswordStats() map[string]interface{} {
	commonPasswordSet.RLock()
	defer commonPasswordSet.RUnlock()

	return map[string]interface{}{
		"loaded":        commonPasswordSet.loaded,
		"password_count": len(commonPasswordSet.passwords),
	}
}
