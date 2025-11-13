package models

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestCalculatePasswordEntropy(t *testing.T) {
	tests := []struct {
		name     string
		password string
		minEntropy float64
	}{
		{
			name:       "simple password",
			password:   "password",
			minEntropy: 0,
		},
		{
			name:       "random password",
			password:   "xK9#mP2$vL5@",
			minEntropy: 40,
		},
		{
			name:       "repeated characters",
			password:   "aaaaaaaa",
			minEntropy: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entropy := CalculatePasswordEntropy(tt.password)
			if entropy < tt.minEntropy {
				t.Errorf("entropy = %v, want >= %v", entropy, tt.minEntropy)
			}
		})
	}
}

func TestCheckPasswordStrength(t *testing.T) {
	tests := []struct {
		name     string
		password string
		minScore int
	}{
		{
			name:     "weak password",
			password: "password",
			minScore: 0,
		},
		{
			name:     "medium password",
			password: "Password123",
			minScore: 2,
		},
		{
			name:     "strong password",
			password: "xK9#mP2$vL5@qR7&",
			minScore: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strength := CheckPasswordStrength(tt.password)
			if strength.Score < tt.minScore {
				t.Errorf("score = %v, want >= %v", strength.Score, tt.minScore)
			}
		})
	}
}

func TestExecuteTemplateSafe(t *testing.T) {
	tests := []struct {
		name    string
		text    string
		data    interface{}
		wantErr bool
	}{
		{
			name: "simple template",
			text: "Hello {{.Name}}",
			data: map[string]string{"Name": "World"},
			wantErr: false,
		},
		{
			name: "template with allowed function",
			text: "Hello {{.Name | lower}}",
			data: map[string]string{"Name": "WORLD"},
			wantErr: false,
		},
		{
			name: "template too large",
			text: strings.Repeat("a", MaxTemplateSize+1),
			data: nil,
			wantErr: true,
		},
		{
			name: "template too deep",
			text: strings.Repeat("{{", MaxTemplateDepth+1) + "test" + strings.Repeat("}}", MaxTemplateDepth+1),
			data: nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ExecuteTemplateSafe(tt.text, tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExecuteTemplateSafe() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestExecuteTemplateWithContextTimeout(t *testing.T) {
	// Template that would take too long
	text := "{{range $i := .Items}}{{.}}{{end}}"
	data := map[string]interface{}{
		"Items": make([]int, 1000000),
	}

	ctx := context.Background()
	start := time.Now()

	_, err := ExecuteTemplateWithContext(ctx, text, data)

	elapsed := time.Since(start)

	if elapsed > MaxTemplateExecutionTime*2 {
		t.Errorf("execution took %v, should timeout around %v", elapsed, MaxTemplateExecutionTime)
	}

	// Should timeout
	if err == nil {
		t.Error("expected timeout error, got nil")
	}
}

func TestValidateTemplateSafe(t *testing.T) {
	tests := []struct {
		name    string
		text    string
		wantErr bool
	}{
		{
			name:    "safe template",
			text:    "Hello {{.FirstName}} {{.LastName}}",
			wantErr: false,
		},
		{
			name:    "template with allowed functions",
			text:    "{{.Email | lower}}",
			wantErr: false,
		},
		{
			name:    "template with define (allowed in V3)",
			text:    "{{define \"greeting\"}}Hello{{end}}{{template \"greeting\"}}",
			wantErr: false,
		},
		{
			name:    "dangerous call pattern",
			text:    "{{call .Exec \"rm -rf /\"}}",
			wantErr: true,
		},
		{
			name:    "dangerous method access",
			text:    "{{.Method}}",
			wantErr: true,
		},
		{
			name:    "environment access",
			text:    "{{$.Env}}",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTemplateSafe(tt.text)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateTemplateSafe() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGetTemplateLimiter(t *testing.T) {
	userID := int64(123)

	// Get limiter for user
	limiter1 := GetTemplateLimiter(userID)
	if limiter1 == nil {
		t.Fatal("expected limiter, got nil")
	}

	// Get same limiter again
	limiter2 := GetTemplateLimiter(userID)
	if limiter1 != limiter2 {
		t.Error("expected same limiter instance for same user")
	}

	// Test rate limiting
	for i := 0; i < 6; i++ {
		if !limiter1.Allow() {
			t.Errorf("request %d should be allowed (burst = 5)", i)
			break
		}
	}

	// 7th request should be denied (burst exhausted)
	if limiter1.Allow() {
		t.Error("request 7 should be denied after burst exhausted")
	}
}

func TestExecuteTemplateWithRateLimit(t *testing.T) {
	userID := int64(456)
	text := "Hello {{.Name}}"
	data := map[string]string{"Name": "World"}

	ctx := context.Background()

	// First few requests should succeed (within burst)
	for i := 0; i < 5; i++ {
		_, err := ExecuteTemplateWithRateLimit(ctx, text, data, userID)
		if err != nil {
			t.Errorf("request %d failed: %v", i+1, err)
		}
	}

	// Next request should fail (burst exhausted)
	_, err := ExecuteTemplateWithRateLimit(ctx, text, data, userID)
	if err == nil {
		t.Error("expected rate limit error, got nil")
	}
	if !strings.Contains(err.Error(), "rate limit") {
		t.Errorf("expected rate limit error, got: %v", err)
	}
}

func TestLoadCommonPasswords(t *testing.T) {
	// Create temporary password file
	tmpfile := t.TempDir() + "/passwords.txt"
	content := `# Test password list
password
password123
admin
# another comment
letmein
`
	if err := os.WriteFile(tmpfile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	// Load passwords
	err := LoadCommonPasswords(tmpfile)
	if err != nil {
		t.Fatalf("LoadCommonPasswords() error = %v", err)
	}

	// Test that passwords were loaded
	tests := []struct {
		password string
		want     bool
	}{
		{"password", true},
		{"password123", true},
		{"admin", true},
		{"letmein", true},
		{"notinlist", false},
	}

	for _, tt := range tests {
		t.Run(tt.password, func(t *testing.T) {
			got := isCommonPassword(tt.password)
			if got != tt.want {
				t.Errorf("isCommonPassword(%q) = %v, want %v", tt.password, got, tt.want)
			}
		})
	}
}

func TestGetTemplateMetrics(t *testing.T) {
	metrics := GetTemplateMetrics()

	if metrics == nil {
		t.Fatal("GetTemplateMetrics() returned nil")
	}

	requiredKeys := []string{
		"active_goroutines",
		"total_timeouts",
		"total_executions",
		"total_errors",
		"system_goroutines",
	}

	for _, key := range requiredKeys {
		if _, ok := metrics[key]; !ok {
			t.Errorf("metrics missing key: %s", key)
		}
	}
}

func BenchmarkExecuteTemplateSafe(b *testing.B) {
	text := "Hello {{.FirstName}} {{.LastName}}"
	data := map[string]string{
		"FirstName": "John",
		"LastName":  "Doe",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ExecuteTemplateSafe(text, data)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCheckPasswordStrength(b *testing.B) {
	passwords := []string{
		"password",
		"Password123",
		"xK9#mP2$vL5@qR7&",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = CheckPasswordStrength(passwords[i%len(passwords)])
	}
}
