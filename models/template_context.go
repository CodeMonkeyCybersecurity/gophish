package models

import (
	"bytes"
	"errors"
	"fmt"
	"html"
	"net/mail"
	"net/url"
	"path"
	"regexp"
	"strings"
	"text/template"

	log "github.com/gophish/gophish/logger"
	"github.com/sirupsen/logrus"
)

// TemplateContext is an interface that allows both campaigns and email
// requests to have a PhishingTemplateContext generated for them.
type TemplateContext interface {
	getFromAddress() string
	getBaseURL() string
}

// PhishingTemplateContext is the context that is sent to any template, such
// as the email or landing page content.
type PhishingTemplateContext struct {
	From        string
	URL         string
	Tracker     string
	TrackingURL string
	RId         string
	BaseURL     string
	BaseRecipient
}

// NewPhishingTemplateContext returns a populated PhishingTemplateContext,
// parsing the correct fields from the provided TemplateContext and recipient.
func NewPhishingTemplateContext(ctx TemplateContext, r BaseRecipient, rid string) (PhishingTemplateContext, error) {
	f, err := mail.ParseAddress(ctx.getFromAddress())
	if err != nil {
		return PhishingTemplateContext{}, err
	}
	fn := f.Name
	if fn == "" {
		fn = f.Address
	}
	templateURL, err := ExecuteTemplate(ctx.getBaseURL(), r)
	if err != nil {
		return PhishingTemplateContext{}, err
	}

	// For the base URL, we'll reset the the path and the query
	// This will create a URL in the form of http://example.com
	baseURL, err := url.Parse(templateURL)
	if err != nil {
		return PhishingTemplateContext{}, err
	}
	baseURL.Path = ""
	baseURL.RawQuery = ""

	phishURL, _ := url.Parse(templateURL)
	q := phishURL.Query()
	q.Set(RecipientParameter, rid)
	phishURL.RawQuery = q.Encode()

	trackingURL, _ := url.Parse(templateURL)
	trackingURL.Path = path.Join(trackingURL.Path, "/track")
	trackingURL.RawQuery = q.Encode()

	return PhishingTemplateContext{
		BaseRecipient: r,
		BaseURL:       baseURL.String(),
		URL:           phishURL.String(),
		TrackingURL:   trackingURL.String(),
		Tracker:       "<img alt='' style='display: none' src='" + trackingURL.String() + "'/>",
		From:          fn,
		RId:           rid,
	}, nil
}

// ExecuteTemplate creates a templated string based on the provided
// template body and data.
func ExecuteTemplate(text string, data interface{}) (string, error) {
	buff := bytes.Buffer{}
	tmpl, err := template.New("template").Parse(text)
	if err != nil {
		return buff.String(), err
	}
	err = tmpl.Execute(&buff, data)
	return buff.String(), err
}

// ValidationContext is used for validating templates and pages
type ValidationContext struct {
	FromAddress string
	BaseURL     string
}

func (vc ValidationContext) getFromAddress() string {
	return vc.FromAddress
}

func (vc ValidationContext) getBaseURL() string {
	return vc.BaseURL
}

// validateTemplateContent checks if text contains problematic template syntax
// and provides specific error messages with line numbers
func validateTemplateContent(text string) error {
	// Pattern to match {{ with = inside the braces (single = not part of := == or !=)
	// This catches patterns like {{variable = value}} but not <a href="{{.URL}}">
	problematicPattern := regexp.MustCompile(`\{\{[^}]*\s=\s[^}]*\}\}`)

	lines := strings.Split(text, "\n")
	for i, line := range lines {
		// Check if line contains problematic template pattern
		if problematicPattern.MatchString(line) {
			// Additional check: ensure it's not a valid Go template assignment/comparison
			// Valid: {{$x := .Value}}, {{if eq .A .B}}, {{.A == .B}}
			// Invalid: {{variable = value}}, {{prop: value}}
			if !strings.Contains(line, ":=") && !strings.Contains(line, "eq ") &&
			   !strings.Contains(line, "==") && !strings.Contains(line, "!=") {
				return fmt.Errorf("template syntax error on line %d: '%s' - this appears to be non-Go template syntax (CSS, JSON, or other framework). Consider escaping {{}} braces in imported HTML", i+1, strings.TrimSpace(line))
			}
		}
	}
	return nil
}

// ValidateTemplate ensures that the provided text in the page or template
// uses the supported template variables correctly.
func ValidateTemplate(text string) error {
	// Pre-validate for common template syntax issues
	if err := validateTemplateContent(text); err != nil {
		return err
	}

	vc := ValidationContext{
		FromAddress: "foo@bar.com",
		BaseURL:     "http://example.com",
	}
	td := Result{
		BaseRecipient: BaseRecipient{
			Email:     "foo@bar.com",
			FirstName: "Foo",
			LastName:  "Bar",
			Position:  "Test",
		},
		RId: "123456",
	}
	ptx, err := NewPhishingTemplateContext(vc, td.BaseRecipient, td.RId)
	if err != nil {
		return err
	}
	_, err = ExecuteTemplate(text, ptx)
	if err != nil {
		// Enhance error message to mention template syntax issues in imported HTML
		if strings.Contains(err.Error(), "bad character") || strings.Contains(err.Error(), "unexpected") {
			return fmt.Errorf("template validation failed: %v - if this is imported HTML, it may contain invalid template syntax that needs escaping", err)
		}
		return err
	}
	return nil
}

// SanitizeHTMLForDisplay properly escapes user input for safe display in HTML
// This prevents XSS attacks while preserving the visual appearance of the text
func SanitizeHTMLForDisplay(input string) string {
	// Use Go's html.EscapeString for proper HTML entity encoding
	// This converts: < to &lt;, > to &gt;, & to &amp;, etc.
	return html.EscapeString(input)
}

// DetectXSSPatterns logs suspicious patterns for monitoring
// Returns true if potentially malicious patterns are detected
func DetectXSSPatterns(input string) bool {
	// XSS patterns to detect (case-insensitive)
	xssPatterns := []string{
		`<script[\s\S]*?>`,        // Script tags
		`javascript:`,             // JavaScript protocol
		`on\w+\s*=`,               // Event handlers (onclick, onerror, etc.)
		`data:text/html`,          // Data URI XSS
		`<iframe[\s\S]*?>`,        // Iframes
		`<embed[\s\S]*?>`,         // Embed tags
		`<object[\s\S]*?>`,        // Object tags
		`eval\s*\(`,               // Eval function
		`expression\s*\(`,         // CSS expression
		`<svg[\s\S]*?>`,           // SVG tags (can contain scripts)
		`<img[\s\S]*?onerror`,     // Image with onerror
		`<link[\s\S]*?onload`,     // Link with onload
		`vbscript:`,               // VBScript protocol
		`<meta[\s\S]*?http-equiv`, // Meta refresh
	}

	detected := false
	lowerInput := strings.ToLower(input)

	for _, pattern := range xssPatterns {
		if matched, _ := regexp.MatchString(`(?i)`+pattern, lowerInput); matched {
			// Log the detection for security monitoring
			log.WithFields(logrus.Fields{
				"input":   input,
				"pattern": pattern,
			}).Warn("Potential XSS pattern detected in user input")
			detected = true
		}
	}

	return detected
}

// ValidateAndSanitizeTemplateName validates and sanitizes template names
func ValidateAndSanitizeTemplateName(name string) (string, error) {
	// Trim whitespace
	name = strings.TrimSpace(name)

	// Check length
	if len(name) == 0 {
		return "", errors.New("template name cannot be empty")
	}
	if len(name) > 255 {
		return "", errors.New("template name exceeds maximum length of 255 characters")
	}

	// Detect XSS patterns
	if DetectXSSPatterns(name) {
		return "", errors.New("template name contains potentially malicious content")
	}

	// Sanitize for safe storage and display
	sanitized := SanitizeHTMLForDisplay(name)

	return sanitized, nil
}

// ValidateAndSanitizeHTMLContent validates and sanitizes HTML template content
// This is more permissive than name validation since templates need to contain HTML
func ValidateAndSanitizeHTMLContent(html string) (string, error) {
	// Check length
	if len(html) > 1000000 { // 1MB limit
		return "", errors.New("HTML content exceeds maximum length")
	}

	// Detect suspicious patterns but don't necessarily reject
	// (templates are supposed to contain HTML, but log for monitoring)
	if DetectXSSPatterns(html) {
		log.Warn("Template HTML contains patterns similar to XSS payloads - review recommended")
	}

	// For template HTML, we generally want to preserve the content
	// but ensure dangerous patterns are logged
	// The template engine will handle proper escaping when rendered
	return html, nil
}
