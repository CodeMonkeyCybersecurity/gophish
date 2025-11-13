package monitoring

import (
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	log "github.com/gophish/gophish/logger"
)

// Metrics holds all application metrics
type Metrics struct {
	// CORS metrics
	CORSAllowedRequests  int64 `json:"cors_allowed_requests"`
	CORSRejectedRequests int64 `json:"cors_rejected_requests"`

	// Template metrics
	TemplateExecutions       int64 `json:"template_executions"`
	TemplateErrors           int64 `json:"template_errors"`
	TemplateTimeouts         int64 `json:"template_timeouts"`
	ActiveTemplateGoroutines int64 `json:"active_template_goroutines"`

	// Session metrics
	SessionValidationErrors int64 `json:"session_validation_errors"`
	SessionCreated          int64 `json:"sessions_created"`
	SessionDestroyed        int64 `json:"sessions_destroyed"`

	// Password metrics
	PasswordStrengthChecks int64 `json:"password_strength_checks"`
	WeakPasswordsRejected  int64 `json:"weak_passwords_rejected"`
	CommonPasswordsBlocked int64 `json:"common_passwords_blocked"`

	// System metrics
	SystemGoroutines int    `json:"system_goroutines"`
	SystemMemoryMB   uint64 `json:"system_memory_mb"`
	Uptime           int64  `json:"uptime_seconds"`
}

var (
	globalMetrics Metrics
	startTime     time.Time
)

func init() {
	startTime = time.Now()
}

// IncrementCORSAllowed increments CORS allowed counter
func IncrementCORSAllowed() {
	atomic.AddInt64(&globalMetrics.CORSAllowedRequests, 1)
}

// IncrementCORSRejected increments CORS rejected counter
func IncrementCORSRejected() {
	atomic.AddInt64(&globalMetrics.CORSRejectedRequests, 1)
}

// IncrementTemplateExecution increments template execution counter
func IncrementTemplateExecution() {
	atomic.AddInt64(&globalMetrics.TemplateExecutions, 1)
}

// IncrementTemplateError increments template error counter
func IncrementTemplateError() {
	atomic.AddInt64(&globalMetrics.TemplateErrors, 1)
}

// IncrementTemplateTimeout increments template timeout counter
func IncrementTemplateTimeout() {
	atomic.AddInt64(&globalMetrics.TemplateTimeouts, 1)
}

// SetActiveTemplateGoroutines sets active template goroutine count
func SetActiveTemplateGoroutines(count int64) {
	atomic.StoreInt64(&globalMetrics.ActiveTemplateGoroutines, count)
}

// IncrementSessionValidationError increments session validation error counter
func IncrementSessionValidationError() {
	atomic.AddInt64(&globalMetrics.SessionValidationErrors, 1)
}

// IncrementSessionCreated increments session created counter
func IncrementSessionCreated() {
	atomic.AddInt64(&globalMetrics.SessionCreated, 1)
}

// IncrementSessionDestroyed increments session destroyed counter
func IncrementSessionDestroyed() {
	atomic.AddInt64(&globalMetrics.SessionDestroyed, 1)
}

// IncrementPasswordStrengthCheck increments password check counter
func IncrementPasswordStrengthCheck() {
	atomic.AddInt64(&globalMetrics.PasswordStrengthChecks, 1)
}

// IncrementWeakPasswordRejected increments weak password counter
func IncrementWeakPasswordRejected() {
	atomic.AddInt64(&globalMetrics.WeakPasswordsRejected, 1)
}

// IncrementCommonPasswordBlocked increments common password counter
func IncrementCommonPasswordBlocked() {
	atomic.AddInt64(&globalMetrics.CommonPasswordsBlocked, 1)
}

// GetMetrics returns current metrics with system stats
func GetMetrics() Metrics {
	m := Metrics{
		CORSAllowedRequests:      atomic.LoadInt64(&globalMetrics.CORSAllowedRequests),
		CORSRejectedRequests:     atomic.LoadInt64(&globalMetrics.CORSRejectedRequests),
		TemplateExecutions:       atomic.LoadInt64(&globalMetrics.TemplateExecutions),
		TemplateErrors:           atomic.LoadInt64(&globalMetrics.TemplateErrors),
		TemplateTimeouts:         atomic.LoadInt64(&globalMetrics.TemplateTimeouts),
		ActiveTemplateGoroutines: atomic.LoadInt64(&globalMetrics.ActiveTemplateGoroutines),
		SessionValidationErrors:  atomic.LoadInt64(&globalMetrics.SessionValidationErrors),
		SessionCreated:           atomic.LoadInt64(&globalMetrics.SessionCreated),
		SessionDestroyed:         atomic.LoadInt64(&globalMetrics.SessionDestroyed),
		PasswordStrengthChecks:   atomic.LoadInt64(&globalMetrics.PasswordStrengthChecks),
		WeakPasswordsRejected:    atomic.LoadInt64(&globalMetrics.WeakPasswordsRejected),
		CommonPasswordsBlocked:   atomic.LoadInt64(&globalMetrics.CommonPasswordsBlocked),
		SystemGoroutines:         runtime.NumGoroutine(),
		Uptime:                   int64(time.Since(startTime).Seconds()),
	}

	// Get memory stats
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	m.SystemMemoryMB = memStats.Alloc / 1024 / 1024

	return m
}

// MetricsHandler returns an HTTP handler that exposes metrics as JSON
func MetricsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		metrics := GetMetrics()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		if err := json.NewEncoder(w).Encode(metrics); err != nil {
			log.Errorf("Failed to encode metrics: %v", err)
			http.Error(w, "Failed to encode metrics", http.StatusInternalServerError)
			return
		}
	}
}

// HealthStatus represents application health
type HealthStatus struct {
	Status         string            `json:"status"` // "healthy", "degraded", "unhealthy"
	Timestamp      time.Time         `json:"timestamp"`
	Uptime         int64             `json:"uptime_seconds"`
	Checks         map[string]string `json:"checks"`
	GoroutineCount int               `json:"goroutine_count"`
	MemoryMB       uint64            `json:"memory_mb"`
}

// HealthCheck performs health checks
type HealthCheck struct {
	DatabaseCheck    func() error
	SessionStoreCheck func() error
	MaxGoroutines    int
	MaxMemoryMB      uint64
}

// Check performs all health checks
func (hc *HealthCheck) Check() HealthStatus {
	status := HealthStatus{
		Status:    "healthy",
		Timestamp: time.Now(),
		Uptime:    int64(time.Since(startTime).Seconds()),
		Checks:    make(map[string]string),
	}

	// Check database
	if hc.DatabaseCheck != nil {
		if err := hc.DatabaseCheck(); err != nil {
			status.Status = "degraded"
			status.Checks["database"] = fmt.Sprintf("error: %v", err)
		} else {
			status.Checks["database"] = "ok"
		}
	}

	// Check session store
	if hc.SessionStoreCheck != nil {
		if err := hc.SessionStoreCheck(); err != nil {
			status.Status = "degraded"
			status.Checks["session_store"] = fmt.Sprintf("error: %v", err)
		} else {
			status.Checks["session_store"] = "ok"
		}
	}

	// Check goroutine count
	status.GoroutineCount = runtime.NumGoroutine()
	if hc.MaxGoroutines > 0 && status.GoroutineCount > hc.MaxGoroutines {
		status.Status = "degraded"
		status.Checks["goroutines"] = fmt.Sprintf("high: %d (max: %d)", status.GoroutineCount, hc.MaxGoroutines)
	} else {
		status.Checks["goroutines"] = "ok"
	}

	// Check memory
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	status.MemoryMB = memStats.Alloc / 1024 / 1024

	if hc.MaxMemoryMB > 0 && status.MemoryMB > hc.MaxMemoryMB {
		status.Status = "degraded"
		status.Checks["memory"] = fmt.Sprintf("high: %d MB (max: %d MB)", status.MemoryMB, hc.MaxMemoryMB)
	} else {
		status.Checks["memory"] = "ok"
	}

	// Check template goroutines specifically
	activeTemplateGoroutines := atomic.LoadInt64(&globalMetrics.ActiveTemplateGoroutines)
	if activeTemplateGoroutines > 100 {
		status.Status = "degraded"
		status.Checks["template_goroutines"] = fmt.Sprintf("leak detected: %d active", activeTemplateGoroutines)
	} else {
		status.Checks["template_goroutines"] = "ok"
	}

	// Check template timeout rate
	totalTimeouts := atomic.LoadInt64(&globalMetrics.TemplateTimeouts)
	if totalTimeouts > 1000 {
		status.Status = "degraded"
		status.Checks["template_timeouts"] = fmt.Sprintf("high: %d total", totalTimeouts)
	} else {
		status.Checks["template_timeouts"] = "ok"
	}

	return status
}

// HealthHandler returns an HTTP handler for health checks
func HealthHandler(check *HealthCheck) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		status := check.Check()

		w.Header().Set("Content-Type", "application/json")

		// Return 503 if unhealthy or degraded
		if status.Status != "healthy" {
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(http.StatusOK)
		}

		if err := json.NewEncoder(w).Encode(status); err != nil {
			log.Errorf("Failed to encode health status: %v", err)
			return
		}
	}
}

// PrometheusMetrics formats metrics in Prometheus text format
func PrometheusMetrics() string {
	m := GetMetrics()

	var output strings.Builder

	// CORS metrics
	output.WriteString(fmt.Sprintf("# HELP gophish_cors_requests_total Total number of CORS requests\n"))
	output.WriteString(fmt.Sprintf("# TYPE gophish_cors_requests_total counter\n"))
	output.WriteString(fmt.Sprintf("gophish_cors_requests_total{allowed=\"true\"} %d\n", m.CORSAllowedRequests))
	output.WriteString(fmt.Sprintf("gophish_cors_requests_total{allowed=\"false\"} %d\n", m.CORSRejectedRequests))

	// Template metrics
	output.WriteString(fmt.Sprintf("# HELP gophish_template_executions_total Total number of template executions\n"))
	output.WriteString(fmt.Sprintf("# TYPE gophish_template_executions_total counter\n"))
	output.WriteString(fmt.Sprintf("gophish_template_executions_total %d\n", m.TemplateExecutions))

	output.WriteString(fmt.Sprintf("# HELP gophish_template_errors_total Total number of template errors\n"))
	output.WriteString(fmt.Sprintf("# TYPE gophish_template_errors_total counter\n"))
	output.WriteString(fmt.Sprintf("gophish_template_errors_total %d\n", m.TemplateErrors))

	output.WriteString(fmt.Sprintf("# HELP gophish_template_timeouts_total Total number of template timeouts\n"))
	output.WriteString(fmt.Sprintf("# TYPE gophish_template_timeouts_total counter\n"))
	output.WriteString(fmt.Sprintf("gophish_template_timeouts_total %d\n", m.TemplateTimeouts))

	output.WriteString(fmt.Sprintf("# HELP gophish_template_goroutines Number of active template goroutines\n"))
	output.WriteString(fmt.Sprintf("# TYPE gophish_template_goroutines gauge\n"))
	output.WriteString(fmt.Sprintf("gophish_template_goroutines %d\n", m.ActiveTemplateGoroutines))

	// Session metrics
	output.WriteString(fmt.Sprintf("# HELP gophish_session_validation_errors_total Total number of session validation errors\n"))
	output.WriteString(fmt.Sprintf("# TYPE gophish_session_validation_errors_total counter\n"))
	output.WriteString(fmt.Sprintf("gophish_session_validation_errors_total %d\n", m.SessionValidationErrors))

	// Password metrics
	output.WriteString(fmt.Sprintf("# HELP gophish_password_checks_total Total number of password strength checks\n"))
	output.WriteString(fmt.Sprintf("# TYPE gophish_password_checks_total counter\n"))
	output.WriteString(fmt.Sprintf("gophish_password_checks_total %d\n", m.PasswordStrengthChecks))

	output.WriteString(fmt.Sprintf("# HELP gophish_weak_passwords_rejected_total Total number of weak passwords rejected\n"))
	output.WriteString(fmt.Sprintf("# TYPE gophish_weak_passwords_rejected_total counter\n"))
	output.WriteString(fmt.Sprintf("gophish_weak_passwords_rejected_total %d\n", m.WeakPasswordsRejected))

	// System metrics
	output.WriteString(fmt.Sprintf("# HELP gophish_goroutines Number of goroutines\n"))
	output.WriteString(fmt.Sprintf("# TYPE gophish_goroutines gauge\n"))
	output.WriteString(fmt.Sprintf("gophish_goroutines %d\n", m.SystemGoroutines))

	output.WriteString(fmt.Sprintf("# HELP gophish_memory_mb Memory usage in MB\n"))
	output.WriteString(fmt.Sprintf("# TYPE gophish_memory_mb gauge\n"))
	output.WriteString(fmt.Sprintf("gophish_memory_mb %d\n", m.SystemMemoryMB))

	output.WriteString(fmt.Sprintf("# HELP gophish_uptime_seconds Application uptime in seconds\n"))
	output.WriteString(fmt.Sprintf("# TYPE gophish_uptime_seconds counter\n"))
	output.WriteString(fmt.Sprintf("gophish_uptime_seconds %d\n", m.Uptime))

	return output.String()
}

// PrometheusHandler returns an HTTP handler for Prometheus metrics
func PrometheusHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(PrometheusMetrics()))
	}
}
