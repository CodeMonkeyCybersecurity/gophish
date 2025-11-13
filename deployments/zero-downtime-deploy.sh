#!/bin/bash
# zero-downtime-deploy.sh - Deploy Gophish with HERA V3 without downtime
#
# This script performs a rolling deployment with health checks to ensure
# zero downtime during updates.
#
# Usage: ./zero-downtime-deploy.sh [OPTIONS]
#   -b, --binary PATH    Path to new binary (default: ./gophish)
#   -c, --config PATH    Path to config file (default: ./config.json)
#   -p, --port PORT      New instance port (default: 3334)
#   -o, --old-port PORT  Old instance port (default: 3333)
#   -w, --wait SECONDS   Wait time for drain (default: 30)
#   -h, --help          Show this help message

set -e

# Default values
NEW_BINARY="./gophish"
CONFIG_FILE="./config.json"
NEW_PORT=3334
OLD_PORT=3333
DRAIN_WAIT=30
PID_FILE="./gophish.pid"
LOG_FILE="./deployment.log"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -b|--binary)
            NEW_BINARY="$2"
            shift 2
            ;;
        -c|--config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        -p|--port)
            NEW_PORT="$2"
            shift 2
            ;;
        -o|--old-port)
            OLD_PORT="$2"
            shift 2
            ;;
        -w|--wait)
            DRAIN_WAIT="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo "  -b, --binary PATH    Path to new binary"
            echo "  -c, --config PATH    Path to config file"
            echo "  -p, --port PORT      New instance port"
            echo "  -o, --old-port PORT  Old instance port"
            echo "  -w, --wait SECONDS   Wait time for drain"
            echo "  -h, --help          Show this help"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

log_info "========================================="
log_info "Gophish Zero-Downtime Deployment (HERA V3)"
log_info "========================================="
log_info ""
log_info "Configuration:"
log_info "  New Binary: $NEW_BINARY"
log_info "  Config File: $CONFIG_FILE"
log_info "  New Port: $NEW_PORT"
log_info "  Old Port: $OLD_PORT"
log_info "  Drain Wait: ${DRAIN_WAIT}s"
log_info ""

# Pre-flight checks
log_info "Running pre-flight checks..."

if [ ! -f "$NEW_BINARY" ]; then
    log_error "New binary not found: $NEW_BINARY"
    exit 1
fi

if [ ! -x "$NEW_BINARY" ]; then
    log_error "New binary is not executable: $NEW_BINARY"
    exit 1
fi

if [ ! -f "$CONFIG_FILE" ]; then
    log_error "Config file not found: $CONFIG_FILE"
    exit 1
fi

log_success "Pre-flight checks passed"
log_info ""

# Check if old instance is running
log_info "Checking for running instance..."
if [ -f "$PID_FILE" ]; then
    OLD_PID=$(cat "$PID_FILE")
    if ps -p "$OLD_PID" > /dev/null 2>&1; then
        log_info "Found running instance (PID: $OLD_PID)"
    else
        log_warning "PID file exists but process not running"
        rm -f "$PID_FILE"
        OLD_PID=""
    fi
else
    log_warning "No PID file found (fresh deployment)"
    OLD_PID=""
fi
log_info ""

# Create backup
log_info "Creating backup..."
BACKUP_DIR="./backups/$(date '+%Y%m%d-%H%M%S')"
mkdir -p "$BACKUP_DIR"

if [ -n "$OLD_PID" ]; then
    OLD_BINARY=$(readlink -f "/proc/$OLD_PID/exe" 2>/dev/null || echo "")
    if [ -n "$OLD_BINARY" ] && [ -f "$OLD_BINARY" ]; then
        cp "$OLD_BINARY" "$BACKUP_DIR/gophish.old"
        log_success "Backed up old binary to $BACKUP_DIR/gophish.old"
    fi
fi

cp "$CONFIG_FILE" "$BACKUP_DIR/config.json.bak"
log_success "Backed up config to $BACKUP_DIR/config.json.bak"
log_info ""

# Start new instance on different port
log_info "Starting new instance on port $NEW_PORT..."
"$NEW_BINARY" --config "$CONFIG_FILE" --port "$NEW_PORT" > "$BACKUP_DIR/new-instance.log" 2>&1 &
NEW_PID=$!

log_info "New instance started (PID: $NEW_PID)"
log_info ""

# Wait for new instance to become healthy
log_info "Waiting for new instance to become healthy..."
HEALTH_URL="http://localhost:$NEW_PORT/health"
MAX_ATTEMPTS=30
ATTEMPT=0

while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
    ATTEMPT=$((ATTEMPT + 1))

    if curl -s -f "$HEALTH_URL" > /dev/null 2>&1; then
        HEALTH_STATUS=$(curl -s "$HEALTH_URL" | grep -o '"status":"[^"]*"' | cut -d'"' -f4 || echo "unknown")

        if [ "$HEALTH_STATUS" = "healthy" ]; then
            log_success "New instance is healthy (attempt $ATTEMPT/$MAX_ATTEMPTS)"
            break
        else
            log_warning "New instance status: $HEALTH_STATUS (attempt $ATTEMPT/$MAX_ATTEMPTS)"
        fi
    else
        log_info "Waiting for health check... (attempt $ATTEMPT/$MAX_ATTEMPTS)"
    fi

    if [ $ATTEMPT -eq $MAX_ATTEMPTS ]; then
        log_error "New instance failed to become healthy"
        log_error "Check logs: $BACKUP_DIR/new-instance.log"
        log_info "Killing new instance..."
        kill "$NEW_PID" 2>/dev/null || true
        exit 1
    fi

    sleep 2
done
log_info ""

# Run smoke tests on new instance
log_info "Running smoke tests on new instance..."

# Test 1: Health check
if curl -s -f "$HEALTH_URL" > /dev/null 2>&1; then
    log_success "✓ Health check passed"
else
    log_error "✗ Health check failed"
    kill "$NEW_PID" 2>/dev/null || true
    exit 1
fi

# Test 2: Metrics endpoint
METRICS_URL="http://localhost:$NEW_PORT/metrics"
if curl -s -f "$METRICS_URL" > /dev/null 2>&1; then
    log_success "✓ Metrics endpoint accessible"
else
    log_warning "⚠ Metrics endpoint not accessible (may be expected)"
fi

log_info ""

# If there's an old instance, drain traffic
if [ -n "$OLD_PID" ]; then
    log_info "Draining traffic from old instance..."
    log_info "Waiting ${DRAIN_WAIT}s for connections to drain..."

    # TODO: Update load balancer here to route traffic to new instance
    # Example for nginx:
    # nginx -s reload

    sleep "$DRAIN_WAIT"

    log_info "Stopping old instance (PID: $OLD_PID)..."
    kill "$OLD_PID" 2>/dev/null || true

    # Wait for graceful shutdown
    SHUTDOWN_WAIT=10
    WAIT_COUNT=0
    while ps -p "$OLD_PID" > /dev/null 2>&1 && [ $WAIT_COUNT -lt $SHUTDOWN_WAIT ]; do
        sleep 1
        WAIT_COUNT=$((WAIT_COUNT + 1))
    done

    if ps -p "$OLD_PID" > /dev/null 2>&1; then
        log_warning "Old instance did not stop gracefully, forcing..."
        kill -9 "$OLD_PID" 2>/dev/null || true
    else
        log_success "Old instance stopped gracefully"
    fi
else
    log_info "No old instance to drain"
fi
log_info ""

# Update PID file and port binding
log_info "Updating configuration..."
echo "$NEW_PID" > "$PID_FILE"
log_success "Updated PID file with new instance (PID: $NEW_PID)"

# TODO: Update port binding if needed
# This depends on your load balancer/proxy configuration

log_info ""
log_success "========================================="
log_success "Deployment Complete!"
log_success "========================================="
log_info ""
log_info "New instance details:"
log_info "  PID: $NEW_PID"
log_info "  Port: $NEW_PORT"
log_info "  Health: $HEALTH_URL"
log_info ""
log_info "Backup location: $BACKUP_DIR"
log_info ""
log_info "Next steps:"
log_info "  1. Monitor logs for any errors"
log_info "  2. Verify metrics and health status"
log_info "  3. Test critical user flows"
log_info "  4. Update monitoring dashboards"
log_info ""

# Post-deployment checks
log_info "Running post-deployment checks..."
sleep 5

if curl -s -f "$HEALTH_URL" > /dev/null 2>&1; then
    HEALTH=$(curl -s "$HEALTH_URL")
    log_info "Health Status:"
    echo "$HEALTH" | grep -o '"[^"]*":"[^"]*"' | sed 's/^/    /' | tee -a "$LOG_FILE"
    log_success "✓ Post-deployment health check passed"
else
    log_error "✗ Post-deployment health check failed!"
    log_error "Investigate immediately!"
    exit 1
fi

log_info ""
log_success "Deployment successful! Monitor the application for the next 24 hours."

exit 0
