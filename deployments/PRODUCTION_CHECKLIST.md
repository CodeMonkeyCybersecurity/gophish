# HERA V3 Production Deployment Checklist

## Pre-Deployment Phase (1 Week Before)

### Code Quality & Testing
- [ ] All unit tests passing (`go test ./...`)
- [ ] Integration tests passing (`./scripts/test-hera-v3.sh`)
- [ ] Race condition checks clean (`go test -race ./...`)
- [ ] Security scan completed (`gosec ./...`)
- [ ] Vulnerability check completed (`govulncheck ./...`)
- [ ] Code coverage > 70% (`go test -cover ./...`)
- [ ] Performance benchmarks acceptable
- [ ] Load testing completed (if applicable)

### Security Configuration
- [ ] **Session keys generated** (`go run scripts/generate-session-keys.go`)
- [ ] Session keys added to `config.json` (signing + encryption)
- [ ] Session keys stored securely (not in version control)
- [ ] CORS origins configured (exact origins or wildcard patterns)
- [ ] CORS configuration validated
- [ ] Common password list file created (`data/common-passwords.txt`)
- [ ] TLS certificates obtained and validated
- [ ] TLS configuration tested (minimum TLS 1.2)

### Infrastructure
- [ ] Database backed up (full backup + verification)
- [ ] Database migrations tested in staging
- [ ] Database connection pooling configured
- [ ] Load balancer configured (if multi-instance)
- [ ] Health check endpoint tested (`/health`)
- [ ] Metrics endpoint accessible (`/metrics`)
- [ ] Prometheus/Grafana configured
- [ ] Alert rules configured
- [ ] Log aggregation configured
- [ ] Backup procedures documented and tested

### Documentation
- [ ] Deployment runbook updated
- [ ] Rollback procedures documented
- [ ] Disaster recovery plan updated
- [ ] Team trained on new features
- [ ] On-call rotation updated
- [ ] Incident response plan updated

### Staging Validation
- [ ] Deployed to staging environment
- [ ] Smoke tests passed in staging
- [ ] Load tests passed in staging
- [ ] Security tests passed in staging
- [ ] Performance tests passed in staging
- [ ] User acceptance testing completed
- [ ] Monitored staging for 48+ hours

---

## Deployment Day (T-0)

### Pre-Deployment (T-4 hours)
- [ ] Announce maintenance window to users
- [ ] Verify team availability (primary + backup)
- [ ] Verify rollback plan is ready
- [ ] Verify monitoring is operational
- [ ] Create deployment incident ticket

### Backup Phase (T-2 hours)
- [ ] Create full database backup
  ```bash
  # MySQL
  mysqldump -u gophish -p gophish > backup-$(date +%Y%m%d-%H%M%S).sql

  # SQLite
  cp gophish.db gophish.db.backup-$(date +%Y%m%d-%H%M%S)
  ```
- [ ] Verify backup integrity
- [ ] Backup current binary
  ```bash
  cp gophish gophish.backup-$(date +%Y%m%d-%H%M%S)
  ```
- [ ] Backup configuration files
  ```bash
  cp config.json config.json.backup-$(date +%Y%m%d-%H%M%S)
  ```
- [ ] Backup stored data/files
- [ ] Document current system state
  - Go version: `go version`
  - Git commit: `git rev-parse HEAD`
  - Database schema version
  - Active connections count

### Deployment Phase (T-0)

#### Option A: Standard Deployment (With Downtime)
- [ ] Stop application
  ```bash
  kill $(cat gophish.pid)
  ```
- [ ] Deploy new binary
  ```bash
  cp gophish-new gophish
  chmod +x gophish
  ```
- [ ] Update configuration
  ```bash
  # Add session keys to config.json
  # Update CORS origins
  # Update any other V3 settings
  ```
- [ ] Run database migrations
  ```bash
  ./gophish --migrate
  ```
- [ ] Start application
  ```bash
  ./gophish --config config.json &
  echo $! > gophish.pid
  ```

#### Option B: Zero-Downtime Deployment
- [ ] Run zero-downtime deployment script
  ```bash
  ./deployments/zero-downtime-deploy.sh \
    --binary ./gophish-new \
    --config ./config.json \
    --port 3334 \
    --old-port 3333 \
    --wait 30
  ```
- [ ] Verify deployment script output
- [ ] Check deployment logs

### Verification Phase (T+0)

#### Health Checks
- [ ] Application started successfully
  ```bash
  ps aux | grep gophish
  ```
- [ ] Health endpoint responding
  ```bash
  curl http://localhost:3333/health
  ```
- [ ] Expected status: `"status":"healthy"`
- [ ] Database connectivity verified
- [ ] Session store initialized
- [ ] No goroutine leaks detected

#### Critical Path Testing
- [ ] **Login/Logout**
  - [ ] Admin login works
  - [ ] Session persists across requests
  - [ ] Logout works correctly
  - [ ] Session invalidated after logout

- [ ] **Campaign Management**
  - [ ] Create new campaign
  - [ ] Send test email
  - [ ] View campaign results
  - [ ] Export campaign data

- [ ] **Template Rendering**
  - [ ] Create new template
  - [ ] Preview template
  - [ ] Template executes without timeout
  - [ ] HTML rendering works correctly

- [ ] **API Authentication**
  - [ ] API key authentication works
  - [ ] API endpoints accessible
  - [ ] API rate limiting functional

- [ ] **CORS Functionality**
  - [ ] Allowed origins can access API
  - [ ] Non-allowed origins blocked
  - [ ] Wildcard patterns work correctly
  - [ ] Preflight requests handled

#### Log Review
- [ ] Check startup logs for errors
  ```bash
  tail -f gophish.log | grep ERROR
  ```
- [ ] No critical errors present
- [ ] No warnings about missing configuration
- [ ] Session keys loaded correctly (not logged!)
- [ ] CORS patterns compiled successfully
- [ ] Common password list loaded

#### Metrics Review
- [ ] Metrics endpoint accessible
  ```bash
  curl http://localhost:3333/metrics
  ```
- [ ] CORS metrics tracking
- [ ] Template execution metrics tracking
- [ ] Session metrics tracking
- [ ] Goroutine count normal (< 100)
- [ ] Memory usage normal

---

## Post-Deployment Phase (T+1 hour to T+24 hours)

### T+1 Hour
- [ ] Monitor error rates (should be < 1%)
- [ ] Monitor response times (p95 < 500ms)
- [ ] Check goroutine count (should be stable)
- [ ] Check memory usage (should not be increasing)
- [ ] Verify session persistence
- [ ] Check CORS rejection rate
- [ ] Review template execution times
- [ ] No unexpected errors in logs

### T+4 Hours
- [ ] User feedback collected (if available)
- [ ] Performance metrics reviewed
- [ ] Error rate still acceptable
- [ ] No memory leaks detected
- [ ] Goroutine count stable
- [ ] Cache hit rates acceptable (CORS > 80%)
- [ ] Database performance acceptable
- [ ] No disk I/O issues

### T+24 Hours
- [ ] Full system health check
- [ ] Security scan repeated
- [ ] Performance metrics compared to baseline
- [ ] User satisfaction survey (if applicable)
- [ ] Incident review (if any issues occurred)
- [ ] Documentation updated with lessons learned
- [ ] Backup jobs verified running
- [ ] Monitoring alerts verified
- [ ] On-call handoff completed

---

## Post-Deployment Monitoring (Week 1)

### Daily Checks
- [ ] **Day 1:** Intensive monitoring (every hour)
- [ ] **Day 2:** Check metrics 3x per day
- [ ] **Day 3:** Check metrics 2x per day
- [ ] **Day 4-7:** Daily health checks

### Weekly Review (End of Week 1)
- [ ] Full system health review
- [ ] Performance baseline established
- [ ] Error rates documented
- [ ] User feedback collected and analyzed
- [ ] Incident post-mortem (if any)
- [ ] Security audit
- [ ] Documentation updates finalized
- [ ] Team retrospective completed

---

## Rollback Procedures

### When to Rollback
Rollback immediately if:
- [ ] Critical functionality broken (login, campaigns, etc.)
- [ ] Error rate > 5%
- [ ] Goroutine leak detected (count > 1000)
- [ ] Memory leak detected (continuous growth)
- [ ] Database corruption detected
- [ ] Security vulnerability discovered

### Rollback Steps
1. [ ] Stop new application
   ```bash
   kill $(cat gophish.pid)
   ```

2. [ ] Restore old binary
   ```bash
   cp gophish.backup-TIMESTAMP gophish
   chmod +x gophish
   ```

3. [ ] Restore old configuration
   ```bash
   cp config.json.backup-TIMESTAMP config.json
   ```

4. [ ] Restore database (if migrations were run)
   ```bash
   # MySQL
   mysql -u gophish -p gophish < backup-TIMESTAMP.sql

   # SQLite
   cp gophish.db.backup-TIMESTAMP gophish.db
   ```

5. [ ] Start old application
   ```bash
   ./gophish --config config.json &
   echo $! > gophish.pid
   ```

6. [ ] Verify rollback successful
   - [ ] Application started
   - [ ] Health check passing
   - [ ] Critical paths working
   - [ ] Users can access system

7. [ ] Notify team and users
8. [ ] Document rollback reason
9. [ ] Schedule post-mortem

---

## Emergency Contacts

| Role | Name | Contact | Availability |
|------|------|---------|-------------|
| Primary On-Call | [Name] | [Phone/Email] | 24/7 |
| Secondary On-Call | [Name] | [Phone/Email] | 24/7 |
| Database Admin | [Name] | [Phone/Email] | Business Hours |
| Security Lead | [Name] | [Phone/Email] | On-Call |
| Infrastructure | [Name] | [Phone/Email] | 24/7 |

---

## Monitoring Dashboards

- [ ] **Grafana Dashboard:** [URL]
- [ ] **Prometheus:** [URL]
- [ ] **Logs:** [URL]
- [ ] **APM:** [URL]
- [ ] **Status Page:** [URL]

---

## Common Issues and Solutions

### Issue: Session keys not loading
**Symptoms:** "session key required" error in logs
**Solution:**
1. Verify keys in `config.json`
2. Check base64 encoding
3. Verify key lengths (signing: 64 bytes, encryption: 32 bytes)
4. Run: `go run scripts/generate-session-keys.go`

### Issue: CORS blocking legitimate origins
**Symptoms:** CORS rejection errors, frontend can't access API
**Solution:**
1. Check `config.json` CORS origins
2. Verify wildcard patterns
3. Check origin cache: `curl http://localhost:3333/metrics`
4. Clear cache if needed (restart application)

### Issue: Template execution timeouts
**Symptoms:** "template timeout" errors
**Solution:**
1. Check template complexity
2. Review template goroutine metrics
3. Verify rate limiting not too aggressive
4. Check for template injection attempts

### Issue: High goroutine count
**Symptoms:** Goroutine count > 1000 and growing
**Solution:**
1. Check template goroutine metrics
2. Review template timeout counter
3. Restart application if leak confirmed
4. Investigate problematic templates

### Issue: Memory leak
**Symptoms:** Memory usage continuously growing
**Solution:**
1. Check CORS origin cache size
2. Review template rate limiters map
3. Check for goroutine leaks
4. Generate heap profile: `curl http://localhost:3333/debug/pprof/heap > heap.prof`

---

## Success Criteria

Deployment is considered successful when:
- [ ] All critical paths working
- [ ] Error rate < 1%
- [ ] Performance within 10% of baseline
- [ ] No critical bugs reported
- [ ] Monitoring shows healthy status
- [ ] Security scans clean
- [ ] No rollback required
- [ ] User feedback positive
- [ ] Team confident in stability
- [ ] 24 hours of stable operation

---

## Sign-Off

| Role | Name | Signature | Date |
|------|------|-----------|------|
| Deployment Lead | __________ | __________ | __________ |
| Security Review | __________ | __________ | __________ |
| QA Approval | __________ | __________ | __________ |
| Product Owner | __________ | __________ | __________ |

---

**Version:** HERA V3
**Last Updated:** 2025-11-12
**Next Review:** Post-Deployment Week 1
