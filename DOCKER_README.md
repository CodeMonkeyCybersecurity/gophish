# Running Gophish with Docker

This guide explains how to build and run Gophish using Docker.

## Prerequisites

- Docker installed on your machine
- Docker Compose (optional, but recommended)

## Quick Start

### Option 1: Using the build script (Easiest)

```bash
# Make the script executable (only needed once)
chmod +x docker-build-and-run.sh

# Build and get run instructions
./docker-build-and-run.sh
```

### Option 2: Using Docker Compose (Recommended)

```bash
# Build and start Gophish
docker-compose up -d

# View logs
docker-compose logs -f gophish

# Stop Gophish
docker-compose down
```

### Option 3: Manual Docker commands

```bash
# Build the image
docker build -f Dockerfile.updated -t gophish:local .

# Run the container
docker run -d \
  --name gophish \
  -p 3333:3333 \
  -p 8080:8080 \
  -e ADMIN_LISTEN_URL=0.0.0.0:3333 \
  -e PHISH_LISTEN_URL=0.0.0.0:8080 \
  gophish:local

# View logs
docker logs -f gophish

# Stop and remove
docker stop gophish && docker rm gophish
```

## Accessing Gophish

Once running, you can access:
- **Admin Panel**: http://localhost:3333
- **Phishing Server**: http://localhost:8080

The default admin credentials will be displayed in the container logs on first run:
```bash
docker logs gophish | grep -A 2 "Please login"
```

## Configuration

### Environment Variables

The Docker image supports configuration through environment variables:

**Admin Server:**
- `ADMIN_LISTEN_URL`: Admin interface listen address (default: 0.0.0.0:3333)
- `ADMIN_USE_TLS`: Enable TLS for admin interface (default: false)
- `ADMIN_CERT_PATH`: Path to admin TLS certificate
- `ADMIN_KEY_PATH`: Path to admin TLS key
- `ADMIN_TRUSTED_ORIGINS`: Comma-separated list of trusted origins

**Phish Server:**
- `PHISH_LISTEN_URL`: Phishing server listen address (default: 0.0.0.0:8080)
- `PHISH_USE_TLS`: Enable TLS for phishing server (default: false)
- `PHISH_CERT_PATH`: Path to phishing server TLS certificate
- `PHISH_KEY_PATH`: Path to phishing server TLS key

**Database:**
- `DB_NAME`: Database type - sqlite3, mysql, or postgres (default: sqlite3)
- `DB_FILE_PATH`: Database connection string

**Other:**
- `CONTACT_ADDRESS`: Contact address for transparency reports

### Database Configuration Examples

**SQLite (Default):**
```yaml
environment:
  - DB_NAME=sqlite3
  - DB_FILE_PATH=gophish.db
```

**MySQL:**
```yaml
environment:
  - DB_NAME=mysql
  - DB_FILE_PATH=username:password@tcp(mysql:3306)/gophish?charset=utf8&parseTime=True&loc=Local
```

**PostgreSQL:**
```yaml
environment:
  - DB_NAME=postgres
  - DB_FILE_PATH=host=postgres port=5432 user=gophish password=gophish dbname=gophish sslmode=disable
```

## Using with External Database

To use MySQL or PostgreSQL, uncomment the respective service in `docker-compose.yml`:

```yaml
# For MySQL, uncomment the mysql service
# For PostgreSQL, uncomment the postgres service
```

Then update the Gophish environment variables to point to the database.

## Data Persistence

The docker-compose configuration creates a named volume `gophish_data` to persist:
- SQLite database
- Generated certificates
- Any uploaded files

## TLS/SSL Configuration

To enable TLS:

1. Place your certificates in a `certs` directory
2. Mount the certificates volume in docker-compose.yml:
   ```yaml
   volumes:
     - ./certs:/opt/gophish/certs:ro
   ```
3. Set the environment variables:
   ```yaml
   environment:
     - ADMIN_USE_TLS=true
     - ADMIN_CERT_PATH=/opt/gophish/certs/admin.crt
     - ADMIN_KEY_PATH=/opt/gophish/certs/admin.key
   ```

## Troubleshooting

1. **Port already in use**: Change the port mappings in docker-compose.yml
2. **Permission denied**: Ensure the user has permission to bind to ports (especially port 80)
3. **Database connection issues**: Check the database connection string and ensure the database service is running

## Building for Production

For production use:
1. Use specific version tags instead of `latest` for base images
2. Enable TLS for both admin and phishing servers
3. Use an external database (MySQL or PostgreSQL) instead of SQLite
4. Set up proper backup procedures for the database
5. Use a reverse proxy (nginx, traefik) for additional security