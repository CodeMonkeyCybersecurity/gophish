#!/bin/bash

# Script to build and run Gophish in Docker

echo "Building Gophish Docker image..."

# Build the image
docker build -f Dockerfile.updated -t gophish:local .

if [ $? -ne 0 ]; then
    echo "Build failed!"
    exit 1
fi

echo "Build successful!"

# Option 1: Run with docker-compose (recommended)
echo ""
echo "To run with docker-compose (recommended):"
echo "  docker-compose up -d"
echo ""
echo "To view logs:"
echo "  docker-compose logs -f gophish"
echo ""
echo "To stop:"
echo "  docker-compose down"

# Option 2: Run with docker run
echo ""
echo "To run with docker run:"
echo "  docker run -d \\"
echo "    --name gophish \\"
echo "    -p 3333:3333 \\"
echo "    -p 8080:8080 \\"
echo "    -e ADMIN_LISTEN_URL=0.0.0.0:3333 \\"
echo "    -e PHISH_LISTEN_URL=0.0.0.0:8080 \\"
echo "    gophish:local"
echo ""
echo "To view logs:"
echo "  docker logs -f gophish"
echo ""
echo "To stop:"
echo "  docker stop gophish && docker rm gophish"

echo ""
echo "Access Gophish at:"
echo "  Admin Panel: http://localhost:3333"
echo "  Phishing Server: http://localhost:8080"
echo ""
echo "Default credentials are printed in the logs on first run."