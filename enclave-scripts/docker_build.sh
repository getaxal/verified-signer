#!/bin/bash

# Docker build script for Nitro Enclave
# Usage: ./docker_build.sh

# Resolve the repo root so this script works from any directory. The Dockerfile
# lives at the repo root and COPYs both common/ and enclave/, so the repo root
# must be the build context.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Variables
DOCKER_IMAGE_NAME="verified-signer"
DOCKER_TAG="latest"
LOG_DIR="./enclave-logs"
BUILD_LOG="$LOG_DIR/build.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Create log directory
mkdir -p "$LOG_DIR"
chmod 750 "$LOG_DIR"  # Owner rwx, group rx, other none
touch "$BUILD_LOG" "$CONSOLE_LOG" "$ENCLAVE_LOG"
chmod 640 "$BUILD_LOG" "$CONSOLE_LOG" "$ENCLAVE_LOG"  # Owner rw, group r, other none
chown root:nitro-enclave "$BUILD_LOG" "$CONSOLE_LOG" "$ENCLAVE_LOG" 2>/dev/null || true

echo "🐳 Docker Build for Nitro Enclave"
echo "=================================="

# Initialize build log
echo "=== Docker Build Log - $(date) ===" >> "$BUILD_LOG"
echo "" >> "$BUILD_LOG"

# Check if Docker image already exists
if docker images | grep -q "$DOCKER_IMAGE_NAME.*$DOCKER_TAG"; then
    echo -e "${YELLOW}⚠️  Docker image $DOCKER_IMAGE_NAME:$DOCKER_TAG already exists${NC}"
    echo "   Use 'docker rmi $DOCKER_IMAGE_NAME:$DOCKER_TAG' to rebuild from scratch"
    echo "   Proceeding with existing image..."
    exit 0
fi

echo "🔧 Starting Docker build process..."
echo "   📝 Build logs: $BUILD_LOG"
echo "" | tee -a "$BUILD_LOG"

# Build Docker image
echo "🔨 Building Docker image: $DOCKER_IMAGE_NAME:$DOCKER_TAG" | tee -a "$BUILD_LOG"
echo "   This may take several minutes..." | tee -a "$BUILD_LOG"
echo "" | tee -a "$BUILD_LOG"

# Enable Docker BuildKit and build with SSH
export DOCKER_BUILDKIT=1

if docker build -f "$REPO_ROOT/Dockerfile" -t "$DOCKER_IMAGE_NAME:$DOCKER_TAG" "$REPO_ROOT" 2>&1 | tee -a "$BUILD_LOG"; then
    echo "" | tee -a "$BUILD_LOG"
    echo -e "${GREEN}✅ Docker image built successfully!${NC}" | tee -a "$BUILD_LOG"
    echo "   📦 Image: $DOCKER_IMAGE_NAME:$DOCKER_TAG" | tee -a "$BUILD_LOG"
    echo "   📝 Build logs saved to: $BUILD_LOG" | tee -a "$BUILD_LOG"
    
    # Show image details
    echo "" | tee -a "$BUILD_LOG"
    echo "📊 Image details:" | tee -a "$BUILD_LOG"
    docker images "$DOCKER_IMAGE_NAME:$DOCKER_TAG" | tee -a "$BUILD_LOG"
    
else
    echo "" | tee -a "$BUILD_LOG"
    echo -e "${RED}❌ Docker build failed!${NC}" | tee -a "$BUILD_LOG"
    echo "   📝 Check build logs: $BUILD_LOG" | tee -a "$BUILD_LOG"
    echo "   💡 Common issues:" | tee -a "$BUILD_LOG"
    echo "      - SSH key not added to agent" | tee -a "$BUILD_LOG"
    echo "      - Private repository access" | tee -a "$BUILD_LOG"
    echo "      - Network connectivity" | tee -a "$BUILD_LOG"
    exit 1
fi

echo "" | tee -a "$BUILD_LOG"
echo "🎉 Docker build completed successfully!" | tee -a "$BUILD_LOG"
echo "   Next: Run './run.sh' to deploy the enclave" | tee -a "$BUILD_LOG"