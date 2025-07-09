#!/bin/bash

# Production Docker build script - Always rebuilds from scratch
# Usage: ./docker_build_prod.sh

# Variables
DOCKER_IMAGE_NAME="verified-signer"
DOCKER_TAG="latest"
LOG_DIR="./log"
BUILD_LOG="$LOG_DIR/build.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Create log directory
mkdir -p "$LOG_DIR"

echo "🏭 Production Docker Build (Clean Build)"
echo "========================================"

# Initialize build log
echo "=== PRODUCTION Docker Build Log - $(date) ===" > "$BUILD_LOG"
echo "Clean build from scratch" >> "$BUILD_LOG"
echo "" >> "$BUILD_LOG"

echo "🧹 Step 1: Complete cleanup..."
echo "   📝 Build logs: $BUILD_LOG"

# Remove existing Docker images
echo "   Removing existing Docker images..." | tee -a "$BUILD_LOG"
docker rmi "$DOCKER_IMAGE_NAME:$DOCKER_TAG" 2>/dev/null || echo "   No existing image found" | tee -a "$BUILD_LOG"

# Remove all related images (including intermediate layers)
echo "   Removing intermediate Docker layers..." | tee -a "$BUILD_LOG"
docker images | grep "$DOCKER_IMAGE_NAME" | awk '{print $3}' | xargs docker rmi -f 2>/dev/null || true

# Clean Docker build cache
echo "   Cleaning Docker build cache..." | tee -a "$BUILD_LOG"
docker builder prune -f 2>&1 | tee -a "$BUILD_LOG"

# Clean system (optional - removes unused containers, networks, etc.)
echo "   Cleaning Docker system..." | tee -a "$BUILD_LOG"
docker system prune -f 2>&1 | tee -a "$BUILD_LOG"

echo "   ✅ Cleanup completed" | tee -a "$BUILD_LOG"
echo "" | tee -a "$BUILD_LOG"

# Fresh build with no cache
echo "🔨 Step 4: Fresh Docker build (no cache)..." | tee -a "$BUILD_LOG"
echo "   Building: $DOCKER_IMAGE_NAME:$DOCKER_TAG" | tee -a "$BUILD_LOG"
echo "   Using: --no-cache for completely fresh build" | tee -a "$BUILD_LOG"
echo "" | tee -a "$BUILD_LOG"

# Enable Docker BuildKit and build with no cache
export DOCKER_BUILDKIT=1

if docker build \
    --no-cache \
    -t "$DOCKER_IMAGE_NAME:$DOCKER_TAG" \
    . 2>&1 | tee -a "$BUILD_LOG"; then
    
    echo "" | tee -a "$BUILD_LOG"
    echo -e "${GREEN}✅ Production Docker build completed successfully!${NC}" | tee -a "$BUILD_LOG"
    
    # Show image details
    echo "" | tee -a "$BUILD_LOG"
    echo "📊 Fresh image details:" | tee -a "$BUILD_LOG"
    docker images "$DOCKER_IMAGE_NAME:$DOCKER_TAG" | tee -a "$BUILD_LOG"
    
    # Verify image integrity
    echo "" | tee -a "$BUILD_LOG"
    echo "🔍 Image verification:" | tee -a "$BUILD_LOG"
    IMAGE_ID=$(docker images "$DOCKER_IMAGE_NAME:$DOCKER_TAG" --format "{{.ID}}")
    echo "   Image ID: $IMAGE_ID" | tee -a "$BUILD_LOG"
    echo "   Created: $(docker images "$DOCKER_IMAGE_NAME:$DOCKER_TAG" --format "{{.CreatedAt}}")" | tee -a "$BUILD_LOG"
    
else
    echo "" | tee -a "$BUILD_LOG"
    echo -e "${RED}❌ Production Docker build failed!${NC}" | tee -a "$BUILD_LOG"
    echo "   📝 Check build logs: $BUILD_LOG" | tee -a "$BUILD_LOG"
    echo "" | tee -a "$BUILD_LOG"
    echo "🔧 Troubleshooting:" | tee -a "$BUILD_LOG"
    echo "   - Check Dockerfile syntax" | tee -a "$BUILD_LOG"
    echo "   - Verify SSH key access to private repos" | tee -a "$BUILD_LOG"
    echo "   - Check network connectivity" | tee -a "$BUILD_LOG"
    echo "   - Review dependency versions" | tee -a "$BUILD_LOG"
    exit 1
fi

echo "" | tee -a "$BUILD_LOG"
echo "🎉 Production build process completed!" | tee -a "$BUILD_LOG"
echo "   📦 Image: $DOCKER_IMAGE_NAME:$DOCKER_TAG (fresh build)" | tee -a "$BUILD_LOG"
echo "   📝 Complete logs: $BUILD_LOG" | tee -a "$BUILD_LOG"
echo "   🚀 Ready for EIF build and deployment" | tee -a "$BUILD_LOG"