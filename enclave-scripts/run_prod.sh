#!/bin/bash

# Production Nitro Enclave deployment script
# Usage: ./run_prod.sh

# Variables
DOCKER_IMAGE_NAME="verified-signer"
DOCKER_TAG="latest"
EIF_FILE="signer.eif"
ENCLAVE_CID="5"
CPU_COUNT="2"  # Allocator supports 2 CPUs
MEMORY="512"   # Allocator supports 512MB

LOG_DIR="./enclave-logs"
BUILD_LOG="$LOG_DIR/build.log"
ENCLAVE_LOG="$LOG_DIR/enclave.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Create log directory
mkdir -p "$LOG_DIR"

echo "🚀 Production Nitro Enclave Deployment"
echo "======================================"

# Check if enclave is already running
if sudo nitro-cli describe-enclaves 2>/dev/null | grep -q "EnclaveID"; then
    echo -e "${YELLOW}⚠️  Enclave is already running${NC}"
    echo "   Use './stop.sh' to stop it first"
    exit 1
fi

# Step 1: Clean up existing artifacts
echo "🧹 Step 1: Cleaning up existing artifacts..."
echo "   Removing existing Docker images..."
docker rmi "$DOCKER_IMAGE_NAME:$DOCKER_TAG" 2>/dev/null || echo "   No existing image to remove"

echo "   Removing existing EIF file..."
rm -f "$EIF_FILE"

echo "   Cleaning Docker build cache..."
docker builder prune -f 2>/dev/null || true

echo "   ✅ Cleanup completed"

# Step 2: Fresh Docker build
echo ""
echo "🐳 Step 2: Fresh Docker build..."
echo "   Building Docker image from scratch..."
if ! ./enclave-scripts/docker_build_prod.sh; then
    echo -e "${RED}❌ Production Docker build failed${NC}"
    exit 1
fi

# Step 3: Build EIF file
echo ""
echo "🔧 Step 3: Building fresh EIF file..."

if sudo nitro-cli build-enclave --docker-uri "$DOCKER_IMAGE_NAME:$DOCKER_TAG" --output-file "$EIF_FILE" 2>&1 | tee -a "$BUILD_LOG"; then
    echo "   ✅ EIF file created: $EIF_FILE"
else
    echo -e "${RED}❌ EIF build failed${NC}"
    exit 1
fi

# Step 4: Clean up existing enclaves
echo ""
echo "🛑 Step 4: Cleaning up existing enclaves..."
sudo nitro-cli terminate-enclave --all 2>/dev/null || true
sleep 2

# Step 5: Deploy enclave in PRODUCTION mode (NO console, NO debug)
echo ""
echo "🚀 Step 5: Deploying Production Enclave..."
echo "   📊 Configuration:"
echo "      - CPU Count: $CPU_COUNT"
echo "      - Memory: ${MEMORY}MB"
echo "      - CID: $ENCLAVE_CID"
echo "      - EIF: $EIF_FILE"
echo "      - Mode: PRODUCTION (no console, no debug)"
echo ""

# Log the deployment
echo "=== Production Enclave Deployment - $(date) ===" >> "$ENCLAVE_LOG"

# Start enclave WITHOUT console and WITHOUT debug mode
DEPLOY_OUTPUT=$(sudo nitro-cli run-enclave \
    --cpu-count "$CPU_COUNT" \
    --memory "$MEMORY" \
    --enclave-cid "$ENCLAVE_CID" \
    --eif-path "$EIF_FILE" 2>&1)

echo "$DEPLOY_OUTPUT" | tee -a "$ENCLAVE_LOG"

# Check if deployment was successful
if echo "$DEPLOY_OUTPUT" | grep -q "Started enclave\|EnclaveID"; then
    echo -e "${GREEN}✅ Production enclave started successfully!${NC}"
    
    # Extract enclave ID from JSON output
    ENCLAVE_ID=$(echo "$DEPLOY_OUTPUT" | grep -o '"EnclaveID": "[^"]*"' | cut -d'"' -f4)
    if [ -z "$ENCLAVE_ID" ]; then
        # Try alternative extraction method
        ENCLAVE_ID=$(echo "$DEPLOY_OUTPUT" | jq -r '.EnclaveID' 2>/dev/null || echo "")
    fi
    
    if [ -n "$ENCLAVE_ID" ]; then
        echo "   📋 Enclave ID: $ENCLAVE_ID"
        echo "$ENCLAVE_ID" > "$LOG_DIR/enclave.id"
    fi
    
    # Wait a moment then check if enclave is still running
    echo "   ⏳ Waiting 3 seconds to verify enclave stability..."
    sleep 3
    
    ENCLAVE_STATUS=$(sudo nitro-cli describe-enclaves 2>/dev/null)
    if echo "$ENCLAVE_STATUS" | grep -q "$ENCLAVE_ID"; then
        echo -e "${GREEN}✅ Enclave is running and stable${NC}"
        
        # Show enclave status
        echo ""
        echo "📊 Enclave Status:"
        echo "$ENCLAVE_STATUS" | jq '.' | tee -a "$ENCLAVE_LOG"
        
        echo ""
        echo -e "${GREEN}🎉 Production deployment completed successfully!${NC}"
        echo ""
        echo "💡 Production monitoring:"
        echo "   ./status.sh                       - Check enclave status"
        echo "   sudo nitro-cli describe-enclaves  - Raw enclave info"
        echo "   tail -f $ENCLAVE_LOG             - View deployment logs"
        echo ""
        echo "⚠️  Note: No console logging in production mode"
        echo "   Monitor your application through its own logging mechanisms"
    else
        echo -e "${RED}❌ Enclave started but then exited${NC}"
        echo "   📝 This usually means your application crashed or exited"
        echo "   🔍 To debug, run with console:"
        echo "   sudo nitro-cli run-enclave --cpu-count $CPU_COUNT --memory $MEMORY --enclave-cid $ENCLAVE_CID --eif-path $EIF_FILE --debug-mode --attach-console"
        exit 1
    fi
    
else
    echo -e "${RED}❌ Failed to deploy production enclave${NC}"
    echo "   📝 Check logs: $ENCLAVE_LOG"
    echo "   📝 Check build logs: $BUILD_LOG"
    echo "   🔍 Deploy output was:"
    echo "$DEPLOY_OUTPUT"
    exit 1
fi