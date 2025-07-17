#!/bin/bash

# Nitro Enclave deployment script
# Usage: ./run.sh

# Variables
DOCKER_IMAGE_NAME="verified-signer"
DOCKER_TAG="latest"
EIF_FILE="signer.eif"
ENCLAVE_CID="5"
CPU_COUNT="2"
MEMORY="512"

LOG_DIR="./enclave-logs"
BUILD_LOG="$LOG_DIR/build.log"
CONSOLE_LOG="$LOG_DIR/console.log"
CONSOLE_PID_FILE="$LOG_DIR/console.pid"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Create log directory
mkdir -p "$LOG_DIR"

echo "🚀 Nitro Enclave Deployment"
echo "============================"

# Check if enclave is already running
if sudo nitro-cli describe-enclaves 2>/dev/null | grep -q "EnclaveID"; then
    echo -e "${YELLOW}⚠️  Enclave is already running${NC}"
    echo "   Use './stop.sh' to stop it first, or check './status.sh'"
    exit 1
fi

# Check if console logging is already running
if [ -f "$CONSOLE_PID_FILE" ] && [ -s "$CONSOLE_PID_FILE" ]; then
    PID=$(cat "$CONSOLE_PID_FILE")
    if ps -p "$PID" > /dev/null 2>&1; then
        echo -e "${YELLOW}⚠️  Console logging is already running (PID: $PID)${NC}"
        echo "   Use './stop.sh' to stop it first"
        exit 1
    else
        echo "   Removing stale console PID file..."
        rm -f "$CONSOLE_PID_FILE"
    fi
fi

# Clean up any existing proxesses before starting
echo "🧹 Cleaning up any existing nitro-cli processes..."
sudo pkill -f "nitro-cli" 2>/dev/null || true
sleep 2

# Step 1: Build Docker image if needed
echo "🐳 Step 1: Building Docker image..."
if ! docker images | grep -q "$DOCKER_IMAGE_NAME.*$DOCKER_TAG"; then
    echo "   Docker image not found, building..."
    if ! ./docker_build.sh; then
        echo -e "${RED}❌ Docker build failed${NC}"
        exit 1
    fi
else
    echo "   ✅ Docker image already exists: $DOCKER_IMAGE_NAME:$DOCKER_TAG"
fi

# Step 2: Build EIF file
echo "" | tee -a "$BUILD_LOG"
echo "🔧 Step 2: Building EIF file..." | tee -a "$BUILD_LOG"
echo "   📝 Build logs: $BUILD_LOG"

if [ -f "$EIF_FILE" ]; then
    echo -e "${YELLOW}⚠️  EIF file already exists: $EIF_FILE${NC}" | tee -a "$BUILD_LOG"
    echo "   Rebuilding EIF file..." | tee -a "$BUILD_LOG"
    rm -f "$EIF_FILE"
fi

if sudo nitro-cli build-enclave --docker-uri "$DOCKER_IMAGE_NAME:$DOCKER_TAG" --output-file "$EIF_FILE" 2>&1 | tee -a "$BUILD_LOG"; then
    echo "   ✅ EIF file created: $EIF_FILE" | tee -a "$BUILD_LOG"
else
    echo -e "${RED}❌ EIF build failed${NC}" | tee -a "$BUILD_LOG"
    echo "   📝 Check build logs: $BUILD_LOG"
    exit 1
fi

# Step 3: Stop any existing enclaves
echo ""
echo "🛑 Step 3: Cleaning up existing enclaves..."
sudo nitro-cli terminate-enclave --all 2>/dev/null || true
sleep 2

# Step 4: Initialize console log
echo ""
echo "📝 Step 4: Initializing console logging..."
echo "=== Nitro Enclave Console Log - $(date) ===" > "$CONSOLE_LOG"
echo "" >> "$CONSOLE_LOG"

# Step 5: Deploy enclave with background console logging
echo ""
echo "🚀 Step 5: Deploying Nitro Enclave..."
echo "   📊 Configuration:"
echo "      - CPU Count: $CPU_COUNT"
echo "      - Memory: ${MEMORY}MB"
echo "      - CID: $ENCLAVE_CID"
echo "      - EIF: $EIF_FILE"
echo "      - Console Log: $CONSOLE_LOG"
echo ""

# Start enclave with console in background
echo "   Starting enclave with background console logging..."
nohup sudo nitro-cli run-enclave \
    --cpu-count "$CPU_COUNT" \
    --memory "$MEMORY" \
    --enclave-cid "$ENCLAVE_CID" \
    --eif-path "$EIF_FILE" \
    --debug-mode \
    --attach-console >> "$CONSOLE_LOG" 2>&1 &

# Capture the PID
CONSOLE_PID=$!
echo $CONSOLE_PID > "$CONSOLE_PID_FILE"

# Wait a moment and verify
sleep 3

if ps -p "$CONSOLE_PID" > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Enclave deployed successfully!${NC}"
    echo "   📋 Console PID: $CONSOLE_PID"
    echo "   📝 Console logs: $CONSOLE_LOG"
    echo "   🔧 PID file: $CONSOLE_PID_FILE"
    echo ""
    
    # Show enclave status
    echo "📊 Enclave Status:"
    sudo nitro-cli describe-enclaves 2>/dev/null || echo "   Failed to get enclave status"
    
    echo ""
    echo "💡 Next steps:"
    echo "   ./status.sh      - Check enclave and console status"
    echo "   tail -f $CONSOLE_LOG  - Follow console logs"
    echo "   ./stop.sh        - Stop enclave and console logging"
    
else
    echo -e "${RED}❌ Failed to start enclave console logging${NC}"
    echo "   📝 Check console logs: $CONSOLE_LOG"
    echo "   📝 Check build logs: $BUILD_LOG"
    rm -f "$CONSOLE_PID_FILE"
    exit 1
fi