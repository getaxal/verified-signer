#!/bin/bash

# Nitro Enclave status script
# Usage: ./status.sh

# Variables
LOG_DIR="./log"
CONSOLE_LOG="$LOG_DIR/console.log"
BUILD_LOG="$LOG_DIR/build.log"
CONSOLE_PID_FILE="$LOG_DIR/console.pid"
DOCKER_IMAGE_NAME="verified-signer"
DOCKER_TAG="latest"
EIF_FILE="signer.eif"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo "📊 Nitro Enclave Status Dashboard"
echo "=================================="

# 1. Docker Image Status
echo ""
echo -e "${BLUE}🐳 Docker Image Status:${NC}"
if docker images | grep -q "$DOCKER_IMAGE_NAME.*$DOCKER_TAG"; then
    echo -e "   ${GREEN}✅ Docker image exists: $DOCKER_IMAGE_NAME:$DOCKER_TAG${NC}"
    IMAGE_INFO=$(docker images "$DOCKER_IMAGE_NAME:$DOCKER_TAG" --format "table {{.Size}}\t{{.CreatedAt}}" | tail -1)
    echo "   📊 Size & Created: $IMAGE_INFO"
else
    echo -e "   ${RED}❌ Docker image not found: $DOCKER_IMAGE_NAME:$DOCKER_TAG${NC}"
    echo "   💡 Run './docker_build.sh' to build the image"
fi

# 2. EIF File Status
echo ""
echo -e "${BLUE}📦 EIF File Status:${NC}"
if [ -f "$EIF_FILE" ]; then
    EIF_SIZE=$(ls -lh "$EIF_FILE" | awk '{print $5}')
    EIF_DATE=$(ls -l "$EIF_FILE" | awk '{print $6, $7, $8}')
    echo -e "   ${GREEN}✅ EIF file exists: $EIF_FILE${NC}"
    echo "   📊 Size: $EIF_SIZE, Modified: $EIF_DATE"
else
    echo -e "   ${RED}❌ EIF file not found: $EIF_FILE${NC}"
    echo "   💡 Run './run.sh' to build and deploy"
fi

# 3. Enclave Status
echo ""
echo -e "${BLUE}🚀 Enclave Status:${NC}"
ENCLAVE_STATUS=$(sudo nitro-cli describe-enclaves 2>/dev/null)
if echo "$ENCLAVE_STATUS" | grep -q "EnclaveID"; then
    echo -e "   ${GREEN}✅ Enclave is running${NC}"
    
    # Extract details
    ENCLAVE_ID=$(echo "$ENCLAVE_STATUS" | grep -o '"EnclaveID": "[^"]*"' | cut -d'"' -f4)
    ENCLAVE_STATE=$(echo "$ENCLAVE_STATUS" | grep -o '"State": "[^"]*"' | cut -d'"' -f4)
    CPU_COUNT=$(echo "$ENCLAVE_STATUS" | grep -o '"CPUCount": [0-9]*' | cut -d':' -f2 | tr -d ' ')
    MEMORY=$(echo "$ENCLAVE_STATUS" | grep -o '"MemoryMiB": [0-9]*' | cut -d':' -f2 | tr -d ' ')
    
    echo "   📋 Enclave ID: $ENCLAVE_ID"
    echo "   🏃 State: $ENCLAVE_STATE"
    echo "   💻 CPU Count: $CPU_COUNT"
    echo "   🧠 Memory: ${MEMORY}MB"
    
    # Show full enclave details
    echo ""
    echo -e "${CYAN}   📊 Full Enclave Details:${NC}"
    echo "$ENCLAVE_STATUS" | jq '.' 2>/dev/null || echo "$ENCLAVE_STATUS"
    
else
    echo -e "   ${RED}❌ No enclave running${NC}"
    echo "   💡 Run './run.sh' to deploy an enclave"
fi

# 4. Console Logging Status
echo ""
echo -e "${BLUE}📝 Console Logging Status:${NC}"
if [ -f "$CONSOLE_PID_FILE" ] && [ -s "$CONSOLE_PID_FILE" ]; then
    PID=$(cat "$CONSOLE_PID_FILE")
    if ps -p "$PID" > /dev/null 2>&1; then
        echo -e "   ${GREEN}✅ Console logging is running (PID: $PID)${NC}"
        
        # Get process start time and resource usage
        PS_INFO=$(ps -o pid,lstart,%cpu,%mem,etime -p "$PID" --no-headers 2>/dev/null)
        if [ -n "$PS_INFO" ]; then
            echo "   ⏰ Process info: $PS_INFO"
        fi
        
        # Check log file
        if [ -f "$CONSOLE_LOG" ]; then
            LOG_SIZE=$(ls -lh "$CONSOLE_LOG" | awk '{print $5}')
            LOG_LINES=$(wc -l < "$CONSOLE_LOG" 2>/dev/null || echo "0")
            echo "   📄 Log file: $CONSOLE_LOG ($LOG_SIZE, $LOG_LINES lines)"
            
            # Show recent log activity
            if [ -s "$CONSOLE_LOG" ]; then
                echo ""
                echo -e "${CYAN}   📋 Recent Console Output (last 5 lines):${NC}"
                tail -5 "$CONSOLE_LOG" 2>/dev/null | sed 's/^/      /' || echo "      No recent output"
            fi
        else
            echo -e "   ${YELLOW}⚠️  Console log file not found${NC}"
        fi
    else
        echo -e "   ${RED}❌ Console logging not running (stale PID file)${NC}"
        echo "   🧹 Cleaning up stale PID file..."
        rm -f "$CONSOLE_PID_FILE"
    fi
else
    echo -e "   ${RED}❌ Console logging is not running${NC}"
    echo "   💡 Run './run.sh' to start enclave with console logging"
fi

# 5. Build Log Status
echo ""
echo -e "${BLUE}🔧 Build Log Status:${NC}"
if [ -f "$BUILD_LOG" ]; then
    BUILD_SIZE=$(ls -lh "$BUILD_LOG" | awk '{print $5}')
    BUILD_DATE=$(ls -l "$BUILD_LOG" | awk '{print $6, $7, $8}')
    echo -e "   ${GREEN}✅ Build log exists: $BUILD_LOG${NC}"
    echo "   📊 Size: $BUILD_SIZE, Modified: $BUILD_DATE"
    
    # Check for recent errors
    if grep -q "ERROR\|FAILED\|❌" "$BUILD_LOG" 2>/dev/null; then
        echo -e "   ${YELLOW}⚠️  Build log contains errors - check for issues${NC}"
    fi
else
    echo -e "   ${YELLOW}⚠️  Build log not found${NC}"
fi

# 6. System Resources
echo ""
echo -e "${BLUE}💻 System Resources:${NC}"
echo "   🖥️  CPU Usage: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)%"
echo "   🧠 Memory Usage: $(free | grep Mem | awk '{printf "%.1f%%", $3/$2 * 100.0}')"
echo "   💾 Disk Usage: $(df -h . | tail -1 | awk '{print $5}')"

# 7. Quick Actions
echo ""
echo -e "${BLUE}💡 Quick Actions:${NC}"
echo "   ./run.sh                    - Deploy/restart enclave"
echo "   ./stop.sh                   - Stop enclave and logging"
echo "   tail -f $CONSOLE_LOG        - Follow console logs"
echo "   tail -f $BUILD_LOG          - Follow build logs"
echo "   sudo nitro-cli describe-enclaves  - Raw enclave status"

# 8. Health Summary
echo ""
echo -e "${BLUE}🏥 Health Summary:${NC}"
HEALTH_SCORE=0
TOTAL_CHECKS=4

# Check Docker image
if docker images | grep -q "$DOCKER_IMAGE_NAME.*$DOCKER_TAG"; then
    ((HEALTH_SCORE++))
fi

# Check EIF file
if [ -f "$EIF_FILE" ]; then
    ((HEALTH_SCORE++))
fi

# Check enclave running
if sudo nitro-cli describe-enclaves 2>/dev/null | grep -q "EnclaveID"; then
    ((HEALTH_SCORE++))
fi

# Check console logging
if [ -f "$CONSOLE_PID_FILE" ] && [ -s "$CONSOLE_PID_FILE" ]; then
    PID=$(cat "$CONSOLE_PID_FILE")
    if ps -p "$PID" > /dev/null 2>&1; then
        ((HEALTH_SCORE++))
    fi
fi

HEALTH_PERCENT=$((HEALTH_SCORE * 100 / TOTAL_CHECKS))

if [ $HEALTH_PERCENT -eq 100 ]; then
    echo -e "   ${GREEN}✅ System Health: $HEALTH_PERCENT% ($HEALTH_SCORE/$TOTAL_CHECKS checks passed)${NC}"
elif [ $HEALTH_PERCENT -ge 75 ]; then
    echo -e "   ${YELLOW}⚠️  System Health: $HEALTH_PERCENT% ($HEALTH_SCORE/$TOTAL_CHECKS checks passed)${NC}"
else
    echo -e "   ${RED}❌ System Health: $HEALTH_PERCENT% ($HEALTH_SCORE/$TOTAL_CHECKS checks passed)${NC}"
fi