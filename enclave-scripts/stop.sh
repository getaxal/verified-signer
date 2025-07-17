#!/bin/bash

# Nitro Enclave stop script
# Usage: ./stop.sh

# Variables
LOG_DIR="./enclave-logs"
CONSOLE_LOG="$LOG_DIR/console.log"
CONSOLE_PID_FILE="$LOG_DIR/console.pid"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "🛑 Stopping Nitro Enclave"
echo "========================="

STOPPED_SOMETHING=false

# 1. Stop Console Logging
echo ""
echo -e "${BLUE}📝 Step 1: Stopping console logging...${NC}"
if [ -f "$CONSOLE_PID_FILE" ] && [ -s "$CONSOLE_PID_FILE" ]; then
    PID=$(cat "$CONSOLE_PID_FILE")
    
    if ps -p "$PID" > /dev/null 2>&1; then
        echo "   Found console logging process (PID: $PID)"
        echo "   Sending TERM signal..."
        
        if sudo kill "$PID" 2>/dev/null; then
            # Wait up to 5 seconds for graceful shutdown
            for i in {1..5}; do
                if ! ps -p "$PID" > /dev/null 2>&1; then
                    break
                fi
                sleep 1
            done
            
            # Force kill if still running
            if ps -p "$PID" > /dev/null 2>&1; then
                echo "   Process still running, force killing..."
                sudo kill -9 "$PID" 2>/dev/null
                sleep 1
            fi
            
            # Verify it's stopped
            if ps -p "$PID" > /dev/null 2>&1; then
                echo -e "   ${RED}❌ Failed to stop console logging process${NC}"
            else
                echo -e "   ${GREEN}✅ Console logging stopped successfully${NC}"
                rm -f "$CONSOLE_PID_FILE"
                STOPPED_SOMETHING=true
            fi
        else
            echo -e "   ${RED}❌ Failed to send signal to console logging process${NC}"
        fi
    else
        echo -e "   ${YELLOW}⚠️  Console logging not running (removing stale PID file)${NC}"
        rm -f "$CONSOLE_PID_FILE"
    fi
else
    echo "   ℹ️  No console logging PID file found"
fi

# 2. Stop All Enclaves
echo ""
echo -e "${BLUE}🚀 Step 2: Stopping all enclaves...${NC}"

# Check if any enclaves are running
ENCLAVE_STATUS=$(sudo nitro-cli describe-enclaves 2>/dev/null)
if echo "$ENCLAVE_STATUS" | grep -q "EnclaveID"; then
    echo "   Found running enclaves:"
    
    # Show enclave details before stopping
    ENCLAVE_IDS=$(echo "$ENCLAVE_STATUS" | grep -o '"EnclaveID": "[^"]*"' | cut -d'"' -f4)
    for ENCLAVE_ID in $ENCLAVE_IDS; do
        echo "      - Enclave ID: $ENCLAVE_ID"
    done
    
    echo "   Terminating all enclaves..."
    if sudo nitro-cli terminate-enclave --all 2>/dev/null; then
        echo -e "   ${GREEN}✅ All enclaves terminated successfully${NC}"
        STOPPED_SOMETHING=true
        
        # Wait a moment and verify
        sleep 2
        REMAINING_ENCLAVES=$(sudo nitro-cli describe-enclaves 2>/dev/null)
        if echo "$REMAINING_ENCLAVES" | grep -q "EnclaveID"; then
            echo -e "   ${YELLOW}⚠️  Some enclaves may still be running${NC}"
            echo "   Remaining enclaves:"
            echo "$REMAINING_ENCLAVES" | jq '.' 2>/dev/null || echo "$REMAINING_ENCLAVES"
        else
            echo "   ✅ Verified: No enclaves running"
        fi
    else
        echo -e "   ${RED}❌ Failed to terminate enclaves${NC}"
        echo "   📝 Check nitro-cli logs for details"
    fi
else
    echo "   ℹ️  No enclaves currently running"
fi

# 3. Check for orphaned processes
echo ""
echo -e "${BLUE}🔍 Step 3: Checking for orphaned processes...${NC}"

# Look for any nitro-cli processes
NITRO_PROCESSES=$(pgrep -f "nitro-cli" 2>/dev/null || true)
if [ -n "$NITRO_PROCESSES" ]; then
    echo "   Found orphaned nitro-cli processes:"
    for PID in $NITRO_PROCESSES; do
        PROCESS_INFO=$(ps -p "$PID" -o pid,cmd --no-headers 2>/dev/null || echo "$PID unknown")
        echo "      PID $PROCESS_INFO"
    done
    
    echo "   Cleaning up orphaned processes..."
    for PID in $NITRO_PROCESSES; do
        if sudo kill "$PID" 2>/dev/null; then
            echo "      ✅ Stopped PID $PID"
            STOPPED_SOMETHING=true
        else
            echo "      ❌ Failed to stop PID $PID"
        fi
    done
else
    echo "   ✅ No orphaned nitro-cli processes found"
fi

# 4. Log Summary
echo ""
echo -e "${BLUE}📊 Step 4: Log summary...${NC}"
if [ -f "$CONSOLE_LOG" ]; then
    LOG_SIZE=$(ls -lh "$CONSOLE_LOG" | awk '{print $5}')
    LOG_LINES=$(wc -l < "$CONSOLE_LOG" 2>/dev/null || echo "0")
    echo "   📄 Console log: $CONSOLE_LOG ($LOG_SIZE, $LOG_LINES lines)"
    echo "   💡 Log file preserved for review"
    
    # Show last few lines if they exist
    if [ -s "$CONSOLE_LOG" ]; then
        echo ""
        echo -e "   ${YELLOW}📋 Last 3 console log entries:${NC}"
        tail -3 "$CONSOLE_LOG" 2>/dev/null | sed 's/^/      /' || echo "      No recent entries"
    fi
else
    echo "   ℹ️  No console log file found"
fi

# 5. Final Status Check
echo ""
echo -e "${BLUE}🏁 Final Status Check:${NC}"

# Check enclaves
FINAL_ENCLAVES=$(sudo nitro-cli describe-enclaves 2>/dev/null)
if echo "$FINAL_ENCLAVES" | grep -q "EnclaveID"; then
    echo -e "   ${RED}⚠️  Warning: Some enclaves are still running${NC}"
    echo "$FINAL_ENCLAVES" | jq '.' 2>/dev/null || echo "$FINAL_ENCLAVES"
else
    echo -e "   ${GREEN}✅ Confirmed: No enclaves running${NC}"
fi

# Check console logging
if [ -f "$CONSOLE_PID_FILE" ]; then
    echo -e "   ${RED}⚠️  Warning: Console PID file still exists${NC}"
else
    echo -e "   ${GREEN}✅ Confirmed: Console logging stopped${NC}"
fi

# 6. Summary
echo ""
echo "🎯 Summary:"
if [ "$STOPPED_SOMETHING" = true ]; then
    echo -e "   ${GREEN}✅ Successfully stopped Nitro Enclave components${NC}"
else
    echo -e "   ${YELLOW}ℹ️  No running components found to stop${NC}"
fi

echo ""
echo "💡 Next steps:"
echo "   ./status.sh      - Check current status"
echo "   ./run.sh         - Deploy enclave again"
echo "   tail $CONSOLE_LOG - Review console logs"

# 7. Cleanup Options
echo ""
echo -e "${BLUE}🧹 Optional Cleanup:${NC}"
echo "   To clean up completely, you can also run:"
echo "   rm -f signer.eif                    # Remove EIF file"
echo "   docker rmi verified-signer:latest   # Remove Docker image"
echo "   rm -f $CONSOLE_LOG                  # Remove console logs"
echo "   rm -f ./log/build.log               # Remove build logs"