#!/bin/bash

# Script to check application status
# Usage: ./status.sh

PID_FILE="./log/app.pid"
LOG_FILE="./log/host.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "📊 Application Status Check"
echo "=========================="

if [ -f "$PID_FILE" ] && [ -s "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    
    if ps -p "$PID" > /dev/null 2>&1; then
        echo -e "${GREEN}✅ Application is RUNNING${NC}"
        echo "   📋 PID: $PID"
        
        # Get process start time
        START_TIME=$(ps -o lstart= -p "$PID" 2>/dev/null | sed 's/^ *//' || echo "Unknown")
        echo "   ⏰ Started: $START_TIME"
        
        # Get CPU and memory usage
        CPU_MEM=$(ps -o %cpu,%mem -p "$PID" --no-headers 2>/dev/null | sed 's/^ *//' || echo "N/A N/A")
        echo "   💻 CPU/Memory: $CPU_MEM"
        
        # Check log file
        if [ -f "$LOG_FILE" ]; then
            LOG_SIZE=$(ls -lh "$LOG_FILE" | awk '{print $5}')
            echo "   📝 Log file: $LOG_FILE ($LOG_SIZE)"
            
            # Show last few log lines if they exist
            if [ -s "$LOG_FILE" ]; then
                echo ""
                echo -e "${BLUE}📋 Recent log entries:${NC}"
                echo "   ===================="
                tail -5 "$LOG_FILE" | sed 's/^/   /'
            fi
        else
            echo -e "   ${YELLOW}⚠️  Log file not found: $LOG_FILE${NC}"
        fi
        
    else
        echo -e "${RED}❌ Application is NOT RUNNING${NC}"
        echo "   (PID file exists but process $PID is not running)"
        echo "   Removing stale PID file..."
        rm -f "$PID_FILE"
    fi
    
else
    echo -e "${RED}❌ Application is NOT RUNNING${NC}"
    echo "   (No PID file found)"
    
    # Check for orphaned processes
    RUNNING_PID=$(pgrep -f "go run cmd/main.go" 2>/dev/null | head -1)
    if [ -n "$RUNNING_PID" ]; then
        echo -e "${YELLOW}⚠️  Found orphaned process: PID $RUNNING_PID${NC}"
        echo "   Run './stop.sh' to clean it up"
    fi
fi

echo ""
echo "Commands:"
echo "  ./run.sh    - Start the application"
echo "  ./stop.sh   - Stop the application" 
echo "  ./logs.sh   - Follow application logs"