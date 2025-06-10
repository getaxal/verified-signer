#!/bin/bash

# Script to stop the Go application
# Usage: ./stop.sh

PID_FILE="./log/app.pid"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "🛑 Stopping Go application..."

if [ -f "$PID_FILE" ] && [ -s "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    
    if ps -p "$PID" > /dev/null 2>&1; then
        echo "   Found running process (PID: $PID)"
        echo "   Sending TERM signal..."
        kill "$PID"
        
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
            kill -9 "$PID"
            sleep 1
        fi
        
        # Verify it's stopped
        if ps -p "$PID" > /dev/null 2>&1; then
            echo -e "${RED}❌ Failed to stop process${NC}"
            exit 1
        else
            echo -e "${GREEN}✅ Application stopped successfully${NC}"
            rm -f "$PID_FILE"
        fi
    else
        echo -e "${YELLOW}⚠️  Process not running (removing stale PID file)${NC}"
        rm -f "$PID_FILE"
    fi
else
    echo -e "${YELLOW}⚠️  No PID file found - application may not be running${NC}"
    
    # Check for any running Go processes anyway
    RUNNING_PID=$(pgrep -f "go run cmd/main.go" 2>/dev/null | head -1)
    if [ -n "$RUNNING_PID" ]; then
        echo "   Found orphaned process (PID: $RUNNING_PID), stopping it..."
        kill "$RUNNING_PID"
        sleep 1
        if ps -p "$RUNNING_PID" > /dev/null 2>&1; then
            kill -9 "$RUNNING_PID"
        fi
        echo -e "${GREEN}✅ Orphaned process stopped${NC}"
    else
        echo "   No running processes found"
    fi
fi