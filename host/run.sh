#!/bin/bash

# Simple script to run Go application in background with logging
# Usage: ./run.sh

LOG_DIR="./log"
LOG_FILE="$LOG_DIR/host.log"
PID_FILE="$LOG_DIR/app.pid"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Create log directory
mkdir -p "$LOG_DIR"

echo "🚀 Starting Go application..."

# Check if already running
if [ -f "$PID_FILE" ] && [ -s "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if ps -p "$PID" > /dev/null 2>&1; then
        echo -e "${YELLOW}⚠️  Application already running with PID: $PID${NC}"
        echo "   Use './stop.sh' to stop it first"
        exit 1
    else
        echo "   Removing stale PID file..."
        rm -f "$PID_FILE"
    fi
fi

# Start the application in background
nohup go run cmd/main.go >> "$LOG_FILE" 2>&1 &
APP_PID=$!

# Save the PID
echo $APP_PID > "$PID_FILE"

# Wait a moment and verify it started
sleep 1

if ps -p "$APP_PID" > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Application started successfully!${NC}"
    echo "   📋 PID: $APP_PID"
    echo "   📝 Logs: $LOG_FILE"
    echo "   🔍 Follow logs: tail -f $LOG_FILE"
    echo "   🛑 Stop with: ./stop.sh"
else
    echo -e "${RED}❌ Failed to start application${NC}"
    echo "   Check logs: tail $LOG_FILE"
    rm -f "$PID_FILE"
    exit 1
fi