#!/bin/bash

# Script to view application logs
# Usage: ./logs.sh [lines]

LOG_FILE="./log/host.log"
LINES=${1:-50}  # Default to 50 lines if no argument provided

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

if [ -f "$LOG_FILE" ]; then
    if [ -s "$LOG_FILE" ]; then
        echo -e "${GREEN}📝 Showing logs from: $LOG_FILE${NC}"
        echo -e "${BLUE}   (Press Ctrl+C to exit when following)${NC}"
        echo "========================================"
        
        # If user provides "follow" as argument, tail -f
        if [ "$1" = "follow" ] || [ "$1" = "f" ]; then
            tail -f "$LOG_FILE"
        else
            # Show last N lines (default 50)
            echo -e "${YELLOW}Last $LINES lines:${NC}"
            tail -n "$LINES" "$LOG_FILE"
            echo ""
            echo "💡 Tips:"
            echo "   ./logs.sh follow  - Follow logs in real-time"
            echo "   ./logs.sh 100     - Show last 100 lines"
            echo "   ./logs.sh f       - Follow logs (short form)"
        fi
    else
        echo -e "${YELLOW}⚠️  Log file exists but is empty: $LOG_FILE${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  Log file not found: $LOG_FILE${NC}"
    echo "   The application may not be running or hasn't started yet."
    echo "   Run './run.sh' to start the application."
fi