#!/bin/bash

# Script to stop the Go application and clear all resources
# Usage: ./stop.sh

PID_FILE="./log/app.pid"
APP_PORT="8080"  # Change this to your application's port
APP_NAME="main"  # Change this to your binary name

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "🛑 Stopping Go application and clearing all resources..."

# Function to kill processes by pattern
kill_by_pattern() {
    local pattern="$1"
    local description="$2"
    
    local pids=$(pgrep -f "$pattern" 2>/dev/null)
    if [ -n "$pids" ]; then
        echo -e "${BLUE}   Found $description processes: $pids${NC}"
        echo "$pids" | xargs kill 2>/dev/null
        sleep 2
        
        # Force kill if still running
        local remaining=$(pgrep -f "$pattern" 2>/dev/null)
        if [ -n "$remaining" ]; then
            echo -e "${YELLOW}   Force killing remaining processes: $remaining${NC}"
            echo "$remaining" | xargs kill -9 2>/dev/null
        fi
    fi
}

# Function to kill processes using specific port
kill_by_port() {
    local port="$1"
    echo -e "${BLUE}   Checking port $port...${NC}"
    
    # Find processes using the port
    local pids=$(sudo lsof -t -i :$port 2>/dev/null)
    if [ -n "$pids" ]; then
        echo -e "${BLUE}   Found processes using port $port: $pids${NC}"
        echo "$pids" | xargs sudo kill 2>/dev/null
        sleep 2
        
        # Force kill if still running
        local remaining=$(sudo lsof -t -i :$port 2>/dev/null)
        if [ -n "$remaining" ]; then
            echo -e "${YELLOW}   Force killing processes on port $port: $remaining${NC}"
            echo "$remaining" | xargs sudo kill -9 2>/dev/null
        fi
    fi
    
    # Double check with fuser
    if sudo netstat -tulpn | grep ":$port " >/dev/null 2>&1; then
        echo -e "${YELLOW}   Port $port still in use, using fuser...${NC}"
        sudo fuser -k -9 $port/tcp 2>/dev/null || true
    fi
}

# 1. Stop process from PID file
if [ -f "$PID_FILE" ] && [ -s "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    
    if ps -p "$PID" > /dev/null 2>&1; then
        echo -e "${BLUE}   Found running process from PID file (PID: $PID)${NC}"
        echo "   Sending TERM signal..."
        kill "$PID" 2>/dev/null
        
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
            kill -9 "$PID" 2>/dev/null
            sleep 1
        fi
        
        # Verify it's stopped
        if ps -p "$PID" > /dev/null 2>&1; then
            echo -e "${RED}❌ Failed to stop main process${NC}"
        else
            echo -e "${GREEN}✅ Main process stopped${NC}"
            rm -f "$PID_FILE"
        fi
    else
        echo -e "${YELLOW}⚠️  Process not running (removing stale PID file)${NC}"
        rm -f "$PID_FILE"
    fi
else
    echo -e "${YELLOW}⚠️  No PID file found${NC}"
fi

# 2. Kill all Go-related processes
echo -e "${BLUE}🔍 Searching for remaining Go processes...${NC}"

# Kill go run processes
kill_by_pattern "go run.*main.go" "go run"
kill_by_pattern "go run.*cmd/main.go" "go run cmd"

# Kill compiled binary
kill_by_pattern "./$APP_NAME" "compiled binary"
kill_by_pattern "$APP_NAME$" "binary"

# Kill any process with your app name
kill_by_pattern "$APP_NAME" "app-related"

# 3. Clear network ports
echo -e "${BLUE}🌐 Clearing network ports...${NC}"
kill_by_port "$APP_PORT"

# If you have other ports, add them here
# kill_by_port "9000"
# kill_by_port "3000"

# 4. Kill any orphaned child processes
echo -e "${BLUE}🧹 Cleaning up orphaned processes...${NC}"

# Find and kill any processes that might be children of your app
ORPHANED_PIDS=$(ps -eo pid,ppid,cmd | grep -E "(go|$APP_NAME)" | grep -v grep | grep -v $$ | awk '{print $1}')
if [ -n "$ORPHANED_PIDS" ]; then
    echo -e "${BLUE}   Found orphaned processes: $ORPHANED_PIDS${NC}"
    echo "$ORPHANED_PIDS" | xargs kill 2>/dev/null
    sleep 2
    
    # Force kill remaining
    REMAINING=$(ps -eo pid,ppid,cmd | grep -E "(go|$APP_NAME)" | grep -v grep | grep -v $$ | awk '{print $1}')
    if [ -n "$REMAINING" ]; then
        echo -e "${YELLOW}   Force killing remaining: $REMAINING${NC}"
        echo "$REMAINING" | xargs kill -9 2>/dev/null
    fi
fi

# 5. Final verification
echo -e "${BLUE}🔍 Final verification...${NC}"

# Check if port is still in use
if sudo netstat -tulpn | grep ":$APP_PORT " >/dev/null 2>&1; then
    echo -e "${RED}❌ Port $APP_PORT is still in use:${NC}"
    sudo netstat -tulpn | grep ":$APP_PORT "
    
    # Last resort - nuclear option
    echo -e "${RED}🚨 Using nuclear option to clear port $APP_PORT${NC}"
    sudo fuser -k -9 $APP_PORT/tcp 2>/dev/null || true
    sleep 1
    
    # Final check
    if sudo netstat -tulpn | grep ":$APP_PORT " >/dev/null 2>&1; then
        echo -e "${RED}❌ Port $APP_PORT still in use after nuclear option${NC}"
        sudo netstat -tulpn | grep ":$APP_PORT "
    else
        echo -e "${GREEN}✅ Port $APP_PORT cleared${NC}"
    fi
else
    echo -e "${GREEN}✅ Port $APP_PORT is free${NC}"
fi

# Check for any remaining Go processes
REMAINING_GO=$(pgrep -f "go" 2>/dev/null | wc -l)
if [ "$REMAINING_GO" -gt 0 ]; then
    echo -e "${YELLOW}⚠️  Found $REMAINING_GO remaining Go processes${NC}"
    ps -eo pid,cmd | grep -E "(go|$APP_NAME)" | grep -v grep | grep -v $$
else
    echo -e "${GREEN}✅ No remaining Go processes found${NC}"
fi

# Clean up any temporary files
echo -e "${BLUE}🧹 Cleaning up temporary files...${NC}"
rm -f ./$APP_NAME 2>/dev/null || true
rm -f ./tmp_* 2>/dev/null || true

echo -e "${GREEN}🎉 Application stopped and all resources cleared!${NC}"

# Summary
echo -e "${BLUE}📊 Summary:${NC}"
echo "   • PID file: $([ -f "$PID_FILE" ] && echo "exists" || echo "removed")"
echo "   • Port $APP_PORT: $(sudo netstat -tulpn | grep ":$APP_PORT " >/dev/null 2>&1 && echo "in use" || echo "free")"
echo "   • Go processes: $(pgrep -f "go" 2>/dev/null | wc -l) running"