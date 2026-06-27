#!/bin/bash
# WEJÀ MVP Startup Script
# Run this script to start all services

echo "🛡️  Starting WEJÀ WAF MVP..."
echo "================================"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Function to cleanup on exit
cleanup() {
    echo -e "\n${RED}Shutting down services...${NC}"
    kill $AI_PID $TARGET_PID $WAF_PID $DASHBOARD_PID 2>/dev/null
    exit 0
}

trap cleanup SIGINT SIGTERM

# Start AI Engine (Python Flask)
echo -e "${BLUE}Starting AI Engine...${NC}"
AI_ENGINE_PORT="${AI_ENGINE_PORT:-5000}"
TARGET_PORT="${TARGET_PORT:-4000}"
WAF_PORT="${WAF_PORT:-3000}"
export AI_ENGINE_PORT TARGET_PORT WAF_PORT
cd "$SCRIPT_DIR/ai-engine"
source venv/Scripts/activate
AI_ENGINE_PORT="$AI_ENGINE_PORT" python app.py &
AI_PID=$!
sleep 2

# Start Dummy Target
echo -e "${BLUE}Starting Dummy Target...${NC}"
cd "$SCRIPT_DIR/dummy-target"
TARGET_PORT="$TARGET_PORT" node server.js &
TARGET_PID=$!
sleep 1

# Start WAF Gateway
echo -e "${BLUE}Starting WAF Gateway...${NC}"
cd "$SCRIPT_DIR/waf-proxy"
PORT="$WAF_PORT" AI_ENGINE_PORT="$AI_ENGINE_PORT" TARGET_PORT="$TARGET_PORT" node server.js &
WAF_PID=$!
sleep 2

# Start Dashboard
echo -e "${BLUE}Starting Dashboard...${NC}"
cd "$SCRIPT_DIR/client-dashboard"
npm run dev &
DASHBOARD_PID=$!

echo ""
echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}All services started!${NC}"
echo ""
echo "📡 AI Engine:    http://localhost:${AI_ENGINE_PORT}"
echo "🎯 Target:       http://localhost:${TARGET_PORT}"
echo "🛡️  WAF Gateway:  http://localhost:${WAF_PORT}"
echo "📊 Dashboard:    http://localhost:5173"
echo ""
echo "To test: node test_traffic.js"
echo ""
echo -e "${RED}Press Ctrl+C to stop all services${NC}"

# Wait for all background processes
wait
