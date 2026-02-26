#!/bin/bash
# Setup NetworkFuzzer MCP server configuration for the current user.
# Generates .mcp.json (Claude Code) and prints claude_desktop_config.json snippet.
#
# Usage:
#   bash scripts/setup_mcp.sh              # auto-detect python
#   NETWORKFUZZER_PYTHON=/path/python3 bash scripts/setup_mcp.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
WRAPPER="$SCRIPT_DIR/run_mcp_server.sh"

echo "NetworkFuzzer MCP Setup"
echo "========================"
echo "Project root: $PROJECT_ROOT"

# Detect Python
if [ -n "$NETWORKFUZZER_PYTHON" ]; then
    PYTHON="$NETWORKFUZZER_PYTHON"
elif [ -f "$PROJECT_ROOT/../acas-server/venv-agent/bin/python3" ]; then
    PYTHON="$PROJECT_ROOT/../acas-server/venv-agent/bin/python3"
elif [ -f "$PROJECT_ROOT/venv/bin/python3" ]; then
    PYTHON="$PROJECT_ROOT/venv/bin/python3"
elif [ -f "$PROJECT_ROOT/.venv/bin/python3" ]; then
    PYTHON="$PROJECT_ROOT/.venv/bin/python3"
else
    PYTHON="$(which python3)"
fi
echo "Python:       $PYTHON"

# Verify mcp is importable
if ! "$PYTHON" -c "from mcp.server.fastmcp import FastMCP" 2>/dev/null; then
    echo ""
    echo "ERROR: mcp package not found in $PYTHON"
    echo "Install it: $PYTHON -m pip install mcp"
    exit 1
fi

# Verify networkfuzzer imports work
if ! PYTHONPATH="$PROJECT_ROOT" "$PYTHON" -c "from fuzzer.mcp.server import mcp" 2>/dev/null; then
    echo ""
    echo "ERROR: fuzzer.mcp.server import failed."
    echo "Make sure you are in the NetworkFuzzer directory and dependencies are installed."
    exit 1
fi

echo ""
echo "✓ MCP server verified"

# ------------------------------------------------------------------
# 1. Generate .mcp.json for Claude Code (project-local)
# ------------------------------------------------------------------
MCP_JSON="$PROJECT_ROOT/.mcp.json"
cat > "$MCP_JSON" <<EOF
{
  "mcpServers": {
    "networkfuzzer": {
      "command": "bash",
      "args": ["$WRAPPER"],
      "cwd": "$PROJECT_ROOT",
      "env": {
        "NETWORKFUZZER_PYTHON": "$PYTHON"
      }
    }
  }
}
EOF
echo "✓ Written: $MCP_JSON"

# ------------------------------------------------------------------
# 2. Offer to add to global Claude Code settings (~/.claude/settings.json)
# ------------------------------------------------------------------
GLOBAL_SETTINGS="$HOME/.claude/settings.json"
echo ""
echo "To add to GLOBAL Claude Code settings ($GLOBAL_SETTINGS),"
echo "add this block under \"mcpServers\":"
cat <<EOF

  "networkfuzzer": {
    "command": "bash",
    "args": ["$WRAPPER"],
    "cwd": "$PROJECT_ROOT",
    "env": { "NETWORKFUZZER_PYTHON": "$PYTHON" }
  }

EOF

# ------------------------------------------------------------------
# 3. Print Claude Desktop config snippet
# ------------------------------------------------------------------
echo "For Claude Desktop (~/.config/claude/claude_desktop_config.json):"
cat <<EOF
{
  "mcpServers": {
    "networkfuzzer": {
      "command": "bash",
      "args": ["$WRAPPER"],
      "cwd": "$PROJECT_ROOT",
      "env": { "NETWORKFUZZER_PYTHON": "$PYTHON" }
    }
  }
}
EOF

# ------------------------------------------------------------------
# 4. Print LangChain usage
# ------------------------------------------------------------------
echo ""
echo "For LangChain agents (install: pip install langchain-mcp-adapters):"
cat <<EOF
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent

async with MultiServerMCPClient({
    "networkfuzzer": {
        "command": "bash",
        "args": ["$WRAPPER"],
        "transport": "stdio",
    }
}) as client:
    tools = client.get_tools()
    agent = create_react_agent(llm, tools)
EOF

echo ""
echo "Setup complete. Restart Claude Code to load the MCP server."
