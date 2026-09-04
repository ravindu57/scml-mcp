# SCML MCP Server

Security middleware for LLM agents. Authorize tool calls, scan for injection, quarantine poisoned memory, and redact PII — all through MCP.

## Prerequisites

A running [SCML mediator](https://github.com/ravindu57/SCML):

```bash
pip install "trust-mediator[server]"
DATABASE_URL="" REDIS_URL="" TRUST_MEDIATOR_API_KEYS="" \
  uvicorn trust_mediator.api.app:app --port 8000
```

## Install

```bash
pip install -r requirements.txt
```

## Run

```bash
SCML_URL=http://localhost:8000 SCML_API_KEY=sk-your-key python server.py
```

## Claude Desktop config

Add to `~/.claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "scml": {
      "command": "python",
      "args": ["/path/to/server.py"],
      "env": {
        "SCML_URL": "http://localhost:8000",
        "SCML_API_KEY": ""
      }
    }
  }
}
```

## Tools

| Tool | What it does |
|---|---|
| `authorize_tool_call` | Check if a tool call is allowed by policy |
| `scan_content` | Detect prompt injection in external content |
| `check_memory_write` | Score a memory write for integrity |
| `redact_output` | Strip PII and secrets from responses |
| `get_audit_trail` | Replay session decisions with hash chain |
| `get_policy` | Show active security policy |
| `health_check` | Verify SCML mediator is running |

## License

Apache 2.0
