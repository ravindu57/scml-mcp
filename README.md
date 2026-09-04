# SCML MCP Server

Security middleware for LLM agents. Authorize tool calls, scan for injection, quarantine poisoned memory, and redact PII — all through MCP.

## Prerequisites

- A **running [SCML mediator](https://github.com/ravindu57/SCML)** (see below).
- **Policies configured** for the agents that will use this server. The MCP server is only a proxy: it forwards your tool-call requests to the mediator, and the mediator decides based on the `agent_id` you pass. There is no automatic policy discovery.

**Policy model (read this first).** SCML authorizes per *agent*. Every `authorize_tool_call` request carries an `agent_id`; the mediator looks up `policy.agents[<agent_id>]` and, if the agent is unknown, falls back to the `default` agent, which is **deny-all**. Concretely:

1. On your mediator, write a policy for your agent — e.g. `freight_booking` with `allowed_tools: [book_shipment, get_rate, create_waybill]`. See `policies/` in the SCML repo.
2. Your AI calls `authorize_tool_call(..., agent_id="freight_booking")`.
3. The mediator allows only tools on that allow-list; anything else (and any unknown `agent_id`) is denied.

Two consequences:

- If you omit `agent_id`, it defaults to `"default"` and **everything is denied**. Always pass the agent id you configured policy for.
- The MCP server relays **one mediator's** policy space. For multi-tenant setups (e.g. several freight customers), give each customer their **own mediator instance** and point this server at it via `SCML_URL` + `SCML_API_KEY`. There is no per-user policy scoping at the MCP layer.

Start a local mediator for development:

```bash
pip install "trust-mediator[server]"
DATABASE_URL="" REDIS_URL="" TRUST_MEDIATOR_API_KEYS="" \
  uvicorn trust_mediator.api.app:app --port 8000
```

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
| `authorize_tool_call` | Check if a tool call is allowed by policy — pass your configured `agent_id`, e.g. `"freight_booking"` |
| `scan_content` | Detect prompt injection in external content |
| `check_memory_write` | Score a memory write for integrity |
| `redact_output` | Strip PII and secrets from responses |
| `get_audit_trail` | Replay session decisions with hash chain |
| `get_policy` | Show active security policy |
| `health_check` | Verify SCML mediator is running |

## Example: freight company policy

```yaml
# policies/freight.yaml — load via PUT /v1/policy on your mediator
version: 1
agents:
  default:
    allowed_tools: []            # deny-all fallback for unconfigured agents
  freight_booking:
    allowed_tools:
      - book_shipment
      - get_rate
      - create_waybill
      - void_shipment
    rate_limits:
      tool_calls_per_minute: 60
```

Tell your agent to pass `agent_id="freight_booking"`, and SCML will deny any tool call outside that allow-list.

## License

Apache 2.0
