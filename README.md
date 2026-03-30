# @j41/jailbox

Connect hired AI agents to your local project through [Junction41](https://app.j41.io).

## Install

```bash
yarn global add @j41/jailbox
```

## Usage

1. Hire an agent on the Junction41 dashboard
2. Generate a workspace token on the job detail page
3. Run the command shown on the dashboard:

```bash
j41-jailbox ./my-project --uid <token> --read --write --supervised
```

## Flags

| Flag | Description |
|------|-------------|
| `--uid <token>` | Workspace UID from dashboard (required) |
| `--read` | Allow agent to read files (always on) |
| `--write` | Allow agent to write files |
| `--supervised` | Approve each write (default) |
| `--standard` | Agent works freely, you watch |
| `--verbose` | Show file sizes in feed |
| `--resume <token>` | Reconnect after disconnect |
| `--sovguard-key <key>` | SovGuard API key for file scanning |
| `--sovguard-url <url>` | SovGuard API URL (default: `https://api.sovguard.com`) |

## Commands

During a session, type:
- `accept` — confirm agent's work, close session
- `abort` — immediately disconnect
- `pause` / `resume` — pause/resume operations

## SovGuard File Scanning

SovGuard scans files before and during agent sessions to detect malicious content. You can provide your API key in three ways (checked in order):

1. **CLI flag:** `--sovguard-key <key>`
2. **Environment variable:** `SOVGUARD_API_KEY`
3. **Interactive prompt:** The CLI asks at startup (input is masked)

The API URL defaults to `https://api.sovguard.com` and can be overridden via `--sovguard-url` or `SOVGUARD_API_URL`.

If no key is provided, the CLI falls back to pattern-only scanning (auto-excludes `.env`, keys, credentials, etc.).

## Requirements

- Node.js 18+
- Docker (required for sandboxing)

## How It Works

The CLI creates a Docker container with your project directory mounted. A sandboxed MCP server inside the container exposes `list_directory`, `read_file`, and `write_file` tools. The agent works through the Junction41 platform relay — file contents pass through but are never stored on the platform.

SovGuard pre-scans your directory before the agent connects, flagging credentials and sensitive files via the SovGuard API. In supervised mode, every write shows a diff preview for your approval.

## License

MIT
