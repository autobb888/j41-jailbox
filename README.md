# @j41/jailbox

Connect hired AI agents to your local project through [Junction41](https://app.j41.io).

## Install

```bash
yarn global add @j41/jailbox
```

## Usage

1. Hire an agent on the Junction41 dashboard
2. Generate a jailbox token on the job detail page
3. Run the command shown on the dashboard:

```bash
j41-jailbox ./my-project --uid <token> --read --write --supervised
```

## Flags

| Flag | Description |
|------|-------------|
| `--uid <token>` | Jailbox UID from dashboard (required) |
| `--read` | Allow agent to read files (always on) |
| `--write` | Allow agent to write files (mount switches to read-write) |
| `--supervised` | Approve each write with diff preview (default) |
| `--standard` | Agent works freely, you watch |
| `--readonly` | No writes at all, even if `--write` is passed |
| `--scope <dirs>` | Restrict agent to specific subdirectories (comma-separated) |
| `--max-reads <n>` | Max file reads per session (default: 500) |
| `--max-writes <n>` | Max file writes per session (default: 100) |
| `--max-duration <min>` | Max session duration in minutes (default: 240 = 4 hours) |
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

## Examples

```bash
# Basic supervised session (default — read-only mount, approve each write)
j41-jailbox ./my-project --uid abc123

# Allow writes with approval
j41-jailbox ./my-project --uid abc123 --write --supervised

# Restrict agent to src/ and tests/ only
j41-jailbox ./my-project --uid abc123 --write --scope src,tests

# Fully read-only session (no writes possible)
j41-jailbox ./my-project --uid abc123 --readonly

# Short session with tight limits
j41-jailbox ./my-project --uid abc123 --write --max-duration 60 --max-writes 20
```

## Security

### Three-Wall Isolation

On first run, jailbox auto-installs security isolation via `@j41/secure-setup`:

```
Buyer's machine
 +-- Wall 1: gVisor (Linux + KVM) or Docker Desktop VM (macOS)
      +-- Wall 2: Docker (seccomp, cap-drop ALL, NetworkMode: none)
           +-- Wall 3: Bubblewrap (VPS fallback)
                +-- MCP server (3 tools: list, read, write)
```

No manual configuration needed. The setup runs once automatically.

### Mount Security

Your project directory is mounted **read-only by default** at the Docker level:

- Default: `:ro` — agent can read files but writes are blocked by the OS
- `--write`: `:rw` — mount becomes read-write, but supervised mode still requires your approval per write
- `--readonly`: `:ro` forced — overrides `--write` if both are passed (CLI warns)
- `--scope src,tests` — only mounts those subdirectories, enforced at both the Docker mount level and the relay handler (defense-in-depth)

The MCP server also checks the `JAILBOX_WRITABLE` env var independently — writes are blocked inside the container even if the mount is misconfigured.

### Symlink Protection

The pre-scan detects symlinks inside your project that point outside the project root. These are automatically excluded with a warning. The MCP server also resolves symlinks via `realpathSync()` and blocks any path that escapes the mount root.

### Session Limits

| Limit | Default | Flag |
|---|---|---|
| Max file reads | 500 | `--max-reads` |
| Max file writes | 100 | `--max-writes` |
| Max session duration | 4 hours | `--max-duration` |
| Max single file size | 10MB | (not configurable) |
| Max total transfer | 500MB | (not configurable) |

The session auto-kills when any limit is reached. The buyer is notified.

### Tamper-Evident Audit Log

Every file operation — successful and blocked — is logged in a hash-chained, signed audit trail:

1. At session start, an ephemeral Ed25519 keypair is generated
2. The public key is registered with the platform
3. Each entry includes: sequence number, operation type, path, bytes, content hash, timestamp, previous entry hash, and Ed25519 signature
4. Blocked operations are recorded with a `_blocked` suffix (e.g., `write_file_blocked`)
5. At session end, the full log is uploaded to the platform

Anyone with the public key can verify the chain. Useful for disputes — cryptographic proof of exactly what the agent did and what was denied.

In supervised mode, writes are stamped `approved: true` in the audit record. In standard mode, `approved: false` — so forensics can distinguish buyer-approved writes from unreviewed ones.

### Container Hardening

The MCP server container runs with:

- `NetworkMode: 'none'` — zero network access
- `ReadonlyRootfs: true` with tmpfs `/tmp`
- `CapDrop: ['ALL']` — zero capabilities (never overridden, even with bwrap)
- Custom seccomp profile (no network syscalls allowed)
- AppArmor confinement (Linux)
- `PidsLimit: 64`, `Memory: 512MB`

## Requirements

- Node.js 18+
- Docker (required for sandboxing)

## How It Works

The CLI creates a Docker container with your project directory mounted. A sandboxed MCP server inside the container exposes `list_directory`, `read_file`, and `write_file` tools. The agent works through the Junction41 platform relay — file contents pass through but are never stored on the platform.

SovGuard pre-scans your directory before the agent connects, flagging credentials and sensitive files via the SovGuard API. In supervised mode, every write shows a diff preview for your approval.

### SovGuard Fail-Secure

SovGuard scanning follows a fail-secure model:

- **Supervised mode**: if SovGuard is unreachable or the file is too large to scan, the buyer is prompted to approve or reject
- **Standard mode**: unscanned writes are **blocked by default** — no silent pass-through. If the SovGuard API fails 3 times consecutively, the session aborts
- Pre-scan confirmation requires explicit `Y` or Enter — unknown keys re-prompt instead of proceeding

## License

MIT
