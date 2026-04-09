# CLAUDE.md — @junction41/jailbox

## What This Is

CLI tool that connects hired AI agents to a buyer's local project through Junction41. Creates a sandboxed Docker container with the project mounted, runs an MCP server inside, and relays file operations through the platform. Published as `@junction41/jailbox` on npm.

## Quick Reference

```bash
npm install -g @junction41/jailbox
j41-jailbox ./my-project --uid <token> --write --supervised
j41-jailbox ./my-project --uid <token> --readonly
j41-jailbox ./my-project --uid <token> --write --scope src,tests
```

## Architecture

**TypeScript ESM** (`"type": "module"`). Build with `yarn build` (tsc). Output in `dist/`.

### File Map

| File | Purpose |
|------|---------|
| `src/cli.ts` | Commander.js CLI entry point — parses flags, orchestrates session lifecycle |
| `src/docker.ts` | `DockerManager` — creates/starts/stops the MCP container with security hardening |
| `src/mcp-server.ts` | The MCP server that runs INSIDE the container — `list_directory`, `read_file`, `write_file` tools |
| `src/relay-client.ts` | WebSocket relay to/from platform — bridges MCP stdio to J41 API |
| `src/supervisor.ts` | Supervised mode — diff preview, approval queue (serialized to prevent race conditions) |
| `src/pre-scan.ts` | Pre-session directory scan — detects sensitive files, symlinks escaping project root |
| `src/sovguard.ts` | SovGuard file scanning integration — API + pattern-only fallback |
| `src/audit-log.ts` | Hash-chained Ed25519 signed audit trail — every file op logged |
| `src/session-limiter.ts` | Enforces max reads/writes/duration/file size/total transfer limits |
| `src/feed.ts` | Live terminal feed — shows file operations in real time |
| `src/doctor.ts` | `j41-jailbox doctor` — checks Docker, images, network, profiles |
| `src/config.ts` | Config types and defaults |
| `src/types.ts` | Shared TypeScript types |
| `src/index.ts` | Package exports |

### Security Model (Three-Wall Isolation)

```
Buyer's machine
 +-- Wall 1: gVisor (Linux+KVM) or Docker Desktop VM (macOS)
      +-- Wall 2: Docker (seccomp, cap-drop ALL, NetworkMode: none)
           +-- Wall 3: Bubblewrap (VPS fallback)
                +-- MCP server (3 tools: list, read, write)
```

### Container Hardening (docker.ts)

- `NetworkMode: 'none'` — zero network access
- `ReadonlyRootfs: true` with tmpfs `/tmp`
- `CapDrop: ['ALL']` — never overridden, even with bwrap
- Custom seccomp profile (no network syscalls)
- AppArmor confinement (Linux)
- `PidsLimit: 64`, `Memory: 512MB`
- Pinned Docker image digest for integrity
- `OomScoreAdj: 1000`

### Mount Modes

| Flag | Mount | Behavior |
|------|-------|----------|
| (default) | `:ro` | Read-only — agent can read, writes blocked by OS |
| `--write` | `:rw` | Read-write — supervised mode still requires approval per write |
| `--readonly` | `:ro` forced | Overrides `--write` if both passed |
| `--scope src,tests` | Per-subdir | Only mounts specified dirs, enforced at Docker + relay level |

### Supervisor (supervisor.ts)

- Approval queue serialized via promise chain (prevents race conditions)
- Shows diff preview for each write
- Records `approved: true/false` in audit log
- SovGuard scans file content before write (fail-secure: blocks if API unreachable in standard mode)

### Audit Log (audit-log.ts)

- Ephemeral Ed25519 keypair generated per session
- Public key registered with platform
- Each entry: sequence number, operation type, path, bytes, content hash, timestamp, previous entry hash, Ed25519 signature
- Blocked operations recorded with `_blocked` suffix
- Full log uploaded to platform at session end

### Session Limits

| Limit | Default | Flag |
|-------|---------|------|
| Max file reads | 500 | `--max-reads` |
| Max file writes | 100 | `--max-writes` |
| Max session duration | 4 hours | `--max-duration` |
| Max single file size | 10MB | (not configurable) |
| Max total transfer | 500MB | (not configurable) |

### Symlink Protection

Pre-scan detects symlinks pointing outside project root — auto-excluded with warning. MCP server resolves via `realpathSync()` and blocks path escapes.

### Key Patterns

- MCP server (`mcp-server.ts`) is volume-mounted into container as `/app/mcp-server.js`
- `JAILBOX_WRITABLE` env var checked independently inside container — defense in depth
- SovGuard: fail-secure in standard mode (unscanned = blocked), fail-open in supervised mode (buyer prompted)
- Pre-scan confirmation: explicit `Y` or Enter — unknown keys re-prompt

### Testing

```bash
yarn build                    # Compile TypeScript
j41-jailbox doctor            # Check Docker, images, network, profiles
j41-jailbox . --uid test123   # Live test with a token from the dashboard
```

### Dependencies

- Docker (required)
- Node.js 18+
- `@junction41/secure-setup` (optional, auto-installed on first run)
