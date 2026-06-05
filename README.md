# @junction41/jailbox

Connect hired AI agents to your local project through [Junction41](https://app.junction41.io).

## Sandbox hardening update

This release tightens the agent-isolation boundary and makes the multi-wall
sandbox self-provisioning. See **[PLATFORMS.md](./PLATFORMS.md)** for the full
Linux/macOS/Windows support matrix.

**Refuses to run as root, and the container is never root.** The CLI exits if
launched as root, and the container always runs as an unprivileged user (the
host uid on Linux; the image's non-root `node` user on macOS/Windows).

**Self-provisioned hardened image with bundled bubblewrap (Wall 3).** jailbox
builds its own hardened image (`docker/Dockerfile.jailbox`) on first run instead
of depending on host-preinstalled tooling, and **verifies bubblewrap is present
before use** — it refuses to run a sandbox image missing its sandbox tool. On
gVisor-default hosts (where the legacy Docker builder drops files when it commits
under `runsc`) the image is built via a run-commit path under a standard runtime.

**Additional kernel-escape hardening.** Private cgroup namespace, explicit masked
/ read-only `/proc` paths, and `nodev` tmpfs are added on top of the always-on
`cap-drop ALL`, `network=none`, read-only rootfs, and pids/memory limits.

**Refuses to start without a kernel wall by default (breaking).** On Linux with
no gVisor runtime registered, the session now **refuses to start** rather than
silently running with only Docker's shared-kernel boundary. Install gVisor
(`npx @junction41/secure-setup --jailbox`) or pass `--insecure` to explicitly
accept a Docker-only sandbox (never for untrusted agents). macOS/Windows are
unaffected — the Docker Desktop VM is always a kernel wall.

**gVisor auto-engages whenever it is registered.** Previously the container only
used gVisor when `runsc` was the Docker daemon *default* runtime; now jailbox
opts into `Runtime: runsc` automatically whenever `runsc` is registered at all,
so you don't have to make it the daemon default. (gVisor still cannot be
*installed* by the CLI — that is a privileged host operation handled by
`@junction41/secure-setup`.)

**Honest isolation reporting.** The startup banner and `doctor` report the walls
that are *actually* active for this session (gVisor / Docker-Desktop VM, AppArmor,
seccomp, and whether bubblewrap engaged), rather than an aspirational count.

**Cross-platform robustness (one release for all three OSes).** Windows
drive-letter paths are translated to a Docker-safe bind form, the Docker
connection auto-selects the Windows named pipe vs Unix socket, and the pinned
base image is multi-arch (`amd64` + `arm64`).

**Bug fix:** the custom seccomp profile is now passed to the Docker Engine API as
inline JSON (the API does not read a file path the way the `docker` CLI does), so
sessions on hosts that deploy `/etc/j41/seccomp-jailbox.json` no longer fail to
start.

## Security update — confinement review (v2.1.3)

Focused hardening of the "a hired SovAgent reads/writes my repo and must not
escape" guarantee. The agent is **remote** and only speaks 3 file tools
(list/read/write) through the relay — it has **no code execution in the
container** — so the practical attack surface is the MCP server's path handling
plus the host-side relay/supervisor.

**Host-side supervisor read is now contained.** The supervised write-approval
flow read the *current* file contents on the **host** via
`readFileSync(join(projectDir, agentPath))` with no `..` guard, size cap, or
file-type check. An agent path like `../../../../etc/passwd` read host files
into your terminal, and `/dev/zero` or a huge file could OOM/hang your machine —
outside the container's limits. Now `safeReadCurrent` realpath-contains the read
to the project, requires a regular file, and caps it at 10MB.

**Sensitive-write highlighter.** Confinement keeps writes inside your repo, but
in-repo files like `.git/hooks/*`, `package.json` scripts, `Makefile`, CI
workflows, `Dockerfile`, and `.envrc` execute on your host *later*. Writes to
these are flagged in the approval prompt (and the live feed in standard mode) as
`EXECUTES-ON-HOST` so they get a closer look. Recorded in the audit log as
`write_sensitive_path`.

Repo confinement (`resolveSafe`) is covered by an adversarial escape-test battery
(traversal, absolute paths, read/write *through* escaping symlinks).


## Security update — 2026-06-02 audit (v2.1.0)

This release closes 5 highs + ~12 mediums/lows from the 2026-06-02 cross-repo security audit. Behavioral changes consumers should know about:

**First-run secure-setup is opt-in (breaking).** Previously `j41-jailbox` would auto-run `@junction41/secure-setup` on first launch, which executes `sudo apt-get install`, `sudo iptables`, `sudo apparmor_parser`, `sudo mv ... /etc/...`. Auto-running this meant any future compromise of secure-setup on npm would get root on every fresh buyer install. Now: refuses unless operator opts in via `J41_JAILBOX_AUTO_SECURE_SETUP=1`. Default prints the manual `npx @junction41/secure-setup --jailbox` command and exits so the buyer can review what's about to run as root.

**Audit log records the realpath, not the agent-supplied claim** (H5). The MCP server's `read_file`/`write_file` now `realpathSync` the resolved absolute path and attach `resolvedPath` to the log's `_meta`. A misbehaving agent that resolves `path: foo` to `foo/../../etc/passwd` now shows the resolved path in the log, not just `foo`.

**Session pubkey + audit log are now sent to the platform** (H4, M-auth-1/2). `relay-client.ts` exposes `sendSessionKey()` and `sendAuditLog()` — previously these were `(relay as any).method?.()` no-ops hidden by a type cast, so the audit-log non-repudiation claim was false-as-shipped. Server-side support is needed on the platform's `/jailbox` namespace (`jailbox:session_key` and `jailbox:audit_log` events) for the audit log to be externally verifiable.

**Inbound size caps on Socket.IO and SovGuard** (H1, M-ddos-2/3, L-ddos-3): `J41_JAILBOX_MAX_PAYLOAD_BYTES=4MB` (relay mcp:call), `J41_JAILBOX_MAX_MCP_LINE_BYTES=16MB` (in-container readline), `J41_SOVGUARD_MAX_RESPONSE_BYTES=4MB` (SovGuard scan response), `J41_JAILBOX_MCP_BUFFER_BYTES=16MB` (container stdout). A hostile relay or SovGuard endpoint can no longer OOM the buyer mid-session.

**`J41_API_URL` override is now logged.** If you set `J41_API_URL` to a non-default value, a clear stderr warning fires at startup so an unintended redirect is visible.

**`@junction41/secure-setup` pinned to exact `0.3.0`** (H2). The previous `>=0.1.0` would auto-resolve any future malicious release.

## Install

```bash
yarn global add @junction41/jailbox
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
| `--max-duration <hours>` | Max session duration in hours (default: 4) |
| `--verbose` | Show file sizes in feed |
| `--resume <token>` | Reconnect after disconnect |
| `--sovguard-key <key>` | SovGuard API key for file scanning |
| `--sovguard-url <url>` | SovGuard API URL (default: `https://api.sovguard.io`) |
| `--strict` | Refuse to start unless the full isolation stack is active (kernel wall + AppArmor + seccomp) |
| `--insecure` | Allow running **without** a kernel-isolation wall (Linux without gVisor). Default refuses. **NOT for untrusted agents.** |

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

The API URL defaults to `https://api.sovguard.io` and can be overridden via `--sovguard-url` or `SOVGUARD_API_URL`.

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
j41-jailbox ./my-project --uid abc123 --write --max-duration 1 --max-writes 20
```

## Security

### Three-Wall Isolation

On first run, jailbox guides you through installing isolation via `@junction41/secure-setup` (it is opt-in, not auto-run — see the v2.1.0 note above):

```
Buyer's machine
 +-- Wall 1: gVisor — Linux (kvm platform w/ /dev/kvm, else systrap, no KVM
 |           needed) or Docker Desktop VM (macOS)
 +-- Wall 2: Docker hardening — custom seccomp (fail-closed: /etc/j41 only on
 |           Linux), cap-drop ALL, NetworkMode: none, read-only rootfs, AppArmor,
 |           pid/mem/cpu limits, no-new-privileges
 +-- MCP server (3 tools: list, read, write) — the agent is REMOTE and only
     speaks JSON-RPC; it has NO code execution inside the container
```

The startup banner reports how many of the **3 container walls** (gVisor / seccomp / AppArmor) are actually active so you aren't given a false sense of the sandbox on a stock host. Docker hardening is always applied. `bwrap`, if present on the host, is **not** one of the jailbox container's walls (the container runs `node` directly on node:alpine) — it is shown as host-only info and excluded from the score.

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
