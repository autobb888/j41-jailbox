# Platform support — Linux, macOS, Windows

`@junction41/jailbox` ships as a **single npm package**. There are no
per-OS builds: it is a Node.js CLI, and the sandbox itself is a **Linux
container** that runs identically on all three host operating systems (macOS and
Windows run Linux containers inside Docker Desktop's VM). The hardened image —
including the bundled `bubblewrap` (Wall 3) — is byte-identical everywhere.

```bash
yarn global add @junction41/jailbox   # same command on Linux, macOS, Windows
```

## Requirements

| Host OS | Requirement |
|---------|-------------|
| Linux   | Docker Engine. gVisor (`runsc`) strongly recommended for untrusted agents — install via `npx @junction41/secure-setup --jailbox`. |
| macOS   | Docker Desktop in **Linux-container mode** (the default). Intel and Apple Silicon both supported — the pinned base image is multi-arch (`amd64` + `arm64`). |
| Windows | Docker Desktop with the **WSL2** (or Hyper-V) backend, in **Linux-container mode** (the default). |

The CLI runs as a **non-root user** on every platform and **refuses to start as
root** (on Windows there is no root concept, so the check is a no-op). The
container is **never** run as root either.

## The isolation walls per OS

Every platform gets a real kernel-isolation boundary plus the always-on Docker
hardening (`cap-drop ALL`, `network=none`, read-only rootfs, non-root user,
private cgroup namespace, masked `/proc` paths, pids/memory limits).

| | Wall 1 — kernel boundary | Wall 2 — Docker hardening | Wall 3 — bubblewrap |
|---|---|---|---|
| **Linux** | gVisor (`runsc`) **if installed**; otherwise Docker's shared-kernel boundary | always applied | bundled in image; nests when the j41 seccomp profile permits unprivileged userns, else falls back to Wall 1 |
| **macOS** | Docker Desktop LinuxKit **VM** (always) | always applied | bundled in image (same as Linux) |
| **Windows** | Docker Desktop WSL2 / Hyper-V **VM** (always) | always applied | bundled in image (same as Linux) |

Notably, **macOS and Windows get a hardware-virtualized VM boundary for free**,
which is generally a stronger Wall 1 than gVisor. The host that needs the most
attention is **plain Linux without gVisor**.

**By default, Linux without a kernel wall refuses to start.** If no gVisor
runtime is registered, the session aborts rather than running with only Docker's
shared-kernel boundary. Your options:

- **Install gVisor (recommended):** `npx @junction41/secure-setup --jailbox`.
  Once `runsc` is registered, jailbox engages it automatically — it does **not**
  need to be the Docker daemon's default runtime.
- **`--insecure`:** explicitly accept a Docker-only sandbox. Use only for code
  you trust; never for an untrusted agent.
- **`--strict`:** the opposite — refuse unless the *full* stack (kernel wall +
  AppArmor + seccomp) is active. `--strict` overrides `--insecure` if both are
  passed.

gVisor cannot be installed by the CLI itself: registering a Docker runtime is a
privileged, host-level operation (it edits `/etc/docker/daemon.json` and restarts
the daemon), which is why it is delegated to `@junction41/secure-setup`. jailbox
only detects and uses `runsc`.

The startup banner reports the **actual** active walls for the current session,
and the container entrypoint logs whether bubblewrap engaged or fell back — so
the reported posture is never more than what is truly active.

## How the cross-platform differences are handled (no separate releases)

All differences are runtime branches keyed on `process.platform`, not separate
artifacts:

- **Docker connection** — `dockerode`/`docker-modem` auto-selects the Windows
  named pipe (`//./pipe/docker_engine`) vs the Unix socket (`/var/run/docker.sock`).
- **Bind-mount paths** — Windows drive paths (`C:\Users\me\proj`) are translated
  to the colon-free Docker form (`//c/Users/me/proj`) so the drive-letter colon
  cannot corrupt the `source:dest:mode` bind string. POSIX paths pass through
  untouched (backslashes are preserved on Linux/macOS, where they are valid
  filename characters).
- **Container user** — Linux runs as the unprivileged host uid (so writes are
  buyer-owned); macOS/Windows use the image's non-root `node` user.
- **Kernel wall detection** — gVisor (`runsc`) on Linux; the Docker Desktop VM is
  recognized as Wall 1 on macOS/Windows.
- **seccomp / AppArmor** — Linux reads `/etc/j41/...`; AppArmor is Linux-only.
  The seccomp profile is passed to the Docker API as inline JSON content (the
  Engine API does not read a path the way the `docker` CLI does).
- **Image** — built locally on first run from `docker/Dockerfile.jailbox` and
  verified to contain `bubblewrap` before use. On gVisor-default hosts the build
  uses a run-commit path under a standard runtime, because the legacy builder
  drops files when it commits under `runsc`.

## Quick check

```bash
j41-jailbox doctor
```

reports Docker, the run user (non-root), the hardened image, and which kernel
wall is active on this host.
