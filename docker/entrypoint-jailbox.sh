#!/bin/sh
# Wall 3 — re-sandbox the MCP server with bubblewrap.
#
# This runs as PID 1 inside the (already cap-dropped, network-none, read-only,
# non-root) Docker container. It wraps the MCP server in a fresh unprivileged
# bubblewrap sandbox so a compromise of the Node process is boxed a second time:
# a private user/PID/IPC/cgroup/UTS namespace, a minimal read-only view of the
# image, and ONLY the project mount writable (and only when Docker mounted it rw).
#
# Robustness: under gVisor (Wall 1) the kernel may forbid nested unprivileged
# user namespaces, so bwrap cannot engage. That is fine — gVisor is already a
# stronger kernel wall. We PROBE first and exec directly on failure rather than
# crash, and we always log which path we took to stderr (the dispatcher surfaces
# container stderr), so the active layer is never silently misrepresented.
set -eu

JAILBOX_MOUNT="${JAILBOX_MOUNT:-/jailbox}"

run_direct() {
  echo "[entrypoint] bubblewrap not engaged — relying on outer kernel wall (gVisor/Docker)" >&2
  exec "$@"
}

if ! command -v bwrap >/dev/null 2>&1; then
  run_direct "$@"
fi

# Probe: can we actually create a user namespace here? (Fails under gVisor or a
# kernel with unprivileged userns disabled.)
if ! bwrap --unshare-user --uid 1000 --gid 1000 --ro-bind / / /bin/true >/dev/null 2>&1; then
  run_direct "$@"
fi

echo "[entrypoint] bubblewrap Wall-3 engaged" >&2

# Writable project mount only; everything else read-only. bwrap preserves the
# underlying Docker mount flags, so a :ro project stays read-only regardless.
#
# We unshare user/ipc/pid/uts/cgroup but NOT the network namespace: Docker
# already runs us with network=none, and asking bwrap to unshare net makes it
# try to configure loopback (RTM_NEWADDR), which fails under an isolated/gVisor
# netns and would abort the sandbox. Skipping --unshare-net keeps the existing
# zero-network namespace intact.
exec bwrap \
  --ro-bind /usr /usr \
  --ro-bind /lib /lib \
  --ro-bind /bin /bin \
  --ro-bind /sbin /sbin \
  --ro-bind /etc /etc \
  --ro-bind /app /app \
  --bind "$JAILBOX_MOUNT" "$JAILBOX_MOUNT" \
  --proc /proc \
  --dev /dev \
  --tmpfs /tmp \
  --chdir "$JAILBOX_MOUNT" \
  --unshare-user-try \
  --unshare-ipc \
  --unshare-pid \
  --unshare-uts \
  --unshare-cgroup-try \
  --new-session \
  --die-with-parent \
  --cap-drop ALL \
  "$@"
