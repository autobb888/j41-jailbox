/**
 * Docker container lifecycle
 *
 * Creates a Node.js Alpine container with the project directory
 * mounted read-write. The MCP server runs inside via stdio.
 */

import Docker from 'dockerode';
import { resolve, dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { Writable, Readable, PassThrough } from 'stream';
import { existsSync, readFileSync } from 'fs';
import { homedir, userInfo } from 'os';
import { execSync } from 'child_process';
import { randomBytes } from 'crypto';
import chalk from 'chalk';

const CONTAINER_NAME_PREFIX = 'j41-jailbox-';
// Base image, pinned by digest. The FROM line in docker/Dockerfile.jailbox MUST
// match this digest — it is the supply-chain anchor for the hardened image we
// build on top of it.
const MCP_BASE_IMAGE_DIGEST = 'node@sha256:8d6421d663b4c28fd3ebc498332f249011d118945588d0a35cb9bc4b8ca09d9e';
// The hardened image jailbox builds and runs: stock base + bubblewrap (Wall 3)
// + the re-sandbox entrypoint. Built locally at first run from the in-repo
// Dockerfile so we never depend on whatever the host happens to have installed.
// Tag carries the package major.minor so a jailbox upgrade rebuilds the image.
const HARDENED_IMAGE_TAG = 'j41-jailbox-hardened:2.1';
const JAILBOX_MOUNT = '/jailbox';
const ENTRYPOINT_IN_IMAGE = '/app/entrypoint-jailbox.sh';

/**
 * Locate the bundled Docker build assets (Dockerfile + entrypoint). Resolves
 * relative to the compiled docker.js: in dev that is `<repo>/dist/docker.js` →
 * `<repo>/docker`; when installed from npm both `dist/` and `docker/` sit at the
 * package root. Shipped via the package.json `files` allowlist.
 */
export function getDockerAssetsDir(): string {
  const thisFile = fileURLToPath(import.meta.url);
  return resolve(dirname(thisFile), '..', 'docker');
}

/**
 * Compute the container `User` spec. Hard invariant: the container is NEVER run
 * as root. On Linux we run as the unprivileged host user so bind-mounted writes
 * are buyer-owned; if that uid is missing/root/out-of-range we fall back to the
 * image's built-in non-root `node` user (uid 1000). Off-Linux (Docker Desktop
 * runs containers inside a Linux VM — Wall 1) we likewise force the non-root
 * `node` user. The dispatcher itself also refuses to launch as root upstream,
 * so the root case here is purely defense-in-depth.
 */
/**
 * Translate a host path into a Docker bind-mount *source* that is safe to embed
 * in a `source:dest:mode` bind string. On Windows a path like `C:\Users\me\proj`
 * contains a drive-letter colon that Docker would mis-split on, corrupting the
 * mount — so we convert it to the colon-free Docker Desktop form
 * `//c/Users/me/proj` (lowercase drive, forward slashes). On Linux/macOS the
 * path is already colon-free and POSIX, so it passes through untouched (and we
 * must NOT rewrite backslashes there — they are valid filename characters).
 */
export function toBindSource(
  hostPath: string,
  platform: NodeJS.Platform | string = process.platform,
): string {
  if (platform !== 'win32') return hostPath;
  // Drive-letter path: C:\Users\me\proj or C:/Users/me/proj -> //c/Users/me/proj
  const drive = /^([A-Za-z]):[\\/](.*)$/.exec(hostPath);
  if (drive) {
    return '//' + drive[1].toLowerCase() + '/' + drive[2].replace(/\\/g, '/');
  }
  // UNC (\\server\share) or other: normalize separators, leave colon-free as-is.
  return hostPath.replace(/\\/g, '/');
}

export function computeUserSpec(
  platform: NodeJS.Platform | string,
  uid: number | undefined,
  gid: number | undefined,
): string {
  const NONROOT = '1000:1000'; // node:18-alpine ships a `node` user at uid/gid 1000
  if (platform === 'linux') {
    if (typeof uid === 'number' && typeof gid === 'number' && uid > 0 && uid < 65536) {
      return `${uid}:${gid >= 0 && gid < 65536 ? gid : 1000}`;
    }
    return NONROOT;
  }
  return NONROOT;
}

// --- Jailbox container security helpers (Plan B) ---

function buildJailboxSecurityOpt(): string[] {
  const opts = ['no-new-privileges:true'];

  // Seccomp profile — deployed by @junction41/secure-setup. NB: the Docker
  // ENGINE API (dockerode) expects the profile JSON *content*, not a path — the
  // `docker` CLI reads the file client-side, the API does not. So we inline the
  // file content. If the file is unreadable/invalid we omit it and fall back to
  // Docker's built-in default seccomp (never `unconfined`).
  const seccompPath = process.platform === 'linux'
    ? '/etc/j41/seccomp-jailbox.json'
    : join(homedir(), '.j41', 'seccomp-jailbox.json');

  if (existsSync(seccompPath)) {
    try {
      const profile = readFileSync(seccompPath, 'utf8');
      JSON.parse(profile); // validate before handing to the daemon
      opts.push(`seccomp=${profile}`);
    } catch {
      // Unreadable/invalid profile — keep Docker's default seccomp.
    }
  }

  // AppArmor — Linux only
  if (process.platform === 'linux') {
    try {
      const profiles = readFileSync('/sys/kernel/security/apparmor/profiles', 'utf8');
      if (profiles.includes('j41-jailbox-profile')) {
        opts.push('apparmor=j41-jailbox-profile');
      }
    } catch {
      // AppArmor not available
    }
  }

  return opts;
}

function detectGvisorRuntime(): string | undefined {
  try {
    const rt = execSync('docker info --format "{{.DefaultRuntime}}"', {
      encoding: 'utf8', timeout: 5000,
    }).trim();
    return rt === 'runsc' ? 'runsc' : undefined;
  } catch {
    return undefined;
  }
}

export interface IsolationLayers {
  gvisor: boolean;
  apparmor: boolean;
  seccomp: boolean;
  bwrap: boolean;
  active: number;
  missing: string[];
}

/**
 * Inspect the host for the four isolation layers jailbox can stack on top of
 * the always-on Docker hardening (cap-drop, no-network, read-only rootfs).
 * Surfaces how much defense-in-depth is actually active so the buyer isn't
 * given a false sense of the full "three-wall" sandbox on a stock host.
 */
export function detectIsolationLayers(): IsolationLayers {
  const linux = process.platform === 'linux';
  const seccompPath = linux
    ? '/etc/j41/seccomp-jailbox.json'
    : join(homedir(), '.j41', 'seccomp-jailbox.json');

  const gvisor = !!detectGvisorRuntime();
  const seccomp = existsSync(seccompPath);

  let apparmor = false;
  if (linux) {
    try {
      const profiles = readFileSync('/sys/kernel/security/apparmor/profiles', 'utf8');
      apparmor = profiles.includes('j41-jailbox-profile');
    } catch { /* AppArmor not available */ }
  }

  // Wall 3 (bubblewrap) lives INSIDE our hardened image and re-sandboxes the
  // MCP server via the entrypoint — it is NOT the host's bwrap. So the layer is
  // "available" when the hardened image has been built. Per-session engagement
  // (bwrap may no-op under gVisor where unprivileged userns is restricted) is
  // logged by the entrypoint to the container's stderr.
  const bwrap = hardenedImagePresent();

  const present = { gvisor, apparmor, seccomp, bwrap };
  const missing: string[] = [];
  if (!gvisor) missing.push('gVisor (kernel isolation)');
  if (!apparmor) missing.push('AppArmor profile (j41-jailbox-profile)');
  if (!seccomp) missing.push('custom seccomp profile (/etc/j41/seccomp-jailbox.json)');
  if (!bwrap) missing.push('hardened image w/ bubblewrap (built on first run)');

  return { ...present, active: Object.values(present).filter(Boolean).length, missing };
}

let _storageOptSupported: boolean | null = null;
function supportsStorageOpt(): boolean {
  if (_storageOptSupported !== null) return _storageOptSupported;
  try {
    const driver = execSync('docker info --format "{{.Driver}}"', {
      encoding: 'utf8', timeout: 5000,
    }).trim();
    if (driver !== 'overlay2') { _storageOptSupported = false; return false; }
    execSync('mount | grep pquota', { encoding: 'utf8', timeout: 5000, stdio: ['pipe', 'pipe', 'pipe'] });
    _storageOptSupported = true;
  } catch {
    _storageOptSupported = false;
  }
  return _storageOptSupported;
}

function hardenedImagePresent(): boolean {
  try {
    execSync(`docker image inspect ${HARDENED_IMAGE_TAG}`, { stdio: 'ignore', timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

/** Whether the hardened jailbox image (Wall 3 / bubblewrap) has been built. */
export function isHardenedImageBuilt(): boolean {
  return hardenedImagePresent();
}

/** The hardened image tag jailbox builds and runs. */
export function getHardenedImageTag(): string {
  return HARDENED_IMAGE_TAG;
}

export class DockerManager {
  private docker: Docker;
  private container: Docker.Container | null = null;
  private containerStream: any = null;
  public containerName: string | null = null;

  constructor() {
    this.docker = new Docker();
  }

  /**
   * Provision the hardened jailbox image. Built locally from the in-repo
   * Dockerfile (digest-pinned base + bubblewrap + entrypoint) so the full
   * sandbox ships with jailbox rather than depending on host-preinstalled
   * tooling. Idempotent: no-op once a VALID image exists.
   *
   * Production hardening: we always VERIFY that bubblewrap is actually present
   * and executable in the resulting image and refuse to run a sandbox image
   * that is missing its sandbox tool. On gVisor-default hosts the legacy Docker
   * builder silently drops files when committing layers, so we build via the
   * run+commit path under a standard runtime there instead of `docker build`.
   */
  async ensureHardenedImage(): Promise<void> {
    if (hardenedImagePresent() && this.imageHasBwrap()) {
      return; // already built and verified
    }
    // Drop any stale/broken image so we never run a half-built one.
    if (hardenedImagePresent()) {
      try { execSync(`docker rmi -f ${HARDENED_IMAGE_TAG}`, { stdio: 'ignore' }); } catch { /* ignore */ }
    }

    const assets = getDockerAssetsDir();
    const dockerfile = join(assets, 'Dockerfile.jailbox');
    const entrypoint = join(assets, 'entrypoint-jailbox.sh');
    if (!existsSync(dockerfile) || !existsSync(entrypoint)) {
      throw new Error(
        `Hardened image assets missing (${dockerfile}). Reinstall @junction41/jailbox.`,
      );
    }

    console.log(chalk.gray(`Building hardened jailbox sandbox image (${HARDENED_IMAGE_TAG})...`));
    console.log(chalk.gray(`  base ${MCP_BASE_IMAGE_DIGEST} + bubblewrap (one-time)`));

    if (detectGvisorRuntime()) {
      // gVisor-default host: `docker build` commits under runsc and drops the
      // installed bwrap binary. Build via run+commit under a standard runtime.
      this.buildHardenedViaRunCommit(entrypoint);
    } else {
      try {
        execSync(
          `docker build --pull -f "${dockerfile}" -t ${HARDENED_IMAGE_TAG} "${assets}"`,
          { stdio: 'inherit', timeout: 300_000 },
        );
      } catch (e: any) {
        throw new Error(
          `Failed to build hardened jailbox image: ${e.message}. ` +
          `Ensure Docker can pull the pinned base ${MCP_BASE_IMAGE_DIGEST}.`,
        );
      }
    }

    // Hard gate: never run a sandbox image without its sandbox binary.
    if (!this.imageHasBwrap()) {
      throw new Error(
        'Hardened image build produced an image WITHOUT bubblewrap (Wall 3). ' +
        'Refusing to run a sandbox image missing its sandbox tool. This commonly ' +
        'happens building under the gVisor runtime without a standard runtime ' +
        '(runc) registered. Fix: register runc, or build the image in CI from ' +
        'docker/Dockerfile.jailbox and distribute it by digest.',
      );
    }
  }

  /** Verify bubblewrap is present and executable in the hardened image. */
  private imageHasBwrap(): boolean {
    try {
      execSync(
        `docker run --rm --network none --entrypoint /usr/bin/bwrap ${HARDENED_IMAGE_TAG} --version`,
        { stdio: 'ignore', timeout: 20_000 },
      );
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Build the hardened image by installing bubblewrap in a container under a
   * standard runtime, then committing — mirrors docker/Dockerfile.jailbox.
   * Used on gVisor-default hosts where the legacy build-by-commit loses files.
   */
  private buildHardenedViaRunCommit(entrypointHostPath: string): void {
    const tmp = `j41-jailbox-build-${randomBytes(4).toString('hex')}`;
    try {
      execSync(`docker pull ${MCP_BASE_IMAGE_DIGEST}`, { stdio: 'inherit', timeout: 180_000 });
      // Install bwrap + create /app under a standard runtime (commits correctly).
      execSync(
        `docker run --runtime=runc --name ${tmp} ${MCP_BASE_IMAGE_DIGEST} ` +
        `sh -c "apk add --no-cache bubblewrap && mkdir -p /app"`,
        { stdio: 'inherit', timeout: 180_000 },
      );
      execSync(`docker cp "${entrypointHostPath}" ${tmp}:/app/entrypoint-jailbox.sh`, { stdio: 'ignore' });
      execSync(
        `docker commit ` +
        `--change 'ENTRYPOINT ["/app/entrypoint-jailbox.sh"]' ` +
        `--change 'CMD ["node", "/app/mcp-server.js"]' ` +
        `${tmp} ${HARDENED_IMAGE_TAG}`,
        { stdio: 'ignore', timeout: 60_000 },
      );
    } catch (e: any) {
      throw new Error(
        `Failed to build hardened image via run+commit: ${e.message}. ` +
        `A standard runtime (runc) must be registered alongside gVisor.`,
      );
    } finally {
      try { execSync(`docker rm -f ${tmp}`, { stdio: 'ignore' }); } catch { /* ignore */ }
    }
  }

  async start(projectDir: string, mcpServerPath: string, options?: {
    writable?: boolean;
    scope?: string[];
  }): Promise<{
    stdin: Writable;
    stdout: Readable;
  }> {
    // Build/verify our hardened image (Wall 3 lives inside it). We never run the
    // mutable stock tag directly: the image is built from a digest-pinned base.
    await this.ensureHardenedImage();
    const useImage = HARDENED_IMAGE_TAG;

    // Random suffix avoids predictable container names across concurrent
    // sessions; the scoped cleanup still targets this.containerName exactly.
    const containerName = CONTAINER_NAME_PREFIX + Date.now() + '-' + randomBytes(6).toString('hex');
    this.containerName = containerName;

    // Container NEVER runs as root. On Linux we run as the unprivileged host
    // user (buyer-owned writes); otherwise the image's non-root `node` user.
    // computeUserSpec guarantees a non-root spec for every input.
    const hostUser = userInfo();
    const userSpec = computeUserSpec(process.platform, hostUser.uid, hostUser.gid);

    this.container = await this.docker.createContainer({
      Image: useImage,
      name: containerName,
      User: userSpec,
      // Entrypoint re-sandboxes with bubblewrap (Wall 3), then execs the MCP
      // server. Cmd is the args bwrap wraps.
      Entrypoint: [ENTRYPOINT_IN_IMAGE],
      Cmd: ['node', '/app/mcp-server.js'],
      WorkingDir: JAILBOX_MOUNT,
      OpenStdin: true,
      StdinOnce: false,
      AttachStdin: true,
      AttachStdout: true,
      AttachStderr: true,
      Tty: false,
      HostConfig: {
        Binds: [
          // Scoped mounts: mount only specified subdirectories. Host sources are
          // normalized via toBindSource so Windows drive-letter paths don't get
          // mis-split on the bind-string ':' separators.
          ...(options?.scope && options.scope.length > 0
            ? options.scope.map(dir => {
                const hostPath = toBindSource(resolve(projectDir, dir));
                const containerPath = `${JAILBOX_MOUNT}/${dir}`;
                return `${hostPath}:${containerPath}:${options?.writable ? 'rw' : 'ro'}`;
              })
            : [`${toBindSource(projectDir)}:${JAILBOX_MOUNT}:${options?.writable ? 'rw' : 'ro'}`]
          ),
          `${toBindSource(mcpServerPath)}:/app/mcp-server.js:ro`,
        ],
        NetworkMode: 'none',
        Memory: 512 * 1024 * 1024, // 512MB
        MemorySwap: 512 * 1024 * 1024,
        CpuPeriod: 100000,
        CpuQuota: 100000, // 1 CPU core
        PidsLimit: 64,
        ReadonlyRootfs: true,
        Tmpfs: { '/tmp': 'rw,noexec,nosuid,nodev,size=32m' },
        SecurityOpt: buildJailboxSecurityOpt(),
        // Kernel-escape hardening (defense-in-depth on top of cap-drop/network):
        // private cgroup namespace so the container can't see/affect host cgroups.
        ...({ CgroupnsMode: 'private' } as any),
        // Explicitly mask & write-protect sensitive kernel/proc paths. Docker
        // applies these by default, but a custom seccomp/SecurityOpt set can
        // silently drop them — pin them so they can never be lost.
        MaskedPaths: [
          '/proc/asound', '/proc/acpi', '/proc/kcore', '/proc/keys',
          '/proc/latency_stats', '/proc/timer_list', '/proc/timer_stats',
          '/proc/sched_debug', '/proc/scsi', '/sys/firmware', '/sys/devices/virtual/powercap',
        ],
        ReadonlyPaths: [
          '/proc/bus', '/proc/fs', '/proc/irq', '/proc/sys', '/proc/sysrq-trigger',
        ],
        // StorageOpt only works on overlay2+xfs with pquota — omit if unsupported
        ...(supportsStorageOpt() ? { StorageOpt: { size: '512m' } } : {}),
        OomScoreAdj: 1000,
        CapDrop: ['ALL'],
        // gVisor runtime. Audit 2026-06-02 L-JAILBOX-ddos-3: if the operator
        // sets J41_REQUIRE_GVISOR=1, refuse to start the container when runsc
        // is not available — was previously a silent fall-through to the
        // default Docker runtime, which undermines the CLAUDE.md claim of
        // Wall-1 isolation.
        ...((): { Runtime?: string } => {
          const rt = detectGvisorRuntime();
          if (rt) return { Runtime: rt };
          if (process.env.J41_REQUIRE_GVISOR === '1') {
            throw new Error(
              'J41_REQUIRE_GVISOR=1 but the `runsc` runtime is not registered with Docker. ' +
              'Install gVisor via `npx @junction41/secure-setup --jailbox` or unset J41_REQUIRE_GVISOR to fall back to default Docker.',
            );
          }
          return {};
        })(),
        // NEVER override CapDrop — bwrap runs inside the container's own user namespace
      },
      Env: [
        `JAILBOX_WRITABLE=${options?.writable ? 'true' : 'false'}`,
        `JAILBOX_MOUNT=${JAILBOX_MOUNT}`,
      ],
    });

    // Attach to container stdio
    this.containerStream = await this.container.attach({
      stream: true,
      stdin: true,
      stdout: true,
      stderr: true,
      hijack: true,
    });

    await this.container.start();

    // Demux stdout/stderr from the multiplexed stream
    // PassThrough is both readable and writable — required by dockerode's demuxStream
    const stdout = new PassThrough();
    const stderr = new Writable({
      write(chunk, _encoding, callback) {
        // Log stderr from container (debug info)
        const msg = chunk.toString().trim();
        if (msg) console.error(chalk.gray(`[docker] ${msg}`));
        callback();
      },
    });

    this.docker.modem.demuxStream(this.containerStream, stdout, stderr);

    return {
      stdin: this.containerStream,
      stdout,
    };
  }

  /** Monitor container health — calls onExit when container stops unexpectedly */
  onContainerExit(callback: (exitCode: number) => void): void {
    if (!this.container) return;
    this.container.wait().then((data: any) => {
      const code = data?.StatusCode ?? 1;
      callback(code);
    }).catch(() => {
      callback(1);
    });
  }

  async stop(): Promise<void> {
    if (!this.container) return;

    try {
      const info = await this.container.inspect();
      if (info.State.Running) {
        await this.container.stop({ t: 5 });
      }
    } catch {
      // Container may already be stopped
    }

    try {
      await this.container.remove({ force: true });
    } catch {
      // Container may already be removed
    }

    this.container = null;
    this.containerStream = null;
  }

  isRunning(): boolean {
    return this.container !== null;
  }
}

/**
 * Get the path to the compiled mcp-server.js
 * This file gets volume-mounted into the Docker container.
 */
export function getMcpServerPath(): string {
  // In production (installed via yarn global): resolve from package directory
  // In development: resolve from dist/
  const thisFile = fileURLToPath(import.meta.url);
  const distDir = dirname(thisFile);
  return resolve(distDir, 'mcp-server.js');
}
