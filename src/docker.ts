/**
 * Docker container lifecycle
 *
 * Creates a Node.js Alpine container with the project directory
 * mounted read-write. The MCP server runs inside via stdio.
 */

import Docker from 'dockerode';
import { resolve, dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';
import { Writable, Readable, PassThrough } from 'stream';
import { existsSync, readFileSync } from 'fs';
import { homedir, userInfo } from 'os';
import { execSync } from 'child_process';
import { randomBytes } from 'crypto';
import chalk from 'chalk';

const require = createRequire(import.meta.url);

const CONTAINER_NAME_PREFIX = 'j41-jailbox-';
const MCP_IMAGE = 'node:18-alpine';
// Pinned digest — update periodically with: docker pull node:18-alpine && docker inspect --format='{{index .RepoDigests 0}}' node:18-alpine
const MCP_IMAGE_DIGEST = 'node@sha256:8d6421d663b4c28fd3ebc498332f249011d118945588d0a35cb9bc4b8ca09d9e';
const JAILBOX_MOUNT = '/jailbox';

// --- Jailbox container security helpers (Plan B) ---

function buildJailboxSecurityOpt(): string[] {
  const opts = ['no-new-privileges:true'];

  // Seccomp profile — deployed by @junction41/secure-setup
  const seccompPath = process.platform === 'linux'
    ? '/etc/j41/seccomp-jailbox.json'
    : join(homedir(), '.j41', 'seccomp-jailbox.json');

  if (existsSync(seccompPath)) {
    opts.push(`seccomp=${seccompPath}`);
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

  let bwrap = false;
  try {
    execSync('which bwrap', { stdio: 'ignore', timeout: 3000 });
    bwrap = true;
  } catch { /* bwrap not installed */ }

  const present = { gvisor, apparmor, seccomp, bwrap };
  const missing: string[] = [];
  if (!gvisor) missing.push('gVisor (kernel isolation)');
  if (!apparmor) missing.push('AppArmor profile (j41-jailbox-profile)');
  if (!seccomp) missing.push('custom seccomp profile (/etc/j41/seccomp-jailbox.json)');
  if (!bwrap) missing.push('bubblewrap (bwrap)');

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

function getJailboxBwrapEntrypoint(): string | undefined {
  // Only use bwrap if gVisor is NOT the runtime
  if (detectGvisorRuntime()) return undefined;

  try {
    execSync('which bwrap', { stdio: 'ignore', timeout: 3000 });
  } catch {
    return undefined; // bwrap not installed
  }

  // Find the entrypoint script from @junction41/secure-setup
  try {
    const setupPkg = require.resolve('@junction41/secure-setup');
    const entrypointPath = join(dirname(setupPkg), '..', 'scripts', 'entrypoint-jailbox.sh');
    if (existsSync(entrypointPath)) return entrypointPath;
  } catch {
    // @junction41/secure-setup not installed
  }

  return undefined;
}

export class DockerManager {
  private docker: Docker;
  private container: Docker.Container | null = null;
  private containerStream: any = null;
  public containerName: string | null = null;

  constructor() {
    this.docker = new Docker();
  }

  async start(projectDir: string, mcpServerPath: string, options?: {
    writable?: boolean;
    scope?: string[];
  }): Promise<{
    stdin: Writable;
    stdout: Readable;
  }> {
    // Pull image — pinned digest ONLY. We deliberately do not fall back to the
    // mutable `node:18-alpine` tag: a repointed tag must never be able to
    // substitute a different image for our pinned, verified one.
    const useImage = MCP_IMAGE_DIGEST;
    try {
      await this.docker.getImage(MCP_IMAGE_DIGEST).inspect();
    } catch {
      // Not present locally by digest. Accept a local tag only if it resolves
      // to our pinned digest; otherwise pull by digest, and if even that fails
      // refuse to start rather than silently using the mutable tag.
      let pinnedPresent = false;
      try {
        const info = await this.docker.getImage(MCP_IMAGE).inspect();
        const digests: string[] = info.RepoDigests || [];
        pinnedPresent = digests.some((d: string) => d === MCP_IMAGE_DIGEST);
      } catch { /* tag not local either */ }

      if (!pinnedPresent) {
        console.log(chalk.gray(`Pulling ${MCP_IMAGE_DIGEST}...`));
        await new Promise<void>((res, rej) => {
          this.docker.pull(MCP_IMAGE_DIGEST, (err: any, stream: any) => {
            if (err) {
              return rej(new Error(
                `Failed to pull pinned MCP image (${MCP_IMAGE_DIGEST}): ${err.message}. ` +
                `Refusing to fall back to the mutable ${MCP_IMAGE} tag for supply-chain safety.`,
              ));
            }
            this.docker.modem.followProgress(stream, (err2: any) => err2 ? rej(err2) : res());
          });
        });
      }
    }

    // Random suffix avoids predictable container names across concurrent
    // sessions; the scoped cleanup still targets this.containerName exactly.
    const containerName = CONTAINER_NAME_PREFIX + Date.now() + '-' + randomBytes(6).toString('hex');
    this.containerName = containerName;

    // On native Linux, run as the host user so files written to the bind-mounted
    // project are owned by the buyer, not root (avoids root-owned writes on the
    // host). Skipped off-Linux where Docker Desktop already maps mount ownership
    // and forcing a UID can break writes to the share.
    const hostUser = userInfo();
    const userSpec = (process.platform === 'linux'
      && typeof hostUser.uid === 'number' && hostUser.uid >= 0 && hostUser.uid < 65536)
      ? `${hostUser.uid}:${hostUser.gid}`
      : undefined;

    this.container = await this.docker.createContainer({
      Image: useImage,
      name: containerName,
      ...(userSpec ? { User: userSpec } : {}),
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
          // Scoped mounts: mount only specified subdirectories
          ...(options?.scope && options.scope.length > 0
            ? options.scope.map(dir => {
                const hostPath = resolve(projectDir, dir);
                const containerPath = `${JAILBOX_MOUNT}/${dir}`;
                return `${hostPath}:${containerPath}:${options?.writable ? 'rw' : 'ro'}`;
              })
            : [`${projectDir}:${JAILBOX_MOUNT}:${options?.writable ? 'rw' : 'ro'}`]
          ),
          `${mcpServerPath}:/app/mcp-server.js:ro`,
        ],
        NetworkMode: 'none',
        Memory: 512 * 1024 * 1024, // 512MB
        MemorySwap: 512 * 1024 * 1024,
        CpuPeriod: 100000,
        CpuQuota: 100000, // 1 CPU core
        PidsLimit: 64,
        ReadonlyRootfs: true,
        Tmpfs: { '/tmp': 'rw,noexec,nosuid,size=32m' },
        SecurityOpt: buildJailboxSecurityOpt(),
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
        // Pass bwrap entrypoint path if available (container reads from env, not capabilities)
        ...(getJailboxBwrapEntrypoint() ? [`JAILBOX_BWRAP_ENTRYPOINT=${getJailboxBwrapEntrypoint()}`] : []),
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
