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
import { homedir } from 'os';
import { execSync } from 'child_process';
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
    // Pull image if needed — prefer pinned digest for integrity
    let useImage = MCP_IMAGE;
    try {
      // Check if pinned digest is available locally
      await this.docker.getImage(MCP_IMAGE_DIGEST).inspect();
      useImage = MCP_IMAGE_DIGEST;
    } catch {
      // Try the tag
      try {
        const info = await this.docker.getImage(MCP_IMAGE).inspect();
        // Verify the tag resolves to our pinned digest
        const digests: string[] = info.RepoDigests || [];
        if (digests.some((d: string) => d === MCP_IMAGE_DIGEST)) {
          useImage = MCP_IMAGE;
        } else {
          console.warn(chalk.yellow(`⚠ Local ${MCP_IMAGE} digest does not match pinned digest. Re-pulling...`));
          throw new Error('digest mismatch');
        }
      } catch {
        console.log(chalk.gray(`Pulling ${MCP_IMAGE_DIGEST}...`));
        await new Promise<void>((resolve, reject) => {
          this.docker.pull(MCP_IMAGE_DIGEST, (err: any, stream: any) => {
            if (err) {
              // Fallback to tag if digest pull fails (e.g., older Docker versions)
              console.log(chalk.gray(`Digest pull failed, falling back to ${MCP_IMAGE}...`));
              this.docker.pull(MCP_IMAGE, (err2: any, stream2: any) => {
                if (err2) return reject(err2);
                this.docker.modem.followProgress(stream2, (err3: any) => {
                  if (err3) reject(err3);
                  else resolve();
                });
              });
              return;
            }
            this.docker.modem.followProgress(stream, (err2: any) => {
              if (err2) reject(err2);
              else resolve();
            });
          });
        });
        useImage = MCP_IMAGE_DIGEST;
      }
    }

    const containerName = CONTAINER_NAME_PREFIX + Date.now();

    this.container = await this.docker.createContainer({
      Image: useImage,
      name: containerName,
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
        // gVisor runtime (if configured as Docker default)
        ...(detectGvisorRuntime() ? { Runtime: 'runsc' } : {}),
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
