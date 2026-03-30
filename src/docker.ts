/**
 * Docker container lifecycle
 *
 * Creates a Node.js Alpine container with the project directory
 * mounted read-write. The MCP server runs inside via stdio.
 */

import Docker from 'dockerode';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import { Writable, Readable, PassThrough } from 'stream';
import chalk from 'chalk';

const CONTAINER_NAME_PREFIX = 'j41-jailbox-';
const MCP_IMAGE = 'node:18-alpine';
// Pinned digest — update periodically with: docker pull node:18-alpine && docker inspect --format='{{index .RepoDigests 0}}' node:18-alpine
const MCP_IMAGE_DIGEST = 'node@sha256:8d6421d663b4c28fd3ebc498332f249011d118945588d0a35cb9bc4b8ca09d9e';
const WORKSPACE_MOUNT = '/workspace';

export class DockerManager {
  private docker: Docker;
  private container: Docker.Container | null = null;
  private containerStream: any = null;

  constructor() {
    this.docker = new Docker();
  }

  async start(projectDir: string, mcpServerPath: string): Promise<{
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
      WorkingDir: WORKSPACE_MOUNT,
      OpenStdin: true,
      StdinOnce: false,
      AttachStdin: true,
      AttachStdout: true,
      AttachStderr: true,
      Tty: false,
      HostConfig: {
        Binds: [
          `${projectDir}:${WORKSPACE_MOUNT}:rw`,
          `${mcpServerPath}:/app/mcp-server.js:ro`,
        ],
        NetworkMode: 'none', // No network access
        Memory: 512 * 1024 * 1024, // 512MB
        MemorySwap: 512 * 1024 * 1024,
        CpuPeriod: 100000,
        CpuQuota: 100000, // 1 CPU core
        PidsLimit: 64,
        ReadonlyRootfs: false, // Need writable for /tmp
        SecurityOpt: ['no-new-privileges'],
      },
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
