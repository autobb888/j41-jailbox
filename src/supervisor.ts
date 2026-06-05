/**
 * Supervised mode — diff preview + Y/N approval for writes
 *
 * Manages stdin state machine to handle both interactive commands
 * (pause/resume/abort/accept) and write approval prompts (Y/N).
 */

import { createInterface, Interface } from 'readline';
import { readFileSync, existsSync, realpathSync, statSync } from 'fs';
import { resolve, sep } from 'path';
import { structuredPatch } from 'diff';
import chalk from 'chalk';
import { DIFF_PREVIEW_LINES } from './types.js';
import type { InputState } from './types.js';
import { classifySensitiveWrite } from './sensitive-paths.js';

// Cap how much of an existing file we'll load on the HOST to render a write
// diff. Without this, an agent-supplied path pointing at /dev/zero (or a
// legitimately huge file in the project) would make readFileSync allocate
// unbounded and OOM/hang the buyer's machine — outside the container's limits.
const MAX_DIFF_READ_BYTES = 10 * 1024 * 1024; // 10MB, matches mcp-server MAX_FILE_SIZE

/**
 * Resolve an agent-supplied write path to a host path for the diff preview,
 * but ONLY if it stays inside projectDir and is a normal file small enough to
 * read safely. The container's mcp-server is the authority on where writes
 * actually land (resolveSafe); this guard exists because the supervisor reads
 * the *current* contents on the HOST, where the container's isolation does not
 * apply. Returns the prior content, or '' when the path escapes / is unreadable
 * (the write itself is still independently gated by the container).
 */
export function safeReadCurrent(projectDir: string, relPath: string): string {
  // Blunt reject: any `..` segment. The realpath containment below is the
  // deeper guard, but rejecting `..` outright keeps the intent obvious.
  if (relPath.includes('..')) return '';

  const root = realpathSync(projectDir);
  const abs = resolve(root, relPath);
  if (abs !== root && !abs.startsWith(root + sep)) return ''; // pre-resolution escape

  if (!existsSync(abs)) return '';
  let real: string;
  try {
    real = realpathSync(abs);
  } catch {
    return '';
  }
  // Symlink must not escape the project root.
  if (real !== root && !real.startsWith(root + sep)) return '';

  let st;
  try {
    st = statSync(real);
  } catch {
    return '';
  }
  // Refuse anything that isn't a plain file (blocks /dev/zero, fifos, sockets).
  if (!st.isFile()) return '';
  if (st.size > MAX_DIFF_READ_BYTES) return '';

  try {
    return readFileSync(real, 'utf-8');
  } catch {
    return '';
  }
}

export class Supervisor {
  private state: InputState = 'IDLE';
  private pendingResolve: ((approved: boolean) => void) | null = null;
  private pendingSovguardResolve: ((decision: 'approve' | 'reject' | 'report') => void) | null = null;
  private fallbackHandler: ((cmd: string) => void) | null = null;
  private _approvalQueue: Promise<void> = Promise.resolve();
  private commandHandler: ((cmd: string) => void) | null = null;
  private rl: Interface;

  constructor() {
    // Ensure stdin is in a clean state for readline
    if (process.stdin.isPaused()) {
      process.stdin.resume();
    }

    this.rl = createInterface({
      input: process.stdin,
      output: process.stdout,
      terminal: false, // Keep stdin in cooked mode so Ctrl+C delivers SIGINT normally
    });

    this.rl.on('line', (line) => {
      const input = line.trim().toLowerCase();

      // abort and Ctrl+C work in ANY state
      if (input === 'abort') {
        let hadPending = false;
        if (this.pendingSovguardResolve) {
          const resolve = this.pendingSovguardResolve;
          this.pendingSovguardResolve = null;
          this.state = 'IDLE';
          resolve('reject');
          hadPending = true;
        }
        if (this.pendingResolve) {
          const resolve = this.pendingResolve;
          this.pendingResolve = null;
          this.state = 'IDLE';
          resolve(false);
          hadPending = true;
        }
        // Only send abort command if no pending promise was resolved
        // (resolved promises will handle their own cleanup flow)
        if (!hadPending) {
          this.commandHandler?.('abort');
        }
        return;
      }

      if (this.state === 'APPROVAL_PENDING' && this.pendingResolve) {
        if (input === 'y' || input === 'yes') {
          const resolve = this.pendingResolve;
          this.pendingResolve = null;
          this.state = 'IDLE';
          resolve(true);
        } else if (input === 'n' || input === 'no') {
          const resolve = this.pendingResolve;
          this.pendingResolve = null;
          this.state = 'IDLE';
          resolve(false);
        } else if (this.fallbackHandler) {
          // Only forward unrecognized input to fallback (not y/n)
          this.fallbackHandler(input);
        }
        return;
      }

      if (this.state === 'SOVGUARD_PENDING' && this.pendingSovguardResolve) {
        if (input === 'y' || input === 'yes' || input === 'retry') {
          const resolve = this.pendingSovguardResolve;
          this.pendingSovguardResolve = null;
          this.state = 'IDLE';
          resolve('approve');
        } else if (input === 'n' || input === 'no' || input === 'a' || input === 'abort') {
          const resolve = this.pendingSovguardResolve;
          this.pendingSovguardResolve = null;
          this.state = 'IDLE';
          resolve('reject');
        } else if (input === 'r' || input === 'report' || input === 'd' || input === 'disable') {
          const resolve = this.pendingSovguardResolve;
          this.pendingSovguardResolve = null;
          this.state = 'IDLE';
          resolve('report');
        }
        return;
      }

      // IDLE state — handle commands
      if (this.state === 'IDLE') {
        if (['pause', 'resume', 'accept'].includes(input) && this.commandHandler) {
          this.commandHandler(input);
        } else if (this.fallbackHandler) {
          this.fallbackHandler(input);
        }
      }
    });
  }

  onCommand(handler: (cmd: string) => void): void {
    this.commandHandler = handler;
  }

  onFallbackCommand(handler: (cmd: string) => void): void {
    this.fallbackHandler = handler;
  }

  async promptWriteApproval(
    path: string,
    proposedContent: string,
    projectDir: string,
  ): Promise<boolean> {
    // Serialize approval prompts to prevent race conditions
    return new Promise<boolean>((outerResolve) => {
      this._approvalQueue = this._approvalQueue.then(() =>
        this._doPromptWriteApproval(path, proposedContent, projectDir).then(outerResolve)
      );
    });
  }

  private async _doPromptWriteApproval(
    path: string,
    proposedContent: string,
    projectDir: string,
  ): Promise<boolean> {
    // Host-side read is contained to projectDir + size/type-capped. A malicious
    // agent path (../../etc/passwd, /dev/zero, a 2GB file) yields '' here rather
    // than reading off the host or OOMing the buyer's machine.
    const currentContent = safeReadCurrent(projectDir, path);

    // Generate diff
    const patch = structuredPatch(path, path, currentContent, proposedContent);
    const diffLines = patch.hunks.flatMap((hunk: { lines: string[] }) =>
      hunk.lines.map((line: string) => {
        if (line.startsWith('+')) return chalk.green(line);
        if (line.startsWith('-')) return chalk.red(line);
        return chalk.gray(line);
      })
    );

    const sizeKB = (Buffer.byteLength(proposedContent, 'utf-8') / 1024).toFixed(1);
    console.log('');
    console.log(chalk.yellow(`WRITE ${path} (${sizeKB}KB)`));

    // The agent can't escape the repo, but it CAN write in-repo files that run
    // on your host later (git hooks, npm scripts, Makefiles, CI, .envrc...).
    // Call those out so they get a harder look before approval.
    const sensitive = classifySensitiveWrite(path);
    if (sensitive.sensitive) {
      console.log(chalk.red(`  ⚠ EXECUTES-ON-HOST [${sensitive.category}]: ${sensitive.reason}`));
      console.log(chalk.red('    Review this write carefully — approving lets it run outside the sandbox later.'));
    }

    // Show first N lines of diff
    const preview = diffLines.slice(0, DIFF_PREVIEW_LINES);
    for (const line of preview) {
      console.log(`  ${line}`);
    }
    if (diffLines.length > DIFF_PREVIEW_LINES) {
      console.log(chalk.gray(`  ... ${diffLines.length - DIFF_PREVIEW_LINES} more lines`));
    }

    console.log(chalk.cyan('[Y]es / [N]o?'));

    // Set state and wait for approval
    this.state = 'APPROVAL_PENDING';
    return new Promise<boolean>((resolve) => {
      this.pendingResolve = resolve;
    });
  }

  async promptSovguardApproval(
    path: string,
    score: number,
    reason?: string,
  ): Promise<'approve' | 'reject' | 'report'> {
    console.log('');
    console.log(chalk.red(`⚠ SOVGUARD  ${path}  BLOCKED (score: ${score.toFixed(2)}${reason ? `, reason: ${reason}` : ''})`));
    console.log(chalk.cyan('  [Y]es allow / [N]o reject / [R]eport false positive'));

    this.state = 'SOVGUARD_PENDING';
    return new Promise<'approve' | 'reject' | 'report'>((resolve) => {
      this.pendingSovguardResolve = resolve;
    });
  }

  async promptSovguardFailure(failures: number): Promise<'approve' | 'reject' | 'report'> {
    console.log('');
    console.log(chalk.red(`SovGuard API appears down (${failures} consecutive failures).`));
    console.log(chalk.cyan('  [R]etry / [D]isable scanning / [A]bort session'));

    this.state = 'SOVGUARD_PENDING';
    return new Promise<'approve' | 'reject' | 'report'>((resolve) => {
      this.pendingSovguardResolve = (decision) => {
        resolve(decision);
      };
    });
  }

  close(): void {
    this.rl.close();
  }
}
