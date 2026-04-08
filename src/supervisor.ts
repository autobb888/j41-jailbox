/**
 * Supervised mode — diff preview + Y/N approval for writes
 *
 * Manages stdin state machine to handle both interactive commands
 * (pause/resume/abort/accept) and write approval prompts (Y/N).
 */

import { createInterface, Interface } from 'readline';
import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import { structuredPatch } from 'diff';
import chalk from 'chalk';
import { DIFF_PREVIEW_LINES } from './types.js';
import type { InputState } from './types.js';

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
    const fullPath = join(projectDir, path);
    const currentContent = existsSync(fullPath)
      ? readFileSync(fullPath, 'utf-8')
      : '';

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
