/**
 * CLI argument parsing and main orchestration
 */

import { Command } from 'commander';
import { existsSync, statSync } from 'fs';
import { resolve, join } from 'path';
import { homedir } from 'os';
import { execSync } from 'child_process';
import chalk from 'chalk';
import type { JailboxConfig, JailboxMode, McpCall, McpResult, ExclusionEntry, OperationMetadata } from './types.js';
import { MAX_SESSION_TRANSFER } from './types.js';
import { preScan, isExcluded } from './pre-scan.js';
import { DockerManager, getMcpServerPath } from './docker.js';
import { RelayClient } from './relay-client.js';
import { Supervisor } from './supervisor.js';
import { Feed } from './feed.js';
import { SovGuardClient, SCAN_MAX_BYTES } from './sovguard.js';
import type { SovGuardScanResult, SovGuardReport } from './sovguard.js';
import { resolveCredentials, writeConfig, DEFAULT_SOVGUARD_URL } from './config.js';
import { SessionLimiter } from './session-limiter.js';
import { AuditLog } from './audit-log.js';

import { createInterface } from 'readline';

const J41_API_URL = process.env.J41_API_URL || 'https://api.junction41.io';

async function loadSecureSetup(): Promise<any> {
  try {
    // @ts-ignore — not on npm yet; graceful fallback below
    return await import('@j41/secure-setup');
  } catch {
    try {
      // @ts-ignore — local dev path, no type declarations
      return await import('../../j41-secure-setup/lib/index.js');
    } catch {
      return null;
    }
  }
}

export function parseArgs(argv: string[]): JailboxConfig {
  const program = new Command();

  program
    .name('j41-jailbox')
    .description('Connect hired AI agents to your local project through Junction41')
    .version('0.1.0')
    .argument('<directory>', 'Project directory to share with the agent')
    .option('--uid <token>', 'Jailbox UID from dashboard')
    .option('--resume <token>', 'Reconnect with fresh reconnect token')
    .option('--read', 'Allow agent to read files (always on)', true)
    .option('--write', 'Allow agent to write files')
    .option('--supervised', 'Approve each write action (default)')
    .option('--standard', 'Agent works freely, buyer watches feed')
    .option('--readonly', 'No writes at all, even with --write')
    .option('--scope <dirs>', 'Restrict agent to specific subdirectories (comma-separated)', (val: string) => val.split(',').map(s => s.trim()))
    .option('--verbose', 'Show file sizes and details in feed')
    .option('--sovguard-key <key>', 'SovGuard API key for file scanning')
    .option('--sovguard-url <url>', 'SovGuard API URL')
    .option('--max-reads <n>', 'Max file reads per session', parseInt)
    .option('--max-writes <n>', 'Max file writes per session', parseInt)
    .option('--max-duration <hours>', 'Max session duration in hours', parseFloat)
    .parse(argv);

  const opts = program.opts();
  const dir = program.args[0];

  // Validate directory
  if (!dir) {
    console.error(chalk.red('Error: Project directory is required'));
    console.error('Usage: j41-jailbox ./my-project --uid <token> --read --write');
    process.exit(1);
  }

  const projectDir = resolve(dir);
  if (!existsSync(projectDir) || !statSync(projectDir).isDirectory()) {
    console.error(chalk.red(`Error: "${dir}" is not a valid directory`));
    process.exit(1);
  }

  // Require either --uid or --resume
  if (!opts.uid && !opts.resume) {
    console.error(chalk.red('Error: --uid <token> or --resume <token> is required'));
    console.error('Generate a jailbox token on the Junction41 dashboard.');
    process.exit(1);
  }

  // Check Docker is available
  if (!isDockerAvailable()) {
    console.error(chalk.red('Docker is required to run j41-jailbox.\n'));
    console.error('Install Docker:');
    console.error('  macOS:   brew install --cask docker');
    console.error('  Ubuntu:  sudo apt install docker.io');
    console.error('  Windows: https://docs.docker.com/desktop/install/windows/');
    console.error('  Other:   https://docs.docker.com/get-docker/');
    process.exit(1);
  }

  // Determine mode
  const mode: JailboxMode = opts.readonly ? 'readonly' : opts.standard ? 'standard' : 'supervised';

  // Readonly mode overrides --write
  const permissions = { read: true, write: opts.readonly ? false : !!opts.write };

  return {
    projectDir,
    uid: opts.uid || '',
    resumeToken: opts.resume,
    permissions,
    mode,
    verbose: !!opts.verbose,
    apiUrl: J41_API_URL,
    sovguard: undefined, // resolved in run() via resolveCredentials
    scope: opts.scope || undefined,
    sessionLimits: {
      ...(opts.maxReads ? { maxReads: opts.maxReads } : {}),
      ...(opts.maxWrites ? { maxWrites: opts.maxWrites } : {}),
      ...(opts.maxDuration ? { maxDurationMs: opts.maxDuration * 3600000 } : {}),
    },
    _cliSovguardKey: opts.sovguardKey,
    _cliSovguardUrl: opts.sovguardUrl,
  };
}

function isDockerAvailable(): boolean {
  try {
    execSync('docker info', { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

function readSecret(prompt: string): Promise<string> {
  return new Promise((resolve) => {
    const stdin = process.stdin;

    // Non-TTY (piped input, CI) — fall back to readline
    if (!stdin.isTTY || typeof stdin.setRawMode !== 'function') {
      const rl = createInterface({ input: stdin, output: process.stdout });
      rl.question(prompt, (answer) => {
        rl.close();
        resolve(answer);
      });
      return;
    }

    process.stdout.write(prompt);
    const wasRaw = stdin.isRaw;
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf-8');
    let key = '';
    const onData = (char: string) => {
      if (char === '\r' || char === '\n') {
        stdin.removeListener('data', onData);
        stdin.setRawMode(wasRaw ?? false);
        stdin.setEncoding('utf-8'); // reset to consistent state
        stdin.pause();
        // Allow event loop to settle before other readers take stdin
        setImmediate(() => {
          process.stdout.write('\n');
          resolve(key);
        });
      } else if (char === '\u0003') { // Ctrl+C
        stdin.setRawMode(wasRaw ?? false);
        process.stdout.write('\n');
        process.exit(1);
      } else if (char === '\u007f' || char === '\b') { // Backspace
        key = key.slice(0, -1);
      } else {
        key += char;
      }
    };
    stdin.on('data', onData);
  });
}

export function checkGitStatus(projectDir: string): void {
  try {
    // Check if it's a git repo
    execSync('git rev-parse --git-dir', { cwd: projectDir, stdio: 'ignore' });

    // Check for uncommitted changes
    const status = execSync('git status --porcelain', { cwd: projectDir, encoding: 'utf-8' });
    if (status.trim()) {
      console.warn(chalk.yellow('Warning: Uncommitted changes detected. Recommend committing before starting.'));
      // Non-blocking warning — user can proceed
    }
  } catch {
    console.warn(chalk.yellow('Warning: Not a git repo. Changes made by the agent cannot be easily reverted.'));
    console.warn(chalk.yellow('Consider: git init && git add -A && git commit -m "pre-jailbox snapshot"'));
  }
}

export async function run(config: JailboxConfig): Promise<void> {
  const feed = new Feed(config.verbose);
  const docker = new DockerManager();
  const relay = new RelayClient();
  const supervisor = config.mode === 'supervised' ? new Supervisor() : null;
  let exclusions: ExclusionEntry[] = [];
  let sessionTransferBytes = 0;
  let sovguardClient: SovGuardClient | null = null;
  let lastFlaggedWrite: { filePath: string; contentHash: string; score: number; mimeType: string } | null = null;
  const limiter = new SessionLimiter(config.sessionLimits);
  const auditLog = new AuditLog();

    function handleReportCommand() {
      if (!lastFlaggedWrite) {
        console.log(chalk.gray('No SovGuard-flagged writes to report.'));
        return;
      }
      if (!sovguardClient) {
        console.log(chalk.gray('SovGuard is not active.'));
        return;
      }
      sovguardClient.queueReport({
        file_path: lastFlaggedWrite.filePath,
        content_hash: lastFlaggedWrite.contentHash,
        score: lastFlaggedWrite.score,
        mime_type: lastFlaggedWrite.mimeType,
        jailbox_uid: config.uid,
        timestamp: new Date().toISOString(),
        verdict: 'false_positive',
      });
      feed.logStatus(`False positive report queued for ${lastFlaggedWrite.filePath}`);
      lastFlaggedWrite = null;
    }

  // ── Cleanup function (used by signals + normal exit) ─────────
  let cleanedUp = false;
  let stdModeRl: any = null; // readline for standard mode cleanup
  async function cleanup() {
    if (cleanedUp) return;
    cleanedUp = true;
    limiter.dispose();
    feed.printSummary();

    // Export and upload audit log
    const logExport = auditLog.exportLog();
    if (logExport.entries.length > 0) {
      feed.logStatus(`Session audit log: ${logExport.entries.length} entries, chain ${auditLog.verifyChain() ? 'valid' : 'BROKEN'}`);
      if (typeof (relay as any).sendAuditLog === 'function') {
        try { (relay as any).sendAuditLog(logExport); } catch { /* best effort */ }
      }
    }

    supervisor?.close();
    stdModeRl?.close();
    relay.disconnect();
    await docker.stop();
  }

  // ── Signal handlers ──────────────────────────────────────────
  const handleSignal = async () => {
    feed.logStatus('Shutting down...');
    relay.sendAbort();
    await cleanup();
    process.exit(0);
  };

  process.on('SIGINT', handleSignal);
  process.on('SIGTERM', handleSignal);
  process.on('SIGHUP', handleSignal);
  process.on('uncaughtException', async (err) => {
    console.error(chalk.red(`Fatal error: ${err.message}`));
    await cleanup();
    process.exit(1);
  });
  process.on('exit', () => {
    // Last-resort safety net — sync cleanup
    if (docker.isRunning()) {
      try { execSync(`docker rm -f $(docker ps -q --filter name=j41-jailbox-)`, { stdio: 'ignore' }); } catch {}
    }
  });

  try {
    // ── Task 20: First-run security setup ─────────────────────
    const initMarker = join(homedir(), '.j41', 'jailbox-security-initialized');
    if (!existsSync(initMarker)) {
      console.log('');
      console.log(chalk.cyan('  J41 Jailbox Security Setup (first run)'));
      console.log('');
      const secureSetupFirst = await loadSecureSetup();
      if (secureSetupFirst) {
        try {
          await secureSetupFirst.setup('jailbox');
          console.log(chalk.green('  Security setup complete'));
        } catch (e: any) {
          console.error(chalk.red(`  Security setup failed: ${e.message}`));
          console.error('  Run manually: yarn dlx @j41/secure-setup --jailbox');
        }
      } else {
        console.warn(chalk.yellow('  @j41/secure-setup not installed.'));
        console.warn(chalk.yellow('  Install: yarn add @j41/secure-setup'));
      }
      console.log('');
    }

    // ── Task 21: Startup security quick-check ─────────────────
    const secureSetupMod = await loadSecureSetup();
    if (secureSetupMod) {
      try {
        const checkResult = secureSetupMod.quickCheck('jailbox');
        if (!checkResult.passed) {
          console.error('');
          console.error(chalk.red('  SECURITY CHECK FAILED'));
          for (const issue of checkResult.issues) {
            console.error(chalk.red(`  - ${issue}`));
          }
          console.error('');
          console.error('  Fix: yarn dlx @j41/secure-setup --jailbox --fix');
          process.exit(1);
        }
        feed.logStatus(`Security: ${checkResult.score}/10 (${checkResult.mode})`);
      } catch (e: any) {
        feed.logStatus(`Security quick-check unavailable: ${e.message}`);
      }
    }

    // ── 1. Git check ───────────────────────────────────────────
    checkGitStatus(config.projectDir);

    // ── 1b. SovGuard credentials ─────────────────────────────
    // Resolve through priority chain: CLI flags > env vars > config file > prompt
    const resolved = resolveCredentials({
      sovguardKey: config._cliSovguardKey,
      sovguardUrl: config._cliSovguardUrl,
    });

    if (resolved.cliKeyUsed) {
      console.warn(chalk.yellow('⚠ Passing API keys via CLI flags is visible in process lists.'));
      console.warn(chalk.yellow('  Run \'j41-jailbox config set\' to store credentials securely.'));
    }

    if (resolved.config) {
      config.sovguard = resolved.config;
    } else if (resolved.needsPrompt) {
      // Interactive first-run prompt
      console.log('');
      console.log(chalk.cyan('No SovGuard configuration found.'));
      const apiKey = (await readSecret('SovGuard API key (or press Enter to skip): ')).trim();

      if (apiKey) {
        const encKey = (await readSecret('Encryption key (optional, press Enter to skip): ')).trim();

        config.sovguard = {
          apiKey,
          apiUrl: DEFAULT_SOVGUARD_URL,
          encryptionKey: encKey || undefined,
        };

        // Persist to config file
        writeConfig({
          sovguard_api_key: apiKey,
          sovguard_encryption_key: encKey || undefined,
        });
        console.log(chalk.green('✓ Saved to ~/.j41/config'));
      }
    }

    if (config.sovguard) {
      sovguardClient = new SovGuardClient(config.sovguard);
      const encLabel = sovguardClient.encrypted ? ' (E2E encrypted)' : '';
      feed.logStatus(`SovGuard file scanning enabled${encLabel} (${config.sovguard.apiUrl})`);
      // Flush queued false positive reports from previous sessions
      const flushResult = await sovguardClient.flushReports();
      if (flushResult.sent > 0) {
        feed.logStatus(`Sent ${flushResult.sent} queued SovGuard report(s)`);
      }
    } else {
      feed.logSovguardDisabledWarning();
    }

    // ── 2. Pre-scan ────────────────────────────────────────────
    const scanResult = await preScan(config.projectDir, config.sovguard);
    if (!scanResult.confirmed) {
      console.log('Aborted.');
      process.exit(0);
    }
    exclusions = scanResult.exclusions;

    // ── 3. Start Docker ────────────────────────────────────────
    feed.logStatus('Starting Docker container...');
    const mcpServerPath = getMcpServerPath();
    const { stdin: dockerStdin, stdout: dockerStdout } = await docker.start(config.projectDir, mcpServerPath, {
      writable: config.permissions.write,
      scope: config.scope,
    });
    feed.logStatus('Docker container running');

    // I3 fix: monitor container health — detect crashes
    docker.onContainerExit((exitCode) => {
      feed.logError(`Docker container exited unexpectedly (code ${exitCode})`);
      relay.sendAbort();
      cleanup().then(() => process.exit(1));
    });

    // Buffer for reading JSON-RPC responses from MCP server
    let mcpBuffer = '';
    const pendingMcpRequests = new Map<number, (result: any) => void>();
    let mcpRequestId = 0;

    dockerStdout.on('data', (chunk: Buffer) => {
      mcpBuffer += chunk.toString();
      const lines = mcpBuffer.split('\n');
      mcpBuffer = lines.pop() || '';
      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const msg = JSON.parse(line);
          if (msg.id !== undefined && pendingMcpRequests.has(msg.id)) {
            pendingMcpRequests.get(msg.id)!(msg);
            pendingMcpRequests.delete(msg.id);
          }
        } catch { /* ignore non-JSON */ }
      }
    });

    // Helper to call MCP server in Docker
    async function callMcpServer(method: string, params: any): Promise<any> {
      const id = ++mcpRequestId;
      const request = { jsonrpc: '2.0', id, method, params };
      return new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
          pendingMcpRequests.delete(id);
          reject(new Error('MCP server timeout'));
        }, 30_000);
        pendingMcpRequests.set(id, (response) => {
          clearTimeout(timeout);
          if (response.error) reject(new Error(response.error.message));
          else resolve(response.result);
        });
        dockerStdin.write(JSON.stringify(request) + '\n');
      });
    }

    // Initialize MCP server
    await callMcpServer('initialize', {
      protocolVersion: '2024-11-05',
      capabilities: {},
      clientInfo: { name: 'j41-jailbox', version: '0.1.0' },
    });

    // ── 4. Connect to relay ────────────────────────────────────
    feed.logStatus('Connecting to platform relay...');
    const auth = config.resumeToken
      ? { type: 'buyer', reconnectToken: config.resumeToken }
      : { type: 'buyer', uid: config.uid };

    await relay.connect(config.apiUrl, auth);
    feed.logStatus('Connected to relay');

    // Send pre-scan data
    relay.sendPreScanDone(scanResult.directoryHash, exclusions);

    // Register session signing key with platform (when relay supports it)
    if (typeof (relay as any).sendSessionKey === 'function') {
      try {
        (relay as any).sendSessionKey(auditLog.getPublicKey());
        feed.logStatus('Session signing key registered with platform');
      } catch {
        feed.logStatus('Warning: could not register session key');
      }
    }
    feed.logStatus('Session signing key generated (Ed25519)');

    // Auto-kill on session expiry
    limiter.startAutoKill(async () => {
      feed.logError('Session time limit reached — auto-terminating');
      relay.sendAbort();
      await cleanup();
      process.exit(0);
    });

    // ── 5. Handle relay events ─────────────────────────────────

    relay.onRelayError((error) => {
      feed.logError(`Relay error: ${error.message}`);
      cleanup().then(() => process.exit(1));
    });

    relay.onStatusChange((status, data) => {
      switch (status) {
        case 'active':
          feed.logStatus('Jailbox active');
          break;
        case 'paused':
          feed.logStatus('Jailbox paused');
          break;
        case 'aborted':
          feed.logStatus('Session aborted');
          cleanup().then(() => process.exit(0));
          break;
        case 'completed':
          feed.logStatus('Session completed');
          cleanup().then(() => process.exit(0));
          break;
        case 'agent_disconnected':
          feed.logStatus('Agent disconnected. Jailbox remains open.');
          break;
        case 'disconnected':
          if (data?.reconnecting) {
            feed.logStatus('Connection lost — reconnecting...');
          } else {
            feed.logError('Disconnected by server');
            cleanup().then(() => process.exit(1));
          }
          break;
        case 'reconnected':
          feed.logStatus('Reconnected to relay');
          break;
        case 'reconnect_failed':
          feed.logError('Failed to reconnect after 5 attempts');
          cleanup().then(() => process.exit(1));
          break;
        default:
          feed.logStatus(`Status: ${status}`);
      }
    });

    relay.onAgentCompletion(() => {
      feed.logStatus('Agent done. Type \'accept\' to confirm or \'abort\' to cancel.');
    });

    // ── 6. Handle MCP calls from agent ─────────────────────────

    relay.onMcpCallReceived(async (call: McpCall) => {
      const toolName = call.tool;
      const relPath = call.params?.path || '.';

      // I5 fix: enforce --write permission
      if (toolName === 'write_file' && !config.permissions.write) {
        const meta: OperationMetadata = {
          operation: 'write',
          path: relPath,
          sovguardScore: 0,
          blocked: true,
          blockReason: 'write permission not granted (run with --write)',
        };
        feed.logOperation(meta);
        relay.sendResult({
          id: call.id,
          success: false,
          error: 'Write permission not granted',
          metadata: meta,
        });
        return;
      }

      // Check exclusion list
      if (isExcluded(relPath, exclusions)) {
        const meta: OperationMetadata = {
          operation: toolName === 'list_directory' ? 'list_dir' : toolName as any,
          path: relPath,
          sovguardScore: 0,
          blocked: true,
          blockReason: 'excluded file',
        };
        feed.logOperation(meta);
        relay.sendResult({
          id: call.id,
          success: false,
          error: 'File is excluded from jailbox',
          metadata: meta,
        });
        return;
      }

      // Check session transfer limit
      if (sessionTransferBytes > MAX_SESSION_TRANSFER) {
        const meta: OperationMetadata = {
          operation: toolName as any,
          path: relPath,
          sovguardScore: 0,
          blocked: true,
          blockReason: 'session transfer limit exceeded (500MB)',
        };
        feed.logOperation(meta);
        relay.sendResult({
          id: call.id,
          success: false,
          error: 'Session transfer limit exceeded',
          metadata: meta,
        });
        return;
      }

      // Session operation limits
      const isRead = toolName === 'read_file' || toolName === 'list_directory';
      const isWrite = toolName === 'write_file';

      if (isRead && !limiter.canRead()) {
        const meta: OperationMetadata = { operation: toolName as any, path: relPath, sovguardScore: 0, blocked: true, blockReason: limiter.blockReason() };
        feed.logOperation(meta);
        relay.sendResult({ id: call.id, success: false, error: limiter.blockReason(), metadata: meta });
        return;
      }
      if (isWrite && !limiter.canWrite()) {
        const meta: OperationMetadata = { operation: toolName as any, path: relPath, sovguardScore: 0, blocked: true, blockReason: limiter.blockReason() };
        feed.logOperation(meta);
        relay.sendResult({ id: call.id, success: false, error: limiter.blockReason(), metadata: meta });
        return;
      }

      // For supervised writes: intercept and prompt before executing
      if (config.mode === 'supervised' && toolName === 'write_file' && supervisor) {
        const approved = await supervisor.promptWriteApproval(
          relPath,
          call.params.content,
          config.projectDir,
        );

        if (!approved) {
          const meta: OperationMetadata = {
            operation: 'write',
            path: relPath,
            sizeBytes: Buffer.byteLength(call.params.content, 'utf-8'),
            sovguardScore: 0,
            approved: false,
          };
          feed.logOperation(meta, false);
          relay.sendResult({
            id: call.id,
            success: false,
            error: 'Write rejected by buyer',
            metadata: meta,
          });
          return;
        }
      }

      let runtimeSovguardScore = 0;

      // SovGuard real-time write scanning
      if (toolName === 'write_file' && sovguardClient && !sovguardClient.isDisabled()) {
        const writeContent = Buffer.from(call.params.content, 'utf-8');

        if (writeContent.length > SCAN_MAX_BYTES) {
          const sizeKB = (writeContent.length / 1024).toFixed(1);
          feed.logSovguardUnscanned(relPath, `too large for scan (${sizeKB}KB > 100KB)`);

          if (supervisor) {
            const decision = await supervisor.promptSovguardApproval(relPath, 0, `file too large for scan (${sizeKB}KB > 100KB) — allow without scanning?`);
            if (decision === 'reject') {
              const meta: OperationMetadata = {
                operation: 'write_file',
                path: relPath,
                sizeBytes: writeContent.length,
                sovguardScore: 0,
                blocked: true,
                blockReason: 'write too large for SovGuard scan — rejected by buyer',
              };
              feed.logOperation(meta, false);
              relay.sendResult({ id: call.id, success: false, error: 'Write rejected — too large for scan', metadata: meta });
              return;
            }
          }
        } else {
          const mimeType = 'text/plain';
          const scanResult = await sovguardClient.scanContent(writeContent, mimeType);

          if (scanResult === null) {
            if (sovguardClient.consecutiveFailures >= 3) {
              if (supervisor) {
                const decision = await supervisor.promptSovguardFailure(sovguardClient.consecutiveFailures);
                if (decision === 'reject') {
                  relay.sendAbort();
                  await cleanup();
                  process.exit(1);
                } else if (decision === 'report') {
                  sovguardClient.disable();
                  feed.logStatus('SovGuard scanning disabled for this session');
                }
              } else {
                sovguardClient.disable();
                feed.logStatus('SovGuard scanning disabled for this session (API unreachable)');
              }
            } else {
              if (supervisor) {
                const decision = await supervisor.promptSovguardApproval(relPath, 0, 'SovGuard API unreachable — allow write without scanning?');
                if (decision === 'reject') {
                  const meta: OperationMetadata = {
                    operation: 'write_file',
                    path: relPath,
                    sovguardScore: 0,
                    blocked: true,
                    blockReason: 'SovGuard API unreachable — write rejected',
                  };
                  feed.logOperation(meta, false);
                  relay.sendResult({ id: call.id, success: false, error: 'SovGuard API unreachable', metadata: meta });
                  return;
                }
              }
            }
          } else if (!scanResult.safe) {
            runtimeSovguardScore = scanResult.score;
            feed.logSovguardBlock(relPath, scanResult.score, scanResult.reason);

            lastFlaggedWrite = {
              filePath: relPath,
              contentHash: sovguardClient.contentHash(writeContent),
              score: scanResult.score,
              mimeType,
            };

            let decision: 'approve' | 'reject' | 'report' = 'reject';
            if (supervisor) {
              decision = await supervisor.promptSovguardApproval(relPath, scanResult.score, scanResult.reason);
            } else {
              const meta: OperationMetadata = {
                operation: 'write_file',
                path: relPath,
                sovguardScore: scanResult.score,
                blocked: true,
                blockReason: `SovGuard blocked (score: ${scanResult.score.toFixed(2)})`,
              };
              feed.logOperation(meta, false);
              relay.sendResult({ id: call.id, success: false, error: 'Write blocked by SovGuard', metadata: meta });
              return;
            }

            if (decision === 'reject') {
              const meta: OperationMetadata = {
                operation: 'write_file',
                path: relPath,
                sovguardScore: scanResult.score,
                blocked: true,
                blockReason: 'blocked by SovGuard — rejected by buyer',
              };
              feed.logOperation(meta, false);
              relay.sendResult({ id: call.id, success: false, error: 'Write blocked by SovGuard', metadata: meta });
              return;
            }

            if (decision === 'report') {
              sovguardClient.queueReport({
                file_path: relPath,
                content_hash: sovguardClient.contentHash(writeContent),
                score: scanResult.score,
                mime_type: mimeType,
                jailbox_uid: config.uid,
                timestamp: new Date().toISOString(),
                verdict: 'false_positive',
              });
              lastFlaggedWrite = null;
              feed.logStatus(`False positive report queued for ${relPath}`);
            }
          } else {
            runtimeSovguardScore = scanResult.score;
          }
        }
      }

      if (toolName === 'write_file' && sovguardClient?.isDisabled()) {
        feed.logSovguardUnscanned(relPath, 'SovGuard disabled');
      }

      // Execute via MCP server in Docker
      try {
        const result = await callMcpServer('tools/call', {
          name: toolName,
          arguments: call.params,
        });

        const mcpMeta = result._meta || {};
        const sizeBytes = mcpMeta.sizeBytes || 0;
        sessionTransferBytes += sizeBytes;

        const meta: OperationMetadata = {
          operation: toolName as any,
          path: mcpMeta.path || relPath,
          sizeBytes,
          contentHash: mcpMeta.contentHash,
          sovguardScore: runtimeSovguardScore,
          approved: toolName === 'write_file' ? true : undefined,
          blocked: !!result.isError,
          blockReason: result.isError ? result.content?.[0]?.text : undefined,
        };

        feed.logOperation(meta, toolName === 'write_file' ? true : undefined);

        relay.sendResult({
          id: call.id,
          success: !result.isError,
          result: result.isError ? undefined : result,
          error: result.isError ? result.content?.[0]?.text : undefined,
          metadata: meta,
        });

        // Record operation in session limiter + audit log
        if (!result.isError) {
          if (isRead) limiter.recordRead();
          if (isWrite) limiter.recordWrite();
          auditLog.record(
            toolName,
            mcpMeta.path || relPath,
            sizeBytes,
            mcpMeta.contentHash || '',
          );
        }

        // Fire-and-forget SovGuard read scan
        if (toolName === 'read_file' && sovguardClient && !sovguardClient.isDisabled() && !result.isError) {
          const readContent = result.content?.[0]?.text;
          if (readContent) {
            const buf = Buffer.from(readContent, 'utf-8');
            if (buf.length <= SCAN_MAX_BYTES) {
              sovguardClient.scanContent(buf, 'text/plain').then((scanResult) => {
                if (scanResult) {
                  feed.logSovguardReadScore(mcpMeta.path || relPath, scanResult.score);
                }
              }).catch(() => { /* silently skip */ });
            }
          }
        }
      } catch (err: any) {
        const meta: OperationMetadata = {
          operation: toolName as any,
          path: relPath,
          sovguardScore: 0,
          blocked: true,
          blockReason: err.message,
        };
        feed.logOperation(meta);
        relay.sendResult({
          id: call.id,
          success: false,
          error: err.message,
          metadata: meta,
        });
      }
    });

    // ── 7. Handle interactive commands ─────────────────────────

    if (supervisor) {
      supervisor.onCommand((cmd) => {
        switch (cmd) {
          case 'pause': relay.sendPause(); feed.logStatus('Pausing...'); break;
          case 'resume': relay.sendResume(); feed.logStatus('Resuming...'); break;
          case 'accept': relay.sendAccept(); feed.logStatus('Accepting...'); break;
          case 'abort': relay.sendAbort(); feed.logStatus('Aborting...'); break;
        }
      });
      supervisor.onFallbackCommand((cmd) => {
        if (cmd === 'report') {
          handleReportCommand();
        }
      });
    } else {
      // Standard mode — simple command reader
      const { createInterface: createRL } = await import('readline');
      stdModeRl = createRL({ input: process.stdin, terminal: false });
      stdModeRl.on('line', (line: string) => {
        const cmd = line.trim().toLowerCase();
        switch (cmd) {
          case 'pause': relay.sendPause(); feed.logStatus('Pausing...'); break;
          case 'resume': relay.sendResume(); feed.logStatus('Resuming...'); break;
          case 'accept': relay.sendAccept(); feed.logStatus('Accepting...'); break;
          case 'abort': relay.sendAbort(); feed.logStatus('Aborting...'); break;
        }
        if (cmd === 'report') {
          handleReportCommand();
        }
      });
    }

    feed.logStatus('Waiting for agent to connect...');
    feed.logStatus('Commands: pause | resume | accept | abort');

    // Keep the process alive
    await new Promise(() => {}); // Never resolves — exits via signal/status handlers

  } catch (err: any) {
    feed.logError(err.message);
    await cleanup();
    process.exit(1);
  }
}
