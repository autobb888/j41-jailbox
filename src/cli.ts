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
import { DockerManager, getMcpServerPath, detectIsolationLayers } from './docker.js';
import { RelayClient } from './relay-client.js';
import { Supervisor } from './supervisor.js';
import { Feed } from './feed.js';
import { SovGuardClient, SCAN_MAX_BYTES } from './sovguard.js';
import type { SovGuardScanResult, SovGuardReport } from './sovguard.js';
import { resolveCredentials, writeConfig, DEFAULT_SOVGUARD_URL } from './config.js';
import { SessionLimiter } from './session-limiter.js';
import { AuditLog } from './audit-log.js';

import { createInterface } from 'readline';

// Audit 2026-06-02 M-JAILBOX-bridge-1 / L-JAILBOX-auth-1: J41_API_URL env
// silently redirects the entire session to a different relay. Log loudly when
// it's set so the operator can verify they intended it.
const J41_API_URL = process.env.J41_API_URL || 'https://api.junction41.io';
if (process.env.J41_API_URL && process.env.J41_API_URL !== 'https://api.junction41.io') {
  console.error(`[j41-jailbox] WARN: J41_API_URL override active → ${process.env.J41_API_URL}`);
  console.error('[j41-jailbox]        If this was unintended, unset the env var and re-run.');
}

async function loadSecureSetup(): Promise<any> {
  try {
    // @ts-ignore — not on npm yet; graceful fallback below
    return await import('@junction41/secure-setup');
  } catch {
    return null;
  }
}

export function parseArgs(argv: string[]): JailboxConfig {
  const program = new Command();

  program
    .name('j41-jailbox')
    .description('Connect hired AI agents to your local project through Junction41')
    .version('2.0.0')
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
    .option('--strict', 'Abort if any expected isolation layer (gVisor/AppArmor/seccomp/bwrap) is missing')
    .option('--insecure', 'Allow running WITHOUT a kernel-isolation wall (no gVisor on Linux). Default refuses. NOT for untrusted agents.')
    .option('--no-sovguard', 'Disable SovGuard content scanning (must be explicit — writes are otherwise blocked)')
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
  if (opts.readonly && opts.write) {
    console.warn(chalk.yellow('Warning: --readonly overrides --write. No writes will be allowed.'));
  }
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
    strict: !!opts.strict,
    insecure: !!opts.insecure,
    noSovguard: opts.sovguard === false, // commander sets `sovguard: false` for --no-sovguard
  };
}

/**
 * Refuse to run the dispatcher as root. Running as root means (a) a sandbox
 * escape would land with full host privileges instead of an unprivileged
 * account, and (b) the container would be launched as root (uid 0 maps to
 * `User: 0:0`), defeating the never-root-container guarantee. Files written by
 * the agent would also be root-owned on the host. `getuid` is undefined on
 * Windows — there is no root concept there, so we no-op.
 */
export function assertNotRoot(
  getuid: (() => number) | undefined = (process.getuid ? process.getuid.bind(process) : undefined),
): void {
  if (typeof getuid === 'function' && getuid() === 0) {
    console.error(chalk.red('\n✗ Refusing to run j41-jailbox as root.'));
    console.error('  A sandbox escape from root would have full host privileges, and the');
    console.error('  container would be launched as root. Re-run as a normal (non-root) user.');
    console.error('  If you used sudo, drop it. If you need Docker access, add your user to');
    console.error('  the `docker` group: sudo usermod -aG docker "$USER" && newgrp docker\n');
    process.exit(1);
  }
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
  // Hard gate: never run the dispatcher (or therefore the container) as root.
  assertNotRoot();

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
  let signalCount = 0;
  const handleSignal = async () => {
    signalCount++;
    if (signalCount >= 2) {
      // Force exit — cleanup is stuck
      console.error(chalk.red('\nForce exiting...'));
      // Audit 2026-06-02 L-JAILBOX-ddos-2: scope mass-kill to THIS session's
// container only, not every j41-jailbox-* on the host. A buyer running
// two concurrent jailboxes (one per project, allowed) was previously
// killing the other on Ctrl+C.
try { if (docker.containerName) execSync(`docker rm -f ${docker.containerName}`, { stdio: 'ignore' }); } catch {}
      process.exit(1);
    }
    feed.logStatus('Shutting down... (Ctrl+C again to force)');
    relay.sendAbort();
    // Timeout cleanup to prevent hanging on Docker
    const cleanupTimeout = setTimeout(() => {
      console.error(chalk.red('Cleanup timed out — force exiting'));
      // Audit 2026-06-02 L-JAILBOX-ddos-2: scope mass-kill to THIS session's
// container only, not every j41-jailbox-* on the host. A buyer running
// two concurrent jailboxes (one per project, allowed) was previously
// killing the other on Ctrl+C.
try { if (docker.containerName) execSync(`docker rm -f ${docker.containerName}`, { stdio: 'ignore' }); } catch {}
      process.exit(1);
    }, 10_000);
    await cleanup();
    clearTimeout(cleanupTimeout);
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
      // Audit 2026-06-02 L-JAILBOX-ddos-2: scope mass-kill to THIS session's
// container only, not every j41-jailbox-* on the host. A buyer running
// two concurrent jailboxes (one per project, allowed) was previously
// killing the other on Ctrl+C.
try { if (docker.containerName) execSync(`docker rm -f ${docker.containerName}`, { stdio: 'ignore' }); } catch {}
    }
  });

  try {
    // ── Task 20: First-run security setup ─────────────────────
    // Audit 2026-06-02 H-JAILBOX-3: secure-setup runs `sudo apt-get install`,
    // `sudo iptables`, `sudo apparmor_parser`, `sudo mv ... /etc/...`. Running
    // this AUTOMATICALLY on first jailbox launch was the H finding: any
    // future compromise of secure-setup on npm would silently get root on
    // every fresh buyer install. Now require explicit consent via
    // J41_JAILBOX_AUTO_SECURE_SETUP=1 OR `--auto-setup` flag (set in the
    // commander program above). Default behavior is to PRINT the manual
    // command and exit — operator runs `npx @junction41/secure-setup
    // --jailbox` themselves with full awareness of what's about to happen.
    const initMarker = join(homedir(), '.j41', 'jailbox-security-initialized');
    if (!existsSync(initMarker)) {
      console.log('');
      console.log(chalk.cyan('  J41 Jailbox Security Setup (first run)'));
      console.log('');
      const autoSetup = process.env.J41_JAILBOX_AUTO_SECURE_SETUP === '1';
      if (!autoSetup) {
        console.error(chalk.yellow(
          '  secure-setup will perform sudo apt-get install, sudo iptables, sudo apparmor_parser, ' +
          'sudo mv into /etc/, etc. It is NOT auto-run by default per audit 2026-06-02 H-JAILBOX-3.',
        ));
        console.error('  Run manually:  npx @junction41/secure-setup --jailbox');
        console.error('  Or opt in to auto-run:  J41_JAILBOX_AUTO_SECURE_SETUP=1 j41-jailbox ...');
        process.exit(1);
      }
      const secureSetupFirst = await loadSecureSetup();
      if (secureSetupFirst) {
        try {
          await secureSetupFirst.setup('jailbox');
          console.log(chalk.green('  Security setup complete'));
        } catch (e: any) {
          console.error(chalk.red(`  Security setup failed: ${e.message}`));
          console.error('  Run manually: npx @junction41/secure-setup --jailbox');
        }
      } else {
        console.warn(chalk.yellow('  @junction41/secure-setup not installed.'));
        console.warn(chalk.yellow('  Install: npm install @junction41/secure-setup'));
      }
      console.log('');
    }

    // ── Task 21: Startup security quick-check ─────────────────
    const secureSetupMod = await loadSecureSetup();
    if (secureSetupMod) {
      try {
        const checkResult = await secureSetupMod.quickCheck('jailbox');
        if (!checkResult.passed) {
          console.error('');
          console.error(chalk.red('  SECURITY CHECK FAILED'));
          for (const c of checkResult.checks.filter((c: any) => c.status === 'fail')) {
            console.error(chalk.red(`  - ${c.name}: ${c.detail}`));
          }
          console.error('');
          console.error('  Fix: npx @junction41/secure-setup --jailbox --fix');
          process.exit(1);
        }
        feed.logStatus(`Security: ${checkResult.score}/10 (${checkResult.mode})`);
      } catch (e: any) {
        feed.logStatus(`Security quick-check unavailable: ${e.message}`);
      }
    }

    // ── 1. Git check ───────────────────────────────────────────
    checkGitStatus(config.projectDir);

    // ── 1a. Provision the hardened sandbox image (Wall 3 / bubblewrap) ──
    // Build it up front (idempotent) so the isolation banner below reflects
    // reality on first run rather than reporting bubblewrap as missing.
    feed.logStatus('Provisioning hardened sandbox image (one-time build on first run)...');
    await docker.ensureHardenedImage();

    // ── 1c. Isolation status (honest) ─────────────────────────
    // Report what ACTUALLY protects this session so the buyer is never given a
    // false sense of a fuller sandbox than is active. Inside Docker the kernel
    // wall is gVisor (Linux) or the Docker-Desktop VM (macOS); bubblewrap is
    // bundled in our image but only engages on a no-Docker/VPS deployment — it
    // cannot nest inside this cap-dropped container, so it is NOT counted as an
    // in-Docker wall here.
    const layers = detectIsolationLayers();
    const onLinux = process.platform === 'linux';
    const kernelWall = layers.gvisor || !onLinux; // gVisor, or Docker-Desktop VM off-Linux
    console.log('');
    console.log(chalk.cyan('  Sandbox status:'));
    console.log('    Always-on Docker hardening: cap-drop ALL, network=none, read-only rootfs,');
    console.log('    non-root user, private cgroup ns, masked /proc paths, pids/mem limits.');
    console.log(`    Kernel wall (gVisor):       ${layers.gvisor ? chalk.green('active') : (onLinux ? chalk.yellow('NOT active') : chalk.green('Docker-Desktop VM'))}`);
    console.log(`    AppArmor profile:           ${layers.apparmor ? chalk.green('active') : chalk.yellow('not loaded')}`);
    console.log(`    seccomp profile:            ${layers.seccomp ? chalk.green('custom (j41)') : chalk.gray('Docker default')}`);
    // bwrap nests only when the custom seccomp profile permits unprivileged
    // userns (Docker's default profile blocks it); otherwise it cleanly falls
    // back to the gVisor/Docker wall. Per-session truth is logged by the
    // entrypoint to the container feed.
    const bwrapEngages = layers.bwrap && layers.seccomp;
    console.log(`    bubblewrap (Wall 3):        ${bwrapEngages ? chalk.green('engages (nested re-sandbox)') : chalk.gray('bundled; needs j41 seccomp to nest — falls back to gVisor/Docker')}`);
    console.log('');

    // ── Kernel-wall gate ──────────────────────────────────────
    // --strict is the strictest: refuse on ANY missing layer (and it wins over
    // --insecure if both are passed). Otherwise the DEFAULT is to refuse when no
    // kernel-isolation wall is active (Linux without gVisor); --insecure is the
    // explicit, documented override for that one case.
    if (config.strict && (!kernelWall || !layers.apparmor || !layers.seccomp)) {
      console.error(chalk.red('✗ --strict: refusing to start without a full isolation stack'));
      console.error(chalk.red(`  (kernel wall: ${kernelWall ? 'ok' : 'MISSING'}, AppArmor: ${layers.apparmor ? 'ok' : 'MISSING'}, seccomp: ${layers.seccomp ? 'ok' : 'default'}).`));
      if (config.insecure) console.error(chalk.red('  (--insecure is ignored when --strict is set.)'));
      process.exit(1);
    }

    if (!kernelWall) {
      // Linux host with no gVisor runtime registered.
      if (!config.insecure) {
        console.error(chalk.red('✗ Refusing to start: no kernel-isolation wall is active.'));
        console.error(chalk.red('  Only Docker\'s shared-kernel boundary protects this session — not'));
        console.error(chalk.red('  escape-proof against a kernel exploit, and unsafe for an untrusted agent.'));
        console.error('');
        console.error('  Fix (recommended):  npx @junction41/secure-setup --jailbox   # installs gVisor');
        console.error('  Override (only for code you trust):  re-run with --insecure');
        console.error('');
        process.exit(1);
      }
      console.log(chalk.red('  ⚠ --insecure: running WITHOUT a kernel wall (Docker shared kernel only).'));
      console.log(chalk.red('    Do NOT use this for an untrusted agent. Install gVisor for real isolation:'));
      console.log(chalk.red('    npx @junction41/secure-setup --jailbox'));
      console.log('');
    }

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
    } else if (resolved.needsPrompt && !config.noSovguard) {
      // Interactive first-run prompt — pressing Enter skips, but writes will be
      // blocked unless the session is re-run with --no-sovguard.
      console.log('');
      console.log(chalk.cyan('No SovGuard configuration found.'));
      console.log(chalk.gray('Without SovGuard, agent writes are blocked. Pass --no-sovguard to override.'));
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
    } else if (config.noSovguard) {
      // Buyer made an explicit, informed choice to disable scanning.
      console.log('');
      console.log(chalk.red('⚠ SovGuard scanning DISABLED via --no-sovguard.'));
      console.log(chalk.red('  Agent writes will NOT be scanned for malicious content.'));
      console.log('');
    } else if (config.permissions.write) {
      // Writes are enabled but SovGuard is not configured and the buyer did not
      // explicitly opt out — refuse to start. Closes the silent-skip loophole
      // where a write session could otherwise run with no content scanning.
      console.error('');
      console.error(chalk.red('✗ Refusing to start: writes are enabled but SovGuard is not configured.'));
      console.error(chalk.red('  Choose one:'));
      console.error(chalk.red('    1. Configure SovGuard:  j41-jailbox config set'));
      console.error(chalk.red('    2. Disable scanning:    re-run with --no-sovguard (writes will not be scanned)'));
      console.error(chalk.red('    3. Read-only session:   re-run with --readonly'));
      console.error('');
      process.exit(1);
    } else {
      // Read-only session: no writes are possible, so scanning is moot.
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
    // Audit 2026-06-02 L-JAILBOX-ddos-3: cap the per-chunk stdout buffer so
    // a misbehaving container that writes a 100 GB line without ever sending
    // a newline cannot OOM the buyer's machine. 16 MB is loose; tighten via
    // J41_JAILBOX_MCP_BUFFER_BYTES.
    const MAX_MCP_BUFFER_BYTES = Number(process.env.J41_JAILBOX_MCP_BUFFER_BYTES ?? 16 * 1024 * 1024);

    dockerStdout.on('data', (chunk: Buffer) => {
      mcpBuffer += chunk.toString();
      if (mcpBuffer.length > MAX_MCP_BUFFER_BYTES) {
        console.error(`[j41-jailbox] MCP stdout buffer exceeded ${MAX_MCP_BUFFER_BYTES} bytes — dropping pending data and aborting`);
        mcpBuffer = '';
        cleanup().then(() => process.exit(1));
        return;
      }
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
      clientInfo: { name: 'j41-jailbox', version: '2.0.0' },
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

    relay.onSessionEnd((data) => {
      const reason = data?.reason || 'job ended';
      feed.logStatus(`Session ended by platform: ${reason}`);
      cleanup().then(() => process.exit(0));
    });

    // ── 6. Handle MCP calls from agent ─────────────────────────

    relay.onMcpCallReceived(async (call: McpCall) => {
      const toolName = call.tool;
      const relPath = call.params?.path || '.';

      // Centralized block helper — logs to audit trail and sends failure to relay
      function blockOperation(reason: string, error: string, extraMeta?: Partial<OperationMetadata>) {
        const meta: OperationMetadata = {
          operation: toolName as any,
          path: relPath,
          sovguardScore: 0,
          blocked: true,
          blockReason: reason,
          ...extraMeta,
        };
        feed.logOperation(meta, false);
        auditLog.record(`${toolName}_blocked`, relPath, 0, '');
        relay.sendResult({ id: call.id, success: false, error, metadata: meta });
      }

      // I5 fix: enforce --write permission
      if (toolName === 'write_file' && !config.permissions.write) {
        blockOperation('write permission not granted (run with --write)', 'Write permission not granted');
        return;
      }

      // Check scope restriction
      if (config.scope && config.scope.length > 0) {
        const inScope = config.scope.some(dir => relPath === dir || relPath.startsWith(dir + '/'));
        if (!inScope) {
          blockOperation(`path outside allowed scope (${config.scope.join(', ')})`, `Path outside scope: ${relPath}`);
          return;
        }
      }

      // Check exclusion list
      if (isExcluded(relPath, exclusions)) {
        blockOperation('excluded file', 'File is excluded from jailbox');
        return;
      }

      // Check session transfer limit
      if (sessionTransferBytes > MAX_SESSION_TRANSFER) {
        blockOperation('session transfer limit exceeded (500MB)', 'Session transfer limit exceeded');
        return;
      }

      // Session operation limits
      const isRead = toolName === 'read_file' || toolName === 'list_directory';
      const isWrite = toolName === 'write_file';

      if (isRead && !limiter.canRead()) {
        blockOperation(limiter.blockReason(), limiter.blockReason());
        return;
      }
      if (isWrite && !limiter.canWrite()) {
        blockOperation(limiter.blockReason(), limiter.blockReason());
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
          } else {
            // Standard mode: block oversized writes — cannot scan, fail secure
            const meta: OperationMetadata = {
              operation: 'write_file',
              path: relPath,
              sizeBytes: writeContent.length,
              sovguardScore: 0,
              blocked: true,
              blockReason: `write too large for SovGuard scan (${sizeKB}KB) — blocked`,
            };
            feed.logOperation(meta, false);
            feed.logError(`Write blocked: ${relPath} — too large for scan (${sizeKB}KB)`);
            relay.sendResult({ id: call.id, success: false, error: 'Write blocked — too large for SovGuard scan', metadata: meta });
            return;
          }
        } else {
          const mimeType = 'text/plain';
          const scanResult = await sovguardClient.scanContent(writeContent, mimeType, { path: relPath, source: 'other_agent' });

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
                // In standard mode (no supervisor), do NOT auto-disable SovGuard.
                // Block the write instead — agent can retry later.
                feed.logStatus('SovGuard API unreachable — write blocked for safety');
                const blockedMeta: OperationMetadata = { operation: toolName as any, path: relPath, sovguardScore: 0, blocked: true, blockReason: 'SovGuard API unreachable' };
                feed.logOperation(blockedMeta);
                relay.sendResult({
                  id: call.id,
                  success: false,
                  error: 'Write blocked: SovGuard scanning unavailable. Please retry later.',
                  metadata: blockedMeta,
                });
                return;
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
              } else {
                // Standard mode: block unscanned writes by default — fail secure
                const meta: OperationMetadata = {
                  operation: 'write_file',
                  path: relPath,
                  sovguardScore: 0,
                  blocked: true,
                  blockReason: 'SovGuard API unreachable — write blocked (fail-secure)',
                };
                feed.logOperation(meta, false);
                feed.logError(`Write blocked: ${relPath} — SovGuard API unreachable`);
                relay.sendResult({ id: call.id, success: false, error: 'SovGuard API unreachable — write blocked', metadata: meta });
                return;
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
            // safe === true. Surface a non-blocking code-exec warning (allowed).
            if (scanResult.action === 'warn') {
              feed.logSovguardWarn(relPath, scanResult.reason);
            }
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
          approved: toolName === 'write_file' ? (config.mode === 'supervised') : undefined,
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
        }
        // Always record in audit log — both successful and failed operations
        auditLog.record(
          result.isError ? `${toolName}_blocked` : toolName,
          mcpMeta.path || relPath,
          sizeBytes,
          mcpMeta.contentHash || '',
        );

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
        blockOperation(err.message, err.message);
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
