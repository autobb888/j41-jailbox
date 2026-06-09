/**
 * j41-jailbox doctor — diagnose setup issues
 */

import { execSync } from 'child_process';
import chalk from 'chalk';
import { existsSync, statSync } from 'fs';
import { join } from 'path';
import { readConfig, CONFIG_FILE } from './config.js';
import { detectIsolationLayers, isHardenedImageBuilt, getHardenedImageTag } from './docker.js';

interface CheckResult {
  name: string;
  status: 'pass' | 'fail' | 'warn';
  message: string;
}

export async function runDoctor(): Promise<void> {
  console.log(chalk.cyan('\nj41-jailbox doctor\n'));

  const checks: CheckResult[] = [];

  // 1. Node.js version
  const nodeVersion = process.version;
  const major = parseInt(nodeVersion.slice(1).split('.')[0], 10);
  if (major >= 18) {
    checks.push({ name: 'Node.js', status: 'pass', message: `${nodeVersion} (>= 18 required)` });
  } else {
    checks.push({ name: 'Node.js', status: 'fail', message: `${nodeVersion} — Node 18+ required` });
  }

  // 2. Docker installed
  try {
    const dockerVersion = execSync('docker --version', { encoding: 'utf-8' }).trim();
    checks.push({ name: 'Docker CLI', status: 'pass', message: dockerVersion });
  } catch {
    checks.push({ name: 'Docker CLI', status: 'fail', message: 'not found — install Docker: https://docs.docker.com/get-docker/' });
  }

  // 3. Docker daemon running
  try {
    execSync('docker info', { stdio: 'pipe' });
    checks.push({ name: 'Docker daemon', status: 'pass', message: 'running' });
  } catch {
    checks.push({ name: 'Docker daemon', status: 'fail', message: 'not running — start Docker Desktop or `sudo systemctl start docker`' });
  }

  // 4. Not running as root
  const uid = typeof process.getuid === 'function' ? process.getuid() : undefined;
  if (uid === 0) {
    checks.push({ name: 'Run user', status: 'fail', message: 'running as root — jailbox refuses to run as root (re-run as a normal user)' });
  } else {
    checks.push({ name: 'Run user', status: 'pass', message: uid === undefined ? 'non-root' : `non-root (uid ${uid})` });
  }

  // 5. Hardened sandbox image (Wall 3 / bubblewrap) built
  if (isHardenedImageBuilt()) {
    checks.push({ name: 'Hardened image', status: 'pass', message: `${getHardenedImageTag()} built (bubblewrap bundled)` });
  } else {
    checks.push({ name: 'Hardened image', status: 'warn', message: `${getHardenedImageTag()} not built — built automatically on first run` });
  }

  // 6. Kernel-isolation layers
  try {
    const layers = detectIsolationLayers();
    if (layers.gvisor) {
      checks.push({ name: 'Kernel isolation', status: 'pass', message: 'gVisor active (kernel wall)' });
    } else if (process.platform !== 'linux') {
      checks.push({ name: 'Kernel isolation', status: 'pass', message: 'Docker Desktop VM (kernel wall)' });
    } else {
      // No gVisor on Linux: only Docker's shared-kernel boundary. bubblewrap is
      // bundled but cannot nest inside the cap-dropped container, so it does NOT
      // substitute for a kernel wall here.
      checks.push({ name: 'Kernel isolation', status: 'warn', message: 'no gVisor — Docker shared-kernel only; install gVisor for untrusted agents' });
    }
  } catch {
    checks.push({ name: 'Kernel isolation', status: 'warn', message: 'could not inspect isolation layers' });
  }

  // 5. Config file
  if (existsSync(CONFIG_FILE)) {
    const stat = statSync(CONFIG_FILE);
    const mode = (stat.mode & 0o777).toString(8);
    const config = readConfig();
    const hasKey = !!config.sovguard_api_key;
    const hasEnc = !!config.sovguard_encryption_key;

    if (mode === '600') {
      checks.push({ name: 'Config file', status: 'pass', message: `~/.j41/config (mode ${mode})` });
    } else {
      checks.push({ name: 'Config file', status: 'warn', message: `~/.j41/config (mode ${mode} — should be 600)` });
    }

    checks.push({
      name: 'SovGuard API key',
      status: hasKey ? 'pass' : 'warn',
      message: hasKey ? 'configured' : 'not set — run `j41-jailbox config set`',
    });
    checks.push({
      name: 'Encryption key',
      status: hasEnc ? 'pass' : 'warn',
      message: hasEnc ? 'configured (E2E encryption enabled)' : 'not set (optional)',
    });
  } else {
    checks.push({ name: 'Config file', status: 'warn', message: 'not found — run `j41-jailbox config set`' });
  }

  // 6. SovGuard API reachable
  const config = readConfig();
  const apiUrl = config.sovguard_api_url || 'https://api.sovguard.io';
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);
    const response = await fetch(`${apiUrl}/health`, {
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (response.ok) {
      checks.push({ name: 'SovGuard API', status: 'pass', message: `${apiUrl} reachable` });
    } else {
      checks.push({ name: 'SovGuard API', status: 'warn', message: `${apiUrl} returned ${response.status}` });
    }
  } catch {
    checks.push({ name: 'SovGuard API', status: 'warn', message: `${apiUrl} unreachable (scanning will be unavailable)` });
  }

  // 7. Platform relay reachable
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);
    const relayUrl = process.env.J41_API_URL || 'https://api.junction41.io';
    const response = await fetch(`${relayUrl}/v1/health`, {
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (response.ok) {
      checks.push({ name: 'Platform relay', status: 'pass', message: `${relayUrl} reachable` });
    } else {
      checks.push({ name: 'Platform relay', status: 'warn', message: `${relayUrl} returned ${response.status}` });
    }
  } catch {
    checks.push({ name: 'Platform relay', status: 'fail', message: 'unreachable — check your internet connection' });
  }

  // Print results
  let hasFailures = false;
  for (const check of checks) {
    const icon = check.status === 'pass' ? chalk.green('✓')
      : check.status === 'warn' ? chalk.yellow('⚠')
      : chalk.red('✗');
    const msg = check.status === 'fail' ? chalk.red(check.message)
      : check.status === 'warn' ? chalk.yellow(check.message)
      : check.message;
    console.log(`  ${icon} ${check.name.padEnd(20)} ${msg}`);
    if (check.status === 'fail') hasFailures = true;
  }

  console.log('');
  if (hasFailures) {
    console.log(chalk.red('Some checks failed. Fix the issues above before running j41-jailbox.'));
  } else {
    console.log(chalk.green('All checks passed. Ready to connect.'));
  }
}
