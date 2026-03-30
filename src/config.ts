// src/config.ts
/**
 * Config file management — ~/.j41/config
 *
 * Reads/writes SovGuard credentials in key=value format.
 * File permissions: 0600 (owner read/write only).
 */

import { readFileSync, writeFileSync, unlinkSync, existsSync, mkdirSync, chmodSync } from 'fs';
import { join, dirname } from 'path';
import chalk from 'chalk';
import type { SovGuardConfig } from './sovguard.js';

const CONFIG_DIR = join(process.env.HOME || '~', '.j41');
const CONFIG_FILE = join(CONFIG_DIR, 'config');
const DEFAULT_SOVGUARD_URL = 'https://api.sovguard.io';

interface ConfigValues {
  sovguard_api_key?: string;
  sovguard_encryption_key?: string;
  sovguard_api_url?: string;
}

export function readConfig(): ConfigValues {
  if (!existsSync(CONFIG_FILE)) return {};

  try {
    const raw = readFileSync(CONFIG_FILE, 'utf-8');
    const values: ConfigValues = {};

    for (const line of raw.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;

      const eqIndex = trimmed.indexOf('=');
      if (eqIndex === -1) continue;

      const key = trimmed.slice(0, eqIndex).trim();
      const value = trimmed.slice(eqIndex + 1).trim();
      if (!value) continue; // empty values treated as absent

      if (key === 'sovguard_api_key' || key === 'sovguard_encryption_key' || key === 'sovguard_api_url') {
        values[key] = value;
      }
    }

    return values;
  } catch {
    console.warn(chalk.yellow('⚠ ~/.j41/config is corrupt. Run \'j41-jailbox config set\' to reconfigure.'));
    return {};
  }
}

export function writeConfig(values: ConfigValues): void {
  if (!existsSync(CONFIG_DIR)) {
    mkdirSync(CONFIG_DIR, { recursive: true });
  }

  const lines = [
    '# ~/.j41/config',
    '# Created by j41-jailbox. Mode 0600.',
  ];

  if (values.sovguard_api_key) {
    lines.push(`sovguard_api_key=${values.sovguard_api_key}`);
  }
  if (values.sovguard_encryption_key) {
    lines.push(`sovguard_encryption_key=${values.sovguard_encryption_key}`);
  }
  if (values.sovguard_api_url && values.sovguard_api_url !== DEFAULT_SOVGUARD_URL) {
    lines.push(`sovguard_api_url=${values.sovguard_api_url}`);
  }

  writeFileSync(CONFIG_FILE, lines.join('\n') + '\n', { mode: 0o600 });

  try {
    chmodSync(CONFIG_FILE, 0o600);
  } catch {
    // Best effort
  }
}

export function clearConfig(): boolean {
  if (!existsSync(CONFIG_FILE)) return false;
  unlinkSync(CONFIG_FILE);
  return true;
}

/**
 * Resolve SovGuard credentials through priority chain:
 * 1. CLI flags
 * 2. Environment variables
 * 3. Config file (~/.j41/config)
 *
 * Returns undefined if no API key found from any source.
 * Does NOT prompt — caller handles the interactive fallback.
 */
export function resolveCredentials(cliFlags: {
  sovguardKey?: string;
  sovguardUrl?: string;
}): { config: SovGuardConfig | undefined; source: string; needsPrompt: boolean; cliKeyUsed: boolean } {
  // 1. CLI flags
  if (cliFlags.sovguardKey) {
    return {
      config: {
        apiKey: cliFlags.sovguardKey,
        apiUrl: cliFlags.sovguardUrl || process.env.SOVGUARD_API_URL || DEFAULT_SOVGUARD_URL,
      },
      source: 'CLI flag',
      needsPrompt: false,
      cliKeyUsed: true,
    };
  }

  // 2. Environment variables
  const envKey = process.env.SOVGUARD_API_KEY;
  if (envKey) {
    const fileConfig = readConfig();
    return {
      config: {
        apiKey: envKey,
        apiUrl: process.env.SOVGUARD_API_URL || fileConfig.sovguard_api_url || DEFAULT_SOVGUARD_URL,
      },
      source: 'env var',
      needsPrompt: false,
      cliKeyUsed: false,
    };
  }

  // 3. Config file
  const fileConfig = readConfig();
  if (fileConfig.sovguard_api_key) {
    return {
      config: {
        apiKey: fileConfig.sovguard_api_key,
        apiUrl: fileConfig.sovguard_api_url || DEFAULT_SOVGUARD_URL,
      },
      source: '~/.j41/config',
      needsPrompt: false,
      cliKeyUsed: false,
    };
  }

  // 4. Nothing found — caller must prompt
  return { config: undefined, source: '', needsPrompt: true, cliKeyUsed: false };
}

/**
 * Handle `j41-jailbox config <subcommand>` — called from index.ts pre-parse.
 */
function readSecret(prompt: string): Promise<string> {
  return new Promise((resolve) => {
    const stdin = process.stdin;
    if (!stdin.isTTY || typeof stdin.setRawMode !== 'function') {
      const { createInterface } = require('readline');
      const rl = createInterface({ input: stdin, output: process.stdout });
      rl.question(prompt, (answer: string) => { rl.close(); resolve(answer); });
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
        stdin.setEncoding('utf-8');
        stdin.pause();
        setImmediate(() => { process.stdout.write('\n'); resolve(key); });
      } else if (char === '\u0003') {
        stdin.setRawMode(wasRaw ?? false);
        process.stdout.write('\n');
        process.exit(1);
      } else if (char === '\u007f' || char === '\b') {
        key = key.slice(0, -1);
      } else {
        key += char;
      }
    };
    stdin.on('data', onData);
  });
}

export async function handleConfigCommand(args: string[]): Promise<void> {

  const sub = args[0];

  if (sub === 'set') {
    console.log('');
    const apiKey = (await readSecret('SovGuard API key: ')).trim();
    if (!apiKey) {
      console.log(chalk.yellow('No API key entered. Config not saved.'));
      return;
    }

    const encKey = (await readSecret('Encryption key (optional, press Enter to skip): ')).trim();

    // Use readline for URL (not secret)
    const { createInterface } = await import('readline');
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    const apiUrl = await new Promise<string>((resolve) =>
      rl.question(`API URL [${DEFAULT_SOVGUARD_URL}]: `, (answer) => { rl.close(); resolve(answer.trim()); })
    );

    writeConfig({
      sovguard_api_key: apiKey,
      sovguard_encryption_key: encKey || undefined,
      sovguard_api_url: apiUrl || undefined,
    });
    console.log(chalk.green('✓ Saved to ~/.j41/config'));

  } else if (sub === 'show') {
    const file = readConfig();
    const envKey = process.env.SOVGUARD_API_KEY;
    const envEncKey = process.env.SOVGUARD_ENCRYPTION_KEY;
    const envUrl = process.env.SOVGUARD_API_URL;

    // API key
    const apiKey = envKey || file.sovguard_api_key;
    if (apiKey) {
      const masked = apiKey.length > 12 ? apiKey.slice(0, 8) + '...' + apiKey.slice(-8) : '••••••••';
      const src = envKey ? 'env var' : '~/.j41/config';
      console.log(`SovGuard API key:        ${masked} ✓  (from: ${src})`);
    } else {
      console.log(`SovGuard API key:        ${chalk.yellow('not set')}`);
    }

    // Encryption key
    const encKey = envEncKey || file.sovguard_encryption_key;
    if (encKey) {
      const src = envEncKey ? 'env var' : '~/.j41/config';
      console.log(`Encryption key:          ${chalk.green('configured')} ✓  (from: ${src})`);
    } else {
      console.log(`Encryption key:          ${chalk.gray('not set')}`);
    }

    // URL
    const url = envUrl || file.sovguard_api_url || DEFAULT_SOVGUARD_URL;
    console.log(`API URL:                 ${url}`);

    // File status
    if (existsSync(CONFIG_FILE)) {
      console.log(`Config file:             ~/.j41/config (0600)`);
    } else {
      console.log(`Config file:             ${chalk.gray('not found')}`);
    }

  } else if (sub === 'clear') {
    if (clearConfig()) {
      console.log('Deleted ~/.j41/config');
    } else {
      console.log(chalk.gray('~/.j41/config does not exist.'));
    }

  } else {
    console.log('Usage: j41-jailbox config <set|show|clear>');
    console.log('');
    console.log('  set    Configure SovGuard credentials (masked input)');
    console.log('  show   Display current configuration');
    console.log('  clear  Delete ~/.j41/config');
  }
}

export { DEFAULT_SOVGUARD_URL, CONFIG_FILE };
