/**
 * Pre-scan — SovGuard directory scan before agent connects
 *
 * Walks the project directory, auto-excludes sensitive files,
 * scans remaining files with SovGuard API, and presents the exclusion
 * list to the buyer for confirmation.
 */

import { readdirSync, readFileSync, statSync, realpathSync } from 'fs';
import { join, relative, extname } from 'path';
import { createHash } from 'crypto';
import chalk from 'chalk';
import { AUTO_EXCLUDE_PATTERNS } from './types.js';
import type { ExclusionEntry } from './types.js';
import { SovGuardClient, SovGuardAuthError, SCAN_MAX_BYTES } from './sovguard.js';
import type { SovGuardConfig } from './sovguard.js';

// File extensions worth scanning via cloud API (text/structured content)
const SCANNABLE_EXTENSIONS = new Set([
  '.txt', '.md', '.json', '.yaml', '.yml', '.toml', '.ini', '.cfg',
  '.csv', '.tsv', '.xml', '.html', '.htm', '.js', '.ts', '.jsx', '.tsx',
  '.py', '.rb', '.sh', '.bash', '.zsh', '.sql', '.go', '.rs', '.java',
  '.conf', '.properties', '.log',
]);

const MIME_MAP: Record<string, string> = {
  '.json': 'application/json', '.yaml': 'text/yaml', '.yml': 'text/yaml',
  '.xml': 'application/xml', '.html': 'text/html', '.htm': 'text/html',
  '.csv': 'text/csv', '.md': 'text/markdown',
};


export async function preScan(projectDir: string, sovguard?: SovGuardConfig): Promise<{
  exclusions: ExclusionEntry[];
  directoryHash: string;
  confirmed: boolean;
}> {
  console.log(chalk.cyan('\nPre-scanning directory...\n'));

  const exclusions: ExclusionEntry[] = [];
  const allFiles: string[] = [];

  // Walk directory (skip auto-excluded dirs)
  walkDir(projectDir, projectDir, allFiles, exclusions);

  // Scan remaining files via SovGuard cloud API
  if (sovguard) {
    const client = new SovGuardClient(sovguard);
    let scanned = 0;
    const scannable = allFiles.filter((f) => {
      const ext = extname(f).toLowerCase();
      return SCANNABLE_EXTENSIONS.has(ext) && statSync(f).size <= SCAN_MAX_BYTES;
    });
    const total = scannable.length;

    for (const filePath of scannable) {
      try {
        const relPath = relative(projectDir, filePath);
        const ext = extname(filePath).toLowerCase();
        const content = readFileSync(filePath);
        const mimeType = MIME_MAP[ext] || 'text/plain';
        const result = await client.scanContent(content, mimeType);
        scanned++;

        // Progress indicator (overwrite line)
        if (process.stdout.isTTY) {
          process.stdout.write(`\r  Scanning ${scanned}/${total} files...`);
        }

        if (result && !result.safe) {
          const reason = result.reason || result.category || `SovGuard flagged as unsafe (score: ${result.score.toFixed(2)})`;
          exclusions.push({ path: relPath, reason, matches: result.matches });
        }
      } catch (err) {
        if (err instanceof SovGuardAuthError) {
          if (process.stdout.isTTY) process.stdout.write('\r' + ' '.repeat(40) + '\r');
          console.warn(chalk.yellow('  SovGuard: invalid API key — skipping scan'));
          break;
        }
        scanned++;
        // Can't read/scan file — skip
      }
    }
    if (scanned > 0) {
      if (process.stdout.isTTY) process.stdout.write('\r' + ' '.repeat(40) + '\r');
      console.log(chalk.gray(`  Scanned ${scanned} files via SovGuard cloud\n`));
    }
  }

  // Generate directory hash (file listing + sizes)
  const hashInput = allFiles.map((f) => {
    const rel = relative(projectDir, f);
    const size = statSync(f).size;
    return `${rel}:${size}`;
  }).sort().join('\n');
  const directoryHash = createHash('sha256').update(hashInput).digest('hex');

  // Present to buyer
  if (exclusions.length > 0) {
    console.log(chalk.yellow(`Excluded (${exclusions.length} items):`));
    for (const ex of exclusions) {
      console.log(`  ${clipPath(ex.path, 40).padEnd(40)} — ${chalk.gray(ex.reason)}`);
    }
  } else {
    console.log(chalk.green('No files excluded.'));
  }

  console.log('');
  const answer = exclusions.length > 0
    ? await promptChoice('Proceed? [Y/Enter] yes / [A] abort / [E] edit exclusions')
    : await promptChoice('Proceed? [Y/Enter] yes / [A] abort');

  if (answer === 'e' && exclusions.length > 0) {
    const kept = await interactiveExclusions(exclusions);
    // Replace exclusions array in-place
    exclusions.length = 0;
    exclusions.push(...kept);
    console.log(chalk.green(`\n  ${kept.length} exclusion(s) after editing.\n`));
    const confirmed = await promptConfirm('Proceed? [Y/Enter] yes / [A] abort');
    return { exclusions, directoryHash, confirmed };
  }

  return { exclusions, directoryHash, confirmed: answer === 'y' };
}

function walkDir(
  rootDir: string,
  currentDir: string,
  files: string[],
  exclusions: ExclusionEntry[],
): void {
  let entries;
  try {
    entries = readdirSync(currentDir, { withFileTypes: true });
  } catch {
    return; // Can't read directory — skip
  }

  for (const entry of entries) {
    const fullPath = join(currentDir, entry.name);
    const relPath = relative(rootDir, fullPath);

    // Symlink traversal protection: detect symlinks pointing outside project root
    if (entry.isSymbolicLink()) {
      try {
        const realTarget = realpathSync(fullPath);
        if (!realTarget.startsWith(rootDir + '/') && realTarget !== rootDir) {
          exclusions.push({
            path: relPath + (entry.isDirectory() ? '/' : ''),
            reason: `symlink points outside project root (-> ${realTarget})`,
          });
          continue;
        }
      } catch {
        // Broken symlink — exclude
        exclusions.push({
          path: relPath,
          reason: 'broken symlink (target does not exist)',
        });
        continue;
      }
    }

    // Check auto-exclude patterns
    if (shouldExclude(relPath, entry.isDirectory())) {
      const reason = getExcludeReason(relPath, entry.isDirectory());
      exclusions.push({ path: relPath + (entry.isDirectory() ? '/' : ''), reason });
      continue;
    }

    if (entry.isDirectory()) {
      walkDir(rootDir, fullPath, files, exclusions);
    } else if (entry.isFile()) {
      files.push(fullPath);
    }
  }
}

function shouldExclude(relPath: string, isDir: boolean): boolean {
  const name = relPath.split('/').pop() || '';

  for (const pattern of AUTO_EXCLUDE_PATTERNS) {
    // Directory patterns (ending with /)
    if (pattern.endsWith('/') && isDir && name === pattern.slice(0, -1)) return true;
    // Glob patterns (*.ext)
    if (pattern.startsWith('*.') && name.endsWith(pattern.slice(1))) return true;
    // Exact match
    if (name === pattern) return true;
    // Wildcard match (e.g., .env.*)
    if (pattern.endsWith('*') && name.startsWith(pattern.slice(0, -1))) return true;
  }

  return false;
}

function clipPath(p: string, max: number): string {
  if (p.length <= max) return p;
  return '…' + p.slice(p.length - max + 1);
}

function getExcludeReason(relPath: string, isDir: boolean): string {
  const name = relPath.split('/').pop() || '';
  if (name.startsWith('.env')) return 'environment variables';
  if (name === '.ssh' || name === '.gnupg') return 'cryptographic keys';
  if (name.endsWith('.pem') || name.endsWith('.key') || name.endsWith('.p12')) return 'certificates/keys';
  if (name === 'credentials.json' || name.startsWith('secrets')) return 'credentials';
  if (name === 'node_modules') return 'too large';
  if (name === '.git') return 'version control';
  if (name === '.DS_Store' || name === 'Thumbs.db') return 'OS metadata';
  return 'auto-excluded';
}

async function promptRawKey(message: string): Promise<string> {
  process.stdout.write(`${message} `);
  return new Promise((resolve) => {
    const stdin = process.stdin;
    const wasRaw = stdin.isRaw;
    if (stdin.isTTY) stdin.setRawMode(true);
    stdin.resume();

    function onData(key: Buffer) {
      const s = key.toString();
      stdin.removeListener('data', onData);
      if (stdin.isTTY && wasRaw !== undefined) stdin.setRawMode(wasRaw);
      stdin.pause();

      if (s === '\x03') { process.stdout.write('\n'); process.exit(0); }

      const ch = s.trim().toLowerCase();
      process.stdout.write(ch + '\n');
      resolve(ch);
    }

    stdin.on('data', onData);
  });
}

async function promptConfirm(message: string): Promise<boolean> {
  while (true) {
    const ch = await promptRawKey(message);
    if (ch === 'y' || ch === '') return true;
    if (ch === 'a' || ch === 'n') return false;
    process.stdout.write(chalk.gray('  Press Y/Enter to confirm or A to abort\n'));
  }
}

async function promptChoice(message: string): Promise<string> {
  while (true) {
    const ch = await promptRawKey(message);
    if (ch === 'y' || ch === '') return 'y';
    if (ch === 'a') return 'a';
    if (ch === 'e') return 'e';
    process.stdout.write(chalk.gray('  Press Y/Enter, A to abort, or E to edit\n'));
  }
}

async function interactiveExclusions(exclusions: ExclusionEntry[]): Promise<ExclusionEntry[]> {
  const selected = new Array(exclusions.length).fill(true); // all excluded by default
  const expanded = new Array(exclusions.length).fill(false);
  let cursor = 0;
  let linesWritten = 0;

  return new Promise((resolve) => {
    const stdin = process.stdin;
    const wasRaw = stdin.isRaw;

    function writeLn(text: string) {
      process.stdout.write(text + '\n');
      linesWritten++;
    }

    function render() {
      const cols = process.stdout.columns || 80;
      // Move cursor up to overwrite previous render
      if (linesWritten > 0) {
        process.stdout.write(`\x1b[${linesWritten}A\x1b[J`);
      }
      linesWritten = 0;
      writeLn(chalk.cyan('  SPACE toggle | \u2190\u2192 details | ENTER confirm | ESC cancel'));
      writeLn('');
      // Dynamic column widths based on terminal size
      const pathMax = Math.max(20, Math.min(40, Math.floor(cols * 0.35)));
      const reasonMax = Math.max(15, Math.min(35, Math.floor(cols * 0.3)));
      for (let i = 0; i < exclusions.length; i++) {
        const marker = selected[i] ? chalk.red('[x]') : chalk.green('[ ]');
        const arrow = i === cursor ? chalk.white('> ') : '  ';
        const clipped = clipPath(exclusions[i].path, pathMax);
        const reasonText = exclusions[i].reason.length > reasonMax
          ? exclusions[i].reason.slice(0, reasonMax - 1) + '\u2026' : exclusions[i].reason;
        const reason = chalk.gray(`\u2014 ${reasonText}`);
        const hasMatches = exclusions[i].matches && exclusions[i].matches!.length > 0;
        const expandIcon = hasMatches ? (expanded[i] ? chalk.gray(' \u25BC') : chalk.gray(' \u25B6')) : '';
        writeLn(`${arrow}${marker} ${clipped.padEnd(pathMax)} ${reason}${expandIcon}`);
        if (expanded[i] && exclusions[i].matches?.length) {
          const matchTextMax = Math.max(20, cols - 25);
          for (const m of exclusions[i].matches!) {
            const lineNum = chalk.yellow(`L${m.line}`);
            const mText = m.text.length > matchTextMax
              ? m.text.slice(0, matchTextMax - 3) + '...' : m.text;
            const flag = chalk.red(`[${m.flag}]`);
            writeLn(`       ${lineNum}: ${chalk.white(mText)}  ${flag}`);
          }
        }
      }
    }

    // Reserve space then render into it
    const initialLines = 2 + exclusions.length;
    for (let i = 0; i < initialLines; i++) process.stdout.write('\n');
    linesWritten = initialLines;
    render();

    if (stdin.isTTY) stdin.setRawMode(true);
    stdin.resume();

    function onData(key: Buffer) {
      const s = key.toString();

      if (s === '\x03') {
        // Ctrl+C — clean exit
        cleanup();
        process.stdout.write('\n');
        process.exit(0);
      }

      if (s === '\x1b' || s === 'q') {
        // ESC or q — cancel, keep original
        cleanup();
        resolve(exclusions);
        return;
      }

      if (s === '\r' || s === '\n') {
        // ENTER — confirm
        cleanup();
        resolve(exclusions.filter((_, i) => selected[i]));
        return;
      }

      if (s === ' ') {
        // SPACE — toggle
        selected[cursor] = !selected[cursor];
        render();
        return;
      }

      // Arrow keys
      if (s === '\x1b[A' || s === 'k') {
        // UP
        cursor = Math.max(0, cursor - 1);
        render();
      } else if (s === '\x1b[B' || s === 'j') {
        // DOWN
        cursor = Math.min(exclusions.length - 1, cursor + 1);
        render();
      } else if (s === '\x1b[C' || s === 'l') {
        // RIGHT — expand
        if (exclusions[cursor].matches?.length) {
          expanded[cursor] = true;
          render();
        }
      } else if (s === '\x1b[D' || s === 'h') {
        // LEFT — collapse
        expanded[cursor] = false;
        render();
      }
    }

    function cleanup() {
      stdin.removeListener('data', onData);
      if (stdin.isTTY && wasRaw !== undefined) stdin.setRawMode(wasRaw);
      stdin.pause();
    }

    stdin.on('data', onData);
  });
}

export function isExcluded(relPath: string, exclusions: ExclusionEntry[]): boolean {
  return exclusions.some((ex) => {
    const exPath = ex.path.replace(/\/$/, '');
    return relPath === exPath || relPath.startsWith(exPath + '/');
  });
}
