import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, writeFileSync, mkdirSync, symlinkSync, rmSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { safeReadCurrent } from '../src/supervisor.js';

// Regression for the host-side supervisor confused-deputy read:
// readFileSync(join(projectDir, agentPath)) had no containment / size / type
// guard, so an agent-controlled path could read arbitrary host files and OOM
// the buyer's machine via /dev/zero or a huge file. safeReadCurrent contains it.
describe('supervisor.safeReadCurrent — host-side read containment', () => {
  let root: string;

  beforeAll(() => {
    root = mkdtempSync(join(tmpdir(), 'jailbox-sup-'));
    mkdirSync(join(root, 'src'));
    writeFileSync(join(root, 'src', 'app.ts'), 'export const x = 1;\n');
    // A symlink inside the project pointing OUT of it.
    try { symlinkSync('/etc/passwd', join(root, 'escape-link')); } catch { /* unsupported */ }
  });

  afterAll(() => { rmSync(root, { recursive: true, force: true }); });

  it('reads a normal in-project file', () => {
    expect(safeReadCurrent(root, 'src/app.ts')).toContain('export const x');
  });

  it('returns empty for a non-existent in-project path (new file)', () => {
    expect(safeReadCurrent(root, 'src/new.ts')).toBe('');
  });

  it('refuses ../ traversal to a host file', () => {
    expect(safeReadCurrent(root, '../../../../etc/passwd')).toBe('');
    expect(safeReadCurrent(root, '../../../../etc/hostname')).toBe('');
  });

  it('refuses an absolute path outside the project', () => {
    expect(safeReadCurrent(root, '/etc/passwd')).toBe('');
  });

  it('refuses a symlink that escapes the project root', () => {
    if (!existsSync(join(root, 'escape-link'))) return; // symlink unsupported on this fs
    expect(safeReadCurrent(root, 'escape-link')).toBe('');
  });

  it('refuses a non-regular file (e.g. /dev/zero) — no unbounded host read', () => {
    // Even if a device node were somehow reachable in-project, isFile() blocks it.
    // Directly probing the type guard: a directory is not a regular file.
    expect(safeReadCurrent(root, 'src')).toBe('');
  });
});
