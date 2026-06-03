import { describe, it, expect, afterEach, beforeEach } from 'vitest';
import { mkdirSync, writeFileSync, symlinkSync, rmSync } from 'fs';
import { join } from 'path';
import { walkDir } from '../src/pre-scan.js';
import type { ExclusionEntry } from '../src/types.js';

// Use the test file's URL parent as anchor (works under pnpm/yarn workspace tooling).
const TEST_DIR = join(new URL('.', import.meta.url).pathname, '__test-symlink__');

describe('symlink traversal protection', () => {
  beforeEach(() => {
    rmSync(TEST_DIR, { recursive: true, force: true });
    mkdirSync(join(TEST_DIR, 'src'), { recursive: true });
  });

  afterEach(() => {
    rmSync(TEST_DIR, { recursive: true, force: true });
  });

  it('excludes symlinks pointing outside project root', () => {
    writeFileSync(join(TEST_DIR, 'src', 'app.ts'), 'export {}');
    symlinkSync('/etc/passwd', join(TEST_DIR, 'src', 'escape-link'));

    const files: string[] = [];
    const exclusions: ExclusionEntry[] = [];
    walkDir(TEST_DIR, TEST_DIR, files, exclusions);

    const symlinkExclusion = exclusions.find((e) => e.path.includes('escape-link'));
    expect(symlinkExclusion).toBeTruthy();
    expect(symlinkExclusion!.reason).toContain('symlink');
    // The legitimate file should still be included.
    expect(files.some((f) => f.endsWith('app.ts'))).toBe(true);
  });

  it('excludes broken symlinks', () => {
    symlinkSync('/nonexistent/target/path', join(TEST_DIR, 'broken-link'));

    const files: string[] = [];
    const exclusions: ExclusionEntry[] = [];
    walkDir(TEST_DIR, TEST_DIR, files, exclusions);

    const broken = exclusions.find((e) => e.path.includes('broken-link'));
    expect(broken).toBeTruthy();
    expect(broken!.reason).toMatch(/broken|symlink/);
  });

  it('keeps symlinks that resolve inside the project root', () => {
    writeFileSync(join(TEST_DIR, 'real.ts'), 'export {}');
    symlinkSync(join(TEST_DIR, 'real.ts'), join(TEST_DIR, 'alias.ts'));

    const files: string[] = [];
    const exclusions: ExclusionEntry[] = [];
    walkDir(TEST_DIR, TEST_DIR, files, exclusions);

    // Internal symlink: should not be excluded as escape.
    const escapeExclusion = exclusions.find((e) =>
      e.path.includes('alias.ts') && /escape|outside/.test(e.reason),
    );
    expect(escapeExclusion).toBeUndefined();
  });
});
