import { describe, it, expect, afterEach } from 'vitest';
import { mkdirSync, writeFileSync, symlinkSync, rmSync } from 'fs';
import { join } from 'path';
import { preScan } from '../src/pre-scan.js';

const TEST_DIR = join(new URL('.', import.meta.url).pathname, '__test-symlink__');

describe('symlink traversal protection', () => {
  afterEach(() => {
    rmSync(TEST_DIR, { recursive: true, force: true });
  });

  it('excludes symlinks pointing outside project root', async () => {
    // Setup
    rmSync(TEST_DIR, { recursive: true, force: true });
    mkdirSync(join(TEST_DIR, 'src'), { recursive: true });
    writeFileSync(join(TEST_DIR, 'src', 'app.ts'), 'export {}');
    symlinkSync('/etc/passwd', join(TEST_DIR, 'src', 'escape-link'));

    const result = await preScan(TEST_DIR);
    const symlinkExclusion = result.exclusions.find(e => e.path.includes('escape-link'));
    expect(symlinkExclusion).toBeTruthy();
    expect(symlinkExclusion!.reason).toContain('symlink');
  });
});
