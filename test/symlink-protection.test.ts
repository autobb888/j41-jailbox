import { describe, it } from 'node:test';
import assert from 'node:assert';
import { mkdirSync, writeFileSync, symlinkSync, rmSync } from 'fs';
import { join } from 'path';
import { preScan } from '../src/pre-scan.js';

const TEST_DIR = join(import.meta.dirname, '__test-symlink__');

describe('symlink traversal protection', () => {
  it('excludes symlinks pointing outside project root', async () => {
    // Setup
    rmSync(TEST_DIR, { recursive: true, force: true });
    mkdirSync(join(TEST_DIR, 'src'), { recursive: true });
    writeFileSync(join(TEST_DIR, 'src', 'app.ts'), 'export {}');
    symlinkSync('/etc/passwd', join(TEST_DIR, 'src', 'escape-link'));

    const result = await preScan(TEST_DIR);
    const symlinkExclusion = result.exclusions.find(e => e.path.includes('escape-link'));
    assert.ok(symlinkExclusion, 'Symlink to /etc/passwd should be excluded');
    assert.ok(symlinkExclusion!.reason.includes('symlink'), 'Reason should mention symlink');

    // Cleanup
    rmSync(TEST_DIR, { recursive: true, force: true });
  });
});
