import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, writeFileSync, mkdirSync, symlinkSync, rmSync, realpathSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Adversarial confinement battery for the in-container MCP server.
// Threat: a hired SovAgent with WRITE access to a mounted repo tries to read or
// write OUTSIDE that repo (escape). resolveSafe is the boundary; every escape
// payload below MUST resolve to null (blocked), every legitimate in-repo path
// MUST resolve inside the root. resolveSafe reads JAILBOX_ROOT at call time.
let root: string;
let outside: string;
let resolveSafe: (p: string) => string | null;

beforeAll(async () => {
  root = realpathSync(mkdtempSync(join(tmpdir(), 'jail-root-')));
  outside = realpathSync(mkdtempSync(join(tmpdir(), 'jail-out-')));
  process.env.JAILBOX_ROOT = root;

  // Repo contents
  mkdirSync(join(root, 'src'));
  writeFileSync(join(root, 'src', 'app.ts'), 'ok\n');
  writeFileSync(join(outside, 'secret.txt'), 'TOP SECRET\n');

  // A symlink INSIDE the repo pointing OUT of it (e.g. left by the user, or a
  // checked-in repo symlink). The agent cannot create symlinks via the 3-tool
  // API, but existing ones must not become an escape hatch.
  try { symlinkSync(outside, join(root, 'escape-dir')); } catch { /* fs w/o symlink */ }
  try { symlinkSync(join(outside, 'secret.txt'), join(root, 'escape-file')); } catch { /* */ }
  // A symlink that stays INSIDE the repo — must remain allowed.
  try { symlinkSync(join(root, 'src'), join(root, 'inside-link')); } catch { /* */ }

  // Import after JAILBOX_ROOT is set.
  ({ resolveSafe } = await import('../dist/mcp-server.js'));
});

afterAll(() => {
  rmSync(root, { recursive: true, force: true });
  rmSync(outside, { recursive: true, force: true });
  delete process.env.JAILBOX_ROOT;
});

describe('repo confinement — legitimate in-repo paths are allowed', () => {
  it('resolves an existing file in the repo', () => {
    expect(resolveSafe('src/app.ts')).toBe(join(root, 'src', 'app.ts'));
  });
  it('allows a NEW file in an existing repo dir (write target)', () => {
    expect(resolveSafe('src/new-feature.ts')).toBe(join(root, 'src', 'new-feature.ts'));
  });
  it('allows a NEW file in NEW nested repo dirs (mkdir -p target)', () => {
    expect(resolveSafe('a/b/c/deep.ts')).toBe(join(root, 'a', 'b', 'c', 'deep.ts'));
  });
  it('allows the repo root itself', () => {
    expect(resolveSafe('.')).toBe(root);
  });
  it('allows a symlink that stays inside the repo', () => {
    if (!existsSync(join(root, 'inside-link'))) return;
    expect(resolveSafe('inside-link/app.ts')).toBe(join(root, 'src', 'app.ts'));
  });
});

describe('repo confinement — every escape attempt is blocked', () => {
  const escapes = [
    '../',
    '../../etc/passwd',
    '../../../../../../etc/passwd',
    'src/../../etc/passwd',
    'src/../../../outside-escape',
    'legit/../../../../etc/shadow',
    '/etc/passwd',                 // absolute
    '/',                           // absolute root
    'foo/../..',                   // climbs to parent of root
    '....//....//etc/passwd',      // doubled-dot obfuscation
  ];
  for (const p of escapes) {
    it(`blocks ${JSON.stringify(p)}`, () => {
      expect(resolveSafe(p)).toBeNull();
    });
  }

  it('blocks reading THROUGH a symlink that escapes the repo (existing target)', () => {
    if (!existsSync(join(root, 'escape-file'))) return;
    expect(resolveSafe('escape-file')).toBeNull();
  });

  it('blocks reading through an escaping symlinked DIRECTORY', () => {
    if (!existsSync(join(root, 'escape-dir'))) return;
    expect(resolveSafe('escape-dir/secret.txt')).toBeNull();
  });

  it('blocks WRITING through an escaping symlinked ancestor (non-existent target)', () => {
    // escape-dir -> outside ; writing escape-dir/planted.txt would land outside.
    if (!existsSync(join(root, 'escape-dir'))) return;
    expect(resolveSafe('escape-dir/planted.txt')).toBeNull();
  });

  it('blocks a NUL-byte truncation attempt', () => {
    // eslint-disable-next-line no-control-regex
    expect(resolveSafe('safe\0/../../etc/passwd')).toBeNull();
  });
});
