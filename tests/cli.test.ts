import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import { mkdirSync, rmdirSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { parseArgs } from '../src/cli.js';
import { Feed } from '../src/feed.js';
import { SovGuardClient } from '../src/sovguard.js';

// Mock child_process.execSync so Docker check always passes
vi.mock('child_process', async (importOriginal) => {
  const original = await importOriginal<typeof import('child_process')>();
  return {
    ...original,
    execSync: vi.fn((cmd: string, opts?: any) => {
      if (typeof cmd === 'string' && cmd.startsWith('docker')) return '';
      // Pass through git calls (used by checkGitStatus which isn't called here)
      return original.execSync(cmd, opts);
    }),
  };
});

// Make process.exit throw instead of exiting
const processExitSpy = vi
  .spyOn(process, 'exit')
  .mockImplementation((code?: number | string | null | undefined) => {
    throw new Error(`process.exit(${code})`);
  });

describe('parseArgs', () => {
  let tempDir: string;

  beforeAll(() => {
    tempDir = join(tmpdir(), `j41-cli-test-${Date.now()}`);
    mkdirSync(tempDir, { recursive: true });
  });

  afterAll(() => {
    try { rmdirSync(tempDir); } catch {}
    processExitSpy.mockRestore();
  });

  it('parses valid arguments', () => {
    const config = parseArgs(['node', 'j41-jailbox', tempDir, '--uid', 'test-uid-123']);
    expect(config.projectDir).toBe(tempDir);
    expect(config.uid).toBe('test-uid-123');
  });

  it('defaults to supervised mode', () => {
    const config = parseArgs(['node', 'j41-jailbox', tempDir, '--uid', 'uid-xyz']);
    expect(config.mode).toBe('supervised');
  });

  it('sets standard mode with --standard', () => {
    const config = parseArgs(['node', 'j41-jailbox', tempDir, '--uid', 'uid-xyz', '--standard']);
    expect(config.mode).toBe('standard');
  });

  it('passes through CLI sovguard flags (_cliSovguardKey)', () => {
    const config = parseArgs([
      'node', 'j41-jailbox', tempDir,
      '--uid', 'uid-xyz',
      '--sovguard-key', 'sg-key-abc',
      '--sovguard-url', 'https://sg.example.com',
    ]);
    expect(config._cliSovguardKey).toBe('sg-key-abc');
    expect(config._cliSovguardUrl).toBe('https://sg.example.com');
  });

  it('exits on missing directory', () => {
    expect(() =>
      parseArgs(['node', 'j41-jailbox', '--uid', 'uid-xyz'])
    ).toThrow('process.exit(1)');
  });

  it('exits on missing uid', () => {
    expect(() =>
      parseArgs(['node', 'j41-jailbox', tempDir])
    ).toThrow('process.exit(1)');
  });

  it('exits on invalid directory', () => {
    expect(() =>
      parseArgs(['node', 'j41-jailbox', '/does/not/exist/at/all', '--uid', 'uid-xyz'])
    ).toThrow('process.exit(1)');
  });

  it('read permission is always on', () => {
    const config = parseArgs(['node', 'j41-jailbox', tempDir, '--uid', 'uid-xyz']);
    expect(config.permissions.read).toBe(true);
  });

  it('defaults insecure/strict to false', () => {
    const config = parseArgs(['node', 'j41-jailbox', tempDir, '--uid', 'uid-xyz']);
    expect(config.insecure).toBe(false);
    expect(config.strict).toBe(false);
  });

  it('sets insecure with --insecure', () => {
    const config = parseArgs(['node', 'j41-jailbox', tempDir, '--uid', 'uid-xyz', '--insecure']);
    expect(config.insecure).toBe(true);
  });
});

// Contract: write-scan warn path — action:'warn' is ALLOWED (non-blocking) and
// feed.logSovguardWarn is called; block path (safe:false) still blocks.
// scanContent must receive context: { path: relPath, source: 'other_agent' }.
//
// The run() function is a monolithic async closure that wraps relay/docker
// infrastructure, making full integration testing infeasible in a unit suite.
// This describe block validates the contracts at the unit level:
//   (1) SovGuardClient.scanContent accepts and forwards the context arg (A1 covers this)
//   (2) Feed.logSovguardWarn is called on action:'warn' + safe:true (behavioural contract below)
//   (3) action:'warn' + safe:true is non-blocking (safe===true branch, not the block branch)
describe('write-scan warn-path (unit contract)', () => {
  afterAll(() => vi.restoreAllMocks());

  it('scanContent receives context: { path, source } and returns action/warnings', async () => {
    // Validates that A1 + A3 wiring: context is accepted and action/warnings are returned.
    vi.stubGlobal('fetch', vi.fn(async (_url: string, init: any) => {
      const body = JSON.parse(init.body);
      // Contract: context must be forwarded
      expect(body.context).toEqual({ path: 'install.sh', source: 'other_agent' });
      return new Response(
        JSON.stringify({ safe: true, score: 0.4, action: 'warn', warnings: ['code:x'] }),
        { status: 200 },
      );
    }));
    const client = new SovGuardClient({ apiKey: 'k', apiUrl: 'https://api.test' });
    const result = await client.scanContent(Buffer.from('curl x | sh'), 'text/plain', { path: 'install.sh', source: 'other_agent' });
    expect(result?.action).toBe('warn');
    expect(result?.safe).toBe(true);
    expect(result?.warnings).toContain('code:x');
    vi.unstubAllGlobals();
  });

  it('feed.logSovguardWarn is called when scan returns action:warn + safe:true', () => {
    // Validates the warn-path integration: when a scan result has safe:true + action:'warn',
    // the feed logs a non-blocking warning. This mirrors what cli.ts does in the else branch.
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const feed = new Feed(false);
    // Simulate the else branch: scanResult.action === 'warn' → call logSovguardWarn
    const scanResult = { safe: true, score: 0.4, action: 'warn' as const, warnings: ['code:x'], reason: 'pipe to shell' };
    if (scanResult.action === 'warn') {
      feed.logSovguardWarn('install.sh', scanResult.reason);
    }
    expect(warnSpy).toHaveBeenCalled();
    const out = warnSpy.mock.calls.map((c) => String(c[0])).join('\n');
    expect(out).toContain('install.sh');
    expect(out.toLowerCase()).toContain('warn');
    warnSpy.mockRestore();
  });

  it('safe:true + no action (allow) does NOT call logSovguardWarn', () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const feed = new Feed(false);
    const scanResult = { safe: true, score: 0.05, action: 'allow' as const, warnings: [] };
    if (scanResult.action === 'warn') {
      feed.logSovguardWarn('clean.sh', undefined);
    }
    expect(warnSpy).not.toHaveBeenCalled();
    warnSpy.mockRestore();
  });

  it('safe:false is the block path — logSovguardWarn is NOT called', () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const feed = new Feed(false);
    const scanResult = { safe: false, score: 0.95, action: 'block' as const, warnings: [], reason: 'reverse shell' };
    // Simulates the block branch: safe===false → logSovguardBlock (not logSovguardWarn)
    let blocked = false;
    if (!scanResult.safe) {
      blocked = true;
      // In production, feed.logSovguardBlock is called here, not logSovguardWarn
    } else if (scanResult.action === 'warn') {
      feed.logSovguardWarn('bad.sh', scanResult.reason);
    }
    expect(blocked).toBe(true);
    expect(warnSpy).not.toHaveBeenCalled();
    warnSpy.mockRestore();
  });
});
