import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import { mkdirSync, rmdirSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { parseArgs } from '../src/cli.js';

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
});
