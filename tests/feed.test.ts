import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { Feed } from '../src/feed.js';
import type { OperationMetadata } from '../src/types.js';

describe('Feed', () => {
  let feed: Feed;
  let consoleSpy: ReturnType<typeof vi.spyOn>;
  let consoleWarnSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    feed = new Feed(false);
    consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    consoleSpy.mockRestore();
    consoleWarnSpy.mockRestore();
  });

  it('logOperation formats read operations', () => {
    const meta: OperationMetadata = {
      operation: 'read_file',
      path: 'src/index.ts',
      sovguardScore: 0,
    };
    feed.logOperation(meta);
    expect(consoleSpy).toHaveBeenCalledOnce();
    const output = consoleSpy.mock.calls[0][0] as string;
    expect(output).toContain('src/index.ts');
    // Should not show BLOCKED
    expect(output).not.toContain('BLOCKED');
  });

  it('logOperation formats blocked operations', () => {
    const meta: OperationMetadata = {
      operation: 'write_file',
      path: 'secrets.json',
      sovguardScore: 0,
      blocked: true,
      blockReason: 'excluded file',
    };
    feed.logOperation(meta);
    expect(consoleSpy).toHaveBeenCalledOnce();
    const output = consoleSpy.mock.calls[0][0] as string;
    expect(output).toContain('BLOCKED');
    expect(output).toContain('secrets.json');
    expect(output).toContain('excluded file');
  });

  it('logSovguardBlock includes score and reason', () => {
    feed.logSovguardBlock('src/malicious.js', 0.95, 'possible exfiltration');
    expect(consoleSpy).toHaveBeenCalledOnce();
    const output = consoleSpy.mock.calls[0][0] as string;
    expect(output).toContain('src/malicious.js');
    expect(output).toContain('0.95');
    expect(output).toContain('possible exfiltration');
    expect(output).toContain('BLOCKED');
  });

  it('logSovguardReadScore includes path and score', () => {
    feed.logSovguardReadScore('src/config.ts', 0.12);
    expect(consoleSpy).toHaveBeenCalledOnce();
    const output = consoleSpy.mock.calls[0][0] as string;
    expect(output).toContain('src/config.ts');
    expect(output).toContain('0.12');
  });

  it('logSovguardDisabledWarning prints warning', () => {
    feed.logSovguardDisabledWarning();
    expect(consoleWarnSpy).toHaveBeenCalledTimes(2);
    const firstWarn = consoleWarnSpy.mock.calls[0][0] as string;
    expect(firstWarn).toContain('SovGuard disabled');
  });

  it('logSovguardUnscanned includes path and reason', () => {
    feed.logSovguardUnscanned('large-file.bin', 'too large for scan');
    expect(consoleSpy).toHaveBeenCalledOnce();
    const output = consoleSpy.mock.calls[0][0] as string;
    expect(output).toContain('large-file.bin');
    expect(output).toContain('too large for scan');
  });
});

describe('logSovguardWarn', () => {
  it('prints a non-blocking warning with the path and reason', () => {
    const spy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const feed = new Feed(false);
    feed.logSovguardWarn('install.sh', 'download and execute (warn)');
    expect(spy).toHaveBeenCalled();
    const out = spy.mock.calls.map((c) => String(c[0])).join('\n');
    expect(out).toContain('install.sh');
    expect(out.toLowerCase()).toContain('warn');
    spy.mockRestore();
  });

  it('increments sovguardScans counter', () => {
    const spy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const feed = new Feed(false);
    feed.logSovguardWarn('install.sh', 'download and execute (warn)');
    expect(feed.getStats().sovguardScans).toBe(1);
    spy.mockRestore();
  });
});
