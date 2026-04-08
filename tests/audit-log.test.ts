import { describe, it, expect } from 'vitest';
import { AuditLog } from '../src/audit-log.js';

describe('AuditLog', () => {
  it('creates signed hash-chained entries', () => {
    const log = new AuditLog();
    log.record('read_file', 'src/app.ts', 2048, 'sha256:abc123');
    log.record('write_file', 'src/fix.ts', 512, 'sha256:def456');

    const entries = log.getEntries();
    expect(entries.length).toBe(2);
    expect(entries[0].seq).toBe(1);
    expect(entries[0].op).toBe('read_file');
    expect(entries[0].path).toBe('src/app.ts');
    expect(entries[0].prev_hash).toBe('sha256:0000000000000000000000000000000000000000000000000000000000000000');
    expect(entries[1].seq).toBe(2);
    expect(entries[1].prev_hash).toBe(entries[0].hash);
  });

  it('detects tampering via broken hash chain', () => {
    const log = new AuditLog();
    log.record('read_file', 'a.ts', 100, 'sha256:aaa');
    log.record('read_file', 'b.ts', 200, 'sha256:bbb');

    expect(log.verifyChain()).toBe(true);

    // Tamper with entry
    const entries = log.getEntries();
    entries[0].path = 'hacked.ts';
    expect(log.verifyChain()).toBe(false);
  });

  it('exports public key for verification', () => {
    const log = new AuditLog();
    const pubKey = log.getPublicKey();
    expect(pubKey.length).toBeGreaterThan(0);
  });

  it('verifies signatures', () => {
    const log = new AuditLog();
    log.record('read_file', 'test.ts', 42, 'sha256:test');
    const entries = log.getEntries();
    expect(log.verifySignature(entries[0])).toBe(true);
  });
});
