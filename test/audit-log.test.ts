import { describe, it } from 'node:test';
import assert from 'node:assert';
import { AuditLog } from '../src/audit-log.js';

describe('AuditLog', () => {
  it('creates signed hash-chained entries', () => {
    const log = new AuditLog();
    log.record('read_file', 'src/app.ts', 2048, 'sha256:abc123');
    log.record('write_file', 'src/fix.ts', 512, 'sha256:def456');

    const entries = log.getEntries();
    assert.strictEqual(entries.length, 2);
    assert.strictEqual(entries[0].seq, 1);
    assert.strictEqual(entries[0].op, 'read_file');
    assert.strictEqual(entries[0].path, 'src/app.ts');
    assert.strictEqual(entries[0].prev_hash, 'sha256:0000000000000000000000000000000000000000000000000000000000000000');
    assert.strictEqual(entries[1].seq, 2);
    assert.strictEqual(entries[1].prev_hash, entries[0].hash);
  });

  it('detects tampering via broken hash chain', () => {
    const log = new AuditLog();
    log.record('read_file', 'a.ts', 100, 'sha256:aaa');
    log.record('read_file', 'b.ts', 200, 'sha256:bbb');

    assert.ok(log.verifyChain());

    // Tamper with entry
    const entries = log.getEntries();
    entries[0].path = 'hacked.ts';
    assert.ok(!log.verifyChain());
  });

  it('exports public key for verification', () => {
    const log = new AuditLog();
    const pubKey = log.getPublicKey();
    assert.ok(pubKey.length > 0);
  });

  it('verifies signatures', () => {
    const log = new AuditLog();
    log.record('read_file', 'test.ts', 42, 'sha256:test');
    const entries = log.getEntries();
    assert.ok(log.verifySignature(entries[0]));
  });
});
