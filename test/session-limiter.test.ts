import { describe, it } from 'node:test';
import assert from 'node:assert';
import { SessionLimiter } from '../src/session-limiter.js';

describe('SessionLimiter', () => {
  it('allows operations within limits', () => {
    const limiter = new SessionLimiter({ maxReads: 5, maxWrites: 3, maxDurationMs: 60000 });
    assert.ok(limiter.canRead());
    limiter.recordRead();
    assert.ok(limiter.canRead());
    assert.ok(limiter.canWrite());
    limiter.recordWrite();
    assert.ok(limiter.canWrite());
  });

  it('blocks reads beyond limit', () => {
    const limiter = new SessionLimiter({ maxReads: 2, maxWrites: 10, maxDurationMs: 60000 });
    limiter.recordRead();
    limiter.recordRead();
    assert.ok(!limiter.canRead());
    assert.strictEqual(limiter.blockReason(), 'read limit exceeded (2/2)');
  });

  it('blocks writes beyond limit', () => {
    const limiter = new SessionLimiter({ maxReads: 10, maxWrites: 1, maxDurationMs: 60000 });
    limiter.recordWrite();
    assert.ok(!limiter.canWrite());
    assert.strictEqual(limiter.blockReason(), 'write limit exceeded (1/1)');
  });

  it('reports remaining time', () => {
    const limiter = new SessionLimiter({ maxReads: 100, maxWrites: 100, maxDurationMs: 1000 });
    assert.ok(limiter.remainingMs() <= 1000);
    assert.ok(limiter.remainingMs() > 0);
  });
});
