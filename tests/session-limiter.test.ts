import { describe, it, expect } from 'vitest';
import { SessionLimiter } from '../src/session-limiter.js';

describe('SessionLimiter', () => {
  it('allows operations within limits', () => {
    const limiter = new SessionLimiter({ maxReads: 5, maxWrites: 3, maxDurationMs: 60000 });
    expect(limiter.canRead()).toBe(true);
    limiter.recordRead();
    expect(limiter.canRead()).toBe(true);
    expect(limiter.canWrite()).toBe(true);
    limiter.recordWrite();
    expect(limiter.canWrite()).toBe(true);
  });

  it('blocks reads beyond limit', () => {
    const limiter = new SessionLimiter({ maxReads: 2, maxWrites: 10, maxDurationMs: 60000 });
    limiter.recordRead();
    limiter.recordRead();
    expect(limiter.canRead()).toBe(false);
    expect(limiter.blockReason()).toBe('read limit exceeded (2/2)');
  });

  it('blocks writes beyond limit', () => {
    const limiter = new SessionLimiter({ maxReads: 10, maxWrites: 1, maxDurationMs: 60000 });
    limiter.recordWrite();
    expect(limiter.canWrite()).toBe(false);
    expect(limiter.blockReason()).toBe('write limit exceeded (1/1)');
  });

  it('reports remaining time', () => {
    const limiter = new SessionLimiter({ maxReads: 100, maxWrites: 100, maxDurationMs: 1000 });
    expect(limiter.remainingMs()).toBeLessThanOrEqual(1000);
    expect(limiter.remainingMs()).toBeGreaterThan(0);
  });
});
