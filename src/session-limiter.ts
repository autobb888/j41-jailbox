/**
 * Session limiter — enforces time and operation limits per jailbox session
 */

import type { SessionLimits } from './types.js';
import { DEFAULT_SESSION_LIMITS } from './types.js';

export class SessionLimiter {
  private limits: SessionLimits;
  private reads = 0;
  private writes = 0;
  private startedAt = Date.now();
  private killTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(limits?: Partial<SessionLimits>) {
    this.limits = { ...DEFAULT_SESSION_LIMITS, ...limits };
  }

  canRead(): boolean {
    return this.reads < this.limits.maxReads && !this.isExpired();
  }

  canWrite(): boolean {
    return this.writes < this.limits.maxWrites && !this.isExpired();
  }

  recordRead(): void { this.reads++; }
  recordWrite(): void { this.writes++; }

  isExpired(): boolean {
    return Date.now() - this.startedAt >= this.limits.maxDurationMs;
  }

  remainingMs(): number {
    return Math.max(0, this.limits.maxDurationMs - (Date.now() - this.startedAt));
  }

  blockReason(): string {
    if (this.isExpired()) return `session time limit exceeded (${this.limits.maxDurationMs / 3600000}h)`;
    if (this.reads >= this.limits.maxReads) return `read limit exceeded (${this.reads}/${this.limits.maxReads})`;
    if (this.writes >= this.limits.maxWrites) return `write limit exceeded (${this.writes}/${this.limits.maxWrites})`;
    return '';
  }

  stats(): { reads: number; writes: number; elapsedMs: number; remainingMs: number } {
    return {
      reads: this.reads,
      writes: this.writes,
      elapsedMs: Date.now() - this.startedAt,
      remainingMs: this.remainingMs(),
    };
  }

  /** Start auto-kill timer. Calls onExpire when session time limit is reached. */
  startAutoKill(onExpire: () => void): void {
    const remaining = this.remainingMs();
    if (remaining <= 0) { onExpire(); return; }
    this.killTimer = setTimeout(onExpire, remaining);
  }

  dispose(): void {
    if (this.killTimer) clearTimeout(this.killTimer);
  }
}
