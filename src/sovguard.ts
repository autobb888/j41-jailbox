/**
 * SovGuard API client — scanning, report queuing, failure tracking
 */

import { writeFileSync, readFileSync, existsSync, mkdirSync, chmodSync } from 'fs';
import { join, dirname } from 'path';
import { createHash, randomBytes, createCipheriv, createDecipheriv } from 'crypto';
import chalk from 'chalk';

export interface SovGuardConfig {
  apiKey: string;
  apiUrl: string;
  encryptionKey?: string; // base64-encoded 256-bit AES key
}

export interface SovGuardScanMatch {
  line: number;
  text: string;
  flag: string;
}

export interface SovGuardScanResult {
  safe: boolean;
  score: number;
  reason?: string;
  category?: string;
  classification?: string;
  flags?: string[];
  matches?: SovGuardScanMatch[];
}

export interface SovGuardReport {
  file_path: string;
  content_hash: string;
  score: number;
  mime_type: string;
  jailbox_uid: string;
  timestamp: string;
  verdict: 'false_positive';
}

export class SovGuardAuthError extends Error {
  constructor() { super('SovGuard: invalid API key'); }
}

const SCAN_TIMEOUT_MS = 5000;
const SCAN_MAX_BYTES = 100 * 1024; // 100KB
const REPORT_FILE = join(process.env.HOME || '~', '.j41', 'sovguard-reports.jsonl');
const REPORT_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

// Simple token bucket rate limiter
class RateLimiter {
  private tokens: number;
  private lastRefill: number;
  private readonly maxTokens: number;
  private readonly refillRate: number; // tokens per ms

  constructor(maxPerSecond: number, burst: number) {
    this.maxTokens = burst;
    this.tokens = burst;
    this.refillRate = maxPerSecond / 1000;
    this.lastRefill = Date.now();
  }

  async acquire(): Promise<void> {
    this.refill();
    if (this.tokens >= 1) {
      this.tokens--;
      return;
    }
    // Wait until a token is available
    const waitMs = Math.ceil((1 - this.tokens) / this.refillRate);
    await new Promise((r) => setTimeout(r, waitMs));
    this.refill();
    this.tokens--;
  }

  private refill(): void {
    const now = Date.now();
    const elapsed = now - this.lastRefill;
    this.tokens = Math.min(this.maxTokens, this.tokens + elapsed * this.refillRate);
    this.lastRefill = now;
  }
}

export class SovGuardClient {
  private config: SovGuardConfig;
  private _consecutiveFailures = 0;
  private _disabled = false;
  private _encryptionKey: Buffer | null = null;
  private rateLimiter = new RateLimiter(10, 20); // 10 req/s, burst 20

  constructor(config: SovGuardConfig) {
    this.config = config;

    if (config.encryptionKey) {
      const decoded = Buffer.from(config.encryptionKey, 'base64');
      if (decoded.length === 32) {
        this._encryptionKey = decoded;
      } else {
        console.warn(chalk.yellow(`⚠ Encryption key must be 32 bytes (256 bits). Got ${decoded.length} bytes. Encryption disabled.`));
      }
    }
  }

  get encrypted(): boolean { return this._encryptionKey !== null; }

  get consecutiveFailures(): number { return this._consecutiveFailures; }
  isDisabled(): boolean { return this._disabled; }
  disable(): void { this._disabled = true; }

  private encryptPayload(jsonBody: string): { iv: string; tag: string; data: string } {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this._encryptionKey!, iv);
    const encrypted = Buffer.concat([cipher.update(jsonBody, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return {
      iv: iv.toString('base64'),
      tag: tag.toString('base64'),
      data: encrypted.toString('base64'),
    };
  }

  private decryptPayload(envelope: { iv: string; tag: string; data: string }): string {
    const decipher = createDecipheriv(
      'aes-256-gcm',
      this._encryptionKey!,
      Buffer.from(envelope.iv, 'base64'),
    );
    decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(envelope.data, 'base64')),
      decipher.final(),
    ]);
    return decrypted.toString('utf8');
  }

  async scanContent(content: Buffer, mimeType: string): Promise<SovGuardScanResult | null> {
    if (this._disabled) return null;

    if (content.length > SCAN_MAX_BYTES) {
      return null; // Caller handles oversized content
    }

    await this.rateLimiter.acquire();

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), SCAN_TIMEOUT_MS);

    try {
      const jsonBody = JSON.stringify({
        content: content.toString('base64'),
        mimeType,
      });

      const headers: Record<string, string> = {
        'X-API-Key': this.config.apiKey,
        'Content-Type': 'application/json',
      };
      let body: string;

      if (this._encryptionKey) {
        headers['X-Encrypted'] = 'true';
        body = JSON.stringify(this.encryptPayload(jsonBody));
      } else {
        body = jsonBody;
      }

      const response = await fetch(`${this.config.apiUrl}/v1/scan/file/content`, {
        method: 'POST',
        headers,
        body,
        signal: controller.signal,
      });

      if (!response.ok) {
        if (response.status === 401) {
          throw new SovGuardAuthError();
        }
        this._consecutiveFailures++;
        return null;
      }

      this._consecutiveFailures = 0;

      // Audit 2026-06-02 M-JAILBOX-ddos-3: cap SovGuard response body size
      // before parsing. A hostile API can otherwise serve multi-GB JSON and
      // OOM the buyer's CLI mid-session.
      const MAX_SOVGUARD_RESPONSE_BYTES = Number(process.env.J41_SOVGUARD_MAX_RESPONSE_BYTES ?? 4 * 1024 * 1024);
      const declared = Number(response.headers.get('content-length'));
      if (Number.isFinite(declared) && declared > MAX_SOVGUARD_RESPONSE_BYTES) {
        this._consecutiveFailures++;
        return null;
      }
      const rawText = await response.text();
      if (rawText.length > MAX_SOVGUARD_RESPONSE_BYTES) {
        this._consecutiveFailures++;
        return null;
      }

      if (this._encryptionKey && response.headers.get('x-encrypted') === 'true') {
        const envelope = JSON.parse(rawText) as { iv: string; tag: string; data: string };
        const decrypted = this.decryptPayload(envelope);
        return JSON.parse(decrypted) as SovGuardScanResult;
      }

      return JSON.parse(rawText) as SovGuardScanResult;
    } catch (err) {
      if (err instanceof SovGuardAuthError) throw err;
      this._consecutiveFailures++;
      return null;
    } finally {
      clearTimeout(timer);
    }
  }

  contentHash(content: Buffer): string {
    return `sha256:${createHash('sha256').update(content).digest('hex')}`;
  }

  queueReport(report: SovGuardReport): void {
    const dir = dirname(REPORT_FILE);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }

    const line = JSON.stringify(report) + '\n';
    writeFileSync(REPORT_FILE, line, { flag: 'a', mode: 0o600 });

    try {
      chmodSync(REPORT_FILE, 0o600);
    } catch {
      // Best effort
    }
  }

  purgeOldReports(): void {
    if (!existsSync(REPORT_FILE)) return;

    try {
      const raw = readFileSync(REPORT_FILE, 'utf-8');
      const lines = raw.trim().split('\n').filter(Boolean);
      const cutoff = Date.now() - REPORT_MAX_AGE_MS;

      const kept = lines.filter((line) => {
        try {
          const report = JSON.parse(line);
          return new Date(report.timestamp).getTime() > cutoff;
        } catch {
          return false;
        }
      });

      writeFileSync(REPORT_FILE, kept.join('\n') + (kept.length ? '\n' : ''), { mode: 0o600 });
    } catch {
      // File read error — skip purge
    }
  }

  /** Send queued false positive reports to POST /v1/report, then purge old entries */
  async flushReports(): Promise<{ sent: number; failed: number }> {
    this.purgeOldReports();

    if (!existsSync(REPORT_FILE)) return { sent: 0, failed: 0 };

    let sent = 0;
    let failed = 0;
    const remaining: string[] = [];

    try {
      const raw = readFileSync(REPORT_FILE, 'utf-8');
      const lines = raw.trim().split('\n').filter(Boolean);

      for (const line of lines) {
        try {
          const report = JSON.parse(line);

          const response = await fetch(`${this.config.apiUrl}/v1/report`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'X-API-Key': this.config.apiKey,
            },
            body: JSON.stringify(report),
          });

          if (response.ok) {
            sent++;
          } else {
            failed++;
            remaining.push(line); // Keep for retry
          }
        } catch {
          failed++;
          remaining.push(line);
        }
      }

      // Rewrite file with only unsent reports
      writeFileSync(REPORT_FILE, remaining.join('\n') + (remaining.length ? '\n' : ''), { mode: 0o600 });
    } catch {
      // File read error — skip flush
    }

    return { sent, failed };
  }
}

export { SCAN_MAX_BYTES };
