/**
 * Tamper-evident audit log — Ed25519 signed, hash-chained entries
 *
 * Every MCP operation gets a signed log entry. At session end,
 * the log is uploaded to the platform as cryptographic proof
 * of what the agent did.
 */

import { createHash, generateKeyPairSync, sign, verify, KeyObject } from 'crypto';

export interface AuditEntry {
  seq: number;
  op: string;
  path: string;
  bytes: number;
  contentHash: string;
  hash: string;
  ts: string;
  prev_hash: string;
  sig: string;
}

const GENESIS_HASH = 'sha256:' + '0'.repeat(64);

export class AuditLog {
  private entries: AuditEntry[] = [];
  private privateKey: KeyObject;
  private publicKey: KeyObject;

  constructor() {
    // Ephemeral Ed25519 keypair — private key held in memory only
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  record(op: string, path: string, bytes: number, contentHash: string): AuditEntry {
    const seq = this.entries.length + 1;
    const prev_hash = seq === 1 ? GENESIS_HASH : this.entries[seq - 2].hash;
    const ts = new Date().toISOString();

    // Hash = SHA256 of (seq + op + path + bytes + contentHash + ts + prev_hash)
    const payload = `${seq}|${op}|${path}|${bytes}|${contentHash}|${ts}|${prev_hash}`;
    const hash = 'sha256:' + createHash('sha256').update(payload).digest('hex');

    // Sign the hash
    const sig = sign(null, Buffer.from(hash), this.privateKey).toString('base64');

    const entry: AuditEntry = { seq, op, path, bytes, contentHash, hash, ts, prev_hash, sig };
    this.entries.push(entry);
    return entry;
  }

  verifyChain(): boolean {
    for (let i = 0; i < this.entries.length; i++) {
      const entry = this.entries[i];

      // Verify prev_hash linkage
      const expectedPrev = i === 0 ? GENESIS_HASH : this.entries[i - 1].hash;
      if (entry.prev_hash !== expectedPrev) return false;

      // Recompute hash from entry fields
      const payload = `${entry.seq}|${entry.op}|${entry.path}|${entry.bytes}|${entry.contentHash}|${entry.ts}|${entry.prev_hash}`;
      const expectedHash = 'sha256:' + createHash('sha256').update(payload).digest('hex');
      if (entry.hash !== expectedHash) return false;

      // Verify signature
      if (!this.verifySignature(entry)) return false;
    }
    return true;
  }

  verifySignature(entry: AuditEntry): boolean {
    try {
      return verify(null, Buffer.from(entry.hash), this.publicKey, Buffer.from(entry.sig, 'base64'));
    } catch {
      return false;
    }
  }

  getEntries(): AuditEntry[] { return this.entries; }

  getPublicKey(): string {
    return this.publicKey.export({ type: 'spki', format: 'pem' }) as string;
  }

  getPublicKeyDer(): Buffer {
    return this.publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
  }

  /** Export full log as JSON for platform upload */
  exportLog(): { publicKey: string; entries: AuditEntry[] } {
    return { publicKey: this.getPublicKey(), entries: [...this.entries] };
  }
}
