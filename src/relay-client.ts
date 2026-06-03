/**
 * Socket.IO client to platform's /jailbox namespace
 *
 * Handles connection, authentication (UID or reconnect token),
 * MCP call routing, and status events.
 */

import { io, Socket } from 'socket.io-client';
import chalk from 'chalk';
import type { McpCall, McpResult, ExclusionEntry } from './types.js';

const KEEPALIVE_INTERVAL_MS = 30_000; // 30 seconds

export class RelayClient {
  private socket: Socket | null = null;
  private keepaliveTimer: ReturnType<typeof setInterval> | null = null;
  private onMcpCall: ((call: McpCall) => void) | null = null;
  private onStatusChanged: ((status: string, data?: any) => void) | null = null;
  private onAgentDone: (() => void) | null = null;
  private onSessionEnded: ((data?: any) => void) | null = null;
  private onError: ((error: { code: string; message: string }) => void) | null = null;

  connect(apiUrl: string, auth: { type: string; uid?: string; reconnectToken?: string }): Promise<void> {
    return new Promise((resolve, reject) => {
      // Connect to /jailbox namespace (append to URL, path is HTTP transport path)
      // Audit 2026-06-02 H-JAILBOX-1: bound the inbound payload size. Without
      // maxPayload, a hostile relay can deliver multi-GB events on mcp:call
      // and OOM the buyer's machine mid-session.
      this.socket = io(apiUrl + '/jailbox', {
        path: '/ws',
        auth,
        transports: ['websocket', 'polling'],
        reconnection: true,
        reconnectionAttempts: 5,
        reconnectionDelay: 2000,
        ...({ maxPayload: Number(process.env.J41_JAILBOX_MAX_PAYLOAD_BYTES ?? 4 * 1024 * 1024) } as any),
      });

      this.socket.on('connect', () => {
        this.startKeepalive();
        resolve();
      });

      this.socket.on('connect_error', (err) => {
        reject(new Error(`Connection failed: ${err.message}`));
      });

      // MCP tool calls from agent (via relay)
      this.socket.on('mcp:call', (data: McpCall) => {
        this.onMcpCall?.(data);
      });

      // Status changes
      this.socket.on('jailbox:status_changed', (data: { status: string; reason?: string }) => {
        this.onStatusChanged?.(data.status, data);
      });

      // Agent signals completion
      this.socket.on('jailbox:agent_done', () => {
        this.onAgentDone?.();
      });

      // Agent disconnected
      this.socket.on('jailbox:agent_disconnected', (data: any) => {
        this.onStatusChanged?.('agent_disconnected', data);
      });

      // Session ended by platform (job closed, review submitted, etc.)
      this.socket.on('jailbox:session_ended', (data: any) => {
        this.onSessionEnded?.(data);
      });

      // Relay errors
      this.socket.on('ws:error', (data: { code: string; message: string }) => {
        this.onError?.(data);
      });

      this.socket.on('disconnect', (reason) => {
        this.stopKeepalive();
        if (reason === 'io server disconnect') {
          // Server intentionally kicked us — don't reconnect
          if (this.socket) this.socket.io.opts.reconnection = false;
          this.onStatusChanged?.('disconnected', { reason: 'server' });
        } else {
          // Transport disconnect — Socket.IO will auto-reconnect
          this.onStatusChanged?.('disconnected', { reason: 'transport', reconnecting: true });
        }
      });

      this.socket.on('reconnect', () => {
        this.startKeepalive();
        this.onStatusChanged?.('reconnected', {});
      });

      this.socket.on('reconnect_failed', () => {
        this.onStatusChanged?.('reconnect_failed', {});
      });
    });
  }

  sendResult(result: McpResult): void {
    this.socket?.emit('mcp:result', result);
  }

  sendPreScanDone(directoryHash: string, exclusions: ExclusionEntry[], overrides?: string[]): void {
    this.socket?.emit('jailbox:pre_scan_done', {
      directoryHash,
      excludedFiles: exclusions.map((e) => e.path),
      exclusionOverrides: overrides,
    });
  }

  sendPause(): void { this.socket?.emit('jailbox:pause'); }
  sendResume(): void { this.socket?.emit('jailbox:resume'); }
  sendAbort(): void { this.socket?.emit('jailbox:abort'); }
  sendAccept(): void { this.socket?.emit('jailbox:accept'); }

  /**
   * Audit 2026-06-02 H-JAILBOX-4 + M-JAILBOX-auth-1/2: register the
   * session's ephemeral Ed25519 pubkey with the platform at connect time
   * (so audit-log signatures can be verified by anyone reviewing the log
   * later), and forward the signed audit log to the platform at session
   * end. Both used to be `(relay as any).method?.()` no-ops with a type
   * cast hiding the missing implementation; the audit log claim of
   * non-repudiation was therefore false-as-shipped.
   *
   * Server-side support: the /jailbox namespace must accept the
   * `jailbox:session_key` event (key: PEM SPKI, sessionId from socket auth)
   * and the `jailbox:audit_log` event (full exported log). Until the
   * platform side ships those events, these are best-effort — the buyer
   * sees a warning on disconnect that audit-log integrity is local-only.
   */
  sendSessionKey(publicKeyPem: string): void {
    this.socket?.emit('jailbox:session_key', { publicKey: publicKeyPem });
  }

  sendAuditLog(exported: { publicKey: string; entries: unknown[] }): void {
    this.socket?.emit('jailbox:audit_log', exported);
  }

  onMcpCallReceived(handler: (call: McpCall) => void): void { this.onMcpCall = handler; }
  onStatusChange(handler: (status: string, data?: any) => void): void { this.onStatusChanged = handler; }
  onAgentCompletion(handler: () => void): void { this.onAgentDone = handler; }
  onSessionEnd(handler: (data?: any) => void): void { this.onSessionEnded = handler; }
  onRelayError(handler: (error: { code: string; message: string }) => void): void { this.onError = handler; }

  disconnect(): void {
    this.stopKeepalive();
    this.socket?.disconnect();
    this.socket = null;
  }

  private startKeepalive(): void {
    this.stopKeepalive();
    this.keepaliveTimer = setInterval(() => {
      this.socket?.emit('jailbox:ping');
    }, KEEPALIVE_INTERVAL_MS);
  }

  private stopKeepalive(): void {
    if (this.keepaliveTimer) {
      clearInterval(this.keepaliveTimer);
      this.keepaliveTimer = null;
    }
  }

  isConnected(): boolean {
    return this.socket?.connected ?? false;
  }
}
