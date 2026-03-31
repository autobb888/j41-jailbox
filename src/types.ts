/**
 * Shared types and constants for j41-jailbox
 */

import type { SovGuardConfig } from './sovguard.js';

// ── Constants ───────────────────────────────────────────────────

export const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB
export const MAX_SESSION_TRANSFER = 500 * 1024 * 1024; // 500MB
export const MAX_DIR_ENTRIES = 10_000;
export const DIFF_PREVIEW_LINES = 20;
export const RECONNECT_GRACE_SECONDS = 300; // 5 minutes

// Patterns to auto-exclude during pre-scan
export const AUTO_EXCLUDE_PATTERNS = [
  '.env', '.env.*',
  '.ssh/', '.gnupg/',
  '*.pem', '*.key', '*.p12',
  'credentials.json', 'secrets.*',
  'node_modules/', '.git/',
  '.DS_Store', 'Thumbs.db',
];

// ── Types ───────────────────────────────────────────────────────

export type JailboxMode = 'supervised' | 'standard';

export interface JailboxConfig {
  projectDir: string;
  uid: string;
  resumeToken?: string;
  permissions: { read: boolean; write: boolean };
  mode: JailboxMode;
  verbose: boolean;
  apiUrl: string;
  sovguard?: SovGuardConfig;
  _cliSovguardKey?: string;
  _cliSovguardUrl?: string;
}

export interface ExclusionEntry {
  path: string;
  reason: string;
  matches?: { line: number; text: string; flag: string }[];
}

export interface OperationMetadata {
  operation: 'read' | 'read_file' | 'write' | 'write_file' | 'list_dir' | 'list_directory' | 'search' | 'search_files' | 'get_file_info' | 'directory_tree';
  path: string;
  sizeBytes?: number;
  contentHash?: string;
  sovguardScore: number;
  approved?: boolean;
  blocked?: boolean;
  blockReason?: string;
}

export interface McpCall {
  id: string;
  tool: string;
  params: Record<string, any>;
}

export interface McpResult {
  id: string;
  success: boolean;
  result?: any;
  error?: string;
  metadata: OperationMetadata;
}

export interface SessionStats {
  reads: number;
  writes: number;
  blocked: number;
  totalBytes: number;
  startedAt: number;
  sovguardScans: number;
  sovguardBlocks: number;
  sovguardReports: number;
}

// Stdin state machine for command/approval coexistence
export type InputState = 'IDLE' | 'APPROVAL_PENDING' | 'SOVGUARD_PENDING';
