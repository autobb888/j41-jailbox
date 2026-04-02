/**
 * MCP Server — runs inside Docker container
 *
 * Self-contained JSON-RPC 2.0 server over stdio.
 * Exposes 3 tools: list_directory, read_file, write_file.
 * Zero npm dependencies — only Node.js built-ins.
 *
 * The /jailbox directory is the mounted project directory.
 */

import { readFileSync, writeFileSync, readdirSync, statSync, existsSync, mkdirSync, realpathSync, lstatSync } from 'fs';
import { join, resolve, relative, dirname } from 'path';
import { createHash } from 'crypto';
import { createInterface } from 'readline';

const JAILBOX_ROOT = '/jailbox';
const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB
const MAX_DIR_ENTRIES = 10_000;

// ── JSON-RPC Protocol ───────────────────────────────────────────

const rl = createInterface({ input: process.stdin });

rl.on('line', (line) => {
  try {
    const msg = JSON.parse(line);
    handleMessage(msg).then((response) => {
      if (response) {
        process.stdout.write(JSON.stringify(response) + '\n');
      }
    }).catch((err) => {
      if (msg.id !== undefined) {
        process.stdout.write(JSON.stringify({
          jsonrpc: '2.0',
          id: msg.id,
          error: { code: -32603, message: err.message },
        }) + '\n');
      }
    });
  } catch {
    // Invalid JSON — ignore
  }
});

async function handleMessage(msg: any): Promise<any> {
  if (msg.method === 'initialize') {
    return {
      jsonrpc: '2.0',
      id: msg.id,
      result: {
        protocolVersion: '2024-11-05',
        capabilities: { tools: {} },
        serverInfo: { name: 'j41-jailbox-mcp', version: '0.1.0' },
      },
    };
  }

  if (msg.method === 'notifications/initialized') {
    return null; // No response for notifications
  }

  if (msg.method === 'tools/list') {
    return {
      jsonrpc: '2.0',
      id: msg.id,
      result: { tools: getToolDefinitions() },
    };
  }

  if (msg.method === 'tools/call') {
    const { name, arguments: args } = msg.params;
    const result = await executeTool(name, args || {});
    return {
      jsonrpc: '2.0',
      id: msg.id,
      result,
    };
  }

  // Unknown method
  return {
    jsonrpc: '2.0',
    id: msg.id,
    error: { code: -32601, message: `Method not found: ${msg.method}` },
  };
}

// ── Tool Definitions ────────────────────────────────────────────

function getToolDefinitions() {
  return [
    {
      name: 'list_directory',
      description: 'List files and directories at the given path within the project',
      inputSchema: {
        type: 'object',
        properties: {
          path: { type: 'string', description: 'Relative path within the project (default: root)' },
        },
      },
    },
    {
      name: 'read_file',
      description: 'Read the contents of a text file',
      inputSchema: {
        type: 'object',
        properties: {
          path: { type: 'string', description: 'Relative path to the file' },
        },
        required: ['path'],
      },
    },
    {
      name: 'write_file',
      description: 'Write content to a file (creates or overwrites)',
      inputSchema: {
        type: 'object',
        properties: {
          path: { type: 'string', description: 'Relative path to the file' },
          content: { type: 'string', description: 'File content to write' },
        },
        required: ['path', 'content'],
      },
    },
  ];
}

// ── Tool Execution ──────────────────────────────────────────────

async function executeTool(name: string, args: Record<string, any>) {
  switch (name) {
    case 'list_directory': return listDirectory(args.path || '.');
    case 'read_file': return readFile(args.path);
    case 'write_file': return writeFile(args.path, args.content);
    default:
      return { content: [{ type: 'text', text: `Unknown tool: ${name}` }], isError: true };
  }
}

function listDirectory(relPath: string) {
  const absPath = resolveSafe(relPath);
  if (!absPath) {
    return { content: [{ type: 'text', text: 'Path is outside the project directory' }], isError: true };
  }

  if (!existsSync(absPath) || !statSync(absPath).isDirectory()) {
    return { content: [{ type: 'text', text: `Not a directory: ${relPath}` }], isError: true };
  }

  const entries = readdirSync(absPath, { withFileTypes: true });
  const result = entries.slice(0, MAX_DIR_ENTRIES).map((e) => ({
    name: e.name,
    type: e.isDirectory() ? 'directory' : 'file',
    size: e.isFile() ? statSync(join(absPath, e.name)).size : undefined,
  }));

  return {
    content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
    _meta: { entryCount: result.length, path: relPath },
  };
}

function readFile(relPath: string) {
  const absPath = resolveSafe(relPath);
  if (!absPath) {
    return { content: [{ type: 'text', text: 'Path is outside the project directory' }], isError: true };
  }

  if (!existsSync(absPath) || !statSync(absPath).isFile()) {
    return { content: [{ type: 'text', text: `File not found: ${relPath}` }], isError: true };
  }

  const stat = statSync(absPath);
  if (stat.size > MAX_FILE_SIZE) {
    return { content: [{ type: 'text', text: `File too large: ${stat.size} bytes (max ${MAX_FILE_SIZE})` }], isError: true };
  }

  // Check if binary
  const buffer = readFileSync(absPath);
  if (isBinary(buffer)) {
    return { content: [{ type: 'text', text: 'Binary files are not supported in v1' }], isError: true };
  }

  const text = buffer.toString('utf-8');
  const hash = createHash('sha256').update(buffer).digest('hex');

  return {
    content: [{ type: 'text', text }],
    _meta: { sizeBytes: stat.size, contentHash: `sha256:${hash}`, path: relPath },
  };
}

function writeFile(relPath: string, content: string) {
  const absPath = resolveSafe(relPath);
  if (!absPath) {
    return { content: [{ type: 'text', text: 'Path is outside the project directory' }], isError: true };
  }

  const contentBuffer = Buffer.from(content, 'utf-8');
  if (contentBuffer.length > MAX_FILE_SIZE) {
    return { content: [{ type: 'text', text: `Content too large: ${contentBuffer.length} bytes (max ${MAX_FILE_SIZE})` }], isError: true };
  }

  // Ensure parent directory exists
  const parentDir = dirname(absPath);
  if (!existsSync(parentDir)) {
    mkdirSync(parentDir, { recursive: true });
  }

  writeFileSync(absPath, content, 'utf-8');
  const hash = createHash('sha256').update(contentBuffer).digest('hex');

  return {
    content: [{ type: 'text', text: `Written: ${relPath} (${contentBuffer.length} bytes)` }],
    _meta: { sizeBytes: contentBuffer.length, contentHash: `sha256:${hash}`, path: relPath },
  };
}

// ── Helpers ─────────────────────────────────────────────────────

function resolveSafe(relPath: string): string | null {
  // Reject paths with .. before resolution
  if (relPath.includes('..')) return null;

  const absPath = resolve(JAILBOX_ROOT, relPath);
  // Must be within jailbox root (pre-resolution check)
  if (!absPath.startsWith(JAILBOX_ROOT + '/') && absPath !== JAILBOX_ROOT) {
    return null;
  }

  // Symlink resolution: follow symlinks and verify the REAL path stays in /jailbox/
  if (existsSync(absPath)) {
    try {
      const realPath = realpathSync(absPath);
      if (!realPath.startsWith(JAILBOX_ROOT + '/') && realPath !== JAILBOX_ROOT) {
        return null; // Symlink escapes jailbox
      }
      return realPath;
    } catch {
      return null; // Broken symlink or permission error
    }
  }

  // Path doesn't exist yet (write_file creates it) — check parent
  const parentDir = resolve(absPath, '..');
  if (existsSync(parentDir)) {
    try {
      const realParent = realpathSync(parentDir);
      if (!realParent.startsWith(JAILBOX_ROOT + '/') && realParent !== JAILBOX_ROOT) {
        return null; // Parent symlink escapes jailbox
      }
    } catch {
      return null;
    }
  }

  return absPath;
}

function isBinary(buffer: Buffer): boolean {
  // Check first 8KB for null bytes (simple binary detection)
  const check = buffer.subarray(0, 8192);
  for (let i = 0; i < check.length; i++) {
    if (check[i] === 0) return true;
  }
  return false;
}

// Exports for testing (not used at runtime)
export { resolveSafe, listDirectory, readFile, writeFile, isBinary, JAILBOX_ROOT, MAX_FILE_SIZE, MAX_DIR_ENTRIES };
