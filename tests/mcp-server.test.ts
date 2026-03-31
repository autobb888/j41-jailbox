import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdirSync, writeFileSync, rmSync, existsSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

// We need to test with a custom jailbox root
// Since mcp-server uses a hardcoded WORKSPACE_ROOT = '/jailbox',
// we'll test resolveSafe logic directly and file ops via the exported functions

describe('mcp-server', () => {
  // For resolveSafe tests, we test the logic pattern directly
  describe('resolveSafe', () => {
    // Import after mock setup
    let resolveSafe: (relPath: string) => string | null;

    beforeEach(async () => {
      const mod = await import('../src/mcp-server.js');
      resolveSafe = mod.resolveSafe;
    });

    it('rejects paths containing ..', () => {
      expect(resolveSafe('../etc/passwd')).toBeNull();
    });

    it('rejects paths with embedded ..', () => {
      expect(resolveSafe('foo/../../etc/passwd')).toBeNull();
    });

    it('resolves valid relative paths under /jailbox', () => {
      const result = resolveSafe('src/main.rs');
      expect(result).toBe('/jailbox/src/main.rs');
    });

    it('resolves root path .', () => {
      const result = resolveSafe('.');
      expect(result).toBe('/jailbox');
    });

    it('rejects absolute paths outside jailbox', () => {
      // Absolute paths get resolved relative to jailbox, so /etc becomes /jailbox/etc
      // This is actually safe — resolveSafe uses resolve() which joins them
      const result = resolveSafe('/etc/passwd');
      // path.resolve('/jailbox', '/etc/passwd') = '/etc/passwd' which is outside /jailbox
      expect(result).toBeNull();
    });
  });

  describe('isBinary', () => {
    let isBinary: (buffer: Buffer) => boolean;

    beforeEach(async () => {
      const mod = await import('../src/mcp-server.js');
      isBinary = mod.isBinary;
    });

    it('detects binary content (null bytes)', () => {
      const buf = Buffer.from([0x48, 0x65, 0x00, 0x6c, 0x6f]); // "He\0lo"
      expect(isBinary(buf)).toBe(true);
    });

    it('passes text content', () => {
      const buf = Buffer.from('Hello, world!\nLine 2\n', 'utf-8');
      expect(isBinary(buf)).toBe(false);
    });

    it('passes empty buffer', () => {
      expect(isBinary(Buffer.alloc(0))).toBe(false);
    });

    it('only checks first 8KB', () => {
      // Create buffer with null byte after 8KB
      const buf = Buffer.alloc(9000, 0x41); // All 'A'
      buf[8193] = 0; // Null byte after 8KB check range
      expect(isBinary(buf)).toBe(false);
    });
  });

  describe('listDirectory', () => {
    let listDirectory: (relPath: string) => any;
    let tempDir: string;

    beforeEach(async () => {
      // Create temp jailbox
      tempDir = join(tmpdir(), `j41-test-${Date.now()}`);
      mkdirSync(join(tempDir, 'subdir'), { recursive: true });
      writeFileSync(join(tempDir, 'file.txt'), 'hello');
      writeFileSync(join(tempDir, 'subdir', 'nested.txt'), 'nested');

      // Note: listDirectory uses the hardcoded WORKSPACE_ROOT = '/jailbox'
      // We can't easily override it, so we test return shape and error handling
      const mod = await import('../src/mcp-server.js');
      listDirectory = mod.listDirectory;
    });

    afterEach(() => {
      if (existsSync(tempDir)) rmSync(tempDir, { recursive: true });
    });

    it('returns error for non-existent directory', () => {
      const result = listDirectory('nonexistent');
      expect(result.isError).toBe(true);
    });

    it('returns error for path traversal', () => {
      const result = listDirectory('../etc');
      expect(result.isError).toBe(true);
    });
  });

  describe('readFile', () => {
    let readFile: (relPath: string) => any;

    beforeEach(async () => {
      const mod = await import('../src/mcp-server.js');
      readFile = mod.readFile;
    });

    it('returns error for non-existent file', () => {
      const result = readFile('nonexistent.txt');
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain('File not found');
    });

    it('returns error for path traversal', () => {
      const result = readFile('../etc/passwd');
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain('outside the project');
    });
  });

  describe('writeFile', () => {
    let writeFile: (relPath: string, content: string) => any;

    beforeEach(async () => {
      const mod = await import('../src/mcp-server.js');
      writeFile = mod.writeFile;
    });

    it('returns error for path traversal', () => {
      const result = writeFile('../etc/evil', 'malicious');
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain('outside the project');
    });

    it('returns error for oversized content', () => {
      const bigContent = 'x'.repeat(11 * 1024 * 1024); // > 10MB
      const result = writeFile('big.txt', bigContent);
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain('too large');
    });
  });
});
