import { describe, it, expect, beforeAll, beforeEach, afterAll } from 'vitest';
import { mkdirSync, writeFileSync, rmSync, symlinkSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

// Use a tmpdir as JAILBOX_ROOT so the resolveSafe ancestor-walk has somewhere
// real to anchor on the host. Production runs in a container where /jailbox
// always exists; this test override is the host-side equivalent.
const TEST_ROOT = join(tmpdir(), `j41-mcp-test-${Date.now()}`);
process.env.JAILBOX_ROOT = TEST_ROOT;

beforeAll(() => {
  rmSync(TEST_ROOT, { recursive: true, force: true });
  mkdirSync(join(TEST_ROOT, 'src'), { recursive: true });
  writeFileSync(join(TEST_ROOT, 'src', 'main.rs'), 'fn main() {}');
  writeFileSync(join(TEST_ROOT, 'hello.txt'), 'hello');
});

afterAll(() => {
  rmSync(TEST_ROOT, { recursive: true, force: true });
});

describe('mcp-server', () => {
  describe('resolveSafe', () => {
    let resolveSafe: (relPath: string) => string | null;

    beforeEach(async () => {
      const mod = await import('../src/mcp-server.js');
      resolveSafe = mod.resolveSafe;
    });

    it('rejects ".." as a leading path segment', () => {
      expect(resolveSafe('../etc/passwd')).toBeNull();
    });

    it('rejects ".." in the middle of a path', () => {
      expect(resolveSafe('foo/../../etc/passwd')).toBeNull();
    });

    it('rejects ".." with backslashes (Windows-style)', () => {
      expect(resolveSafe('..\\etc\\passwd')).toBeNull();
    });

    it('rejects any path containing ".." (strict defense-in-depth)', () => {
      // Origin keeps the blunt `includes("..")` check: even non-traversal names
      // like `..foo` are rejected. The realpath walk is the deeper guard.
      expect(resolveSafe('..foo')).toBeNull();
      expect(resolveSafe('foo..bar')).toBeNull();
    });

    it('resolves valid relative paths under root', () => {
      expect(resolveSafe('src/main.rs')).toBe(join(TEST_ROOT, 'src/main.rs'));
    });

    it('resolves root path .', () => {
      expect(resolveSafe('.')).toBe(TEST_ROOT);
    });

    it('rejects absolute paths outside jailbox', () => {
      expect(resolveSafe('/etc/passwd')).toBeNull();
    });

    it('rejects paths whose realpath escapes via symlink', () => {
      const linkPath = join(TEST_ROOT, 'escape');
      try { rmSync(linkPath, { force: true }); } catch {}
      symlinkSync('/etc/passwd', linkPath);
      expect(resolveSafe('escape')).toBeNull();
      rmSync(linkPath, { force: true });
    });
  });

  describe('isBinary', () => {
    let isBinary: (buffer: Buffer) => boolean;

    beforeEach(async () => {
      const mod = await import('../src/mcp-server.js');
      isBinary = mod.isBinary;
    });

    it('detects binary content (null bytes)', () => {
      const buf = Buffer.from([0x48, 0x65, 0x00, 0x6c, 0x6f]);
      expect(isBinary(buf)).toBe(true);
    });

    it('passes text content', () => {
      expect(isBinary(Buffer.from('Hello, world!\nLine 2\n', 'utf-8'))).toBe(false);
    });

    it('passes empty buffer', () => {
      expect(isBinary(Buffer.alloc(0))).toBe(false);
    });

    it('only checks first 8KB', () => {
      const buf = Buffer.alloc(9000, 0x41);
      buf[8193] = 0;
      expect(isBinary(buf)).toBe(false);
    });
  });

  describe('listDirectory', () => {
    let listDirectory: (relPath: string) => any;

    beforeEach(async () => {
      const mod = await import('../src/mcp-server.js');
      listDirectory = mod.listDirectory;
    });

    it('returns error for non-existent directory', () => {
      const result = listDirectory('nonexistent');
      expect(result.isError).toBe(true);
    });

    it('returns error for path traversal', () => {
      const result = listDirectory('../etc');
      expect(result.isError).toBe(true);
    });

    it('lists root directory entries', () => {
      const result = listDirectory('.');
      expect(result.isError).toBeUndefined();
      const entries = JSON.parse(result.content[0].text);
      const names = entries.map((e: any) => e.name);
      expect(names).toContain('hello.txt');
      expect(names).toContain('src');
    });
  });

  describe('readFile', () => {
    let readFile: (relPath: string) => any;

    beforeEach(async () => {
      const mod = await import('../src/mcp-server.js');
      readFile = mod.readFile;
    });

    it('reads file content', () => {
      const result = readFile('hello.txt');
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toBe('hello');
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
      // Defense-in-depth env is checked inside writeFile; ensure it's not blocking
      process.env.JAILBOX_WRITABLE = 'true';
    });

    it('writes a new file', () => {
      const result = writeFile('written.txt', 'hi');
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain('Written');
    });

    it('returns error for path traversal', () => {
      const result = writeFile('../etc/evil', 'malicious');
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain('outside the project');
    });

    it('returns error for oversized content', () => {
      const bigContent = 'x'.repeat(11 * 1024 * 1024);
      const result = writeFile('big.txt', bigContent);
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain('too large');
    });

    it('honors JAILBOX_WRITABLE=false defense-in-depth', () => {
      process.env.JAILBOX_WRITABLE = 'false';
      const result = writeFile('should-not-write.txt', 'x');
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain('disabled');
      process.env.JAILBOX_WRITABLE = 'true';
    });
  });
});
