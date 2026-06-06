import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { SovGuardClient, SovGuardAuthError, SovGuardConfig, SCAN_MAX_BYTES } from '../src/sovguard.js';
import { existsSync, readFileSync, mkdirSync, rmSync, writeFileSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { randomBytes, createCipheriv, createDecipheriv } from 'crypto';

describe('SovGuardClient', () => {
  let mockFetch: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    mockFetch = vi.fn();
    vi.stubGlobal('fetch', mockFetch);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  const baseConfig: SovGuardConfig = {
    apiKey: 'sg_test_key',
    apiUrl: 'https://test.sovguard.io',
  };

  describe('scanContent', () => {
    it('returns scan result on success', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        headers: new Headers(),
        json: async () => ({ safe: true, score: 0.05 }),
        text: async () => JSON.stringify({ safe: true, score: 0.05 }),
      });

      const client = new SovGuardClient(baseConfig);
      const result = await client.scanContent(Buffer.from('hello'), 'text/plain');
      expect(result).toEqual({ safe: true, score: 0.05 });
      expect(client.consecutiveFailures).toBe(0);
    });

    it('returns null and increments failures on non-OK response', async () => {
      mockFetch.mockResolvedValueOnce({ ok: false, status: 500 });

      const client = new SovGuardClient(baseConfig);
      const result = await client.scanContent(Buffer.from('hello'), 'text/plain');
      expect(result).toBeNull();
      expect(client.consecutiveFailures).toBe(1);
    });

    it('throws SovGuardAuthError on 401', async () => {
      mockFetch.mockResolvedValueOnce({ ok: false, status: 401 });

      const client = new SovGuardClient(baseConfig);
      await expect(client.scanContent(Buffer.from('hello'), 'text/plain')).rejects.toThrow(SovGuardAuthError);
    });

    it('returns null for oversized content', async () => {
      const client = new SovGuardClient(baseConfig);
      const bigContent = Buffer.alloc(SCAN_MAX_BYTES + 1);
      const result = await client.scanContent(bigContent, 'text/plain');
      expect(result).toBeNull();
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it('returns null when disabled', async () => {
      const client = new SovGuardClient(baseConfig);
      client.disable();
      const result = await client.scanContent(Buffer.from('hello'), 'text/plain');
      expect(result).toBeNull();
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it('resets failure count on success', async () => {
      mockFetch
        .mockResolvedValueOnce({ ok: false, status: 500 })
        .mockResolvedValueOnce({
          ok: true,
          headers: new Headers(),
          json: async () => ({ safe: true, score: 0.0 }),
          text: async () => JSON.stringify({ safe: true, score: 0.0 }),
        });

      const client = new SovGuardClient(baseConfig);
      await client.scanContent(Buffer.from('a'), 'text/plain');
      expect(client.consecutiveFailures).toBe(1);
      await client.scanContent(Buffer.from('b'), 'text/plain');
      expect(client.consecutiveFailures).toBe(0);
    });
  });

  describe('encryption', () => {
    const encKey = randomBytes(32);
    const encConfig: SovGuardConfig = {
      ...baseConfig,
      encryptionKey: encKey.toString('base64'),
    };

    it('sets encrypted flag when valid 32-byte key provided', () => {
      const client = new SovGuardClient(encConfig);
      expect(client.encrypted).toBe(true);
    });

    it('rejects key that is not 32 bytes', () => {
      const badConfig: SovGuardConfig = {
        ...baseConfig,
        encryptionKey: randomBytes(16).toString('base64'), // 16 bytes, not 32
      };
      const client = new SovGuardClient(badConfig);
      expect(client.encrypted).toBe(false);
    });

    it('sends X-Encrypted header and encrypted payload', async () => {
      // Mock server response (encrypted)
      const responseData = JSON.stringify({ safe: true, score: 0.01 });
      const iv = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', encKey, iv);
      const encResp = Buffer.concat([cipher.update(responseData, 'utf8'), cipher.final()]);
      const tag = cipher.getAuthTag();

      mockFetch.mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ 'x-encrypted': 'true' }),
        json: async () => ({
          iv: iv.toString('base64'),
          tag: tag.toString('base64'),
          data: encResp.toString('base64'),
        }),
        text: async () => JSON.stringify({
          iv: iv.toString('base64'),
          tag: tag.toString('base64'),
          data: encResp.toString('base64'),
        }),
      });

      const client = new SovGuardClient(encConfig);
      const result = await client.scanContent(Buffer.from('test content'), 'text/plain');

      // Verify request had X-Encrypted header
      const callArgs = mockFetch.mock.calls[0];
      expect(callArgs[1].headers['X-Encrypted']).toBe('true');

      // Verify response was decrypted
      expect(result).toEqual({ safe: true, score: 0.01 });
    });

    it('handles decryption failure gracefully', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ 'x-encrypted': 'true' }),
        json: async () => ({
          iv: randomBytes(12).toString('base64'),
          tag: randomBytes(16).toString('base64'),
          data: randomBytes(50).toString('base64'), // garbage
        }),
      });

      const client = new SovGuardClient(encConfig);
      const result = await client.scanContent(Buffer.from('test'), 'text/plain');
      expect(result).toBeNull(); // Treated as API failure
      expect(client.consecutiveFailures).toBe(1);
    });
  });

  describe('contentHash', () => {
    it('returns sha256 hash', () => {
      const client = new SovGuardClient(baseConfig);
      const hash = client.contentHash(Buffer.from('hello'));
      expect(hash).toMatch(/^sha256:[a-f0-9]{64}$/);
    });
  });
});

describe('scanContent context + action/warnings', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('includes context in the request body when provided', async () => {
    let sentBody: any = null;
    vi.stubGlobal('fetch', vi.fn(async (_url: string, init: any) => {
      sentBody = JSON.parse(init.body);
      return new Response(JSON.stringify({ safe: true, score: 0, action: 'allow', warnings: [] }), { status: 200 });
    }));
    const client = new SovGuardClient({ apiKey: 'k', apiUrl: 'https://api.test' });
    await client.scanContent(Buffer.from('x'), 'text/plain', { path: '.git/hooks/pre-commit', source: 'other_agent' });
    expect(sentBody.context).toEqual({ path: '.git/hooks/pre-commit', source: 'other_agent' });
  });

  it('omits context when not provided', async () => {
    let sentBody: any = null;
    vi.stubGlobal('fetch', vi.fn(async (_url: string, init: any) => {
      sentBody = JSON.parse(init.body);
      return new Response(JSON.stringify({ safe: true, score: 0 }), { status: 200 });
    }));
    const client = new SovGuardClient({ apiKey: 'k', apiUrl: 'https://api.test' });
    await client.scanContent(Buffer.from('x'), 'text/plain');
    expect('context' in sentBody).toBe(false);
  });

  it('passes through action/warnings from the response', async () => {
    vi.stubGlobal('fetch', vi.fn(async () =>
      new Response(JSON.stringify({ safe: true, score: 0.4, action: 'warn', warnings: ['code:download_and_execute:pipe_to_shell'] }), { status: 200 })));
    const client = new SovGuardClient({ apiKey: 'k', apiUrl: 'https://api.test' });
    const r = await client.scanContent(Buffer.from('curl x | sh'), 'text/plain', { path: 'install.sh' });
    expect(r?.action).toBe('warn');
    expect(r?.warnings).toContain('code:download_and_execute:pipe_to_shell');
  });
});
