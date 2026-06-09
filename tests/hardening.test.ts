import { describe, it, expect, vi } from 'vitest';
import { assertNotRoot } from '../src/cli.js';
import { computeUserSpec, toBindSource } from '../src/docker.js';

describe('assertNotRoot (refuse to run as root)', () => {
  it('exits when effective uid is 0', () => {
    const exitSpy = vi.spyOn(process, 'exit').mockImplementation(((code?: any) => {
      throw new Error(`exit(${code})`);
    }) as any);
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(() => assertNotRoot(() => 0)).toThrow('exit(1)');
    exitSpy.mockRestore();
    errSpy.mockRestore();
  });

  it('does nothing for a normal non-root uid', () => {
    const exitSpy = vi.spyOn(process, 'exit').mockImplementation(((code?: any) => {
      throw new Error(`exit(${code})`);
    }) as any);
    expect(() => assertNotRoot(() => 1000)).not.toThrow();
    exitSpy.mockRestore();
  });

  it('does nothing when getuid is unavailable (e.g. Windows)', () => {
    const exitSpy = vi.spyOn(process, 'exit').mockImplementation(((code?: any) => {
      throw new Error(`exit(${code})`);
    }) as any);
    expect(() => assertNotRoot(undefined)).not.toThrow();
    exitSpy.mockRestore();
  });
});

describe('computeUserSpec (container never runs as root)', () => {
  it('uses the host uid:gid on Linux for a normal user', () => {
    expect(computeUserSpec('linux', 1000, 1000)).toBe('1000:1000');
    expect(computeUserSpec('linux', 1500, 20)).toBe('1500:20');
  });

  it('never returns a root spec on Linux even if uid is 0', () => {
    const spec = computeUserSpec('linux', 0, 0);
    expect(spec).not.toMatch(/^0:/);
    expect(spec).toBe('1000:1000');
  });

  it('falls back to non-root for out-of-range / unknown uid on Linux', () => {
    expect(computeUserSpec('linux', undefined, undefined)).toBe('1000:1000');
    expect(computeUserSpec('linux', 70000, 70000)).toBe('1000:1000');
    expect(computeUserSpec('linux', -1, -1)).toBe('1000:1000');
  });

  it('forces the image non-root user off-Linux (Docker Desktop VM)', () => {
    expect(computeUserSpec('darwin', 501, 20)).toBe('1000:1000');
    expect(computeUserSpec('win32', undefined, undefined)).toBe('1000:1000');
  });

  it('never returns a root or empty spec for any input', () => {
    for (const p of ['linux', 'darwin', 'win32'] as const) {
      for (const uid of [undefined, 0, 1, 1000, 65536, -5, 99999]) {
        const spec = computeUserSpec(p, uid as any, uid as any);
        expect(spec).toBeTruthy();
        expect(spec.startsWith('0:')).toBe(false);
      }
    }
  });
});

describe('toBindSource (cross-platform bind mount sources)', () => {
  it('passes POSIX paths through unchanged on Linux/macOS', () => {
    expect(toBindSource('/home/me/proj', 'linux')).toBe('/home/me/proj');
    expect(toBindSource('/Users/me/proj', 'darwin')).toBe('/Users/me/proj');
  });

  it('does NOT rewrite backslashes off-Windows (valid filename chars)', () => {
    // A literal backslash in a Linux filename must survive untouched.
    expect(toBindSource('/home/me/weird\\name', 'linux')).toBe('/home/me/weird\\name');
  });

  it('converts a Windows drive path to the colon-free Docker form', () => {
    expect(toBindSource('C:\\Users\\me\\proj', 'win32')).toBe('//c/Users/me/proj');
    expect(toBindSource('D:\\a\\b', 'win32')).toBe('//d/a/b');
  });

  it('handles forward-slash Windows input and lowercases the drive', () => {
    expect(toBindSource('C:/Users/me/proj', 'win32')).toBe('//c/Users/me/proj');
    expect(toBindSource('E:/data', 'win32')).toBe('//e/data');
  });

  it('produces a source with NO colon so bind-string splitting is safe', () => {
    const src = toBindSource('C:\\Users\\me\\proj', 'win32');
    const bind = `${src}:/jailbox:ro`;
    // Docker splits binds on ':' — source segment must contain none.
    expect(src.includes(':')).toBe(false);
    expect(bind.split(':')).toEqual(['//c/Users/me/proj', '/jailbox', 'ro']);
  });

  it('normalizes UNC paths to forward slashes (colon-free)', () => {
    expect(toBindSource('\\\\server\\share\\x', 'win32')).toBe('//server/share/x');
  });
});
