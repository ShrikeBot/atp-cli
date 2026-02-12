import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm, writeFile, readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir, homedir } from 'node:os';
import { generateEd25519, saveKeypair, ensureKeysDir } from '../src/lib/keys.js';
import { toBase64url } from '../src/lib/encoding.js';
import { computeFingerprint } from '../src/lib/fingerprint.js';
import { execFileSync } from 'node:child_process';

const CLI = join(import.meta.dirname, '..', 'dist', 'index.js');
const KEYS_DIR = join(homedir(), '.atp', 'keys');

function run(...args: string[]): string {
  return execFileSync('node', [CLI, ...args], { encoding: 'utf8', timeout: 10000 }).trim();
}

function runFail(...args: string[]): string {
  try {
    execFileSync('node', [CLI, ...args], { encoding: 'utf8', timeout: 10000, stdio: 'pipe' });
    throw new Error('Expected command to fail');
  } catch (e: any) {
    return (e.stderr || e.stdout || '').toString().trim();
  }
}

describe('key commands', () => {
  let tmpDir: string;
  let fingerprint: string;

  beforeEach(async () => {
    tmpDir = await mkdtemp(join(tmpdir(), 'atp-key-test-'));
    // Generate a keypair and save a raw hex key file for import testing
    const { privateKey, publicKey } = generateEd25519();
    fingerprint = computeFingerprint(publicKey, 'ed25519');
    // Write hex format key file
    await writeFile(join(tmpDir, 'test.hex'), privateKey.toString('hex'));
    // Write JSON format key file
    await writeFile(join(tmpDir, 'test.json'), JSON.stringify({ privateKey: toBase64url(privateKey) }));
    // Clean up any existing key with this fingerprint
    try { await rm(join(KEYS_DIR, `${fingerprint}.json`)); } catch {}
  });

  afterEach(async () => {
    await rm(tmpDir, { recursive: true });
    try { await rm(join(KEYS_DIR, `${fingerprint}.json`)); } catch {}
  });

  it('imports a hex key file and prints fingerprint', () => {
    const out = run('key', 'import', '--private-key', join(tmpDir, 'test.hex'));
    expect(out).toBe(fingerprint);
  });

  it('imports a JSON key file', () => {
    const out = run('key', 'import', '--private-key', join(tmpDir, 'test.json'));
    expect(out).toBe(fingerprint);
  });

  it('errors on duplicate import without --force', () => {
    run('key', 'import', '--private-key', join(tmpDir, 'test.hex'));
    const err = runFail('key', 'import', '--private-key', join(tmpDir, 'test.hex'));
    expect(err).toContain('already exists');
  });

  it('allows duplicate import with --force', () => {
    run('key', 'import', '--private-key', join(tmpDir, 'test.hex'));
    const out = run('key', 'import', '--private-key', join(tmpDir, 'test.hex'), '--force');
    expect(out).toBe(fingerprint);
  });

  it('lists keys including the imported one', () => {
    run('key', 'import', '--private-key', join(tmpDir, 'test.hex'));
    const out = run('key', 'list');
    expect(out).toContain(fingerprint);
    expect(out).toContain('ed25519');
  });

  it('exports key as json', () => {
    run('key', 'import', '--private-key', join(tmpDir, 'test.hex'));
    const out = run('key', 'export', fingerprint);
    const data = JSON.parse(out);
    expect(data.fingerprint).toBe(fingerprint);
    expect(data.privateKey).toBeDefined();
    expect(data.publicKey).toBeDefined();
  });

  it('exports public-only as json', () => {
    run('key', 'import', '--private-key', join(tmpDir, 'test.hex'));
    const out = run('key', 'export', fingerprint, '--public-only');
    const data = JSON.parse(out);
    expect(data.publicKey).toBeDefined();
    expect(data.privateKey).toBeUndefined();
  });

  it('exports key as hex', () => {
    run('key', 'import', '--private-key', join(tmpDir, 'test.hex'));
    const out = run('key', 'export', fingerprint, '--format', 'hex');
    expect(out).toMatch(/^[0-9a-f]{64}$/);
  });

  it('deletes key with --force', () => {
    run('key', 'import', '--private-key', join(tmpDir, 'test.hex'));
    const out = run('key', 'delete', fingerprint, '--force');
    expect(out).toContain('Deleted');
  });

  it('refuses to delete without --force', () => {
    run('key', 'import', '--private-key', join(tmpDir, 'test.hex'));
    const err = runFail('key', 'delete', fingerprint);
    expect(err).toContain('--force');
  });
});
