import { StorageAdapter } from './StorageAdapter';

const SDK_SALT = 'sdk-simple-auth-v1-salt';
const DEFAULT_SECRET = 'sdk-simple-auth-v1';
const PBKDF2_ITERATIONS = 100_000;
const IV_LENGTH = 12;

function getCrypto(): SubtleCrypto | null {
  if (typeof globalThis !== 'undefined' && globalThis.crypto?.subtle) {
    return globalThis.crypto.subtle;
  }
  return null;
}

function base64Encode(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64Decode(str: string): Uint8Array {
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

async function deriveKey(secret: string, subtle: SubtleCrypto): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const keyMaterial = await subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  return subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: enc.encode(SDK_SALT),
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Decorator adapter that transparently encrypts/decrypts values using AES-GCM 256-bit.
 * Wraps any StorageAdapter. Falls back to passthrough when Web Crypto API is unavailable (SSR).
 * Migration: if decryption fails on a stored value, returns it as-is (plain text migration path).
 */
export class EncryptedStorageAdapter implements StorageAdapter {
  private inner: StorageAdapter;
  private keyPromise: Promise<CryptoKey> | null;
  private subtle: SubtleCrypto | null;

  constructor(inner: StorageAdapter, secret: string = DEFAULT_SECRET) {
    this.inner = inner;
    this.subtle = getCrypto();

    if (this.subtle) {
      this.keyPromise = deriveKey(secret, this.subtle);
    } else {
      this.keyPromise = null;
      console.warn('[sdk-simple-auth] Web Crypto API unavailable — encryption disabled, storing unencrypted.');
    }
  }

  async setItem(key: string, value: string): Promise<void> {
    if (!this.subtle || !this.keyPromise) {
      return this.inner.setItem(key, value);
    }

    const cryptoKey = await this.keyPromise;
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_LENGTH));
    const enc = new TextEncoder();

    const ciphertext = await this.subtle.encrypt(
      { name: 'AES-GCM', iv },
      cryptoKey,
      enc.encode(value)
    );

    const combined = new Uint8Array(IV_LENGTH + ciphertext.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(ciphertext), IV_LENGTH);

    return this.inner.setItem(key, base64Encode(combined));
  }

  async getItem(key: string): Promise<string | null> {
    const stored = await this.inner.getItem(key);

    if (stored === null) {
      return null;
    }

    if (!this.subtle || !this.keyPromise) {
      return stored;
    }

    try {
      const cryptoKey = await this.keyPromise;
      const combined = base64Decode(stored);

      if (combined.length <= IV_LENGTH) {
        // Too short to be encrypted — treat as plain text (migration)
        return stored;
      }

      const iv = combined.slice(0, IV_LENGTH);
      const ciphertext = combined.slice(IV_LENGTH);

      const plainBuffer = await this.subtle.decrypt(
        { name: 'AES-GCM', iv },
        cryptoKey,
        ciphertext
      );

      return new TextDecoder().decode(plainBuffer);
    } catch {
      // Decryption failed — legacy plain text value, return as-is for migration
      return stored;
    }
  }

  async removeItem(key: string): Promise<void> {
    return this.inner.removeItem(key);
  }

  async clear(): Promise<void> {
    return this.inner.clear();
  }
}
