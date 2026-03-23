import 'fake-indexeddb/auto';
import { IndexedDBAdapter } from '../src/storage/IndexedDBAdapter';

// fake-indexeddb v6 uses structuredClone internally; jsdom doesn't expose it
// even though Node 17+ has it globally — polyfill to bridge the gap.
if (typeof globalThis.structuredClone === 'undefined') {
  globalThis.structuredClone = (obj: any) => JSON.parse(JSON.stringify(obj));
}

// fake-indexeddb/auto replaces window.indexedDB with a real in-memory
// implementation, so these tests exercise the actual IDBDatabase code paths.

describe('IndexedDBAdapter', () => {
  let adapter: IndexedDBAdapter;

  beforeEach(() => {
    // Fresh store per test — different dbName avoids cross-test bleed
    adapter = new IndexedDBAdapter(`TestDB_${Math.random()}`, 1, 'auth_store');
  });

  test('setItem and getItem round-trip', async () => {
    await adapter.setItem('token', 'abc123');
    const value = await adapter.getItem('token');
    expect(value).toBe('abc123');
  });

  test('getItem returns null for missing key', async () => {
    const value = await adapter.getItem('nonexistent');
    expect(value).toBeNull();
  });

  test('setItem overwrites existing value', async () => {
    await adapter.setItem('token', 'first');
    await adapter.setItem('token', 'second');
    const value = await adapter.getItem('token');
    expect(value).toBe('second');
  });

  test('removeItem deletes a key', async () => {
    await adapter.setItem('token', 'abc123');
    await adapter.removeItem('token');
    const value = await adapter.getItem('token');
    expect(value).toBeNull();
  });

  test('removeItem on missing key does not throw', async () => {
    await expect(adapter.removeItem('ghost')).resolves.toBeUndefined();
  });

  test('clear removes all keys', async () => {
    await adapter.setItem('token', 'abc');
    await adapter.setItem('refresh', 'xyz');
    await adapter.clear();
    expect(await adapter.getItem('token')).toBeNull();
    expect(await adapter.getItem('refresh')).toBeNull();
  });

  test('multiple keys coexist independently', async () => {
    await adapter.setItem('token', 'tok');
    await adapter.setItem('refresh', 'ref');
    await adapter.setItem('user', '{"id":"1"}');

    expect(await adapter.getItem('token')).toBe('tok');
    expect(await adapter.getItem('refresh')).toBe('ref');
    expect(await adapter.getItem('user')).toBe('{"id":"1"}');
  });

  test('rejects with error when IndexedDB is unavailable', async () => {
    // Simulate environment without indexedDB
    const original = window.indexedDB;
    Object.defineProperty(window, 'indexedDB', { value: undefined, writable: true, configurable: true });

    const brokenAdapter = new IndexedDBAdapter('TestDB', 1, 'auth_store');
    await expect(brokenAdapter.getItem('key')).rejects.toThrow('IndexedDB not supported');

    Object.defineProperty(window, 'indexedDB', { value: original, writable: true, configurable: true });
  });
});
