import { EncryptedStorageAdapter } from '../src/storage/EncryptedStorageAdapter';
import { LocalStorageAdapter } from '../src/storage/LocalStorageAdapter';

const localStorageMock = {
  getItem: jest.fn(),
  setItem: jest.fn(),
  removeItem: jest.fn(),
  clear: jest.fn(),
};
Object.defineProperty(window, 'localStorage', { value: localStorageMock, writable: true });

describe('EncryptedStorageAdapter', () => {
  let inner: LocalStorageAdapter;
  let warnSpy: jest.SpyInstance;

  beforeEach(() => {
    jest.clearAllMocks();
    localStorageMock.getItem.mockReturnValue(null);
    inner = new LocalStorageAdapter();
    warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    warnSpy.mockRestore();
  });

  // ─── Seguridad: secret por defecto ──────────────────────────────────────

  describe('default secret warning', () => {
    test('lanza advertencia cuando se usa el secret por defecto', () => {
      new EncryptedStorageAdapter(inner); // sin secret → usa DEFAULT_SECRET

      const defaultWarnCalls = warnSpy.mock.calls.filter(args =>
        String(args[0]).toLowerCase().includes('default')
      );
      expect(defaultWarnCalls.length).toBeGreaterThan(0);
    });

    test('NO lanza advertencia de default secret cuando se provee un secret personalizado', () => {
      new EncryptedStorageAdapter(inner, 'mi-secret-unico-de-produccion');

      const defaultWarnCalls = warnSpy.mock.calls.filter(args =>
        String(args[0]).toLowerCase().includes('default')
      );
      expect(defaultWarnCalls).toHaveLength(0);
    });

    test('el mensaje incluye la palabra "secret" para guiar al usuario', () => {
      new EncryptedStorageAdapter(inner);

      const allWarnMessages = warnSpy.mock.calls.map(args => String(args[0]));
      const hasSecretMention = allWarnMessages.some(msg => /secret/i.test(msg));
      expect(hasSecretMention).toBe(true);
    });
  });
});
