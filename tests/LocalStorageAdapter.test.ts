import { LocalStorageAdapter } from '../src/storage/LocalStorageAdapter';

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('LocalStorageAdapter', () => {
  let adapter: LocalStorageAdapter;
  const localStorageMock = {
    getItem: jest.fn(),
    setItem: jest.fn(),
    removeItem: jest.fn(),
    clear: jest.fn(),
  };

  beforeEach(() => {
    jest.clearAllMocks();
    Object.defineProperty(window, 'localStorage', {
      value: localStorageMock,
      writable: true,
    });
    adapter = new LocalStorageAdapter();
  });

  // ─── Bug #3: sin manejo de errores ──────────────────────────────────────

  describe('error handling', () => {
    test('setItem no propaga QuotaExceededError', async () => {
      localStorageMock.setItem.mockImplementation(() => {
        const err = new DOMException('QuotaExceededError');
        Object.defineProperty(err, 'name', { value: 'QuotaExceededError' });
        throw err;
      });

      // No debe reventar
      await expect(adapter.setItem('key', 'value')).resolves.not.toThrow();
    });

    test('getItem no propaga SecurityError (modo privado Firefox)', async () => {
      localStorageMock.getItem.mockImplementation(() => {
        throw new DOMException('SecurityError: The operation is insecure.');
      });

      const result = await adapter.getItem('key');
      expect(result).toBeNull();
    });

    test('removeItem no propaga errores inesperados', async () => {
      localStorageMock.removeItem.mockImplementation(() => {
        throw new Error('Unexpected storage error');
      });

      await expect(adapter.removeItem('key')).resolves.not.toThrow();
    });

    test('clear no propaga errores inesperados', async () => {
      localStorageMock.clear.mockImplementation(() => {
        throw new Error('Unexpected storage error');
      });

      await expect(adapter.clear()).resolves.not.toThrow();
    });
  });

  describe('comportamiento normal', () => {
    test('setItem y getItem funcionan correctamente', async () => {
      localStorageMock.setItem.mockImplementation(() => {});
      localStorageMock.getItem.mockReturnValue('stored-value');

      await adapter.setItem('key', 'stored-value');
      const result = await adapter.getItem('key');

      expect(localStorageMock.setItem).toHaveBeenCalledWith('key', 'stored-value');
      expect(result).toBe('stored-value');
    });

    test('removeItem llama a localStorage.removeItem', async () => {
      localStorageMock.removeItem.mockImplementation(() => {});
      await adapter.removeItem('key');
      expect(localStorageMock.removeItem).toHaveBeenCalledWith('key');
    });

    test('getItem retorna null si no existe la clave', async () => {
      localStorageMock.getItem.mockReturnValue(null);
      const result = await adapter.getItem('nonexistent');
      expect(result).toBeNull();
    });
  });
});
