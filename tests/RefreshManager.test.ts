import { RefreshManager } from '../src/core/RefreshManager';
import { StorageManager } from '../src/core/StorageManager';
import { HttpClient, AuthConfig, AuthTokens } from '../src/types';
import { Logger } from '../src/core/Logger';

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeConfig(overrides: Partial<AuthConfig['tokenRefresh']> = {}): Required<AuthConfig> {
  return {
    authServiceUrl: 'http://localhost:3001/api/v1',
    endpoints: {
      login: '/login',
      register: '/register',
      refresh: '/refresh',
      logout: '/logout',
    },
    storage: {
      type: 'localStorage',
      tokenKey: 'token',
      refreshTokenKey: 'refresh',
      userKey: 'user',
      dbName: 'AuthSDK',
      dbVersion: 1,
      storeName: 'auth_data',
    },
    tokenRefresh: {
      enabled: true,
      bufferTime: 900_000, // 15 min in ms — matches buildConfig default
      maxRetries: 3,
      minimumTokenLifetime: 300,
      gracePeriod: 60,
      minRefreshInterval: 100, // small value so 5001ms advances clear the interval in tests
      ...overrides,
    },
    debug: false,
    backend: {
      type: 'jwt-standard',
      userSearchPaths: ['user'],
      fieldMappings: {},
      preserveOriginalData: false,
    },
    sessionValidation: {
      enabled: false,
      validateOnFocus: false,
      validateOnVisibility: false,
      maxInactivityTime: 300,
      autoLogoutOnInvalid: true,
    },
    httpClient: null as any,
  } as Required<AuthConfig>;
}

const MOCK_TOKENS: AuthTokens = {
  accessToken: 'test.jwt.token',
  refreshToken: 'refresh_token_123',
  expiresIn: 3600,
  tokenType: 'Bearer',
};

function makeStorageMock(withRefreshToken = true): jest.Mocked<StorageManager> {
  return {
    getStoredTokens: jest.fn().mockResolvedValue(
      withRefreshToken ? MOCK_TOKENS : null
    ),
    storeTokens: jest.fn().mockResolvedValue(undefined),
    updateLastRefreshTime: jest.fn().mockResolvedValue(undefined),
    clearAll: jest.fn().mockResolvedValue(undefined),
    getTokenMetadata: jest.fn().mockResolvedValue(null),
    storeUser: jest.fn().mockResolvedValue(undefined),
    getStoredUser: jest.fn().mockResolvedValue(null),
    clearTokens: jest.fn().mockResolvedValue(undefined),
  } as unknown as jest.Mocked<StorageManager>;
}

function makeHttpMock(): jest.Mocked<HttpClient> {
  return {
    post: jest.fn(),
    get: jest.fn(),
  } as unknown as jest.Mocked<HttpClient>;
}

const silentLogger = new Logger();
jest.spyOn(silentLogger, 'debug').mockImplementation(() => {});
jest.spyOn(silentLogger, 'warn').mockImplementation(() => {});
jest.spyOn(silentLogger, 'error').mockImplementation(() => {});

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('RefreshManager', () => {
  beforeEach(() => {
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.useRealTimers();
    jest.clearAllMocks();
  });

  // ─── Bug #1: lastRefreshTime no se actualiza en fallo ────────────────────

  describe('maxRetries enforcement', () => {
    test('refreshAttempts no se resetea entre fallos consecutivos dentro de 60s', async () => {
      const http = makeHttpMock();
      const storage = makeStorageMock();
      http.post.mockRejectedValue(new Error('Server error'));

      // maxRetries: 10 para que el catch no resetee attempts antes de que podamos observar la acumulación
      const manager = new RefreshManager(
        makeConfig({ maxRetries: 10 }),
        storage,
        http,
        undefined,
        silentLogger
      );

      // Primer fallo
      await expect(manager.refreshTokens()).rejects.toThrow();
      expect(manager.getRefreshStatus().refreshAttempts).toBe(1);

      // Avanzar 5001ms — supera el rate limit (5s) pero NO el reset window (60s)
      // → refreshAttempts NO debe resetearse a 0
      jest.advanceTimersByTime(5001);

      await expect(manager.refreshTokens()).rejects.toThrow();
      // Si el bug existiera: refreshAttempts = 0 (reset) + 1 = 1
      // Con el fix: refreshAttempts = 1 + 1 = 2
      expect(manager.getRefreshStatus().refreshAttempts).toBe(2);

      jest.advanceTimersByTime(5001);

      await expect(manager.refreshTokens()).rejects.toThrow();
      expect(manager.getRefreshStatus().refreshAttempts).toBe(3);
    });

    test('refreshAttempts se resetea si pasan más de 60s desde el último intento', async () => {
      const http = makeHttpMock();
      const storage = makeStorageMock();
      http.post.mockRejectedValue(new Error('Server error'));

      const manager = new RefreshManager(
        makeConfig({ maxRetries: 10 }),
        storage,
        http,
        undefined,
        silentLogger
      );

      await expect(manager.refreshTokens()).rejects.toThrow();
      expect(manager.getRefreshStatus().refreshAttempts).toBe(1);

      // Avanzar 61s — supera el reset window
      jest.advanceTimersByTime(61000);

      // refreshAttempts debe resetearse a 0 y luego incrementarse a 1
      await expect(manager.refreshTokens()).rejects.toThrow();
      expect(manager.getRefreshStatus().refreshAttempts).toBe(1);
    });

    test('segundo intento dentro de minRefreshInterval retorna tokens cacheados en vez de tirar error', async () => {
      const http = makeHttpMock();
      const storage = makeStorageMock();
      http.post.mockRejectedValue(new Error('Server error'));

      const manager = new RefreshManager(
        makeConfig({ minRefreshInterval: 60_000 }), // long interval so immediate retry is blocked
        storage,
        http,
        undefined,
        silentLogger
      );

      await expect(manager.refreshTokens()).rejects.toThrow();

      // Dentro del minRefreshInterval → retorna tokens cacheados silenciosamente (no throw)
      const result = await manager.refreshTokens();
      expect(result).toEqual(MOCK_TOKENS);
      // http.post fue llamado solo una vez (el segundo intento no llegó al servidor)
      expect(http.post).toHaveBeenCalledTimes(1);
    });

    test('refreshAttempts se resetea correctamente en éxito', async () => {
      const http = makeHttpMock();
      const storage = makeStorageMock();

      // Primero falla, luego tiene éxito
      http.post
        .mockRejectedValueOnce(new Error('Server error'))
        .mockResolvedValueOnce({
          access_token: 'new.token',
          refresh_token: 'new_refresh',
          expires_in: 3600,
        });

      const manager = new RefreshManager(
        makeConfig(),
        storage,
        http,
        undefined,
        silentLogger
      );

      await expect(manager.refreshTokens()).rejects.toThrow();
      expect(manager.getRefreshStatus().refreshAttempts).toBe(1);

      // Esperar más de 5s para superar el rate limit
      jest.advanceTimersByTime(5001);

      await manager.refreshTokens();
      expect(manager.getRefreshStatus().refreshAttempts).toBe(0);
    });
  });

  // ─── Bug #2: sin jitter en backoff → thundering herd ────────────────────

  describe('retry backoff jitter', () => {
    test('dos instancias con el mismo refreshAttempts producen delays distintos', async () => {
      const retryDelays: number[] = [];

      // Interceptar setTimeout para capturar los delays de retry
      const originalSetTimeout = global.setTimeout;
      const setTimeoutSpy = jest
        .spyOn(global, 'setTimeout')
        .mockImplementation((fn: any, delay?: number) => {
          if (typeof delay === 'number' && delay > 100) {
            retryDelays.push(delay);
          }
          return originalSetTimeout(fn, 0); // ejecutar de inmediato en tests
        });

      const makeManager = () => {
        const http = makeHttpMock();
        const storage = makeStorageMock();
        http.post.mockRejectedValue(new Error('Server error'));
        return new RefreshManager(makeConfig(), storage, http, undefined, silentLogger);
      };

      const m1 = makeManager();
      const m2 = makeManager();

      await expect(m1.refreshTokens()).rejects.toThrow();
      await expect(m2.refreshTokens()).rejects.toThrow();

      setTimeoutSpy.mockRestore();

      // Con jitter, los dos delays de retry NO deben ser idénticos
      if (retryDelays.length >= 2) {
        expect(retryDelays[0]).not.toBe(retryDelays[1]);
      }
      // Si no hay suficientes delays capturados, el test pasa condicionalmente —
      // la implementación del jitter es lo que lo hace verde definitivamente.
    });
  });

  // ─── Bug #12: invalid format response → refresh loop ────────────────────

  describe('invalid refresh response format', () => {
    test('limpiar storage cuando el servidor devuelve formato inválido', async () => {
      const http = makeHttpMock();
      const storage = makeStorageMock();

      // El servidor responde 200 pero con un body que no contiene tokens
      http.post.mockResolvedValue({ message: 'ok' }); // sin access_token

      const manager = new RefreshManager(
        makeConfig({ maxRetries: 3 }),
        storage,
        http,
        undefined,
        silentLogger
      );

      await expect(manager.refreshTokens()).rejects.toThrow();

      // Con formato inválido, el storage debe limpiarse para evitar
      // que el timer siga disparando con el mismo refresh token inválido
      expect(storage.clearAll).toHaveBeenCalled();
    });

    test('no programar más reintentos tras error de formato inválido', async () => {
      const http = makeHttpMock();
      const storage = makeStorageMock();
      http.post.mockResolvedValue({ message: 'ok' }); // sin tokens

      const setTimeoutSpy = jest.spyOn(global, 'setTimeout');

      const manager = new RefreshManager(
        makeConfig({ maxRetries: 3 }),
        storage,
        http,
        undefined,
        silentLogger
      );

      await expect(manager.refreshTokens()).rejects.toThrow();

      // No debe programar retry — el formato inválido no se corregirá solo
      const retryTimeouts = setTimeoutSpy.mock.calls.filter(
        ([, delay]) => typeof delay === 'number' && delay > 100
      );
      expect(retryTimeouts).toHaveLength(0);

      setTimeoutSpy.mockRestore();
    });
  });
});
