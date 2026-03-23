import { AuthSDK } from '../src/core/AuthSDK';
import { LocalStorageAdapter } from '../src/storage/LocalStorageAdapter';
import { IndexedDBAdapter } from '../src/storage/IndexedDBAdapter';

// Mock fetch globally
global.fetch = jest.fn();

// In-memory localStorage mock that actually persists set/get
const localStorageStore: Record<string, string> = {};
const localStorageMock = {
  getItem: jest.fn((key: string) => localStorageStore[key] ?? null),
  setItem: jest.fn((key: string, value: string) => { localStorageStore[key] = value; }),
  removeItem: jest.fn((key: string) => { delete localStorageStore[key]; }),
  clear: jest.fn(() => { Object.keys(localStorageStore).forEach(k => delete localStorageStore[k]); }),
};
Object.defineProperty(window, 'localStorage', {
  value: localStorageMock
});

// Mock IndexedDB
const indexedDBMock = {
  open: jest.fn(),
  deleteDatabase: jest.fn(),
};
Object.defineProperty(window, 'indexedDB', {
  value: indexedDBMock
});

// createDefaultHttpClient uses response.text() for success and response.json() for errors
function mockFetchSuccess(data: any) {
  return {
    ok: true,
    text: async () => JSON.stringify(data),
    json: async () => data,
  };
}

function mockFetchError(status: number, data: any) {
  return {
    ok: false,
    status,
    statusText: 'Error',
    json: async () => data,
    text: async () => JSON.stringify(data),
  };
}

describe('Enhanced AuthSDK Tests', () => {
  let authSDK: AuthSDK;

  beforeEach(() => {
    // Clear in-memory store and reset call history
    localStorageMock.clear();
    jest.clearAllMocks();
    // Restore implementations after clearAllMocks resets them
    localStorageMock.getItem.mockImplementation((key: string) => localStorageStore[key] ?? null);
    localStorageMock.setItem.mockImplementation((key: string, value: string) => { localStorageStore[key] = value; });
    localStorageMock.removeItem.mockImplementation((key: string) => { delete localStorageStore[key]; });
    localStorageMock.clear.mockImplementation(() => { Object.keys(localStorageStore).forEach(k => delete localStorageStore[k]); });

    authSDK = new AuthSDK({
      authServiceUrl: 'http://localhost:3001/api/v1',
      endpoints: {
        login: '/login',
        register: '/register',
        refresh: '/refresh',
        logout: '/logout',
      },
      storage: {
        type: 'localStorage',
        tokenKey: 'test_auth_token',
        refreshTokenKey: 'test_auth_refresh_token',
        userKey: 'test_auth_user',
      },
      tokenRefresh: {
        enabled: true,
        bufferTime: 30,
        maxRetries: 3,
      }
    });
  });

  afterEach(() => {
    authSDK.logout();
  });

  describe('Initialization', () => {
    test('should initialize correctly with default config', () => {
      expect(authSDK).toBeDefined();
      expect(authSDK.getState().isAuthenticated).toBe(false);
      expect(authSDK.getCurrentUser()).toBeNull();
      expect(authSDK.getAccessToken()).toBeNull();
    });

    test('should restore session from storage', async () => {
      const mockTokens = {
        accessToken: '1|stored_access_token',
        refreshToken: 'stored_refresh_token',
        expiresIn: 3600,
        tokenType: 'Bearer',
      };

      const mockUser = {
        id: '123',
        email: 'test@example.com',
        name: 'Test User',
      };

      // Seed the in-memory store directly
      localStorageStore['test_auth_token'] = JSON.stringify({
        ...mockTokens,
        storedAt: Math.floor(Date.now() / 1000) - 100,
      });
      localStorageStore['test_auth_refresh_token'] = mockTokens.refreshToken;
      localStorageStore['test_auth_user'] = JSON.stringify(mockUser);

      const newSDK = new AuthSDK({
        authServiceUrl: 'http://localhost:3001/api/v1',
        storage: {
          type: 'localStorage',
          tokenKey: 'test_auth_token',
          refreshTokenKey: 'test_auth_refresh_token',
          userKey: 'test_auth_user',
        },
        sessionValidation: {
          validateOnStartup: false,
        },
      });

      await newSDK.ready;

      expect(newSDK.getState().isAuthenticated).toBe(true);
      expect(newSDK.getCurrentUser()).toMatchObject(mockUser);
    });
  });

  describe('Authentication Flow', () => {
    test('should login successfully with tokens', async () => {
      const credentials = { email: 'test@example.com', password: 'password123' };
      const mockResponse = {
        access_token: '1|new_access_token',
        refresh_token: 'new_refresh_token',
        expires_in: 3600,
        token_type: 'Bearer',
        user: {
          id: '123',
          email: 'test@example.com',
          name: 'Test User',
        },
      };

      (global.fetch as jest.Mock).mockResolvedValueOnce(mockFetchSuccess(mockResponse));

      const user = await authSDK.login(credentials);

      expect(user).toMatchObject(mockResponse.user);
      expect(authSDK.getState().isAuthenticated).toBe(true);
      expect(authSDK.getAccessToken()).toBe(mockResponse.access_token);
      expect(localStorageMock.setItem).toHaveBeenCalled();
    });

    test('should register successfully with immediate login', async () => {
      const userData = {
        email: 'newuser@example.com',
        password: 'password123',
        name: 'New User',
      };

      const mockResponse = {
        access_token: '1|new_access_token_register',
        refresh_token: 'new_refresh_token',
        user: {
          id: '456',
          email: 'newuser@example.com',
          name: 'New User',
        },
      };

      (global.fetch as jest.Mock).mockResolvedValueOnce(mockFetchSuccess(mockResponse));

      const user = await authSDK.register(userData);

      expect(user).toMatchObject(mockResponse.user);
      expect(authSDK.getState().isAuthenticated).toBe(true);
      expect(authSDK.getAccessToken()).toBe(mockResponse.access_token);
    });

    test('should register successfully without immediate login', async () => {
      const userData = {
        email: 'newuser@example.com',
        password: 'password123',
        name: 'New User',
      };

      const mockResponse = {
        message: 'User created successfully',
        user: {
          id: '456',
          email: 'newuser@example.com',
          name: 'New User',
        },
      };

      (global.fetch as jest.Mock).mockResolvedValueOnce(mockFetchSuccess(mockResponse));

      const user = await authSDK.register(userData);

      expect(user).toMatchObject(mockResponse.user);
      expect(authSDK.getState().isAuthenticated).toBe(false);
      expect(authSDK.getAccessToken()).toBeNull();
    });

    test('should logout successfully', async () => {
      await loginUser();

      (global.fetch as jest.Mock).mockResolvedValueOnce(
        mockFetchSuccess({ message: 'Logged out successfully' })
      );

      await authSDK.logout();

      expect(authSDK.getState().isAuthenticated).toBe(false);
      expect(authSDK.getCurrentUser()).toBeNull();
      expect(authSDK.getAccessToken()).toBeNull();
      expect(localStorageMock.removeItem).toHaveBeenCalled();
    });
  });

  describe('Token Management', () => {
    beforeEach(async () => {
      await loginUser();
    });

    test('should refresh tokens successfully', async () => {
      const mockRefreshResponse = {
        access_token: '1|refreshed_access_token',
        refresh_token: 'new_refresh_token',
        expires_in: 3600,
      };

      (global.fetch as jest.Mock).mockResolvedValueOnce(mockFetchSuccess(mockRefreshResponse));

      const tokens = await authSDK.refreshTokens();

      expect(tokens.accessToken).toBe(mockRefreshResponse.access_token);
      expect(authSDK.getAccessToken()).toBe(mockRefreshResponse.access_token);
    });

    test('should get valid access token', async () => {
      const token = await authSDK.getValidAccessToken();
      expect(token).toBeTruthy();
      expect(typeof token).toBe('string');
    });

    test('should get auth headers', async () => {
      const headers = await authSDK.getAuthHeaders();
      expect(headers).toHaveProperty('Authorization');
      expect(headers.Authorization).toMatch(/^Bearer /);
    });

    test('should handle token refresh failure', async () => {
      (global.fetch as jest.Mock).mockRejectedValueOnce(new Error('Refresh failed'));

      await expect(authSDK.refreshTokens()).rejects.toThrow('Refresh failed');
    });
  });

  describe('State Management', () => {
    test('should notify state change listeners', async () => {
      const mockListener = jest.fn();
      const unsubscribe = authSDK.onAuthStateChanged(mockListener);

      expect(mockListener).toHaveBeenCalledWith(authSDK.getState());

      await loginUser();

      expect(mockListener).toHaveBeenCalledWith(
        expect.objectContaining({
          isAuthenticated: true,
          user: expect.any(Object),
        })
      );

      unsubscribe();
    });

    test('should get session info', async () => {
      await loginUser();

      const sessionInfo = await authSDK.getSessionInfo();
      expect(sessionInfo).toEqual({
        isValid: expect.any(Boolean),
        user: expect.any(Object),
        tokenType: 'Bearer',
        expiresIn: expect.any(Number),
        refreshAvailable: expect.any(Boolean),
        sessionId: expect.any(String),
      });
    });
  });

  describe('Error Handling', () => {
    test('should handle login failure', async () => {
      (global.fetch as jest.Mock).mockResolvedValueOnce(
        mockFetchError(401, { message: 'Invalid credentials' })
      );

      await expect(authSDK.login({
        email: 'test@example.com',
        password: 'wrongpassword',
      })).rejects.toThrow('Invalid credentials');

      expect(authSDK.getState().isAuthenticated).toBe(false);
      expect(authSDK.getState().error).toBeTruthy();
    });

    test('should handle network errors', async () => {
      (global.fetch as jest.Mock).mockRejectedValueOnce(new Error('Network error'));

      await expect(authSDK.login({
        email: 'test@example.com',
        password: 'password123',
      })).rejects.toThrow('Network error');
    });
  });

  describe('Storage Adapters', () => {
    test('should work with localStorage adapter', () => {
      const adapter = new LocalStorageAdapter();
      expect(adapter).toBeDefined();
    });

    test('should work with IndexedDB adapter', () => {
      const adapter = new IndexedDBAdapter('TestDB', 1, 'auth_store');
      expect(adapter).toBeDefined();
    });
  });

  describe('Token Types', () => {
    test('should handle JWT tokens', async () => {
      const jwtToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
      authSDK.debugToken(jwtToken);
    });

    test('should handle Sanctum tokens', async () => {
      const sanctumToken = '1|abcdefghijklmnopqrstuvwxyz1234567890abcdef';
      authSDK.debugToken(sanctumToken);
    });
  });

  describe('Debug Methods', () => {
    test('should debug API responses', () => {
      const mockResponse = {
        data: {
          access_token: 'token123',
          user: { id: '1', name: 'Test' },
        },
      };
      expect(() => authSDK.debugResponse(mockResponse)).not.toThrow();
    });

    test('should debug tokens', () => {
      expect(() => authSDK.debugToken('test.token.here')).not.toThrow();
    });
  });

  // Helper
  async function loginUser() {
    const mockResponse = {
      access_token: '1|test_access_token',
      refresh_token: 'test_refresh_token',
      expires_in: 3600,
      user: {
        id: '123',
        email: 'test@example.com',
        name: 'Test User',
      },
    };

    (global.fetch as jest.Mock).mockResolvedValueOnce(mockFetchSuccess(mockResponse));

    return authSDK.login({
      email: 'test@example.com',
      password: 'password123',
    });
  }
});
