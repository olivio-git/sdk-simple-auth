import { AuthSDK } from '../src/core/AuthSDK';
import { LocalStorageAdapter } from '../src/storage/LocalStorageAdapter';
import { IndexedDBAdapter } from '../src/storage/IndexedDBAdapter';

// Mock fetch globally
global.fetch = jest.fn();

// Mock localStorage
const localStorageMock = {
  getItem: jest.fn(),
  setItem: jest.fn(),
  removeItem: jest.fn(),
  clear: jest.fn(),
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

describe('Enhanced AuthSDK Tests', () => {
  let authSDK: AuthSDK;
  
  beforeEach(() => {
    // Reset all mocks
    jest.clearAllMocks();
    localStorageMock.getItem.mockReturnValue(null);
    localStorageMock.setItem.mockImplementation(() => {});
    localStorageMock.removeItem.mockImplementation(() => {});
    localStorageMock.clear.mockImplementation(() => {});

    // Create fresh SDK instance
    authSDK = new AuthSDK({
      authServiceUrl: 'http://localhost:3001/api/v1',
      endpoints: {
        login: '/login',
        register: '/register',
        refresh: '/refresh',
        logout: '/logout',
      },
      storage: {
        type: 'indexedDB',
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
    // Cleanup timers
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
        accessToken: 'stored.jwt.token',
        refreshToken: 'stored_refresh_token',
        expiresIn: 3600,
        tokenType: 'Bearer',
      };

      const mockUser = {
        id: '123',
        email: 'test@example.com',
        name: 'Test User',
      };

      // Mock stored data
      localStorageMock.getItem.mockImplementation((key) => {
        if (key === 'test_auth_token') {
          return JSON.stringify({
            ...mockTokens,
            storedAt: Math.floor(Date.now() / 1000) - 100, // Stored 100 seconds ago
          });
        }
        if (key === 'test_auth_refresh_token') {
          return mockTokens.refreshToken;
        }
        if (key === 'test_auth_user') {
          return JSON.stringify(mockUser);
        }
        return null;
      });

      // Create new SDK to trigger initialization
      const newSDK = new AuthSDK({
        authServiceUrl: 'http://localhost:3001/api/v1',
        storage: {
          type: 'localStorage',
          tokenKey: 'test_auth_token',
          refreshTokenKey: 'test_auth_refresh_token',
          userKey: 'test_auth_user',
        },
      });

      // Wait for initialization
      await new Promise(resolve => setTimeout(resolve, 100));

      expect(newSDK.getState().isAuthenticated).toBe(true);
      expect(newSDK.getCurrentUser()).toEqual(mockUser);
    });
  });

  describe('Authentication Flow', () => {
    test('should login successfully with tokens', async () => {
      const credentials = { email: 'test@example.com', password: 'password123' };
      const mockResponse = {
        access_token: 'new.jwt.token',
        refresh_token: 'new_refresh_token',
        expires_in: 3600,
        token_type: 'Bearer',
        user: {
          id: '123',
          email: 'test@example.com',
          name: 'Test User',
        },
      };

      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse,
      });

      const user = await authSDK.login(credentials);

      expect(user).toEqual(mockResponse.user);
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
        access_token: 'new.jwt.token',
        refresh_token: 'new_refresh_token',
        user: {
          id: '456',
          email: 'newuser@example.com',
          name: 'New User',
        },
      };

      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse,
      });

      const user = await authSDK.register(userData);

      expect(user).toEqual(mockResponse.user);
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

      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse,
      });

      const user = await authSDK.register(userData);

      expect(user).toEqual(mockResponse.user);
      expect(authSDK.getState().isAuthenticated).toBe(false); // No tokens provided
      expect(authSDK.getAccessToken()).toBeNull();
    });

    test('should logout successfully', async () => {
      // First login
      await loginUser();

      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => ({ message: 'Logged out successfully' }),
      });

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
        access_token: 'refreshed.jwt.token',
        refresh_token: 'new_refresh_token',
        expires_in: 3600,
      };

      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockRefreshResponse,
      });

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
      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: false,
        status: 401,
        json: async () => ({ message: 'Invalid credentials' }),
      });

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
      // Should not throw error
    });

    test('should handle Sanctum tokens', async () => {
      const sanctumToken = '1|abcdefghijklmnopqrstuvwxyz1234567890abcdef';
      
      authSDK.debugToken(sanctumToken);
      // Should not throw error
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

  // Helper function for tests
  async function loginUser() {
    const mockResponse = {
      access_token: 'test.jwt.token',
      refresh_token: 'test_refresh_token',
      expires_in: 3600,
      user: {
        id: '123',
        email: 'test@example.com',
        name: 'Test User',
      },
    };

    (global.fetch as jest.Mock).mockResolvedValueOnce({
      ok: true,
      json: async () => mockResponse,
    });

    return authSDK.login({
      email: 'test@example.com',
      password: 'password123',
    });
  }
});
