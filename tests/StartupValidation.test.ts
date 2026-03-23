import { AuthSDK } from '../src/core/AuthSDK';

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

describe('Startup Session Validation', () => {
  let authSDK: AuthSDK;
  
  beforeEach(() => {
    jest.clearAllMocks();
    localStorageMock.getItem.mockReturnValue(null);
  });

  test('should clear session if startup validation fails', async () => {
    // 1. Setup stored valid session
    // Valid JWT: header.payload.signature
    // payload: {"exp": 1999999999} -> eyJleHAiOjE5OTk5OTk5OTl9
    const validJwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE5OTk5OTk5OTl9.signature';
    
    const mockTokens = {
      accessToken: validJwt,
      refreshToken: 'stored_refresh_token',
      expiresIn: 3600,
      tokenType: 'Bearer',
    };
    const mockUser = { id: '123', email: 'test@example.com' };

    localStorageMock.getItem.mockImplementation((key) => {
      if (key === 'test_auth_token') return JSON.stringify({ ...mockTokens, storedAt: Date.now() / 1000 });
      if (key === 'test_auth_refresh_token') return mockTokens.refreshToken;
      if (key === 'test_auth_user') return JSON.stringify(mockUser);
      return null;
    });

    // 2. Mock fetch to fail validation (401)
    (global.fetch as jest.Mock).mockResolvedValue({
      ok: false,
      status: 401,
      statusText: 'Unauthorized',
      json: async () => ({ message: 'Unauthenticated' }),
      text: async () => JSON.stringify({ message: 'Unauthenticated' }),
    });

    // 3. Initialize SDK with validation enabled
    authSDK = new AuthSDK({
      authServiceUrl: 'http://localhost:3001',
      storage: {
        type: 'localStorage',
        tokenKey: 'test_auth_token',
        refreshTokenKey: 'test_auth_refresh_token',
        userKey: 'test_auth_user',
      },
      sessionValidation: {
        enabled: true,
        validateOnStartup: true, // Enable startup validation
        autoLogoutOnInvalid: true,
      }
    });

    // 4. Wait for initialization and validation to complete
    await authSDK.ready;

    // 5. Assert session is cleared
    expect(authSDK.getState().isAuthenticated).toBe(false);
    expect(authSDK.getCurrentUser()).toBeNull();
    // Verify storage was cleared
    expect(localStorageMock.removeItem).toHaveBeenCalledWith('test_auth_token');
    expect(localStorageMock.removeItem).toHaveBeenCalledWith('test_auth_user');
  });

  test('should keep session if startup validation succeeds', async () => {
    // 1. Setup stored valid session
    // Valid JWT: header.payload.signature
    // payload: {"exp": 1999999999} -> eyJleHAiOjE5OTk5OTk5OTl9
    const validJwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE5OTk5OTk5OTl9.signature';
    
    const mockTokens = {
      accessToken: validJwt,
      refreshToken: 'stored_refresh_token',
      expiresIn: 3600,
      tokenType: 'Bearer',
    };
    const mockUser = { id: '123', email: 'test@example.com' };

    localStorageMock.getItem.mockImplementation((key) => {
      if (key === 'test_auth_token') return JSON.stringify({ ...mockTokens, storedAt: Date.now() / 1000 });
      if (key === 'test_auth_refresh_token') return mockTokens.refreshToken;
      if (key === 'test_auth_user') return JSON.stringify(mockUser);
      return null;
    });

    // 2. Mock fetch to succeed validation (refresh)
    const refreshBody = {
      access_token: '1|new_access_token',
      refresh_token: 'new_refresh_token',
      expires_in: 3600
    };
    (global.fetch as jest.Mock).mockResolvedValue({
      ok: true,
      text: async () => JSON.stringify(refreshBody),
      json: async () => refreshBody,
    });

    // 3. Initialize SDK
    authSDK = new AuthSDK({
      authServiceUrl: 'http://localhost:3001',
      storage: {
        type: 'localStorage',
        tokenKey: 'test_auth_token',
        refreshTokenKey: 'test_auth_refresh_token',
        userKey: 'test_auth_user',
      },
      sessionValidation: {
        validateOnStartup: true,
      }
    });

    // 4. Wait for initialization and validation to complete
    await authSDK.ready;

    // 5. Assert session remains valid and updated
    expect(authSDK.getState().isAuthenticated).toBe(true);
    expect(authSDK.getAccessToken()).toBe('1|new_access_token'); // Should have new token
  });
});
