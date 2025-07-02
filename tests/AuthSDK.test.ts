import { AuthSDK } from '../src/core/AuthSDK';

global.fetch = jest.fn();

describe('AuthSDK', () => {
  let authSDK: AuthSDK;
  beforeEach(() => {
    authSDK = new AuthSDK({
      authServiceUrl: 'http://localhost:3000',
      endpoints: {
        login: '/auth/login',
        refresh: '/auth/refreshToken',
      },
      storage: {
        type: 'localStorage', // or 'indexedDB'
        // For IndexedDB, you can specify these options
        // dbName: 'sdk_simple_auth',
        // dbVersion: 1,
        // storeName: 'auth_data',
        // For LocalStorage, you can specify these options
        tokenKey: 'auth_token',
        refreshTokenKey: 'auth_refresh_token',
        userKey: 'auth_user',
      },
      tokenRefresh: {
        enabled: true, // Enable automatic token refresh
        bufferTime: 30, // seconds before expiration
      }
    });
    jest.clearAllMocks();
    localStorage.clear();
  });

  function login(credentials: { email: string; password: string }) {
    if (!authSDK) {
      throw new Error('AuthSDK is not initialized');
    }
    if (!credentials || !credentials.email || !credentials.password) {
      throw new Error('Email and password are required for login');
    }
    const email = credentials.email || '';
    const password = credentials.password || '';
    return authSDK.login({ email, password });
  }




  test('should initialize correctly', () => {
    expect(authSDK).toBeDefined();
    expect(authSDK.isAuthenticated()).toBe(false);
  });

  //Login test
  test('should login successfully', async () => {

    const mockResponse = {
      access_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI2ODYzNjAyMzdmYmNhNGQwODQyNDZjZmMiLCJpYXQiOjE3NTE0ODE4NDMsImV4cCI6MTc1MTQ4MTkwM30.Tkoi90dVbhpRJ2JxzbG0fEMlUfE2GPXVxllRoWLoz9Q',
      refresh_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI2ODYzNjAyMzdmYmNhNGQwODQyNDZjZmMiLCJpYXQiOjE3NTE0ODE4NDMsImV4cCI6MTc1MjA4NjY0M30.SQZOWei3IL0ivHHiS9T0vHn9xQQPv2Pci2ZHEzt0BKc',
      user: { email: 'user@example.com' },
    };

    (fetch as jest.Mock).mockResolvedValueOnce({
      ok: true,
      json: async () => mockResponse,
    });

    await login({ email: 'user@example.com', password: 'user123' });
    expect(authSDK.getCurrentUser()?.email).toEqual('user@example.com');
    expect(authSDK.getCurrentUser()).toEqual(mockResponse.user);
    expect(authSDK.getAccessToken()).toEqual(mockResponse.access_token);
  });


  // RefreshToken test
  test('should be refreshToken', async () => {
    const mockResponse = {
      access_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI2ODYzNjAyMzdmYmNhNGQwODQyNDZjZmMiLCJpYXQiOjE3NTE0ODE4NDMsImV4cCI6MTc1MTQ4MTkwM30.Tkoi90dVbhpRJ2JxzbG0fEMlUfE2GPXVxllRoWLoz9Q',
      refresh_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI2ODYzNjAyMzdmYmNhNGQwODQyNDZjZmMiLCJpYXQiOjE3NTE0ODE4NDMsImV4cCI6MTc1MjA4NjY0M30.SQZOWei3IL0ivHHiS9T0vHn9xQQPv2Pci2ZHEzt0BKc',
      user: { email: 'user@example.com' },
    };

    (fetch as jest.Mock).mockResolvedValueOnce({
      ok: true,
      json: async () => mockResponse,
    });

    await login({ email: 'user@example.com', password: 'user123' });
    expect(authSDK.getRefreshToken()).toBeTruthy();
    expect(authSDK.getAccessToken()).toEqual(mockResponse.access_token);
  });

  // Logout test
  test('should logout successfully', async () => {
    const mockResponseLogin = {
      access_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI2ODYzNjAyMzdmYmNhNGQwODQyNDZjZmMiLCJpYXQiOjE3NTE0ODE4NDMsImV4cCI6MTc1MTQ4MTkwM30.Tkoi90dVbhpRJ2JxzbG0fEMlUfE2GPXVxllRoWLoz9Q',
      refresh_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI2ODYzNjAyMzdmYmNhNGQwODQyNDZjZmMiLCJpYXQiOjE3NTE0ODE4NDMsImV4cCI6MTc1MjA4NjY0M30.SQZOWei3IL0ivHHiS9T0vHn9xQQPv2Pci2ZHEzt0BKc',
      user: { email: 'user@example.com' },
    }; 

    (fetch as jest.Mock).mockResolvedValueOnce({
      ok: true,
      json: async () => mockResponseLogin,
    });
    await login({ email: 'user@example.com', password: 'user123' });
    expect(authSDK.getCurrentUser()?.email).toEqual('user@example.com');
    
    await authSDK.logout();
    expect(authSDK.isAuthenticated()).toBe(false);
    expect(authSDK.getCurrentUser()).toBeNull();
    expect(authSDK.getAccessToken()).toBeNull();
    expect(authSDK.getRefreshToken()).toBeNull();
  });

});
