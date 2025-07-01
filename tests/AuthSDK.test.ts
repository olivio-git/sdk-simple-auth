import { AuthSDK } from '../src/core/AuthSDK';

describe('AuthSDK', () => {
  let authSDK: AuthSDK;

  beforeEach(() => {
    authSDK = new AuthSDK({
      authServiceUrl: 'http://localhost:3000',
      endpoints:{
        login: '/auth/login'
      }
    });
    jest.clearAllMocks();
  });

  test('should initialize correctly', () => {
    expect(authSDK).toBeDefined();
    expect(authSDK.isAuthenticated()).toBe(false);
  });

  test('should login successfully', async () => {
    const mockResponse = {
      access_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI2ODYzNjAyMzdmYmNhNGQwODQyNDZjZmMiLCJpYXQiOjE3NTEzNDMxNTUsImV4cCI6MTc1MTM0NDA1NX0.GESTM_e0HOtYjMgmbUaz8eqkiAcWmx9rtw9VC79BxAs',
      refresh_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI2ODYzNjAyMzdmYmNhNGQwODQyNDZjZmMiLCJpYXQiOjE3NTEzNDMxNTUsImV4cCI6MTc1MTk0Nzk1NX0.3uzdrZnnrQHuQ12_VUAtiBjrxq7LakD3-rdm60jS0D8',
      user: { id: '686360237fbca4d084246cfc', email: 'user@example.com' },
    };

    (fetch as jest.Mock).mockResolvedValueOnce({
      ok: true,
      json: async () => mockResponse,
    });

    const user = await authSDK.login({
      email: 'user@example.com',
      password: 'user123',
    });

    expect(user).toEqual(mockResponse.user);
    expect(authSDK.isAuthenticated()).toBe(true);
  });

});
 