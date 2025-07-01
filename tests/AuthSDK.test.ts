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
      access_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI2ODYzNjAyMzdmYmNhNGQwODQyNDZjZmMiLCJpYXQiOjE3NTEzNDU1NTUsImV4cCI6MTc1MTM0NjQ1NX0.jTTcENp_nYQ2Ts-FndYraBbt_mWXvhAn3tfKLx5HP6I',
      refresh_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI2ODYzNjAyMzdmYmNhNGQwODQyNDZjZmMiLCJpYXQiOjE3NTEzNDU1NTUsImV4cCI6MTc1MTk1MDM1NX0.kpBjHHvIZbdfUWIxDVIPwSqcEgg0u0Sf5UguubttY-4',
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
 