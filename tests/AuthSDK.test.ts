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
      access_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
      refresh_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
      user: { id: '6863062f0d86a4ac0811fa2e', email: 'user@example.com' },
    };

    (fetch as jest.Mock).mockResolvedValueOnce({
      ok: true,
      json: async () => mockResponse,
    });

    const user = await authSDK.login({
      email: 'user@example.com',
      password: 'olivio12',
    });

    expect(user).toEqual(mockResponse.user);
    expect(authSDK.isAuthenticated()).toBe(true);
  });

});
 