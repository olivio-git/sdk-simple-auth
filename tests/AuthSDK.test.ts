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
      access_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI2ODYzMDYyZjBkODZhNGFjMDgxMWZhMmUiLCJpYXQiOjE3NTEzMzgyMTEsImV4cCI6MTc1MTMzOTExMX0.z6ng9aYz9Brlr8YUcI4QzyO-g2oNYBgr59BIxpYv1bo',
      refresh_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI2ODYzMDYyZjBkODZhNGFjMDgxMWZhMmUiLCJpYXQiOjE3NTEzMzgyMTEsImV4cCI6MTc1MTk0MzAxMX0.rS8EYVOrzC-poRDohvBmtv7wbrtIWkOshnESoiAG16w',
      user: { id: '6863062f0d86a4ac0811fa2e', email: 'subelzaolivitocabezas@gmail.com' },
    };

    (fetch as jest.Mock).mockResolvedValueOnce({
      ok: true,
      json: async () => mockResponse,
    });

    const user = await authSDK.login({
      email: 'subelzaolivitocabezas@gmail.com',
      password: 'olivio12',
    });

    expect(user).toEqual(mockResponse.user);
    expect(authSDK.isAuthenticated()).toBe(true);
  });

  // Más tests... Aquí puedes agregar más pruebas para otros métodos como register, logout, etc.
});
 