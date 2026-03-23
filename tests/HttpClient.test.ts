import { AuthSDK } from '../src/core/AuthSDK';

const BASE_CONFIG = {
  authServiceUrl: 'http://localhost:3001/api',
  storage: { type: 'localStorage' as const },
};

describe('AuthSDK — default HttpClient', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  test('lanza error descriptivo cuando fetch no está disponible', () => {
    // Simular entorno sin fetch (Node.js < 18)
    const originalFetch = (global as any).fetch;
    delete (global as any).fetch;

    expect(() => {
      new AuthSDK(BASE_CONFIG);
    }).toThrow(/fetch is not available/);

    (global as any).fetch = originalFetch;
  });

  test('no lanza error cuando fetch está disponible', () => {
    (global as any).fetch = jest.fn();

    expect(() => {
      new AuthSDK(BASE_CONFIG);
    }).not.toThrow();
  });

  test('no lanza error cuando se provee un httpClient personalizado', () => {
    delete (global as any).fetch;

    const customHttpClient = {
      post: jest.fn(),
      get: jest.fn(),
      put: jest.fn(),
      delete: jest.fn(),
    };

    expect(() => {
      new AuthSDK({ ...BASE_CONFIG, httpClient: customHttpClient });
    }).not.toThrow();

    (global as any).fetch = undefined;
  });
});
