import { AxiosInterceptorManager } from '../src/core/AxiosInterceptorManager';

// Mock Axios
const mockAxios = {
  interceptors: {
    request: {
      use: jest.fn().mockReturnValue(1),
      eject: jest.fn(),
    },
    response: {
      use: jest.fn().mockReturnValue(1),
      eject: jest.fn(),
    },
  },
  request: jest.fn(),
};

describe('AxiosInterceptorManager', () => {
  let interceptorManager: AxiosInterceptorManager;
  let mockCallbacks: any;

  beforeEach(() => {
    jest.clearAllMocks();
    
    mockCallbacks = {
      getAccessToken: jest.fn(),
      onSessionInvalid: jest.fn(),
      onTokenRefresh: jest.fn(),
    };

    interceptorManager = new AxiosInterceptorManager(mockAxios, mockCallbacks);
  });

  describe('Setup', () => {
    test('should configure interceptors correctly', () => {
      interceptorManager.setup();

      expect(mockAxios.interceptors.request.use).toHaveBeenCalled();
      expect(mockAxios.interceptors.response.use).toHaveBeenCalled();
      expect(interceptorManager.isActive()).toBe(true);
    });

    test('should not configure if disabled in options', () => {
      interceptorManager.setup({ autoInjectToken: false, handleAuthErrors: false });

      expect(mockAxios.interceptors.request.use).not.toHaveBeenCalled();
      expect(mockAxios.interceptors.response.use).not.toHaveBeenCalled();
    });
  });

  describe('Request Interceptor (Token Injection)', () => {
    test('should inject token into headers', async () => {
      interceptorManager.setup({ autoInjectToken: true });
      
      // Get the success handler from the mock call
      const requestHandler = mockAxios.interceptors.request.use.mock.calls[0][0];
      
      mockCallbacks.getAccessToken.mockResolvedValue('valid-token');
      
      const config = { headers: {} };
      const result = await requestHandler(config);

      expect(result.headers.Authorization).toBe('Bearer valid-token');
    });

    test('should not overwrite existing Authorization header', async () => {
      interceptorManager.setup({ autoInjectToken: true });
      
      const requestHandler = mockAxios.interceptors.request.use.mock.calls[0][0];
      
      mockCallbacks.getAccessToken.mockResolvedValue('valid-token');
      
      const config = { headers: { Authorization: 'Basic existing' } };
      const result = await requestHandler(config);

      expect(result.headers.Authorization).toBe('Basic existing');
    });
  });

  describe('Response Interceptor (Error Handling)', () => {
    test('should handle 401 error and retry', async () => {
      interceptorManager.setup({ handleAuthErrors: true });
      
      // Get the error handler from the mock call
      const errorHandler = mockAxios.interceptors.response.use.mock.calls[0][1];
      
      const error = {
        response: { status: 401 },
        config: { headers: {} }
      };

      // Mock successful refresh and new token
      mockCallbacks.onTokenRefresh.mockResolvedValue(undefined);
      mockCallbacks.getAccessToken.mockResolvedValue('new-token');
      mockAxios.request.mockResolvedValue('retry-success');

      const result = await errorHandler(error);

      expect(mockCallbacks.onTokenRefresh).toHaveBeenCalled();
      expect(mockAxios.request).toHaveBeenCalledWith(expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: 'Bearer new-token'
        })
      }));
      expect(result).toBe('retry-success');
    });

    test('should logout if refresh fails', async () => {
      interceptorManager.setup({ handleAuthErrors: true });
      
      const errorHandler = mockAxios.interceptors.response.use.mock.calls[0][1];
      
      const error = {
        response: { status: 401 },
        config: { headers: {} }
      };

      mockCallbacks.onTokenRefresh.mockRejectedValue(new Error('Refresh failed'));

      await expect(errorHandler(error)).rejects.toThrow('Refresh failed');
      
      expect(mockCallbacks.onSessionInvalid).toHaveBeenCalled();
    });

    test('should logout on 401 if no refresh callback provided', async () => {
      // Re-init without refresh callback
      interceptorManager = new AxiosInterceptorManager(mockAxios, {
        ...mockCallbacks,
        onTokenRefresh: undefined
      });
      
      interceptorManager.setup({ handleAuthErrors: true });
      
      const errorHandler = mockAxios.interceptors.response.use.mock.calls[0][1];
      
      const error = {
        response: { status: 401 },
        config: { headers: {} }
      };

      await expect(errorHandler(error)).rejects.toEqual(error);
      
      expect(mockCallbacks.onSessionInvalid).toHaveBeenCalled();
    });
    test('should handle concurrent 401s with single refresh', async () => {
      interceptorManager.setup({ handleAuthErrors: true });
      
      const errorHandler = mockAxios.interceptors.response.use.mock.calls[0][1];
      
      const error1 = { response: { status: 401 }, config: { headers: {}, _retry: false } };
      const error2 = { response: { status: 401 }, config: { headers: {}, _retry: false } };
      const error3 = { response: { status: 401 }, config: { headers: {}, _retry: false } };

      // Mock successful refresh
      mockCallbacks.onTokenRefresh.mockImplementation(async () => {
        await new Promise(resolve => setTimeout(resolve, 100)); // Simulate delay
      });
      mockCallbacks.getAccessToken.mockResolvedValue('new-token');
      mockAxios.request.mockResolvedValue('retry-success');

      // Execute 3 concurrent requests
      const results = await Promise.all([
        errorHandler(error1),
        errorHandler(error2),
        errorHandler(error3)
      ]);

      // Verify refresh was called ONLY ONCE
      expect(mockCallbacks.onTokenRefresh).toHaveBeenCalledTimes(1);
      
      // Verify all requests were retried
      expect(mockAxios.request).toHaveBeenCalledTimes(3);
      expect(results).toEqual(['retry-success', 'retry-success', 'retry-success']);
    });
  });
});
