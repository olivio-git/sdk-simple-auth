import { AuthCallbacks, AuthConfig, AuthState, AuthTokens, AuthUser, ExtendedSessionInfo, HttpClient, LoginCredentials, RegisterData } from '../types';
import { AxiosInterceptorManager } from './AxiosInterceptorManager';
import { AuthDebugger } from './AuthDebugger';
import ExpirationHandler from './ExpirationHandler';
import { Logger } from './Logger';
import { RefreshManager } from './RefreshManager';
import { SessionValidator } from './SessionValidator';
import { StorageManager } from './StorageManager';
import { TokenHandler } from './TokenHandler';
import { TokenExtractor } from './TokenManager';

// Type for state change listeners
type StateChangeListener = (state: AuthState) => void;

/**
 * Refactored AuthSDK with improved modularity and session management
 */
export class AuthSDK {
  private config: Required<AuthConfig>;
  private state: AuthState;
  private callbacks: AuthCallbacks;

  // Managers
  private storageManager: StorageManager;
  private refreshManager: RefreshManager;
  private sessionValidator: SessionValidator | null = null;
  private axiosInterceptorManager: AxiosInterceptorManager | null = null;
  private authDebugger: AuthDebugger;

  // Session management
  private expirationTimer: NodeJS.Timeout | null = null;
  private stateChangeListeners: StateChangeListener[] = [];
  private isInitialized = false;
  public readonly ready: Promise<void>;
  private logger: Logger;

  constructor(config: AuthConfig, callbacks?: AuthCallbacks) {
    this.config = this.buildConfig(config);
    this.callbacks = callbacks || {};

    // Create per-instance logger
    this.logger = new Logger(this.config.debug || false);

    this.storageManager = new StorageManager(this.config.storage, this.logger);
    this.refreshManager = new RefreshManager(
      this.config,
      this.storageManager,
      this.config.httpClient,
      {
        onTokenRefresh: (tokens) => {
          this.handleTokenRefresh(tokens);
        },
        onRefreshError: (error) => {
          this.callbacks.onError?.(error.message);
        },
        onSessionRenewed: (tokens) => {
          this.callbacks.onTokenRefresh?.(tokens);
        }
      },
      this.logger
    );

    this.authDebugger = new AuthDebugger(
      this.config.debug,
      () => this.state,
      () => this.refreshManager.getRefreshStatus()
    );

    // Initial state
    this.state = {
      isAuthenticated: false,
      user: null,
      tokens: null,
      loading: false,
      error: null,
      backendType: 'unknown',
      capabilities: {
        canRefresh: Boolean(this.config.tokenRefresh?.enabled),
        hasProfile: true,
        supportsOTP: false,
        supportsBiometric: false
      }
    };

    // Initialize SessionValidator if enabled
    if (this.config.sessionValidation.enabled && SessionValidator.isSupported()) {
      this.sessionValidator = new SessionValidator(
        this.config.sessionValidation,
        () => this.validateSession(),
        this.logger
      );
    }

    // Initialize AxiosInterceptorManager if Axios instance is provided
    if (this.config.interceptors.enabled && this.config.interceptors.axiosInstance) {
      this.axiosInterceptorManager = new AxiosInterceptorManager(
        this.config.interceptors.axiosInstance,
        {
          getAccessToken: () => this.getValidAccessToken(),
          onSessionInvalid: async () => {
            this.logger.warn('Axios interceptor detected invalid session');
            await this.clearSession();
            this.callbacks.onSessionInvalid?.();
          },
          onTokenRefresh: async () => {
            await this.refreshTokens();
          }
        },
        this.logger
      );

      // Configurar interceptores
      this.axiosInterceptorManager.setup({
        autoInjectToken: this.config.interceptors.autoInjectToken,
        handleAuthErrors: this.config.interceptors.handleAuthErrors
      });

      this.logger.debug('Axios interceptors initialized');
    }

    // Initialize from storage
    this.ready = this.initializeFromStorage();
  }

  /**
   * Build complete configuration with defaults
   */
  private buildConfig(config: AuthConfig): Required<AuthConfig> {
    return {
      authServiceUrl: config.authServiceUrl,
      endpoints: {
        login: '/auth/login',
        register: '/auth/register',
        refresh: '/auth/refreshToken',
        logout: '/auth/logout',
        profile: '/auth/profile',
        ...config.endpoints,
      },
      storage: {
        type: 'indexedDB',
        dbName: 'AuthSDK',
        dbVersion: 1,
        storeName: 'auth_data',
        tokenKey: 'auth_access_token',
        refreshTokenKey: 'auth_refresh_token',
        userKey: 'auth_user',
        ...config.storage,
      },
      tokenRefresh: {
        enabled: true,
        bufferTime: 900, // 15 minutes
        maxRetries: 3,
        minimumTokenLifetime: 300, // 5 minutos mínimo
        gracePeriod: 60, // 1 minuto de gracia
        ...config.tokenRefresh,
      },
      httpClient: config.httpClient || this.createDefaultHttpClient(),
      debug: config.debug || false,
      backend: {
        type: config.backend?.type || 'jwt-standard',
        userSearchPaths: config.backend?.userSearchPaths || ['user', 'data.user'],
        fieldMappings: config.backend?.fieldMappings || {},
        preserveOriginalData: config.backend?.preserveOriginalData ?? false,
      },
      sessionValidation: {
        enabled: true,
        validateOnFocus: true,
        validateOnVisibility: true,
        maxInactivityTime: 300, // 5 minutos
        autoLogoutOnInvalid: true,
        validateOnStartup: true,
        ...config.sessionValidation,
      },
      interceptors: {
        enabled: false, // Deshabilitado por defecto
        autoInjectToken: true,
        handleAuthErrors: true,
        axiosInstance: undefined,
        ...config.interceptors,
      },
    };
  }

  /**
   * Enhanced login with automatic session establishment
   */
  async login(credentials: LoginCredentials): Promise<AuthUser> {
    this.setLoading(true);
    this.setError(null);

    try {
      const url = `${this.config.authServiceUrl}${this.config.endpoints.login}`;
      const response = await this.config.httpClient.post(url, credentials);

      const tokens = TokenExtractor.extractTokens(response);
      const user = TokenExtractor.extractUser(response);

      if (!user) {
        throw new Error('No user information found in login response');
      }

      await this.establishSession(tokens, user);

      this.callbacks.onLogin?.(user, tokens);
      this.logger.debug('Login successful, session established');

      return user;

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Login failed';
      this.setError(errorMessage);
      this.callbacks.onError?.(errorMessage);
      throw error;
    } finally {
      this.setLoading(false);
    }
  }

  /**
   * Enhanced register with automatic session establishment when tokens are provided
   */
  async register(userData: RegisterData): Promise<AuthUser> {
    this.setLoading(true);
    this.setError(null);

    try {
      const url = `${this.config.authServiceUrl}${this.config.endpoints.register}`;
      const response = await this.config.httpClient.post(url, userData);

      // Try to extract tokens - some APIs provide immediate authentication
      try {
        const tokens = TokenExtractor.extractTokens(response);
        const user = TokenExtractor.extractUser(response);

        if (!user) {
          throw new Error('No user information found in register response');
        }

        // If tokens are provided, establish session immediately
        await this.establishSession(tokens, user);

        this.callbacks.onLogin?.(user, tokens);
        this.logger.debug('Registration successful with automatic login');

        return user;

      } catch (tokenError) {
        // If no tokens, registration was successful but requires separate login
        this.logger.debug('Registration successful, manual login required');
        
        const user = TokenExtractor.extractUser(response);
        
        if (!user) {
          // Return basic user info if available
          return {
            id: 'unknown',
            name: userData.name || userData.email || 'User',
            email: userData.email
          };
        }

        return user;
      }

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Registration failed';
      this.setError(errorMessage);
      this.callbacks.onError?.(errorMessage);
      throw error;
    } finally {
      this.setLoading(false);
    }
  }

  /**
   * Enhanced logout with complete session cleanup
   */
  async logout(): Promise<void> {
    try {
      // Attempt server-side logout if token is available
      if (this.state.tokens?.accessToken) {
        try {
          const url = `${this.config.authServiceUrl}${this.config.endpoints.logout}`;
          await this.config.httpClient.post(url, {}, {
            headers: {
              Authorization: `Bearer ${this.state.tokens.accessToken}`,
            },
          });
          this.logger.debug('Server-side logout successful');
        } catch (error) {
          this.logger.warn('Server-side logout failed, continuing with client-side cleanup:', error);
        }
      }
    } finally {
      await this.clearSession();
      this.callbacks.onLogout?.();
      this.logger.debug('Logout completed, session cleared');
    }
  }

  /**
   * Tear down all listeners and timers without clearing auth state.
   * Call this when the SDK instance is being discarded (e.g. React hot-reload)
   * to prevent duplicate event listeners on the next instantiation.
   */
  destroy(): void {
    this.sessionValidator?.stopListening();
    this.refreshManager.clearRefreshTimer();
    this.stateChangeListeners = [];
    this.logger.debug('AuthSDK instance destroyed');
  }

  /**
   * Clear local session without calling backend
   * Useful when the server has already invalidated the session (401/422)
   */
  async clearLocalSession(): Promise<void> {
    this.logger.debug('Clearing local session only (no backend call)');
    await this.clearSession();
    this.callbacks.onLogout?.();
    this.logger.debug('Local session cleared');
  }

  /**
   * Enhanced token refresh with session renewal
   */
  async refreshTokens(): Promise<AuthTokens> {
    return this.refreshManager.refreshTokens();
  }

  /**
   * Subscribe to authentication state changes
   */
  onAuthStateChanged(listener: StateChangeListener): () => void {
    this.stateChangeListeners.push(listener);

    // Call immediately with current state
    if (this.isInitialized) {
      listener(this.getState());
    }

    // Return unsubscribe function
    return () => {
      const index = this.stateChangeListeners.indexOf(listener);
      if (index > -1) {
        this.stateChangeListeners.splice(index, 1);
      }
    };
  }

  /**
   * Get current authentication state
   */
  getState(): AuthState {
    return { ...this.state };
  }

  /**
   * Get current authenticated user
   */
  getCurrentUser(): AuthUser | null {
    return this.state.user;
  }

  /**
   * Get current access token
   */
  getAccessToken(): string | null {
    return this.state.tokens?.accessToken || null;
  }

  /**
   * Get current refresh token
   */
  getRefreshToken(): string | null {
    return this.state.tokens?.refreshToken || null;
  }

  /**
   * Check if user is currently authenticated
   */
  async isAuthenticated(): Promise<boolean> {
    await this.ready;
    if (!this.state.isAuthenticated || !this.state.tokens?.accessToken) {
      return false;
    }

    return this.isTokenValid(this.state.tokens.accessToken);
  }

  /**
   * Validate current session with the server using refresh token
   * This is called automatically when the app regains focus/visibility
   */
  async validateSession(): Promise<boolean> {
    this.logger.debug('Validating session with server...');

    // Si no hay sesión activa, no hay nada que validar
    if (!this.state.isAuthenticated || !this.state.tokens) {
      this.logger.debug('No active session to validate');
      return false;
    }

    // Si no hay refresh token, no podemos validar con el servidor
    if (!this.config.tokenRefresh.enabled || !this.state.tokens.refreshToken) {
      this.logger.debug('Cannot validate session: refresh token not available');
      // Para tokens sin refresh, asumir válidos hasta que fallen en una petición
      return true;
    }

    try {
      // Intentar refrescar el token como forma de validación
      // Si el servidor acepta el refresh token, la sesión es válida
      await this.refreshTokens();

      this.logger.debug('Session validated successfully');
      this.callbacks.onSessionValidated?.();

      return true;

    } catch (error) {
      this.logger.warn('Session validation failed:', error);

      // Si falla el refresh, la sesión es inválida
      if (this.config.sessionValidation.autoLogoutOnInvalid) {
        this.logger.debug('Auto-logout due to invalid session');
        await this.clearSession();
        this.callbacks.onSessionInvalid?.();
      }

      return false;
    }
  }

  /**
   * Get a valid access token, refreshing if necessary
   */
  async getValidAccessToken(): Promise<string | null> {
    await this.ready;
    if (!this.state.tokens?.accessToken) {
      return null;
    }

    // If refresh is disabled, return token only if valid
    if (!this.config.tokenRefresh.enabled) {
      const isValid = await this.isTokenValid(this.state.tokens.accessToken);
      return isValid ? this.state.tokens.accessToken : null;
    }

    // Check if token should be refreshed using async method for better accuracy
    const shouldRefresh = await this.refreshManager.shouldRefreshTokenAsync(this.state.tokens.accessToken);
    
    if (shouldRefresh && await this.refreshManager.canRefresh()) {
      try {
        const tokens = await this.refreshManager.refreshTokens();
        return tokens.accessToken;
      } catch (error) {
        this.logger.error('Failed to refresh token:', error);
        return null;
      }
    }

    const isValid = await this.isTokenValid(this.state.tokens.accessToken);
    return isValid ? this.state.tokens.accessToken : null;
  }

  /**
   * Get authorization headers for API requests
   */
  async getAuthHeaders(): Promise<Record<string, string>> {
    const token = await this.getValidAccessToken();
    if (!token) {
      throw new Error('No valid authentication token available');
    }

    return {
      Authorization: `Bearer ${token}`,
    };
  }

  /**
   * Debug token information
   */
  debugToken(token?: string): void {
    this.authDebugger.debugToken(token);
  }

  /**
   * Debug API response structure
   */
  debugResponse(response: any): void {
    this.authDebugger.debugResponse(response);
  }

  /**
   * Force refresh tokens regardless of expiration
   */
  async forceRefreshTokens(): Promise<AuthTokens> {
    return this.refreshManager.forceRefresh();
  }

  /**
   * Get comprehensive session information
   */
  async getExtendedSessionInfo(): Promise<ExtendedSessionInfo> {
    const tokens = await this.storageManager.getStoredTokens();
    const metadata = await this.storageManager.getTokenMetadata();
    const isValid = tokens?.accessToken ? await this.isTokenValid(tokens.accessToken) : false;

    return {
      isValid,
      user: this.state.user,
      tokens: this.state.tokens,
      tokenType: tokens?.tokenType || null,
      tokenFormat: this.detectTokenFormat(tokens?.accessToken),
      expiresIn: tokens?.expiresIn || null,
      refreshAvailable: await this.refreshManager.canRefresh(),
      canRefresh: Boolean(this.config.tokenRefresh?.enabled) && await this.refreshManager.canRefresh(),
      sessionId: metadata?.sessionId || null,
      backendType: this.state.backendType || null,
      storedAt: metadata?.storedAt || null,
      lastRefreshed: metadata?.lastRefreshed || null,
      originalResponse: this.state.user?._originalUserResponse || null,
    };
  }

  /**
   * Get detailed session information (legacy method)
   */
  async getSessionInfo(): Promise<{
    isValid: boolean;
    user: AuthUser | null;
    tokenType: string | null;
    expiresIn: number | null;
    refreshAvailable: boolean;
    sessionId: string | null;
  }> {
    const extendedInfo = await this.getExtendedSessionInfo();
    return {
      isValid: extendedInfo.isValid,
      user: extendedInfo.user,
      tokenType: extendedInfo.tokenType,
      expiresIn: extendedInfo.expiresIn,
      refreshAvailable: extendedInfo.refreshAvailable,
      sessionId: extendedInfo.sessionId,
    };
  }

  /**
   * Test extraction with mock response (debugging)
   */
  testExtraction(response: any): void {
    this.authDebugger.testExtraction(response);
  }

  /**
   * Detect token format
   */
  private detectTokenFormat(token?: string): 'jwt' | 'opaque' | 'sanctum' | null {
    if (!token) return null;
    
    if (token.includes('|')) return 'sanctum';
    if (token.split('.').length === 3) return 'jwt';
    return 'opaque';
  }

  /**
   * Initialize from stored authentication data
   */
  private async initializeFromStorage(): Promise<void> {
    try {
      // Migrate storage if needed
      await this.storageManager.migrateStorage();

      const [storedTokens, storedUser] = await Promise.all([
        this.storageManager.getStoredTokens(),
        this.storageManager.getStoredUser()
      ]);

      if (storedTokens?.accessToken && storedUser) {
        // Validate token before establishing session
        const isValid = await this.isTokenValid(storedTokens.accessToken);

        if (isValid) {
          this.state = {
            isAuthenticated: true,
            user: storedUser,
            tokens: storedTokens,
            loading: false,
            error: null,
          };

          // Setup refresh if enabled
          if (this.config.tokenRefresh.enabled && storedTokens.refreshToken) {
            this.refreshManager.scheduleTokenRefresh(storedTokens);
          }

          // Schedule expiration handling
          this.scheduleTokenExpiration(storedTokens);

          // Start session validation listeners
          if (this.sessionValidator) {
            this.sessionValidator.startListening();
            this.logger.debug('Session validation listeners started');
          }

          // Validar sesión al inicio — awaited para que `ready` garantice
          // que el estado es consistente antes de que el consumidor continúe
          if (this.config.sessionValidation.validateOnStartup) {
            this.logger.debug('Performing startup session validation...');
            try {
              const isValid = await this.validateSession();
              if (!isValid) {
                this.logger.warn('Startup session validation failed');
                if (!this.config.sessionValidation.autoLogoutOnInvalid) {
                  await this.clearSession();
                }
              } else {
                this.logger.debug('Startup session validation successful');
              }
            } catch (err) {
              this.logger.error('Error during startup session validation:', err);
            }
          }

          // console.debug('Session restored from storage');
        } else {
          this.logger.debug('Stored token is invalid, clearing storage');
          await this.storageManager.clearAll();
        }
      } else {
        this.logger.debug('No valid session found in storage');
        await this.storageManager.clearAll();
      }
    } catch (error) {
      this.logger.error('Error initializing from storage:', error);
      await this.storageManager.clearAll();
    } finally {
      this.isInitialized = true;
      this.notifyStateChange();
    }
  }

  /**
   * Establish new session with tokens and user
   */
  private async establishSession(tokens: AuthTokens, user: AuthUser): Promise<void> {
    // Store tokens and user
    await Promise.all([
      this.storageManager.storeTokens(tokens),
      this.storageManager.storeUser(user)
    ]);

    // Update state
    this.state = {
      isAuthenticated: true,
      user,
      tokens,
      loading: false,
      error: null,
    };

    // Setup refresh scheduling
    if (this.config.tokenRefresh.enabled && tokens.refreshToken) {
      this.refreshManager.scheduleTokenRefresh(tokens);
    }

    // Schedule expiration handling
    this.scheduleTokenExpiration(tokens);

    // Start session validation listeners
    if (this.sessionValidator) {
      this.sessionValidator.startListening();
      this.logger.debug('Session validation listeners started');
    }

    this.notifyStateChange();
  }

  /**
   * Clear current session completely
   */
  private async clearSession(): Promise<void> {
    // Stop session validation listeners
    if (this.sessionValidator) {
      this.sessionValidator.stopListening();
      this.logger.debug('Session validation listeners stopped');
    }

    // Clear storage
    await this.storageManager.clearAll();

    // Clear timers
    this.clearExpirationTimer();
    this.refreshManager.clearRefreshTimer();
    this.refreshManager.reset();

    // Reset state
    this.state = {
      isAuthenticated: false,
      user: null,
      tokens: null,
      loading: false,
      error: null,
      isRefreshing: false,
      lastActivity: Date.now(),
      backendType: 'unknown',
      capabilities: {
        canRefresh: Boolean(this.config.tokenRefresh?.enabled),
        hasProfile: true,
        supportsOTP: false,
        supportsBiometric: false
      }
    };

    this.notifyStateChange();
  }

  /**
   * Handle token refresh completion
   */
  private handleTokenRefresh(tokens: AuthTokens): void {
    this.state.tokens = tokens;

    // Reschedule expiration
    this.scheduleTokenExpiration(tokens);

    this.notifyStateChange();
  }

  /**
   * Schedule automatic token expiration handling
   */
  private scheduleTokenExpiration(tokens: AuthTokens): void {
    this.clearExpirationTimer();

    const expiresInSeconds = ExpirationHandler.calculateExpiration(
      tokens.accessToken,
      tokens.expiresIn,
      tokens.expiresAt
    );

    if (expiresInSeconds && expiresInSeconds > 0) {
      this.expirationTimer = setTimeout(() => {
        this.handleTokenExpiration();
      }, expiresInSeconds * 1000);

      // console.debug(`Token expiration scheduled in ${expiresInSeconds} seconds`);
    }
  }

  /**
   * Handle automatic token expiration
   */
  private async handleTokenExpiration(): Promise<void> {
    this.logger.debug('Token expired, handling expiration...');

    // Try to refresh if possible
    if (this.config.tokenRefresh.enabled && await this.refreshManager.canRefresh()) {
      try {
        await this.refreshManager.refreshTokens();
        this.logger.debug('Token refreshed successfully on expiration');
        return;
      } catch (error) {
        this.logger.error('Failed to refresh expired token:', error);
      }
    }

    // If refresh fails or is not available, logout
    this.logger.debug('Performing automatic logout due to token expiration');
    await this.logout();
    this.callbacks.onTokenExpired?.();
  }

  /**
   * Clear expiration timer
   */
  private clearExpirationTimer(): void {
    if (this.expirationTimer) {
      clearTimeout(this.expirationTimer);
      this.expirationTimer = null;
    }
  }

  /**
   * Validate token based on its type
   */
  private async isTokenValid(token: string): Promise<boolean> {
    if (!token) return false;

    const tokenInfo = TokenHandler.parseToken(token);
    
    switch (tokenInfo.type) {
      case 'jwt':
        return tokenInfo.isValid;
      
      case 'sanctum':
      case 'opaque':
        // For non-JWT tokens, check metadata
        return this.validateStoredToken(token);
      
      default:
        return false;
    }
  }

  /**
   * Validate stored token using metadata
   */
  private async validateStoredToken(token: string): Promise<boolean> {
    try {
      const metadata = await this.storageManager.getTokenMetadata();
      const tokens = await this.storageManager.getStoredTokens();

      if (!metadata?.storedAt || !tokens?.expiresIn) {
        // No expiration info, assume valid for now
        return true;
      }

      const now = Math.floor(Date.now() / 1000);
      const timeElapsed = now - metadata.storedAt;
      return timeElapsed < tokens.expiresIn;

    } catch {
      return false;
    }
  }

  /**
   * Create default HTTP client using fetch
   */
  private createDefaultHttpClient(): HttpClient {
    if (typeof fetch === 'undefined') {
      throw new Error(
        '[AuthSDK] fetch is not available in this environment. ' +
        'In Node.js < 18, provide a custom httpClient (e.g. using axios or node-fetch) via config.httpClient.'
      );
    }

    const makeRequest = async (url: string, options: RequestInit) => {
      const response = await fetch(url, {
        headers: {
          'Content-Type': 'application/json',
          ...options.headers,
        },
        ...options,
      });

      if (!response.ok) {
        const error = await response.json().catch(() => ({
          message: `HTTP ${response.status}: ${response.statusText}`
        }));
        throw new Error(error.message || `Request failed with status ${response.status}`);
      }

      const text = await response.text();
      if (!text) return null;
      try {
        return JSON.parse(text);
      } catch {
        throw new Error(`Expected JSON response but received non-JSON content (status ${response.status})`);
      }
    };

    return {
      async post(url: string, data?: any, config?: any) {
        return makeRequest(url, {
          method: 'POST',
          body: data ? JSON.stringify(data) : undefined,
          ...config,
        });
      },

      async get(url: string, config?: any) {
        return makeRequest(url, {
          method: 'GET',
          ...config,
        });
      },

      async put(url: string, data?: any, config?: any) {
        return makeRequest(url, {
          method: 'PUT',
          body: data ? JSON.stringify(data) : undefined,
          ...config,
        });
      },

      async delete(url: string, config?: any) {
        return makeRequest(url, {
          method: 'DELETE',
          ...config,
        });
      },
    };
  }

  /**
   * Set loading state
   */
  private setLoading(loading: boolean): void {
    this.state.loading = loading;
    this.notifyStateChange();
  }

  /**
   * Set error state
   */
  private setError(error: string | null): void {
    this.state.error = error;
    this.notifyStateChange();
  }

  /**
   * Notify all state change listeners
   */
  private notifyStateChange(): void {
    const currentState = this.getState();

    // Call traditional callback
    this.callbacks.onAuthStateChanged?.(currentState);

    // Notify all subscribers
    this.stateChangeListeners.forEach(listener => {
      try {
        listener(currentState);
      } catch (error) {
        this.logger.error('Error in state change listener:', error);
      }
    });
  }

  /**
   * Debug current session with comprehensive info
   */
  debugSession(): void {
    this.authDebugger.debugSession();
  }
}
