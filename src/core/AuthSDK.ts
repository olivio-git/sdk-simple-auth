import { IndexedDBAdapter } from '../storage/IndexedDBAdapter';
import { LocalStorageAdapter } from '../storage/LocalStorageAdapter';
import { StorageAdapter } from '../storage/StorageAdapter';
import { AuthCallbacks, AuthConfig, AuthState, AuthTokens, AuthUser, HttpClient, LoginCredentials, RegisterData } from '../types';

// Tipo para el callback de suscripción
type StateChangeListener = (state: AuthState) => void;
 
class AuthSDK {
  private config: Required<AuthConfig>;
  private state: AuthState;
  private callbacks: AuthCallbacks;
  private refreshTimer: NodeJS.Timeout | null = null;
  private isRefreshing = false;
  private refreshPromise: Promise<AuthTokens> | null = null;
  private storageAdapter: StorageAdapter;
  
  // Array para almacenar los listeners de cambio de estado
  private stateChangeListeners: StateChangeListener[] = [];

  constructor(config: AuthConfig, callbacks?: AuthCallbacks) {
    // Configuración por defecto
    this.config = {
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
        bufferTime: 900, // 15 minutos
        maxRetries: 3,
        ...config.tokenRefresh,
      },
      httpClient: config.httpClient || this.createDefaultFetchClient(),
    };

    this.callbacks = callbacks || {};

    // Inicializar el adaptador de storage
    this.storageAdapter = this.createStorageAdapter();

    // Estado inicial
    this.state = {
      isAuthenticated: false,
      user: null,
      tokens: null,
      loading: false,
      error: null,
    };

    // Inicializar desde storage
    this.initializeFromStorage();
  }

  private createStorageAdapter(): StorageAdapter {
    const storageType = this.config.storage.type || 'indexedDB';
    
    if (storageType === 'localStorage') {
      return new LocalStorageAdapter();
    } else {
      return new IndexedDBAdapter(
        this.config.storage.dbName,
        this.config.storage.dbVersion,
        this.config.storage.storeName
      );
    }
  }

  // NUEVO MÉTODO: Suscribirse a cambios de estado
  public onAuthStateChanged(listener: StateChangeListener): () => void {
    // Agregar el listener al array
    this.stateChangeListeners.push(listener);
    
    // Llamar inmediatamente con el estado actual
    listener(this.getState());
    
    // Retornar función para cancelar la suscripción
    return () => {
      const index = this.stateChangeListeners.indexOf(listener);
      if (index > -1) {
        this.stateChangeListeners.splice(index, 1);
      }
    };
  }

  // Cliente HTTP por defecto usando fetch
  private createDefaultFetchClient(): HttpClient {
    return {
      async post(url: string, data?: any, config?: any) {
        const response = await fetch(url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            ...config?.headers,
          },
          body: data ? JSON.stringify(data) : undefined,
          ...config,
        });
        
        if (!response.ok) {
          const error = await response.json().catch(() => ({ message: 'Request failed' }));
          throw new Error(error.message || `HTTP ${response.status}`);
        }
        
        return response.json();
      },
      
      async get(url: string, config?: any) {
        const response = await fetch(url, {
          method: 'GET',
          headers: {
            'Content-Type': 'application/json',
            ...config?.headers,
          },
          ...config,
        });
        
        if (!response.ok) {
          const error = await response.json().catch(() => ({ message: 'Request failed' }));
          throw new Error(error.message || `HTTP ${response.status}`);
        }
        
        return response.json();
      },
      
      async put(url: string, data?: any, config?: any) {
        const response = await fetch(url, {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json',
            ...config?.headers,
          },
          body: data ? JSON.stringify(data) : undefined,
          ...config,
        });
        
        if (!response.ok) {
          const error = await response.json().catch(() => ({ message: 'Request failed' }));
          throw new Error(error.message || `HTTP ${response.status}`);
        }
        
        return response.json();
      },
      
      async delete(url: string, config?: any) {
        const response = await fetch(url, {
          method: 'DELETE',
          headers: {
            'Content-Type': 'application/json',
            ...config?.headers,
          },
          ...config,
        });
        
        if (!response.ok) {
          const error = await response.json().catch(() => ({ message: 'Request failed' }));
          throw new Error(error.message || `HTTP ${response.status}`);
        }
        
        return response.json();
      },
    };
  }

  // Inicializar desde storage
  private async initializeFromStorage(): Promise<void> {
    try {
      const storedTokens = await this.getStoredTokens();
      const storedUser = await this.getStoredUser();

      if (storedTokens && storedUser && this.isTokenValid(storedTokens.accessToken)) {
        this.state = {
          isAuthenticated: true,
          user: storedUser,
          tokens: storedTokens,
          loading: false,
          error: null,
        };

        // Programar refresh automático solo si está habilitado
        if (this.config.tokenRefresh.enabled && storedTokens.refreshToken) {
          this.scheduleTokenRefresh(storedTokens.accessToken);
        }

        this.notifyStateChange();
      } else {
        await this.clearStorage();
      }
    } catch (error) {
      console.error('Error initializing from storage:', error);
      await this.clearStorage();
    }
  }

  // Métodos públicos principales
  public async login(credentials: LoginCredentials): Promise<AuthUser> {
    this.setLoading(true);
    this.setError(null);

    try {
      const url = `${this.config.authServiceUrl}${this.config.endpoints.login}`;
      const response = await this.config.httpClient.post(url, credentials); 
      const tokens: AuthTokens = {
        accessToken: response.access_token || response.accessToken,
        refreshToken: response.refresh_token || response.refreshToken,
        expiresIn: response.expires_in || response.expiresIn,
        tokenType: response.token_type || response.tokenType || 'Bearer',
      };

      const user: AuthUser = response.user || this.parseTokenPayload(tokens.accessToken);
      
      // Guardar en storage
      await this.storeTokens(tokens);
      await this.storeUser(user);

      // Actualizar estado
      this.state = {
        isAuthenticated: true,
        user,
        tokens,
        loading: false,
        error: null,
      };

      // Programar refresh automático solo si está habilitado y hay refresh token
      if (this.config.tokenRefresh.enabled && tokens.refreshToken) {
        this.scheduleTokenRefresh(tokens.accessToken);
      }

      this.notifyStateChange();
      this.callbacks.onLogin?.(user, tokens);

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

  public async register(userData: RegisterData): Promise<AuthUser> {
    this.setLoading(true);
    this.setError(null);

    try {
      const url = `${this.config.authServiceUrl}${this.config.endpoints.register}`;
      const response = await this.config.httpClient.post(url, userData);

      // Después del registro, hacer login automático si se devuelven tokens
      if (response.access_token || response.accessToken) {
        const tokens: AuthTokens = {
          accessToken: response.access_token || response.accessToken,
          refreshToken: response.refresh_token || response.refreshToken,
          expiresIn: response.expires_in || response.expiresIn,
          tokenType: response.token_type || response.tokenType || 'Bearer',
        };

        const user: AuthUser = response.user || this.parseTokenPayload(tokens.accessToken);

        await this.storeTokens(tokens);
        await this.storeUser(user);

        this.state = {
          isAuthenticated: true,
          user,
          tokens,
          loading: false,
          error: null,
        };

        // Programar refresh automático solo si está habilitado y hay refresh token
        if (this.config.tokenRefresh.enabled && tokens.refreshToken) {
          this.scheduleTokenRefresh(tokens.accessToken);
        }

        this.notifyStateChange();
        this.callbacks.onLogin?.(user, tokens);

        return user;
      }

      return response.user;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Registration failed';
      this.setError(errorMessage);
      this.callbacks.onError?.(errorMessage);
      throw error;
    } finally {
      this.setLoading(false);
    }
  }

  public async logout(): Promise<void> {
    try {
      // Intentar hacer logout en el servidor
      if (this.state.tokens?.accessToken) {
        const url = `${this.config.authServiceUrl}${this.config.endpoints.logout}`;
        await this.config.httpClient.post(url, {}, {
          headers: {
            Authorization: `Bearer ${this.state.tokens.accessToken}`,
          },
        }).catch(() => {
          // Ignorar errores del servidor en logout
          // pero continuar con el logout local
        });
      }
    } finally {
      // Limpiar estado local siempre
      await this.clearStorage();
      this.clearRefreshTimer();

      this.state = {
        isAuthenticated: false,
        user: null,
        tokens: null,
        loading: false,
        error: null,
      };

      this.notifyStateChange();
      this.callbacks.onLogout?.();
    }
  }

  public async refreshTokens(): Promise<AuthTokens> {
    // Si el refresh de tokens está deshabilitado, lanzar error
    if (!this.config.tokenRefresh.enabled) {
      throw new Error('Token refresh is disabled');
    }

    // Evitar múltiples refreshes simultáneos
    if (this.isRefreshing && this.refreshPromise) {
      return this.refreshPromise;
    }

    this.isRefreshing = true;
    this.refreshPromise = this.performTokenRefresh();

    try {
      const tokens = await this.refreshPromise;
      return tokens;
    } finally {
      this.isRefreshing = false;
      this.refreshPromise = null;
    }
  }

  private async performTokenRefresh(): Promise<AuthTokens> {
    const refreshToken = this.state.tokens?.refreshToken;

    if (!refreshToken) {
      throw new Error('No refresh token available');
    }

    try {
      const url = `${this.config.authServiceUrl}${this.config.endpoints.refresh}`;
      const response = await this.config.httpClient.post(url, {
        refresh_token: refreshToken,
      });

      const tokens: AuthTokens = {
        accessToken: response.access_token || response.accessToken,
        refreshToken: response.refresh_token || response.refreshToken || refreshToken,
        expiresIn: response.expires_in || response.expiresIn,
        tokenType: response.token_type || response.tokenType || 'Bearer',
      };

      // Actualizar storage y estado
      await this.storeTokens(tokens);
      this.state.tokens = tokens;

      // Programar próximo refresh solo si está habilitado
      if (this.config.tokenRefresh.enabled) {
        this.scheduleTokenRefresh(tokens.accessToken);
      }

      this.notifyStateChange();
      this.callbacks.onTokenRefresh?.(tokens);

      return tokens;
    } catch (error) {
      // Si falla el refresh, hacer logout
      await this.logout();
      throw error;
    }
  }

  // Métodos de utilidad públicos
  public getState(): AuthState {
    return { ...this.state };
  }

  public getCurrentUser(): AuthUser | null {
    return this.state.user;
  }

  public getAccessToken(): string | null {
    return this.state.tokens?.accessToken || null;
  }

  public getRefreshToken(): string | null {
    return this.state.tokens?.refreshToken || null;
  }

  public isAuthenticated(): boolean {
    return this.state.isAuthenticated && this.isTokenValid(this.state.tokens?.accessToken);
  }

  public async getValidAccessToken(): Promise<string | null> {
    if (!this.state.tokens?.accessToken) {
      return null;
    }

    // Si el refresh está deshabilitado, solo devolver el token actual si es válido
    if (!this.config.tokenRefresh.enabled) {
      return this.isTokenValid(this.state.tokens.accessToken) ? this.state.tokens.accessToken : null;
    }

    // Si el token está próximo a expirar y hay refresh token, refrescarlo
    if (this.shouldRefreshToken(this.state.tokens.accessToken) && this.state.tokens.refreshToken) {
      try {
        const tokens = await this.refreshTokens();
        return tokens.accessToken;
      } catch (error) {
        return null;
      }
    }

    return this.state.tokens.accessToken;
  }

  // Métodos para integración con otros clientes HTTP
  public async getAuthHeaders(): Promise<Record<string, string>> {
    const token = await this.getValidAccessToken();
    if (!token) {
      throw new Error('No valid authentication token');
    }

    return {
      Authorization: `Bearer ${token}`,
    };
  }

  // Métodos privados de utilidad
  private isTokenValid(token?: string): boolean {
    if (!token) return false;

    try {
      const payload = this.parseTokenPayload(token);
      const now = Math.floor(Date.now() / 1000);
      return payload.exp > now;
    } catch {
      return false;
    }
  }

  private shouldRefreshToken(token: string): boolean {
    if (!this.config.tokenRefresh.enabled) {
      return false;
    }

    try {
      const payload = this.parseTokenPayload(token);
      const now = Math.floor(Date.now() / 1000);
      return payload.exp - now < this.config.tokenRefresh.bufferTime!;
    } catch {
      return false;
    }
  }

  private parseTokenPayload(token: string): any {
    const base64Payload = token.split('.')[1];
    const payload = JSON.parse(atob(base64Payload));
    return payload;
  }

  private scheduleTokenRefresh(token: string): void {
    // Solo programar refresh si está habilitado
    if (!this.config.tokenRefresh.enabled) {
      return;
    }

    this.clearRefreshTimer();

    try {
      const payload = this.parseTokenPayload(token);
      const now = Math.floor(Date.now() / 1000);
      const timeUntilRefresh = (payload.exp - now - this.config.tokenRefresh.bufferTime!) * 1000;

      if (timeUntilRefresh > 0) {
        this.refreshTimer = setTimeout(() => {
          this.refreshTokens().catch(console.error);
        }, timeUntilRefresh);
      }
    } catch (error) {
      console.error('Error scheduling token refresh:', error);
    }
  }

  private clearRefreshTimer(): void {
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
      this.refreshTimer = null;
    }
  }

  // Métodos de storage actualizados para usar el adaptador
  private async storeTokens(tokens: AuthTokens): Promise<void> {
    try {
      await this.storageAdapter.setItem(this.config.storage.tokenKey || '', tokens.accessToken || '');
      if (tokens.refreshToken) {
        await this.storageAdapter.setItem(this.config.storage.refreshTokenKey || '', tokens.refreshToken);
      }
    } catch (error) {
      console.error('Error storing tokens:', error);
    }
  }

  private async storeUser(user: AuthUser): Promise<void> {
    try {
      await this.storageAdapter.setItem(this.config.storage.userKey || '', JSON.stringify(user));
    } catch (error) {
      console.error('Error storing user:', error);
    }
  }

  private async getStoredTokens(): Promise<AuthTokens | null> {
    try {
      const accessToken = await this.storageAdapter.getItem(this.config.storage.tokenKey || '');
      const refreshToken = await this.storageAdapter.getItem(this.config.storage.refreshTokenKey || '');

      if (accessToken) {
        return {
          accessToken,
          refreshToken: refreshToken || undefined,
        };
      }
    } catch (error) {
      console.error('Error getting stored tokens:', error);
    }
    return null;
  }

  private async getStoredUser(): Promise<AuthUser | null> {
    try {
      const userData = await this.storageAdapter.getItem(this.config.storage.userKey || '');
      if (userData) {
        try {
          return JSON.parse(userData);
        } catch {
          return null;
        }
      }
    } catch (error) {
      console.error('Error getting stored user:', error);
    }
    return null;
  }

  private async clearStorage(): Promise<void> {
    try {
      await this.storageAdapter.removeItem(this.config.storage.tokenKey || '');
      await this.storageAdapter.removeItem(this.config.storage.refreshTokenKey || '');
      await this.storageAdapter.removeItem(this.config.storage.userKey || '');
    } catch (error) {
      console.error('Error clearing storage:', error);
    }
  }

  // Métodos de estado
  private setLoading(loading: boolean): void {
    this.state.loading = loading;
    this.notifyStateChange();
  }

  private setError(error: string | null): void {
    this.state.error = error;
    this.notifyStateChange();
  }

  // MÉTODO ACTUALIZADO: Notificar cambios a todos los listeners
  private notifyStateChange(): void {
    const currentState = this.getState();
    
    // Notificar a los callbacks tradicionales
    this.callbacks.onAuthStateChanged?.(currentState);
    
    // Notificar a todos los listeners suscritos
    this.stateChangeListeners.forEach(listener => {
      try {
        listener(currentState);
      } catch (error) {
        console.error('Error in state change listener:', error);
      }
    });
  }
}

export { AuthSDK };
export type { AuthConfig, AuthState, AuthUser, AuthTokens, LoginCredentials, RegisterData };