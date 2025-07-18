import { IndexedDBAdapter } from '../storage/IndexedDBAdapter';
import { LocalStorageAdapter } from '../storage/LocalStorageAdapter';
import { StorageAdapter } from '../storage/StorageAdapter';
import { AuthCallbacks, AuthConfig, AuthState, AuthTokens, AuthUser, HttpClient, LoginCredentials, RegisterData } from '../types';
import ExpirationHandler from './ExpirationHandler';
import { TokenHandler } from './TokenHandler';

// Tipo para el callback de suscripción
type StateChangeListener = (state: AuthState) => void;
class TokenExtractor {
  private static readonly TOKEN_KEYS = [
    'accessToken', 'access_token', 'token', 'authToken', 'auth_token',
    'bearerToken', 'bearer_token', 'jwt', 'jwtToken', 'jwt_token'
  ];

  private static readonly REFRESH_TOKEN_KEYS = [
    'refreshToken', 'refresh_token', 'renewToken', 'renew_token'
  ];

  private static readonly EXPIRES_KEYS = [
    'expiresIn', 'expires_in', 'exp', 'expiration', 'expires_at', 'expiresAt',
    'expiry', 'expiry_time', 'expiryTime', 'valid_until', 'validUntil'
  ];

  private static readonly TOKEN_TYPE_KEYS = [
    'tokenType', 'token_type', 'type', 'authType', 'auth_type'
  ];

  private static readonly USER_KEYS = [
    'user', 'userData', 'user_data', 'profile', 'userProfile', 'user_profile',
    'data', 'userInfo', 'user_info', 'account', 'accountData', 'account_data',
    'accountProfile', 'account_profile', 'me', 'myProfile', 'my_profile',
    'currentUser', 'current_user', 'loggedInUser', 'logged_in_user',
    'usuario', 'usuarioData', 'usuario_data', 'perfil', 'perfilData', 'perfil_data',
    'name', 'username', 'userName', 'email', 'userEmail', 'user_email', 'userId', 'id',
    'userIdData', 'user_id_data', 'userIdProfile', 'user_id_profile'
  ];

  /**
   * Búsqueda profunda recursiva en un objeto
   */
  private static deepSearch(obj: any, keys: string[]): any {
    if (!obj || typeof obj !== 'object') return null;

    // Buscar en el nivel actual
    for (const key of keys) {
      if (obj.hasOwnProperty(key) && obj[key] !== null && obj[key] !== undefined) {
        return obj[key];
      }
    }

    // Buscar recursivamente en objetos anidados
    for (const value of Object.values(obj)) {
      if (value && typeof value === 'object') {
        const result = this.deepSearch(value, keys);
        if (result) return result;
      }
    }

    return null;
  }

  /**
   * Normaliza el tiempo de expiración a segundos desde ahora
   */
  private static normalizeExpirationTime(expiresValue: any): number | undefined {
    if (!expiresValue) return undefined;

    // Si ya es un número, asumimos que son segundos
    if (typeof expiresValue === 'number') {
      return expiresValue;
    }

    // Si es una cadena, intentar parsearlo
    if (typeof expiresValue === 'string') {
      // Intentar parsear como timestamp Unix (segundos)
      const timestampSeconds = parseInt(expiresValue);
      if (!isNaN(timestampSeconds) && timestampSeconds > 1000000000) {
        const now = Math.floor(Date.now() / 1000);
        return Math.max(0, timestampSeconds - now);
      }

      // Intentar parsear como fecha ISO/readable
      const date = new Date(expiresValue);
      if (!isNaN(date.getTime())) {
        const now = Date.now();
        const expiresMs = date.getTime();
        const secondsUntilExpiry = Math.floor((expiresMs - now) / 1000);
        return Math.max(0, secondsUntilExpiry);
      }

      // Intentar parsear como número en string
      const numberValue = parseInt(expiresValue);
      if (!isNaN(numberValue)) {
        return numberValue;
      }
    }

    console.warn('Could not parse expiration time:', expiresValue);
    return undefined;
  }

  /**
   * Extrae y normaliza el tiempo de expiración
   */
  private static extractExpirationTime(response: any): number | undefined {
    const expiresValue = this.deepSearch(response, this.EXPIRES_KEYS);
    return this.normalizeExpirationTime(expiresValue);
  }
  static extractTokens(response: any): AuthTokens {
    const accessToken = this.deepSearch(response, this.TOKEN_KEYS);
    const refreshToken = this.deepSearch(response, this.REFRESH_TOKEN_KEYS);
    const expiresIn = this.extractExpirationTime(response);
    const tokenType = this.deepSearch(response, this.TOKEN_TYPE_KEYS);
    if (!accessToken) {
      throw new Error('No access token found in response');
    }

    return {
      accessToken,
      refreshToken,
      expiresIn,
      tokenType: tokenType || 'Bearer',
    };
  }

  /**
   * Extrae información del usuario de cualquier estructura de respuesta
   */
  static extractUser(response: any): AuthUser | null {
    const userData = this.deepSearch(response, this.USER_KEYS);

    if (userData) {
      return userData;
    }

    // Si no hay datos de usuario explícitos, intentar extraer del token
    const accessToken = this.deepSearch(response, this.TOKEN_KEYS);
    if (accessToken) {
      try {
        return this.parseUserFromToken(accessToken);
      } catch (error) {
        console.warn('Could not parse user from token:', error);
      }
    }

    // Como último recurso, crear un usuario básico con datos disponibles
    const name = this.deepSearch(response, ['name', 'username', 'user_name', 'email']);
    if (name) {
      return {
        id: this.deepSearch(response, ['id', 'user_id', 'userId']) || 'unknown',
        name,
        email: this.deepSearch(response, ['email', 'user_email', 'userEmail']),
      };
    }

    return null;
  }

  /**
   * Intenta parsear información del usuario desde el token JWT
   */
  private static parseUserFromToken(token: string): AuthUser | null {
    try {
      const base64Payload = token.split('.')[1];
      const payload = JSON.parse(atob(base64Payload));

      return {
        id: payload.sub || payload.user_id || payload.id || 'unknown',
        name: payload.name || payload.username || payload.email || 'User',
        email: payload.email,
        ...payload // Incluir cualquier otro campo del payload
      };
    } catch {
      return null;
    }
  }

  /**
   * Método de debugging para ver toda la estructura de la respuesta
   */
  static debugResponse(response: any, depth: number = 0): void {
    const indent = '  '.repeat(depth);

    if (response && typeof response === 'object') {
      console.log(`${indent}Object keys:`, Object.keys(response));

      for (const [key, value] of Object.entries(response)) {
        console.log(`${indent}${key}:`, typeof value, Array.isArray(value) ? '[Array]' : '');

        if (depth < 3 && value && typeof value === 'object') {
          this.debugResponse(value, depth + 1);
        }
      }
    } else {
      console.log(`${indent}Primitive value:`, response);
    }
  }

  /**
   * Método de debugging específico para tiempos de expiración
   */
  static debugExpirationTime(response: any): void {
    console.log('=== Expiration Time Debug ===');

    const expiresValue = this.deepSearch(response, this.EXPIRES_KEYS);
    console.log('Raw expiration value:', expiresValue, typeof expiresValue);

    if (expiresValue) {
      const normalized = this.normalizeExpirationTime(expiresValue);
      console.log('Normalized to seconds:', normalized);

      if (normalized) {
        const expiryDate = new Date(Date.now() + normalized * 1000);
        console.log('Will expire at:', expiryDate.toISOString());
      }
    }

    // Mostrar todos los campos que podrían contener expiración
    console.log('All possible expiration fields:');
    this.EXPIRES_KEYS.forEach(key => {
      const value = this.deepSearch(response, [key]);
      if (value) {
        console.log(`  ${key}:`, value, typeof value);
      }
    });
  }
}

class AuthSDK {
  private config: Required<AuthConfig>;
  private state: AuthState;
  private callbacks: AuthCallbacks;
  private refreshTimer: NodeJS.Timeout | null = null;
  private expirationTimer: NodeJS.Timeout | null = null; // Para manejar mi expiracion d tokens// test aun no se si funciona
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


  // nuevo metodo para probar a ver////// 
  // Método helper para obtener datos del token almacenado
  private async getStoredTokenData(): Promise<any> {
    try {
      const tokenDataStr = await this.storageAdapter.getItem(this.config.storage.tokenKey || '');
      if (tokenDataStr) {
        const tokenData = JSON.parse(tokenDataStr);
        if (tokenData.storedAt) {
          return tokenData;
        }
      }
    } catch (error) {
      console.error('Error getting stored token data:', error);
    }
    return null;
  }

  // Limpiar timer de expiración
  private clearExpirationTimer(): void {
    if (this.expirationTimer) {
      clearTimeout(this.expirationTimer);
      this.expirationTimer = null;
    }
  }
  private scheduleTokenExpiration(tokens: AuthTokens): void {
    this.clearExpirationTimer();

    const expiresInSeconds = ExpirationHandler.calculateExpiration(
      tokens.accessToken,
      tokens.expiresIn,
      tokens.expiresAt
    );

    if (!expiresInSeconds) {
      // Usar tiempo por defecto basado en el tipo de token
      const tokenInfo = TokenHandler.parseToken(tokens.accessToken);
      const defaultExpiration = tokenInfo.type === 'sanctum' ? 24 * 60 * 60 : 60 * 60;
      console.warn(`No expiration info found, using default ${defaultExpiration}s expiration`);

      this.expirationTimer = setTimeout(() => {
        this.handleTokenExpiration();
      }, defaultExpiration * 1000);
      return;
    }

    this.expirationTimer = setTimeout(() => {
      this.handleTokenExpiration();
    }, expiresInSeconds * 1000);

    // console.log(`Token expiration scheduled in ${expiresInSeconds} seconds`);
  }
  // Nuevo método para manejar expiración automática
  private async handleTokenExpiration(): Promise<void> {
    // console.log('Token expired, handling expiration...');

    // Si el refresh está habilitado e tenemos refresh token, intentar refresh
    if (this.config.tokenRefresh.enabled && this.state.tokens?.refreshToken) {
      try {
        // console.log('Attempting automatic token refresh...');
        await this.refreshTokens();
        return; // Refresh exitoso, no hacer logout
      } catch (error) {
        console.error('Automatic token refresh failed:', error);
        // Continuar con logout automático
      }
    }

    // Si no se puede refresh o está deshabilitado, hacer logout automático
    // console.log('Performing automatic logout due to token expiration');
    await this.logout();

    // Notificar que la sesión expiró
    this.callbacks.onTokenExpired?.();
  }




  ///Aqui separo los metodos de expiracion.
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

  // NUEVO MÉTODO: Habilitar debug de respuestas
  public enableDebugMode(): void {
    console.log('AuthSDK Debug Mode enabled');
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

      if (storedTokens && storedUser) {
        this.state = {
          isAuthenticated: true,
          user: storedUser,
          tokens: storedTokens,
          loading: false,
          error: null,
        };

        if (this.config.tokenRefresh.enabled && storedTokens.refreshToken) {
          this.scheduleTokenRefresh(storedTokens);
        }

        // NUEVO: Siempre programar expiración automática
        this.scheduleTokenExpiration(storedTokens);

        this.notifyStateChange();
      } else {
        await this.clearStorage();
      }
    } catch (error) {
      console.error('Error initializing from storage:', error);
      await this.clearStorage();
    }
  }

  // Métodos públicos principales - ACTUALIZADOS con búsqueda profunda
  public async login(credentials: LoginCredentials): Promise<AuthUser> {
    this.setLoading(true);
    this.setError(null);

    try {
      const url = `${this.config.authServiceUrl}${this.config.endpoints.login}`;
      const response = await this.config.httpClient.post(url, credentials);

      const tokens = TokenExtractor.extractTokens(response);
      const user = TokenExtractor.extractUser(response);

      if (!user) {
        throw new Error('No user information found in response');
      }

      await this.storeTokens(tokens);
      await this.storeUser(user);

      this.state = {
        isAuthenticated: true,
        user,
        tokens,
        loading: false,
        error: null,
      };

      // Programar refresh automático si está habilitado
      if (this.config.tokenRefresh.enabled && tokens.refreshToken) {
        this.scheduleTokenRefresh(tokens);
      }

      // NUEVO: Siempre programar expiración automática
      this.scheduleTokenExpiration(tokens);

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

      // Usar el nuevo extractor de tokens
      try {
        const tokens = TokenExtractor.extractTokens(response);
        const user = TokenExtractor.extractUser(response);

        if (!user) {
          throw new Error('No user information found in response');
        }

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
          this.scheduleTokenRefresh(tokens);
        }

        this.notifyStateChange();
        this.callbacks.onLogin?.(user, tokens);

        return user;
      } catch (tokenError) {
        // Si no se pueden extraer tokens, asumir que el registro requiere login separado
        console.warn('No tokens found in register response, assuming manual login required');
        const user = TokenExtractor.extractUser(response);
        return user || { id: 'unknown', name: 'User' };
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

  public async logout(): Promise<void> {
    try {
      if (this.state.tokens?.accessToken) {
        const url = `${this.config.authServiceUrl}${this.config.endpoints.logout}`;
        await this.config.httpClient.post(url, {}, {
          headers: {
            Authorization: `Bearer ${this.state.tokens.accessToken}`,
          },
        }).catch(() => {
          // Ignorar errores del servidor
        });
      }
    } finally {
      await this.clearStorage();
      this.clearRefreshTimer();
      this.clearExpirationTimer(); // NUEVO: Limpiar timer de expiración

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

  private processRefreshResponse(response: any, originalRefreshToken: string): AuthTokens {
    const tokens = TokenExtractor.extractTokens(response);

    // Mantener el refresh token original si no viene uno nuevo
    if (!tokens.refreshToken) {
      tokens.refreshToken = originalRefreshToken;
    }

    // Actualizar storage y estado
    this.storeTokens(tokens);
    this.state.tokens = tokens;

    // Programar próximo refresh
    if (this.config.tokenRefresh.enabled) {
      this.scheduleTokenRefresh(tokens);
    }

    // Programar expiración automática
    this.scheduleTokenExpiration(tokens);

    this.notifyStateChange();
    this.callbacks.onTokenRefresh?.(tokens);

    return tokens;
  }

  private async performTokenRefresh(): Promise<AuthTokens> {
    const refreshToken = this.state.tokens?.refreshToken;

    if (!refreshToken) {
      throw new Error('No refresh token available');
    }

    try {
      const url = `${this.config.authServiceUrl}${this.config.endpoints.refresh}`;

      // Detectar tipo de token para decidir cómo enviarlo
      const tokenInfo = TokenHandler.parseToken(refreshToken);

      let requestConfig: any = {};

      if (tokenInfo.type === 'sanctum') {
        // Para Sanctum, enviar el token en Authorization header
        requestConfig = {
          headers: {
            Authorization: `Bearer ${refreshToken}`
          }
        };

        // También enviar en el body por compatibilidad
        const response = await this.config.httpClient.post(url, {
          refresh_token: refreshToken,
        }, requestConfig);

        return this.processRefreshResponse(response, refreshToken);
      } else {
        // Para JWT y otros, enviar en el body
        const response = await this.config.httpClient.post(url, {
          refresh_token: refreshToken,
        });

        return this.processRefreshResponse(response, refreshToken);
      }
    } catch (error) {
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

  public async isAuthenticated(): Promise<boolean> {
    return this.state.isAuthenticated && await this.isTokenValid(this.state.tokens?.accessToken);
  }

  public async getValidAccessToken(): Promise<string | null> {
    if (!this.state.tokens?.accessToken) {
      return null;
    }

    // Si el refresh está deshabilitado, solo devolver el token actual si es válido
    if (!this.config.tokenRefresh.enabled) {
      return await this.isTokenValid(this.state.tokens.accessToken) ? this.state.tokens.accessToken : null;
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
  public debugToken(token: string): void {
    console.log('=== Token Debug ===');
    const tokenInfo = TokenHandler.parseToken(token);
    console.log('Token type:', tokenInfo.type);
    console.log('Token info:', tokenInfo);

    if (tokenInfo.type === 'jwt' && tokenInfo.payload) {
      console.log('JWT Payload:', tokenInfo.payload);
      if (tokenInfo.exp) {
        const expiryDate = new Date(tokenInfo.exp * 1000);
        console.log('JWT expires at:', expiryDate.toISOString());
      }
    }
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

  // NUEVO MÉTODO: Debug manual de respuesta
  public debugResponse(response: any): void {
    console.log('=== AuthSDK Response Debug ===');
    TokenExtractor.debugResponse(response);

    // Debug específico de expiración
    TokenExtractor.debugExpirationTime(response);

    try {
      const tokens = TokenExtractor.extractTokens(response);
      console.log('Extracted tokens:', tokens);

      if (tokens.expiresIn) {
        const expiryDate = new Date(Date.now() + tokens.expiresIn * 1000);
        console.log('Token will expire at:', expiryDate.toISOString());
      }
    } catch (error) {
      console.log('Token extraction error:', error);
    }

    try {
      const user = TokenExtractor.extractUser(response);
      console.log('Extracted user:', user);
    } catch (error) {
      console.log('User extraction error:', error);
    }
  }
  private async validateSanctumToken(token: string): Promise<boolean> {
    const tokenData = await this.getStoredTokenData();
    if (!tokenData?.storedAt) return false;

    // Si tenemos expiresAt (formato ISO), usarlo
    if (tokenData.expiresAt) {
      const expiresIn = ExpirationHandler.normalizeExpiration(tokenData.expiresAt);
      return expiresIn ? expiresIn > 0 : false;
    }

    // Si tenemos expiresIn, calcular basándose en cuándo se almacenó
    if (tokenData.expiresIn) {
      const now = Math.floor(Date.now() / 1000);
      const timeElapsed = now - tokenData.storedAt;
      return timeElapsed < tokenData.expiresIn;
    }

    // Tiempo por defecto para Sanctum: 24 horas
    const now = Math.floor(Date.now() / 1000);
    const timeElapsed = now - tokenData.storedAt;
    const defaultExpiration = 24 * 60 * 60; // 24 horas
    return timeElapsed < defaultExpiration;
  }
  //CLAUDE
  private async validateOpaqueToken(token: string): Promise<boolean> {
    const tokenData = await this.getStoredTokenData();
    if (!tokenData?.storedAt) return false;

    const now = Math.floor(Date.now() / 1000);
    const timeElapsed = now - tokenData.storedAt;
    const defaultExpiration = 60 * 60; // 1 hora por defecto
    return timeElapsed < defaultExpiration;
  }
  // Métodos privados de utilidad
  private async isTokenValid(token?: string): Promise<boolean> {
    if (!token) return false;

    const tokenInfo = TokenHandler.parseToken(token);
    if (!tokenInfo) {
      console.warn('Invalid token format');
      return false;
    }
    switch (tokenInfo.type) {
      case 'jwt':
        // Para JWT, usar la información del payload
        return tokenInfo.isValid;

      case 'sanctum':
        // Para Sanctum, verificar con información almacenada
        return await this.validateSanctumToken(token);

      case 'opaque':
        // Para tokens opacos, verificar con información almacenada
        return await this.validateOpaqueToken(token);

      default:
        return false;
    }
  }

  //CLAUDE

  private shouldRefreshToken(token: string): boolean {
    if (!this.config.tokenRefresh.enabled) {
      return false;
    }

    // Si tenemos información de expiración en el estado, usarla
    if (this.state.tokens?.expiresIn) {
      const now = Math.floor(Date.now() / 1000);
      const estimatedExpiry = now + this.state.tokens.expiresIn;
      return estimatedExpiry - now < this.config.tokenRefresh.bufferTime!;
    }

    // Fallback: intentar parsear el JWT
    try {
      const payload = this.parseTokenPayload(token);
      const now = Math.floor(Date.now() / 1000);
      return payload.exp - now < this.config.tokenRefresh.bufferTime!;
    } catch {
      // Si no se puede parsear, no refrescar automáticamente
      return false;
    }
  }

  private parseTokenPayload(token: string): any {
    try {
      if (!token || typeof token !== 'string') {
        throw new Error('Token inválido o vacío');
      }

      // Detectar si es un token de Sanctum (contiene |)
      if (token.includes("|")) {
        // console.log('Token de Sanctum detectado');
        return {
          type: 'sanctum',
          tokenId: token.split('|')[0],
          hash: token.split('|')[1],
          warning: 'Sanctum tokens do not contain payload data'
        };
      }

      // Procesar tokens JWT
      const parts = token.split('.');
      if (parts.length !== 3) {
        throw new Error('Token JWT inválido: debe tener 3 partes');
      }

      const base64Payload = parts[1];

      // Añadir padding si es necesario
      const paddedBase64 = base64Payload.padEnd(
        base64Payload.length + (4 - (base64Payload.length % 4)) % 4,
        '='
      );

      // console.log('JWT Base64 payload:', paddedBase64);

      // Decodificar base64
      const decodedPayload = atob(paddedBase64);
      // console.log('JWT Decoded payload:', decodedPayload);

      // Parsear JSON
      const payload = JSON.parse(decodedPayload);
      return {
        type: 'jwt',
        ...payload
      };

    } catch (error: any) {
      console.error('Error parsing token payload:', error);
      console.error('Token recibido:', token);
      throw new Error(`Error parsing token: ${error.message}`);
    }
  }

  private scheduleTokenRefresh(tokens: AuthTokens): void { //CLAUDE
    if (!this.config.tokenRefresh.enabled || !tokens.refreshToken) return;

    this.clearRefreshTimer();

    let expiresInSeconds: number | undefined;

    // Calcular cuándo refrescar usando el nuevo handler
    expiresInSeconds = ExpirationHandler.calculateExpiration(
      tokens.accessToken,
      tokens.expiresIn,
      tokens.expiresAt
    );

    if (!expiresInSeconds) {
      console.warn('No expiration info available, skipping automatic refresh');
      return;
    }

    const bufferMs = this.config.tokenRefresh.bufferTime! * 1000;
    const expiresMs = expiresInSeconds * 1000;
    const timeUntilRefresh = expiresMs - bufferMs;

    if (timeUntilRefresh > 0) {
      this.refreshTimer = setTimeout(() => {
        this.refreshTokens().catch(console.error);
      }, timeUntilRefresh);

      // console.log(`Token refresh scheduled in ${Math.floor(timeUntilRefresh / 1000)}s`);
    } else {
      console.warn('Buffer time mayor que expiresIn, refresh inmediato requerido');
      // Programar refresh inmediato si el token está muy cerca de expirar
      this.refreshTimer = setTimeout(() => {
        this.refreshTokens().catch(console.error);
      }, 1000);
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
    const tokenData = {
      ...tokens,
      storedAt: Math.floor(Date.now() / 1000)
    };
    await this.storageAdapter.setItem(this.config.storage.tokenKey!, JSON.stringify(tokenData));
    if (tokens.refreshToken) {
      await this.storageAdapter.setItem(this.config.storage.refreshTokenKey!, tokens.refreshToken);
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
      const tokenDataStr = await this.storageAdapter.getItem(this.config.storage.tokenKey || '');
      const refreshToken = await this.storageAdapter.getItem(this.config.storage.refreshTokenKey || '');

      if (tokenDataStr) {
        try {
          // Intentar parsear como objeto con timestamp
          const tokenData = JSON.parse(tokenDataStr);

          if (tokenData.accessToken && tokenData.storedAt) {
            // Calcular tiempo restante basado en cuándo se almacenó
            const now = Math.floor(Date.now() / 1000);
            const timeElapsed = now - tokenData.storedAt;
            const remainingTime = tokenData.expiresIn ? Math.max(0, tokenData.expiresIn - timeElapsed) : undefined;

            return {
              accessToken: tokenData.accessToken,
              refreshToken: refreshToken || tokenData.refreshToken,
              expiresIn: remainingTime,
              tokenType: tokenData.tokenType,
            };
          }
        } catch {
          // Fallback: tratar como string simple (compatibilidad hacia atrás)
          return {
            accessToken: tokenDataStr,
            refreshToken: refreshToken || undefined,
          };
        }
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