export interface AuthConfig {
  authServiceUrl: string;
  endpoints?: {
    login?: string;
    register?: string;
    refresh?: string;
    logout?: string;
    profile?: string;
  };
  storage?: {
    type?: 'localStorage' | 'indexedDB';
    dbName?: string;
    dbVersion?: number;
    storeName?: string;
    tokenKey?: string;
    refreshTokenKey?: string;
    userKey?: string;
  };
  tokenRefresh?: {
    enabled?: boolean;
    bufferTime?: number; // segundos antes de expirar
    maxRetries?: number;
    minimumTokenLifetime?: number; // NUEVO: tiempo mínimo de vida del token en segundos
    gracePeriod?: number; // NUEVO: período de gracia para tokens que expiran rápido
  };
  httpClient?: HttpClient;
  
  /**
   * Enable debug mode for verbose logging
   * @default false
   */
  debug?: boolean;

  // NUEVO: Configuración flexible para diferentes backends
  backend?: {
    type?: 'node-express' | 'laravel-sanctum' | 'jwt-standard' | 'custom';
    userSearchPaths?: string[];
    fieldMappings?: Record<string, string[]>;
    preserveOriginalData?: boolean;
  };

  // NUEVO: Configuración de validación de sesión
  sessionValidation?: {
    enabled?: boolean; // Habilitar validación automática
    validateOnFocus?: boolean; // Validar cuando la app vuelve al foco
    validateOnVisibility?: boolean; // Validar cuando la página se vuelve visible
    maxInactivityTime?: number; // Tiempo máximo de inactividad en segundos antes de validar
    autoLogoutOnInvalid?: boolean; // Cerrar sesión automáticamente si es inválida
    validateOnStartup?: boolean; // Validar sesión al iniciar la aplicación
  };

  // NUEVO: Configuración de interceptores HTTP
  interceptors?: {
    enabled?: boolean; // Habilitar interceptores automáticos
    autoInjectToken?: boolean; // Inyectar token automáticamente en requests
    handleAuthErrors?: boolean; // Manejar 401/422 automáticamente
    axiosInstance?: any; // Instancia de Axios (opcional)
  };
}
 
export interface HttpClient {
  post(url: string, data?: any, config?: any): Promise<any>;
  get(url: string, config?: any): Promise<any>;
  put(url: string, data?: any, config?: any): Promise<any>;
  delete(url: string, config?: any): Promise<any>;
}

export interface AuthTokens {
  accessToken: string;
  refreshToken?: string;
  expiresIn?: number;
  expiresAt?: string | number;
  tokenType?: string;
  
  // NUEVO: Metadatos para debugging y backend detection
  _originalTokenResponse?: any;
  _backendType?: string;
  _tokenFormat?: 'jwt' | 'opaque' | 'sanctum';
}

export interface AuthUser {
  id: string;
  email?: string;
  name?: string;
  roles?: string[];
  
  // NUEVO: Campos comunes extendidos
  firstName?: string;
  lastName?: string;
  username?: string;
  role?: string | string[];
  permissions?: string[];
  isActive?: boolean;
  profile?: any;
  
  // NUEVO: Campos específicos por backend
  // Laravel Sanctum
  email_verified_at?: string;
  created_at?: string;
  updated_at?: string;
  sucursales?: Array<{
    id: number;
    sucursal: string;
    sigla: string;
    rol: string;
  }>;
  full_name?: string;
  
  // Node.js específicos
  lastLogin?: string | Date;
  createdAt?: string | Date;
  updatedAt?: string | Date;
  _id?: string;
  
  // JWT específicos
  sub?: string;
  aud?: string | string[];
  iss?: string;
  exp?: number;
  iat?: number;
  
  // NUEVO: Metadatos para preservar datos originales
  _originalUserResponse?: any;
  _backendType?: string;
  _extractionMethod?: 'direct' | 'nested' | 'jwt-parsed' | 'scattered';
  
  // Permite cualquier campo adicional del backend
  [key: string]: any;
}

export interface LoginCredentials {
  usuario?: string; // For legacy support
  clave?: string; // For legacy support
  code?: string; // For legacy support
  email?: string; // For new implementations
  password?: string; // For new implementations
  
  // NUEVO: Campos adicionales comunes
  username?: string;
  phone?: string;
  device_name?: string; // Para Sanctum
  
  // Permite campos adicionales
  [key: string]: any;
}

export interface RegisterData {
  usuario?: string; // For legacy support
  clave?: string; // For legacy support
  code?: string; // For legacy support
  email: string;
  password: string;
  name?: string;
  
  // NUEVO: Campos opcionales estándar
  firstName?: string;
  lastName?: string;
  username?: string;
  phone?: string;
  
  // Permite campos adicionales del backend
  [key: string]: any;
}

export interface AuthState {
  isAuthenticated: boolean;
  user: AuthUser | null;
  tokens: AuthTokens | null;
  loading: boolean;
  error: string | null;
  
  // NUEVO: Estados adicionales
  isRefreshing?: boolean;
  lastActivity?: number;
  sessionExpiry?: number;
  backendType?: string;
  
  // NUEVO: Información de capacidades
  capabilities?: {
    canRefresh: boolean;
    hasProfile: boolean;
    supportsOTP: boolean;
    supportsBiometric: boolean;
  };
}

export interface AuthCallbacks {
  onAuthStateChanged?: (state: AuthState) => void;
  onTokenRefresh?: (tokens: AuthTokens) => void;
  onLogin?: (user: AuthUser, tokens: AuthTokens) => void;
  onLogout?: () => void;
  onError?: (error: string) => void;
  onTokenExpired?: () => void;

  // NUEVO: Callbacks adicionales
  onSessionRestored?: (user: AuthUser) => void;
  onRefreshFailed?: (error: string) => void;
  onUserUpdated?: (user: AuthUser) => void;
  onBackendDetected?: (backendType: string) => void;
  onSessionInvalid?: () => void; // Cuando la sesión es inválida en el servidor
  onSessionValidated?: () => void; // Cuando se valida exitosamente la sesión
}

// NUEVO: Información extendida de sesión
export interface ExtendedSessionInfo {
  isValid: boolean;
  user: AuthUser | null;
  tokens: AuthTokens | null;
  
  // Información de token
  tokenType: string | null;
  tokenFormat: 'jwt' | 'opaque' | 'sanctum' | null;
  expiresIn: number | null;
  
  // Capacidades
  refreshAvailable: boolean;
  canRefresh: boolean;
  
  // Metadatos
  sessionId: string | null;
  backendType: string | null;
  storedAt: number | null;
  lastRefreshed: number | null;
  
  // Información original
  originalResponse: any;
}
