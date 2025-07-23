// =============================================
// TIPOS MEJORADOS PARA SOPORTE FLEXIBLE
// =============================================

// Re-export tipos existentes para compatibilidad
export * from './index';

export interface EnhancedAuthConfig {
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
    bufferTime?: number;
    maxRetries?: number;
    minimumTokenLifetime?: number;
    gracePeriod?: number;
  };
  httpClient?: HttpClient;
  
  // NUEVO: Configuración flexible para diferentes backends
  backend?: {
    type?: 'node-express' | 'laravel-sanctum' | 'jwt-standard' | 'custom';
    userSearchPaths?: string[];
    fieldMappings?: BackendFieldMappings;
    preserveOriginalData?: boolean;
  };
}

// NUEVO: Mapeo flexible de campos para diferentes backends
export interface BackendFieldMappings {
  userId?: string[];
  email?: string[];
  name?: string[];
  firstName?: string[];
  lastName?: string[];
  role?: string[];
  permissions?: string[];
  token?: string[];
  refreshToken?: string[];
  expires?: string[];
  tokenType?: string[];
  // Index signature para compatibilidad con Record<string, string[]>
  [key: string]: string[] | undefined;
}

// NUEVO: Configuraciones predefinidas para backends conocidos
export interface BackendPresets {
  'node-express': BackendConfig;
  'laravel-sanctum': BackendConfig;
  'jwt-standard': BackendConfig;
  'custom': BackendConfig;
}

export interface BackendConfig {
  userSearchPaths: string[];
  fieldMappings: BackendFieldMappings;
  preserveOriginalData: boolean;
  tokenFormat: 'jwt' | 'opaque' | 'mixed';
}

export interface HttpClient {
  post(url: string, data?: any, config?: any): Promise<any>;
  get(url: string, config?: any): Promise<any>;
  put(url: string, data?: any, config?: any): Promise<any>;
  delete(url: string, config?: any): Promise<any>;
}

// MEJORADO: AuthTokens con soporte para metadatos adicionales
export interface EnhancedAuthTokens {
  accessToken: string;
  refreshToken?: string;
  expiresIn?: number;
  expiresAt?: string | number;
  tokenType?: string;
  
  // NUEVO: Campos adicionales para flexibilidad
  scope?: string;
  tokenId?: string;
  issuedAt?: number;
  
  // NUEVO: Metadatos para debugging y backend detection
  _originalTokenResponse?: any;
  _backendType?: string;
  _tokenFormat?: 'jwt' | 'opaque' | 'sanctum';
}

// MEJORADO: AuthUser con preservación completa de datos
export interface EnhancedAuthUser {
  id: string;
  email?: string;
  name?: string;
  
  // Campos comunes extendidos
  firstName?: string;
  lastName?: string;
  username?: string;
  role?: string | string[];
  roles?: string[];
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
  
  // Node.js específicos
  lastLogin?: string | Date;
  createdAt?: string | Date;
  updatedAt?: string | Date;
  
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

// NUEVO: Información extendida de sesión
export interface ExtendedSessionInfo {
  isValid: boolean;
  user: EnhancedAuthUser | null;
  tokens: EnhancedAuthTokens | null;
  
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

export interface EnhancedLoginCredentials {
  // Campos estándar
  email?: string;
  password?: string;
  
  // Legacy support
  usuario?: string;
  clave?: string;
  code?: string;
  
  // Campos adicionales comunes
  username?: string;
  phone?: string;
  
  // OTP y 2FA
  otp?: string;
  twoFactorCode?: string;
  
  // Remember me
  remember?: boolean;
  
  // Backend específicos
  grant_type?: string; // OAuth
  device_name?: string; // Sanctum
  
  // Permite campos adicionales
  [key: string]: any;
}

export interface EnhancedRegisterData {
  // Campos obligatorios
  email: string;
  password: string;
  
  // Campos opcionales estándar
  name?: string;
  firstName?: string;
  lastName?: string;
  username?: string;
  phone?: string;
  
  // Legacy support
  usuario?: string;
  clave?: string;
  code?: string;
  
  // Campos adicionales
  confirmPassword?: string;
  acceptTerms?: boolean;
  newsletter?: boolean;
  
  // Permite campos adicionales del backend
  [key: string]: any;
}

// MEJORADO: AuthState con información adicional
export interface EnhancedAuthState {
  isAuthenticated: boolean;
  user: EnhancedAuthUser | null;
  tokens: EnhancedAuthTokens | null;
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

export interface EnhancedAuthCallbacks {
  onAuthStateChanged?: (state: EnhancedAuthState) => void;
  onTokenRefresh?: (tokens: EnhancedAuthTokens) => void;
  onLogin?: (user: EnhancedAuthUser, tokens: EnhancedAuthTokens) => void;
  onLogout?: () => void;
  onError?: (error: string) => void;
  onTokenExpired?: () => void;
  
  // NUEVO: Callbacks adicionales
  onSessionRestored?: (user: EnhancedAuthUser) => void;
  onRefreshFailed?: (error: string) => void;
  onUserUpdated?: (user: EnhancedAuthUser) => void;
  onBackendDetected?: (backendType: string) => void;
}

// NUEVO: Configuraciones predefinidas para backends populares
export const BACKEND_PRESETS: BackendPresets = {
  'node-express': {
    userSearchPaths: ['data.user', 'user', 'data', ''],
    fieldMappings: {
      userId: ['_id', 'id', 'userId'],
      email: ['email'],
      name: ['name', 'username'],
      firstName: ['firstName'],
      lastName: ['lastName'],
      role: ['role'],
      permissions: ['permissions'],
      token: ['accessToken', 'access_token', 'token'],
      refreshToken: ['refreshToken', 'refresh_token'],
      expires: ['expiresIn', 'expires_in', 'exp']
    },
    preserveOriginalData: true,
    tokenFormat: 'jwt'
  },
  
  'laravel-sanctum': {
    userSearchPaths: ['resultado.data', 'data', ''],
    fieldMappings: {
      userId: ['id', 'user_id'],
      email: ['email'],
      name: ['name', 'full_name'],
      firstName: ['first_name', 'name'],
      lastName: ['last_name'],
      role: ['rol', 'role'],
      permissions: ['permissions', 'abilities'],
      token: ['token', 'access_token'],
      refreshToken: ['refresh_token'],
      expires: ['expires_at', 'rt_expires_at', 'expires_in']
    },
    preserveOriginalData: true,
    tokenFormat: 'opaque'
  },
  
  'jwt-standard': {
    userSearchPaths: ['', 'user', 'data'],
    fieldMappings: {
      userId: ['sub', 'id', 'user_id'],
      email: ['email'],
      name: ['name', 'username'],
      firstName: ['given_name', 'firstName'],
      lastName: ['family_name', 'lastName'],
      role: ['role', 'roles'],
      permissions: ['permissions', 'scope'],
      token: ['access_token', 'token'],
      refreshToken: ['refresh_token'],
      expires: ['exp', 'expires_in']
    },
    preserveOriginalData: true,
    tokenFormat: 'jwt'
  },
  
  'custom': {
    userSearchPaths: [''],
    fieldMappings: {
      userId: ['id'],
      email: ['email'],
      name: ['name'],
      firstName: ['firstName'],
      lastName: ['lastName'],
      role: ['role'],
      permissions: ['permissions'],
      token: ['token'],
      refreshToken: ['refreshToken'],
      expires: ['expiresIn']
    },
    preserveOriginalData: true,
    tokenFormat: 'mixed'
  }
};

// NUEVO: Tipos para debugging y análisis
export interface ResponseAnalysis {
  backendType: string;
  structure: {
    hasUser: boolean;
    hasTokens: boolean;
    userPath: string | null;
    tokenFields: string[];
    userFields: string[];
  };
  extraction: {
    tokensExtracted: boolean;
    userExtracted: boolean;
    missingFields: string[];
  };
  recommendations: string[];
}

// NUEVO: Factory types para crear instancias configuradas
export interface AuthSDKFactory {
  create(backendType: keyof BackendPresets, customConfig?: Partial<EnhancedAuthConfig>): any;
  createCustom(config: EnhancedAuthConfig): any;
  analyzeResponse(response: any): ResponseAnalysis;
}

// NUEVO: Event types para el sistema de eventos
export type AuthEventType = 
  | 'login'
  | 'logout'
  | 'token-refresh'
  | 'token-expired'
  | 'session-restored'
  | 'user-updated'
  | 'error';

export interface AuthEvent {
  type: AuthEventType;
  payload: any;
  timestamp: number;
  sessionId?: string;
}

// Para compatibilidad hacia atrás, re-export de tipos básicos con nuevos nombres
export type AuthConfig = EnhancedAuthConfig;
export type AuthTokens = EnhancedAuthTokens;
export type AuthUser = EnhancedAuthUser;
export type AuthState = EnhancedAuthState;
export type AuthCallbacks = EnhancedAuthCallbacks;
export type LoginCredentials = EnhancedLoginCredentials;
export type RegisterData = EnhancedRegisterData;
