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
  };
  httpClient?: HttpClient;
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
  tokenType?: string;
}

export interface AuthUser {
  id: string;
  email?: string;
  name?: string;
  roles?: string[];
  [key: string]: any;
}

export interface LoginCredentials {
  usuario?: string; // For legacy support
  clave?: string; // For legacy support
  code?: string; // For legacy support
  email?: string; // For new implementations
  password?: string; // For new implementations
}

export interface RegisterData {
  usuario?: string; // For legacy support
  clave?: string; // For legacy support
  code?: string; // For legacy support
  email: string;
  password: string;
  name?: string;
  [key: string]: any;
}

export interface AuthState {
  isAuthenticated: boolean;
  user: AuthUser | null;
  tokens: AuthTokens | null;
  loading: boolean;
  error: string | null;
}

export interface AuthCallbacks {
  onAuthStateChanged?: (state: AuthState) => void;
  onTokenRefresh?: (tokens: AuthTokens) => void;
  onLogin?: (user: AuthUser, tokens: AuthTokens) => void;
  onLogout?: () => void;
  onError?: (error: string) => void;
}
