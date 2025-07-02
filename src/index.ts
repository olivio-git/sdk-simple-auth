export { AuthSDK } from './core/AuthSDK';
export { useAuth } from './hooks/useAuth';
export { LocalStorageAdapter,  } from './storage/LocalStorageAdapter';
export { IndexedDBAdapter } from './storage/IndexedDBAdapter';

export type { StorageAdapter } from './storage/StorageAdapter'

export type {
  AuthConfig,
  AuthState,
  AuthUser,
  AuthTokens,
  LoginCredentials,
  RegisterData,
  HttpClient,
  AuthCallbacks,
} from './types';
