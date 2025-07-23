// =============================================
// SDK SIMPLE AUTH - ENHANCED VERSION - FIXED
// Fixed version with proper module resolution
// =============================================

// === CORE EXPORTS ===
export { AuthSDK } from './core/AuthSDK';
export { useAuth } from './hooks/useAuth';
export { LocalStorageAdapter } from './storage/LocalStorageAdapter';
export { IndexedDBAdapter } from './storage/IndexedDBAdapter';
export { TokenExtractor } from './core/TokenManager';
export { StorageManager } from './core/StorageManager';
export { RefreshManager } from './core/RefreshManager';

export type { StorageAdapter } from './storage/StorageAdapter';
 
// === TYPES ===
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

export type {
  EnhancedAuthConfig,
  EnhancedAuthTokens,
  EnhancedAuthUser,
  EnhancedAuthState,
  EnhancedAuthCallbacks,
  ExtendedSessionInfo,
  BackendConfig,
  BackendFieldMappings,
  ResponseAnalysis,
  AuthEventType,
  AuthEvent
} from './types/enhanced_types';

// === FACTORY AND PRESETS ===
export { 
  AuthSDKFactory,
  createNodeExpressAuth,
  createLaravelSanctumAuth,
  createJWTStandardAuth,
  createAutoDetectAuth,
  testBackendResponse,
  createDevAuth,
  runMockTests
} from './factory/AuthSDKFactory';

export { BACKEND_PRESETS } from './types/enhanced_types';

// === EXAMPLES ===
export { default as examples } from './examples';

// === QUICK FACTORY FUNCTIONS - FIXED ===
// Import statically and use directly to avoid dynamic require()
import { 
  createNodeExpressAuth as _createNodeExpressAuth,
  createLaravelSanctumAuth as _createLaravelSanctumAuth,
  createAutoDetectAuth as _createAutoDetectAuth,
  testBackendResponse as _testBackendResponse
} from './factory/AuthSDKFactory';

/**
 * Quick Node.js/Express Auth Setup
 */
export function createQuickNodeAuth(baseUrl: string = 'http://localhost:3000') {
  return _createNodeExpressAuth(baseUrl);
}

/**
 * Quick Laravel Sanctum Auth Setup
 */
export function createQuickSanctumAuth(baseUrl: string = 'http://localhost:8000/api') {
  return _createLaravelSanctumAuth(baseUrl);
}

/**
 * Quick analyze and create SDK
 */
export function quickAnalyzeAndCreate(sampleResponse: any, baseUrl: string) {
  return _createAutoDetectAuth(sampleResponse, baseUrl);
}

/**
 * Quick response testing
 */
export function quickTest(response: any) {
  return _testBackendResponse(response);
}

// === VERSION INFO ===
export const SDK_VERSION = '2.0.0-enhanced-fixed';
export const SDK_FEATURES = {
  multiBackend: true,
  dataPreservation: true,
  autoDetection: true,
  advancedDebugging: true,
  backwardCompatible: true,
  esmFixed: true
};

// === DEFAULT EXPORT ===
export { AuthSDKFactory as default } from './factory/AuthSDKFactory';
