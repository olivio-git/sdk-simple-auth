// =============================================
// SDK SIMPLE AUTH - ENHANCED VERSION
// Compatibilidad total hacia atrás + Nuevas características
// =============================================

// === EXPORTS EXISTENTES (Compatibilidad hacia atrás) ===
export { AuthSDK } from './core/AuthSDK';
export { useAuth } from './hooks/useAuth';
export { LocalStorageAdapter } from './storage/LocalStorageAdapter';
export { IndexedDBAdapter } from './storage/IndexedDBAdapter';
export { TokenExtractor } from './core/TokenManager';
export { StorageManager } from './core/StorageManager';
export { RefreshManager } from './core/RefreshManager';

export type { StorageAdapter } from './storage/StorageAdapter';
 
// Tipos existentes para compatibilidad
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

// === NUEVAS CARACTERÍSTICAS MEJORADAS ===

// Factory principal para configuración fácil
export { 
  AuthSDKFactory,
  createNodeExpressAuth,
  createLaravelSanctumAuth,
  createJWTStandardAuth,
  createAutoDetectAuth,
  testBackendResponse,
  createDevAuth,
  runMockTests
} from './factory/AuthSDKFactory.js';

// Tipos mejorados con preservación de datos
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

// Presets de configuración para backends populares
export { BACKEND_PRESETS } from './types/enhanced_types';

// Ejemplos y utilities
export { default as examples } from './examples';

// === SHORTCUTS PARA USO RÁPIDO ===

/**
 * Crear SDK para tu sistema Node.js/Express actual
 * 
 * @example
 * ```typescript
 * import { createQuickNodeAuth } from 'sdk-simple-auth';
 * 
 * const auth = createQuickNodeAuth('http://localhost:3000');
 * const user = await auth.login({ email: 'user@test.com', password: 'pass' });
 * 
 * // Ahora preserva TODOS los datos del backend
 * console.log(user._originalUserResponse); // Respuesta completa
 * console.log(user.firstName, user.lastName); // Campos antes perdidos
 * ```
 */
export function createQuickNodeAuth(baseUrl: string = 'http://localhost:3000') {
  const { createNodeExpressAuth } = require('./factory/AuthSDKFactory');
  return createNodeExpressAuth(baseUrl);
}

/**
 * Crear SDK para Laravel Sanctum
 * 
 * @example
 * ```typescript
 * import { createQuickSanctumAuth } from 'sdk-simple-auth';
 * 
 * const auth = createQuickSanctumAuth('http://localhost:8000/api');
 * const user = await auth.login({ 
 *   email: 'user@test.com', 
 *   password: 'pass',
 *   device_name: 'mi-app' 
 * });
 * 
 * console.log(user.sucursales); // Campos específicos preservados
 * ```
 */
export function createQuickSanctumAuth(baseUrl: string = 'http://localhost:8000/api') {
  const { createLaravelSanctumAuth } = require('./factory/AuthSDKFactory');
  return createLaravelSanctumAuth(baseUrl);
}

/**
 * Analizar respuesta de backend y crear SDK automáticamente configurado
 * 
 * @example
 * ```typescript
 * import { quickAnalyzeAndCreate } from 'sdk-simple-auth';
 * 
 * const sampleResponse = { success: true, data: { user: {...} } };
 * const auth = quickAnalyzeAndCreate(sampleResponse, 'http://localhost:3000');
 * ```
 */
export function quickAnalyzeAndCreate(sampleResponse: any, baseUrl: string) {
  const { createAutoDetectAuth } = require('./factory/AuthSDKFactory');
  return createAutoDetectAuth(sampleResponse, baseUrl);
}

/**
 * Testing rápido de respuesta de backend
 * 
 * @example
 * ```typescript
 * import { quickTest } from 'sdk-simple-auth';
 * 
 * const response = await fetch('/api/login', { ... });
 * quickTest(response); // Ver análisis en consola
 * ```
 */
export function quickTest(response: any) {
  const { testBackendResponse } = require('./factory/AuthSDKFactory');
  return testBackendResponse(response);
}

// === INFORMACIÓN DE VERSIÓN ===
export const SDK_VERSION = '2.0.0-enhanced';
export const SDK_FEATURES = {
  multiBackend: true,
  dataPreservation: true,
  autoDetection: true,
  advancedDebugging: true,
  backwardCompatible: true
};

// === DEFAULT EXPORT PARA CONVENIENCIA ===
import { AuthSDKFactory } from './factory/AuthSDKFactory.js';
export default AuthSDKFactory;
