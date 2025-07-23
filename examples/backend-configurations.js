// ===================================
// EJEMPLO: Configuraciones para diferentes backends
// ===================================

import { AuthSDK, createQuickNodeAuth, createQuickSanctumAuth, AuthSDKFactory } from 'sdk-simple-auth';

// ===================================
// 1. BACKEND NODE.JS/EXPRESS ESTÁNDAR
// ===================================

// Respuesta típica de Node.js/Express:
// {
//   "success": true,
//   "data": {
//     "user": { "id": 1, "email": "user@test.com", "name": "Usuario" },
//     "token": "eyJhbGciOiJIUzI1NiIs...",
//     "refreshToken": "refresh-token-here"
//   }
// }

const nodeAuth = createQuickNodeAuth('http://localhost:3000');

// O configuración manual:
const nodeAuthManual = new AuthSDK({
  authServiceUrl: 'http://localhost:3000',
  backend: {
    type: 'node-express',
    userSearchPaths: ['data.user', 'user'],
    fieldMappings: {
      userId: ['id', 'user_id'],
      email: ['email'],
      name: ['name', 'full_name'],
      token: ['token', 'access_token'],
      refreshToken: ['refreshToken', 'refresh_token']
    }
  }
});

// ===================================
// 2. LARAVEL SANCTUM
// ===================================

// Respuesta típica de Laravel Sanctum:
// {
//   "user": {
//     "id": 1,
//     "email": "user@test.com",
//     "created_at": "2025-01-01T00:00:00.000000Z",
//     "sucursales": [...]
//   },
//   "token": "1|sanctum-token-here"
// }

const sanctumAuth = createQuickSanctumAuth('http://localhost:8000/api');

// Login con device_name (requerido por Sanctum)
async function loginSanctum() {
  try {
    const user = await sanctumAuth.login({
      email: 'usuario@ejemplo.com',
      password: 'password',
      device_name: 'mi-app-web' // Requerido por Sanctum
    });
    
    console.log('Usuario Sanctum:', user);
    // Todos los campos originales se preservan: sucursales, created_at, etc.
  } catch (error) {
    console.error('Error Sanctum:', error);
  }
}

// ===================================
// 3. JWT ESTÁNDAR
// ===================================

// Respuesta típica JWT:
// {
//   "access_token": "eyJhbGciOiJIUzI1NiIs...",
//   "refresh_token": "refresh-token-here",
//   "user": { "sub": "1", "email": "user@test.com" }
// }

const jwtAuth = new AuthSDK({
  authServiceUrl: 'http://localhost:3000',
  backend: {
    type: 'jwt-standard',
    userSearchPaths: ['user', 'data'],
    fieldMappings: {
      userId: ['sub', 'id'],
      email: ['email'],
      name: ['name', 'username'],
      token: ['access_token', 'token'],
      refreshToken: ['refresh_token']
    }
  }
});

// ===================================
// 4. BACKEND PERSONALIZADO
// ===================================

// Si tu backend tiene una estructura única:
// {
//   "status": "ok",
//   "profile": {
//     "userId": 123,
//     "mail": "user@test.com",
//     "fullName": "Usuario Test"
//   },
//   "credentials": {
//     "accessToken": "token-here",
//     "renewToken": "refresh-here"
//   }
// }

const customAuth = new AuthSDK({
  authServiceUrl: 'http://localhost:3000',
  backend: {
    type: 'custom',
    userSearchPaths: ['profile', 'data.profile'],
    fieldMappings: {
      userId: ['userId', 'id'],
      email: ['mail', 'email'],
      name: ['fullName', 'name'],
      token: ['credentials.accessToken', 'accessToken'],
      refreshToken: ['credentials.renewToken', 'renewToken']
    },
    preserveOriginalData: true // Mantener estructura original
  }
});

// ===================================
// 5. AUTO-DETECCIÓN DE BACKEND
// ===================================

async function autoDetectBackend() {
  // Paso 1: Hacer login manual para obtener respuesta
  const response = await fetch('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'test@test.com', password: '123' })
  });
  
  const data = await response.json();
  
  // Paso 2: Analizar y crear SDK automáticamente
  const auth = quickAnalyzeAndCreate(data, 'http://localhost:3000');
  
  console.log('SDK configurado automáticamente');
  return auth;
}

// ===================================
// 6. CONFIGURACIÓN CON AXIOS
// ===================================

import axios from 'axios';

const axiosAuth = new AuthSDK({
  authServiceUrl: 'http://localhost:3000',
  httpClient: {
    async post(url, data, config) {
      const response = await axios.post(url, data, config);
      return response.data;
    },
    async get(url, config) {
      const response = await axios.get(url, config);
      return response.data;
    },
    async put(url, data, config) {
      const response = await axios.put(url, data, config);
      return response.data;
    },
    async delete(url, config) {
      const response = await axios.delete(url, config);
      return response.data;
    }
  }
});

// ===================================
// 7. CONFIGURACIÓN COMPLETA AVANZADA
// ===================================

const advancedAuth = new AuthSDK({
  authServiceUrl: 'http://localhost:3000',
  
  // Endpoints personalizados
  endpoints: {
    login: '/auth/signin',
    register: '/auth/signup',
    refresh: '/auth/refresh-token',
    logout: '/auth/signout',
    profile: '/auth/me'
  },
  
  // Storage personalizado
  storage: {
    type: 'indexedDB', // 'localStorage' | 'indexedDB'
    dbName: 'MyAppAuth',
    dbVersion: 1,
    storeName: 'auth_store',
    tokenKey: 'my_access_token',
    refreshTokenKey: 'my_refresh_token',
    userKey: 'my_user_data'
  },
  
  // Refresh automático
  tokenRefresh: {
    enabled: true,
    bufferTime: 300, // 5 minutos antes de expirar
    maxRetries: 3,
    minimumTokenLifetime: 300, // 5 minutos mínimo
    gracePeriod: 60 // 1 minuto de gracia
  },
  
  // Backend específico
  backend: {
    type: 'custom',
    userSearchPaths: ['user', 'data.user', 'profile'],
    fieldMappings: {
      userId: ['id', 'user_id', 'userId'],
      email: ['email', 'mail', 'email_address'],
      name: ['name', 'username', 'full_name', 'display_name'],
      firstName: ['first_name', 'firstName', 'given_name'],
      lastName: ['last_name', 'lastName', 'family_name'],
      role: ['role', 'roles', 'user_role'],
      permissions: ['permissions', 'abilities', 'scopes'],
      token: ['token', 'access_token', 'accessToken'],
      refreshToken: ['refresh_token', 'refreshToken', 'renewalToken']
    },
    preserveOriginalData: true
  }
});

// ===================================
// 8. TESTING DE CONFIGURACIONES
// ===================================

async function testConfiguration(auth, testData) {
  console.log('🧪 Testing configuración...');
  
  // Test de extracción
  auth.testExtraction(testData);
  
  try {
    // Test de login
    const user = await auth.login({
      email: 'test@example.com',
      password: 'password123'
    });
    
    console.log('✅ Login exitoso:', user);
    
    // Test de token
    const token = await auth.getValidAccessToken();
    console.log('✅ Token obtenido:', token ? 'OK' : 'FAIL');
    
    // Test de headers
    const headers = await auth.getAuthHeaders();
    console.log('✅ Headers:', headers);
    
    // Test de sesión
    const sessionInfo = await auth.getExtendedSessionInfo();
    console.log('✅ Sesión:', sessionInfo);
    
  } catch (error) {
    console.error('❌ Error en test:', error);
  }
}

// Ejemplo de uso:
// testConfiguration(nodeAuth, sampleNodeResponse);

// ===================================
// EXPORTAR CONFIGURACIONES
// ===================================

export {
  nodeAuth,
  sanctumAuth,
  jwtAuth,
  customAuth,
  advancedAuth,
  loginSanctum,
  autoDetectBackend,
  testConfiguration
};
