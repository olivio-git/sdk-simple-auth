/**
 * Ejemplo de Uso con Axios y Interceptores Automáticos
 *
 * Este ejemplo muestra cómo configurar el SDK con tu instancia de Axios
 * para que automáticamente:
 * 1. Inyecte tokens en todas las peticiones
 * 2. Detecte errores 401/422 y cierre sesión automáticamente
 * 3. Intente refresh automático antes de cerrar sesión
 */

import { AuthSDK } from 'sdk-simple-auth';
import axios from 'axios';

// =====================================================
// CONFIGURACIÓN COMPLETA (Tu caso de uso)
// =====================================================

// 1. Crear instancia de Axios (SIN interceptores manuales)
const apiClient = axios.create({
  baseURL: 'http://localhost:8000/api',
  headers: {
    'Content-Type': 'application/json',
  },
});

// 2. Configurar AuthSDK con interceptores de Axios
const authSDK = new AuthSDK({
  authServiceUrl: 'http://localhost:8000/api',
  endpoints: {
    login: '/login',
    logout: '/logout',
    refresh: '/refresh'
  },
  storage: {
    type: 'indexedDB',
    dbName: 'tps-intermotors',
    storeName: 'auth',
    dbVersion: 1,
    tokenKey: 'tps-intermotors_auth_token',
    userKey: 'tps-intermotors_auth_user',
    refreshTokenKey: 'tps-intermotors_auth_refresh_token',
  },
  tokenRefresh: {
    enabled: true,
    bufferTime: 1800 // 30 minutos
  },
  sessionValidation: {
    enabled: true,
    validateOnFocus: true,
    validateOnVisibility: true,
    maxInactivityTime: 300, // 5 minutos
    autoLogoutOnInvalid: true
  },
  // NUEVA CONFIGURACIÓN: Interceptores de Axios
  interceptors: {
    enabled: true, // ⚠️ IMPORTANTE: Activar interceptores
    autoInjectToken: true, // Inyectar token automáticamente
    handleAuthErrors: true, // Manejar 401/422 automáticamente
    axiosInstance: apiClient // Tu instancia de Axios
  }
}, {
  // Callbacks
  onLogin: (user, tokens) => {
    console.log('✅ Login exitoso:', user.name);
  },
  onSessionInvalid: () => {
    console.warn('❌ Sesión inválida detectada por interceptor');
    // Redirigir al login
    window.location.href = '/login?expired=true';
  },
  onTokenRefresh: (tokens) => {
    console.log('🔄 Tokens refrescados automáticamente');
  },
  onError: (error) => {
    console.error('❌ Error:', error);
  }
});

// =====================================================
// AHORA TU apiClient YA TIENE INTERCEPTORES AUTOMÁTICOS
// =====================================================

// Ya NO necesitas esto:
/*
apiClient.interceptors.request.use(
  async (config) => {
    const token = await authSDK.getAccessToken();
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  }
);
*/

// El SDK ya lo hace automáticamente! 🎉

// =====================================================
// EJEMPLO DE USO
// =====================================================

// Login
async function login() {
  try {
    const user = await authSDK.login({
      email: 'usuario@example.com',
      password: 'password123'
    });

    console.log('Usuario logueado:', user);
    return user;
  } catch (error) {
    console.error('Error en login:', error);
    throw error;
  }
}

// Hacer peticiones con apiClient (token inyectado automáticamente)
async function fetchProviders() {
  try {
    // ✅ Token se inyecta automáticamente
    // ✅ Si el token expiró, intenta refresh automático
    // ✅ Si el servidor retorna 401, cierra sesión y redirige
    const response = await apiClient.get('/providers');

    console.log('Proveedores:', response.data);
    return response.data;
  } catch (error) {
    // Si llega aquí, es un error que NO es 401
    // Los 401 se manejan automáticamente
    console.error('Error obteniendo proveedores:', error);
    throw error;
  }
}

// Crear un proveedor
async function createProvider(data) {
  try {
    const response = await apiClient.post('/providers', data);
    console.log('Proveedor creado:', response.data);
    return response.data;
  } catch (error) {
    console.error('Error creando proveedor:', error);
    throw error;
  }
}

// =====================================================
// FLUJO COMPLETO DE EJEMPLO
// =====================================================

async function exampleFlow() {
  console.log('=== Iniciando flujo de ejemplo ===\n');

  // 1. Login
  console.log('1️⃣ Haciendo login...');
  await login();

  // 2. Hacer peticiones normalmente
  console.log('\n2️⃣ Obteniendo proveedores...');
  await fetchProviders();

  // 3. Simular que el token expira en el servidor
  console.log('\n3️⃣ [Simulación] Token expira en el servidor...');
  console.log('   (En tu backend, el token fue revocado o expiró)');

  // 4. Intentar hacer otra petición
  console.log('\n4️⃣ Intentando obtener proveedores de nuevo...');
  try {
    await fetchProviders();
  } catch (error) {
    // El interceptor detectará el 401 automáticamente
    console.log('\n📊 Resultado:');
    console.log('   ✅ Interceptor detectó 401');
    console.log('   ✅ Intentó refresh automático');
    console.log('   ✅ Refresh falló (token inválido)');
    console.log('   ✅ Sesión cerrada automáticamente');
    console.log('   ✅ Redirigido a /login');
  }
}

// =====================================================
// VENTAJAS DE USAR INTERCEPTORES
// =====================================================

/*

❌ ANTES (Sin interceptores):
- Tenías que agregar manualmente el token en cada petición
- Si el token expiraba, seguía intentando peticiones
- Tenías que manejar manualmente errores 401 en cada componente
- La sesión persistía incluso con tokens inválidos

✅ AHORA (Con interceptores):
- Token se inyecta automáticamente en TODAS las peticiones
- Detecta 401 automáticamente en CUALQUIER petición
- Cierra sesión local cuando el servidor rechaza el token
- Intenta refresh automático antes de cerrar sesión
- Código más limpio y centralizado

*/

// =====================================================
// COMPARACIÓN DE CÓDIGO
// =====================================================

// ANTES: Tenías que hacer esto en CADA petición
async function fetchProviders_OLD() {
  const token = await authSDK.getAccessToken();

  try {
    const response = await apiClient.get('/providers', {
      headers: {
        Authorization: `Bearer ${token}`
      }
    });
    return response.data;
  } catch (error) {
    if (error.response?.status === 401) {
      // Manejar manualmente
      await authSDK.logout();
      window.location.href = '/login';
    }
    throw error;
  }
}

// AHORA: Simple y limpio
async function fetchProviders_NEW() {
  const response = await apiClient.get('/providers');
  return response.data;
  // ¡Eso es todo! El resto se maneja automáticamente
}

// =====================================================
// DEBUGGING
// =====================================================

// Ver estado de los interceptores
function debugInterceptors() {
  console.log('\n🔍 Debug de Interceptores:');
  console.log('Interceptor Manager:', authSDK.axiosInterceptorManager);

  if (authSDK.axiosInterceptorManager) {
    const status = authSDK.axiosInterceptorManager.getStatus();
    console.log('Estado:', status);
    console.log('  - Activo:', status.isActive);
    console.log('  - Request Interceptor:', status.hasRequestInterceptor);
    console.log('  - Response Interceptor:', status.hasResponseInterceptor);
  } else {
    console.log('⚠️  Interceptores no configurados');
  }
}

// =====================================================
// CASOS DE USO COMUNES
// =====================================================

// Caso 1: Petición GET simple
async function getUsers() {
  // Token inyectado automáticamente
  const { data } = await apiClient.get('/users');
  return data;
}

// Caso 2: Petición POST con datos
async function createUser(userData) {
  // Token inyectado automáticamente
  const { data } = await apiClient.post('/users', userData);
  return data;
}

// Caso 3: Petición con parámetros
async function searchProducts(filters) {
  // Token inyectado automáticamente
  const { data } = await apiClient.get('/products', {
    params: filters
  });
  return data;
}

// Caso 4: Upload de archivo
async function uploadFile(file) {
  const formData = new FormData();
  formData.append('file', file);

  // Token inyectado automáticamente
  const { data } = await apiClient.post('/upload', formData, {
    headers: {
      'Content-Type': 'multipart/form-data'
    }
  });
  return data;
}

// =====================================================
// CONFIGURACIÓN PARA DIFERENTES ESCENARIOS
// =====================================================

// Escenario 1: Solo inyección de token (sin manejo de errores)
const authSDK_OnlyInject = new AuthSDK({
  authServiceUrl: 'http://localhost:8000/api',
  interceptors: {
    enabled: true,
    autoInjectToken: true,
    handleAuthErrors: false, // Manejar errores manualmente
    axiosInstance: apiClient
  }
});

// Escenario 2: Solo manejo de errores (sin inyección automática)
const authSDK_OnlyErrors = new AuthSDK({
  authServiceUrl: 'http://localhost:8000/api',
  interceptors: {
    enabled: true,
    autoInjectToken: false, // Inyectar token manualmente
    handleAuthErrors: true,
    axiosInstance: apiClient
  }
});

// Escenario 3: Todo automático (Recomendado)
const authSDK_Full = new AuthSDK({
  authServiceUrl: 'http://localhost:8000/api',
  interceptors: {
    enabled: true,
    autoInjectToken: true,
    handleAuthErrors: true,
    axiosInstance: apiClient
  }
});

// =====================================================
// EXPORTAR PARA USO EN TU APP
// =====================================================

export {
  authSDK,
  apiClient,
  login,
  fetchProviders,
  createProvider,
  debugInterceptors,
  getUsers,
  createUser,
  searchProducts,
  uploadFile
};

// =====================================================
// INSTRUCCIONES DE USO EN TU APP
// =====================================================

/*

PASO 1: En tu archivo de configuración del SDK (ej: src/services/sdk-simple-auth.js)

import { AuthSDK } from 'sdk-simple-auth';
import axios from 'axios';

const apiClient = axios.create({
  baseURL: 'http://localhost:8000/api',
  headers: { 'Content-Type': 'application/json' }
});

const authSDK = new AuthSDK({
  authServiceUrl: 'http://localhost:8000/api',
  endpoints: {
    login: '/login',
    logout: '/logout',
    refresh: '/refresh'
  },
  interceptors: {
    enabled: true,
    autoInjectToken: true,
    handleAuthErrors: true,
    axiosInstance: apiClient
  }
}, {
  onSessionInvalid: () => {
    window.location.href = '/login?expired=true';
  }
});

export { authSDK, apiClient };

---

PASO 2: En tus componentes, usa apiClient directamente

import { apiClient } from '@/services/sdk-simple-auth';

async function fetchData() {
  // ¡Token automático! ¡Manejo de 401 automático!
  const { data } = await apiClient.get('/providers');
  return data;
}

---

PASO 3: ¡Disfruta de código más limpio!

Ya NO necesitas:
❌ Agregar manualmente Authorization headers
❌ Verificar tokens en cada petición
❌ Manejar 401 en cada componente
❌ Preocuparte por sesiones inválidas

Todo se maneja automáticamente! ✅

*/

console.log('\n✨ Ejemplo de Axios Interceptors cargado\n');
console.log('📖 Lee los comentarios del código para ver cómo funciona');
console.log('🧪 Ejecuta exampleFlow() para ver el flujo completo\n');
