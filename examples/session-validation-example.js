/**
 * Ejemplo Completo de Validación de Sesión
 *
 * Este ejemplo muestra cómo usar la validación automática de sesión
 * para detectar cuando el usuario vuelve a la app después de cerrarla
 */

import { AuthSDK } from 'sdk-simple-auth';

// ===================================================
// EJEMPLO 1: Configuración Básica con Laravel Sanctum
// ===================================================
console.log('\n=== EJEMPLO 1: Laravel Sanctum ===\n');

const laravelAuth = new AuthSDK({
  authServiceUrl: 'http://localhost:8000/api',
  endpoints: {
    login: '/login',
    logout: '/logout',
    refresh: '/refresh' // Asegúrate de tener este endpoint en Laravel
  },
  backend: {
    type: 'laravel-sanctum'
  },
  tokenRefresh: {
    enabled: true,
    bufferTime: 900, // 15 minutos antes de expirar
    maxRetries: 3
  },
  // CONFIGURACIÓN DE VALIDACIÓN DE SESIÓN
  sessionValidation: {
    enabled: true, // Habilitar validación automática
    validateOnFocus: true, // Validar cuando la ventana obtiene foco
    validateOnVisibility: true, // Validar cuando la página se vuelve visible
    maxInactivityTime: 300, // Solo validar si estuvo inactivo más de 5 minutos
    autoLogoutOnInvalid: true // Cerrar sesión automáticamente si el token es inválido
  }
}, {
  // CALLBACKS
  onLogin: (user, tokens) => {
    console.log('✅ Login exitoso:', user.name);
    console.log('🔑 Access Token:', tokens.accessToken.substring(0, 20) + '...');
  },

  onSessionValidated: () => {
    console.log('✅ Sesión validada con el servidor');
    // Aquí puedes mostrar un mensaje amigable al usuario
  },

  onSessionInvalid: () => {
    console.warn('❌ Sesión inválida detectada');
    console.log('🔄 Redirigiendo al login...');
    // Redirigir al usuario al login
    if (typeof window !== 'undefined') {
      window.location.href = '/login?reason=session_expired';
    }
  },

  onTokenRefresh: (tokens) => {
    console.log('🔄 Tokens refrescados automáticamente');
  },

  onError: (error) => {
    console.error('❌ Error:', error);
  },

  onLogout: () => {
    console.log('👋 Logout completado');
  }
});

// ===================================================
// EJEMPLO 2: Node.js/Express con JWT
// ===================================================
console.log('\n=== EJEMPLO 2: Node.js/Express con JWT ===\n');

const nodeAuth = new AuthSDK({
  authServiceUrl: 'http://localhost:3000',
  endpoints: {
    login: '/auth/login',
    logout: '/auth/logout',
    refresh: '/auth/refresh'
  },
  backend: {
    type: 'node-express'
  },
  tokenRefresh: {
    enabled: true
  },
  sessionValidation: {
    enabled: true,
    maxInactivityTime: 600 // 10 minutos para sistema admin
  }
}, {
  onSessionInvalid: () => {
    // Guardar trabajo pendiente antes de cerrar sesión
    const unsavedData = localStorage.getItem('unsaved_work');
    if (unsavedData) {
      console.log('💾 Guardando trabajo pendiente...');
      // Aquí guardarías el trabajo
    }
    console.log('Redirigiendo al login...');
  }
});

// ===================================================
// EJEMPLO 3: Validación Manual
// ===================================================
console.log('\n=== EJEMPLO 3: Validación Manual ===\n');

async function validateSessionManually() {
  try {
    const isValid = await laravelAuth.validateSession();

    if (isValid) {
      console.log('✅ Sesión válida');
      return true;
    } else {
      console.log('❌ Sesión inválida');
      return false;
    }
  } catch (error) {
    console.error('Error validando sesión:', error);
    return false;
  }
}

// ===================================================
// EJEMPLO 4: Simulación de Uso Completo
// ===================================================
console.log('\n=== EJEMPLO 4: Simulación Completa ===\n');

async function simulateUserFlow() {
  console.log('👤 Simulando flujo de usuario...\n');

  // 1. Login
  console.log('1️⃣ Usuario inicia sesión...');
  try {
    const user = await laravelAuth.login({
      email: 'usuario@example.com',
      password: 'password123'
    });
    console.log('   ✅ Login exitoso:', user.name);
  } catch (error) {
    console.error('   ❌ Error en login:', error.message);
    return;
  }

  // 2. Usuario usa la app normalmente
  console.log('\n2️⃣ Usuario usa la aplicación...');
  await new Promise(resolve => setTimeout(resolve, 1000));
  console.log('   📱 Haciendo peticiones a la API...');

  // 3. Usuario minimiza la app (simulado)
  console.log('\n3️⃣ Usuario minimiza la app...');
  console.log('   💤 App en background...');

  // Simular tiempo pasando (en realidad serían horas)
  console.log('\n⏰ [Simulando paso del tiempo - varias horas...]');
  await new Promise(resolve => setTimeout(resolve, 2000));

  // 4. Usuario vuelve a abrir la app
  console.log('\n4️⃣ Usuario vuelve a abrir la app...');
  console.log('   🔍 SessionValidator detecta evento de visibilidad');
  console.log('   ⏱️  Verificando tiempo de inactividad...');
  console.log('   🔄 Intentando validar sesión con el servidor...');

  // Simular validación
  const isValid = await validateSessionManually();

  if (isValid) {
    console.log('   ✅ Sesión válida - Usuario puede continuar');
  } else {
    console.log('   ❌ Sesión inválida - Cerrando sesión local');
    console.log('   🔄 Redirigiendo al login...');
  }
}

// ===================================================
// EJEMPLO 5: Configuración Personalizada por Caso de Uso
// ===================================================
console.log('\n=== EJEMPLO 5: Configuraciones Personalizadas ===\n');

// Caso 1: PWA Móvil - Validación agresiva
const mobileAuth = new AuthSDK({
  authServiceUrl: 'https://api.mobile.com',
  sessionValidation: {
    enabled: true,
    maxInactivityTime: 180, // 3 minutos - menos tiempo
    autoLogoutOnInvalid: true
  }
}, {
  onSessionInvalid: () => {
    // Mostrar modal amigable
    console.log('📱 Mostrando modal: "Tu sesión ha expirado"');
  }
});

// Caso 2: Dashboard Admin - Validación moderada
const adminAuth = new AuthSDK({
  authServiceUrl: 'https://admin.example.com',
  sessionValidation: {
    enabled: true,
    maxInactivityTime: 900, // 15 minutos - más tiempo
    validateOnFocus: true,
    validateOnVisibility: true
  }
}, {
  onSessionInvalid: async () => {
    // Guardar datos antes de logout
    console.log('💾 Guardando datos pendientes...');
    // await saveUnsavedData();
    console.log('🔄 Redirigiendo a login admin...');
  }
});

// Caso 3: E-commerce - No auto-logout (permitir navegar)
const shopAuth = new AuthSDK({
  authServiceUrl: 'https://api.shop.com',
  sessionValidation: {
    enabled: true,
    maxInactivityTime: 600, // 10 minutos
    autoLogoutOnInvalid: false // No cerrar automáticamente
  }
}, {
  onSessionInvalid: () => {
    // Solo mostrar banner, permitir seguir navegando
    console.log('🛒 Mostrando banner: "Inicia sesión para completar tu compra"');
  }
});

// ===================================================
// EJEMPLO 6: Testing de Eventos del DOM
// ===================================================
console.log('\n=== EJEMPLO 6: Testing de Eventos ===\n');

// Verificar si SessionValidator está soportado
if (typeof window !== 'undefined' && typeof document !== 'undefined') {
  console.log('✅ SessionValidator soportado en este entorno');

  // Simular cambio de visibilidad
  console.log('\n🧪 Simulando evento de visibilidad...');
  document.dispatchEvent(new Event('visibilitychange'));

  // Simular foco de ventana
  console.log('🧪 Simulando evento de foco...');
  window.dispatchEvent(new Event('focus'));

} else {
  console.log('⚠️  SessionValidator no soportado (entorno Node.js)');
}

// ===================================================
// EJEMPLO 7: Debugging y Monitoreo
// ===================================================
console.log('\n=== EJEMPLO 7: Debugging ===\n');

// Obtener información del estado del validador
function debugSessionValidator() {
  const status = laravelAuth.sessionValidator?.getStatus();

  if (status) {
    console.log('📊 Estado del SessionValidator:');
    console.log('   - Escuchando eventos:', status.isListening);
    console.log('   - Última actividad:', new Date(status.lastActivityTime).toLocaleString());
    console.log('   - Tiempo inactivo:', status.inactiveSeconds, 'segundos');
  } else {
    console.log('⚠️  SessionValidator no está inicializado');
  }
}

// Obtener información completa de la sesión
async function debugFullSession() {
  console.log('\n🔍 Información Completa de Sesión:');

  const sessionInfo = await laravelAuth.getExtendedSessionInfo();

  console.log('   - Sesión válida:', sessionInfo.isValid);
  console.log('   - Usuario:', sessionInfo.user?.name);
  console.log('   - Formato de token:', sessionInfo.tokenFormat);
  console.log('   - Expira en:', sessionInfo.expiresIn, 'segundos');
  console.log('   - Puede refrescar:', sessionInfo.canRefresh);
  console.log('   - Backend:', sessionInfo.backendType);
  console.log('   - Almacenado en:', new Date((sessionInfo.storedAt || 0) * 1000).toLocaleString());
}

// ===================================================
// EJECUTAR EJEMPLOS
// ===================================================

// Descomentar para ejecutar la simulación
// simulateUserFlow();

// Descomentar para ver debugging
// debugSessionValidator();
// debugFullSession();

// ===================================================
// EXPORTAR PARA USO EN OTROS ARCHIVOS
// ===================================================
export {
  laravelAuth,
  nodeAuth,
  mobileAuth,
  adminAuth,
  shopAuth,
  validateSessionManually,
  simulateUserFlow,
  debugSessionValidator,
  debugFullSession
};

console.log('\n✨ Ejemplos cargados. Descomenta las funciones para probarlas.\n');
