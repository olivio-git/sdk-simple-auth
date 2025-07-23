/**
 * EJEMPLOS PRÁCTICOS - SDK SIMPLE AUTH MEJORADO
 * 
 * Este archivo muestra cómo usar las nuevas funcionalidades
 * de la librería mejorada con soporte para múltiples backends.
 */

import { AuthSDKFactory, createNodeExpressAuth, createLaravelSanctumAuth, testBackendResponse, runMockTests } from './factory/AuthSDKFactory';
import { AuthSDK } from './core/AuthSDK';

// ==============================================
// EJEMPLO 1: USO BÁSICO CON TU BACKEND ACTUAL
// ==============================================

export async function ejemplo1_BackendActual() {
  console.log('\n🚀 EJEMPLO 1: Backend Node.js/Express Actual');
  
  // Crear instancia para tu backend actual
  const auth = createNodeExpressAuth('http://localhost:3000');
  
  try {
    // Login normal - ahora preserva TODOS los datos
    const user = await auth.login({
      email: 'subelzacabezasolivio@gmail.com',
      password: 'tu-password'
    });
    
    console.log('✅ Login exitoso!');
    console.log('👤 Usuario estándar:', {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role
    });
    
    // NUEVO: Acceso a datos originales completos
    console.log('📥 Respuesta original del backend:', user._originalUserResponse);
    console.log('🔧 Backend detectado:', user._backendType);
    
    // NUEVO: Información extendida de sesión
    const sessionInfo = await auth.getExtendedSessionInfo();
    console.log('📋 Información de sesión:', sessionInfo);
    
    // Tu código existente funciona igual que antes
    const token = await auth.getValidAccessToken();
    console.log('🔑 Token actual:', token ? 'Disponible' : 'No disponible');
    
  } catch (error) {
    console.error('❌ Error en login:', error);
  }
}

// ==============================================
// EJEMPLO 2: SOPORTE PARA LARAVEL SANCTUM
// ==============================================

export async function ejemplo2_LaravelSanctum() {
  console.log('\n🚀 EJEMPLO 2: Laravel Sanctum Backend');
  
  const auth = createLaravelSanctumAuth('http://localhost:8000/api');
  
  // Simular respuesta de Sanctum (como la que proporcionaste)
  const mockSanctumResponse = {
    status: 'success',
    resultado: {
      data: {
        token: '539|S1O3LzUcTVyjE0UQVMc15RquzYXyvpPP1ktrGbYPe65008ec',
        expires_at: '2025-07-22 15:20:27',
        name: 'olivio',
        full_name: 'Olivio Subelza',
        sucursales: [
          { id: 1, sucursal: 'CENTRAL', rol: 'Administrador' }
        ]
      }
    }
  };
  
  // Testear extracción
  console.log('🧪 Testing Sanctum extraction:');
  auth.testExtraction(mockSanctumResponse);
  
  // En un login real, ahora tendrías acceso a:
  /*
  const user = await auth.login({
    email: 'usuario@ejemplo.com',
    password: 'password',
    device_name: 'mi-dispositivo' // Específico de Sanctum
  });
  
  console.log('🏢 Sucursales:', user.sucursales); // Campo preservado del backend
  console.log('👤 Nombre completo:', user.full_name); // Campo original
  */
}

// ==============================================
// EJEMPLO 3: AUTO-DETECCIÓN DE BACKEND
// ==============================================

export function ejemplo3_AutoDeteccion() {
  console.log('\n🚀 EJEMPLO 3: Auto-detección de Backend');
  
  // Diferentes respuestas de ejemplo
  const respuestas = {
    nodeExpress: {
      success: true,
      data: {
        user: { _id: '123', email: 'test@test.com' },
        accessToken: 'jwt-token'
      }
    },
    
    laravelSanctum: {
      resultado: {
        data: {
          token: '123|sanctum-token',
          name: 'Usuario Test'
        }
      }
    },
    
    jwtStandard: {
      access_token: 'jwt.token.here',
      name: 'User',
      email: 'user@test.com'
    }
  };
  
  // Analizar cada respuesta automáticamente
  Object.entries(respuestas).forEach(([tipo, respuesta]) => {
    console.log(`\n🔍 Analizando respuesta ${tipo}:`);
    testBackendResponse(respuesta, false);
  });
}

// ==============================================
// EJEMPLO 4: CONFIGURACIÓN PERSONALIZADA
// ==============================================

export function ejemplo4_ConfiguracionPersonalizada() {
  console.log('\n🚀 EJEMPLO 4: Configuración Personalizada');
  
  // Para un backend con estructura muy específica
  const auth = AuthSDKFactory.createCustom({
    authServiceUrl: 'https://mi-api-especial.com',
    backend: {
      type: 'custom',
      userSearchPaths: [
        'response.userData',    // Path específico
        'payload.user',
        'data.profile'
      ],
      fieldMappings: {
        userId: ['usuario_id', 'id_usuario', 'id'],
        email: ['correo_electronico', 'email'],
        name: ['nombre_completo', 'nombre'],
        token: ['token_acceso', 'access_token'],
        expires: ['expira_en', 'tiempo_vida']
      },
      preserveOriginalData: true
    },
    tokenRefresh: {
      enabled: true,
      bufferTime: 300 // 5 minutos
    }
  });
  
  console.log('✅ SDK personalizado creado');
  
  // Mock para testear la configuración custom
  const respuestaCustom = {
    response: {
      userData: {
        usuario_id: '123',
        correo_electronico: 'test@test.com',
        nombre_completo: 'Usuario Prueba',
        datos_extra: 'información específica'
      }
    },
    token_acceso: 'mi-token-custom',
    expira_en: 7200
  };
  
  auth.testExtraction(respuestaCustom);
}

// ==============================================
// EJEMPLO 5: DEBUGGING Y ANÁLISIS AVANZADO
// ==============================================

export function ejemplo5_DebuggingAvanzado() {
  console.log('\n🚀 EJEMPLO 5: Debugging Avanzado');
  
  const auth = createNodeExpressAuth();
  
  // Simular una sesión existente
  const mockResponse = {
    success: true,
    data: {
      user: {
        _id: '687fd4d0b0b1db461b716dbc',
        email: 'test@test.com',
        firstName: 'Test',
        lastName: 'User',
        role: 'proctor',
        permissions: ['session.monitor', 'exam.proctor', 'student.verify'],
        customField: 'valor personalizado'
      },
      accessToken: 'eyJhbGciOiJIUzI1NiIs...',
      expiresIn: 3600
    }
  };
  
  // Debug completo de la respuesta
  console.log('\n🔍 Análisis detallado de respuesta:');
  const analysis = AuthSDKFactory.analyzeResponse(mockResponse);
  console.log('📊 Resultado del análisis:', analysis);
  
  // Test de extracción detallado
  console.log('\n🧪 Test de extracción:');
  auth.testExtraction(mockResponse);
  
  // Comparar con diferentes métodos
  console.log('\n⚖️ Comparación entre presets:');
  AuthSDKFactory.testAllPresets(mockResponse);
}

// ==============================================
// EJEMPLO 6: MIGRACIÓN DE DATOS EXISTENTES
// ==============================================

export async function ejemplo6_MigracionDatos() {
  console.log('\n🚀 EJEMPLO 6: Migración de Datos');
  
  // Tu SDK existente (simulado)
  const sdkAntiguo = createNodeExpressAuth();
  
  // Simular datos existentes en el formato antiguo
  const datosAntiguos = {
    user: {
      id: '123',
      email: 'user@test.com',
      name: 'Usuario Test'
    },
    token: 'token-antiguo'
  };
  
  console.log('📦 Datos antiguos:', datosAntiguos);
  
  // El nuevo SDK maneja automáticamente la migración
  // preservando todos los datos
  const nuevoSDK = createNodeExpressAuth();
  
  // Simular respuesta con datos mejorados
  const respuestaMejorada = {
    success: true,
    data: {
      user: {
        ...datosAntiguos.user,
        // Nuevos campos que antes se perdían
        lastLogin: new Date(),
        preferences: { theme: 'dark' },
        metadata: { source: 'migration' }
      },
      accessToken: datosAntiguos.token,
      expiresIn: 3600
    }
  };
  
  nuevoSDK.testExtraction(respuestaMejorada);
  
  console.log('✅ Migración completada - todos los datos preservados');
}

// ==============================================
// EJEMPLO 7: TESTING COMPLETO DEL SISTEMA
// ==============================================

export function ejemplo7_TestingCompleto() {
  console.log('\n🚀 EJEMPLO 7: Testing Completo del Sistema');
  
  // Ejecutar todos los tests mock
  runMockTests();
  
  // Test individual con tu formato exacto
  const tuFormatoActual = {
    success: true,
    message: "Usuario registrado exitosamente",
    data: {
      user: {
        email: "subelzacabezasolivio@gmail.com",
        firstName: "olivio",
        lastName: "olivio",
        role: "admin",
        isActive: true,
        permissions: ["*"],
        profile: {},
        createdAt: "2025-07-22T18:06:29.082Z",
        updatedAt: "2025-07-22T18:06:29.082Z",
        _id: "687fd3259e7f5bab1712d9ea"
      },
      accessToken: "eyJhbGciOiJIUzI1Ni......",
      refreshToken: "eyJhbGciOiJ.......",
      expiresIn: 3600
    }
  };
  
  console.log('\n📋 Testing con tu formato actual:');
  testBackendResponse(tuFormatoActual);
  
  // Crear SDK específico para tu formato
  const authTuSistema = createNodeExpressAuth('http://localhost:3000');
  authTuSistema.testExtraction(tuFormatoActual);
}

// ==============================================
// FUNCIÓN PRINCIPAL PARA EJECUTAR TODOS LOS EJEMPLOS
// ==============================================

export async function ejecutarTodosLosEjemplos() {
  console.log('🎬 INICIANDO EJEMPLOS DEL SDK MEJORADO\n');
  
  try {
    // Ejemplos que no requieren conexión real
    ejemplo3_AutoDeteccion();
    ejemplo4_ConfiguracionPersonalizada();
    ejemplo5_DebuggingAvanzado();
    await ejemplo6_MigracionDatos();
    ejemplo7_TestingCompleto();
    
    // Ejemplos que requieren servidor (comentados por defecto)
    // await ejemplo1_BackendActual();
    // await ejemplo2_LaravelSanctum();
    
    console.log('\n🎉 Todos los ejemplos completados exitosamente!');
    
  } catch (error) {
    console.error('❌ Error en ejemplos:', error);
  }
}

// ==============================================
// UTILIDADES PARA TUS TESTS ESPECÍFICOS
// ==============================================

/**
 * Función específica para testear TUS respuestas reales
 */
export function testearTusRespuestas() {
  console.log('🧪 TESTING CON TUS RESPUESTAS REALES\n');
  
  // Formato 1: Tu Node.js actual
  const tuNodeResponse = {
    success: true,
    message: "Inicio de sesión exitoso",
    data: {
      user: {
        _id: "687f1dc236e46ee3b734907a",
        email: "subelzaolivitocabezas@gmail.com",
        firstName: "Olivio",
        lastName: "Cabezas",
        role: "admin",
        isActive: true,
        permissions: ["*"],
        profile: {},
        createdAt: "2025-07-22T05:12:34.303Z",
        updatedAt: "2025-07-22T05:13:14.934Z",
        lastLogin: "2025-07-22T05:13:14.934Z"
      },
      accessToken: "eyJhbGciOiJI.......",
      refreshToken: "eyJhbGciOiJIUzI1NiIs.......",
      expiresIn: 3600
    }
  };
  
  // Formato 2: Laravel Sanctum que mencionaste
  const tuSanctumResponse = {
    status: "success",
    code: 200,
    message: "Successfuly Connected",
    resultado: {
      status: "success",
      code: 200,
      message: "Inicio de sesión exitoso.",
      data: {
        token: "539|S1O3LzUcTVyjE0UQVMc15RquzYXyvpPP1ktrGbYPe65008ec",
        expires_at: "2025-07-22 15:20:27",
        refresh_token: "540|9AP2QMCXKhzDt3u6YHzPq6tE3eT8jdsk50X6dtoV6b8dc0b4",
        rt_expires_at: "2025-07-23 14:20:27",
        token_type: "Bearer",
        name: "olivio",
        full_name: "Olivio Subelza",
        sucursales: [
          {
            id: 1,
            sucursal: "CENTRAL",
            sigla: "T01",
            nombre_comercial: null,
            rol: "Administrador"
          },
          {
            id: 2,
            sucursal: "Sucursal 2",
            sigla: "T02",
            nombre_comercial: null,
            rol: "Administrador"
          }
        ]
      }
    }
  };
  
  console.log('=== TU FORMATO NODE.JS ===');
  testBackendResponse(tuNodeResponse);
  
  console.log('\n=== TU FORMATO SANCTUM ===');
  testBackendResponse(tuSanctumResponse);
  
  // Crear SDKs específicos y testear
  console.log('\n=== TESTING CON SDK NODE EXPRESS ===');
  const authNode = createNodeExpressAuth();
  authNode.testExtraction(tuNodeResponse);
  
  console.log('\n=== TESTING CON SDK SANCTUM ===');
  const authSanctum = createLaravelSanctumAuth();
  authSanctum.testExtraction(tuSanctumResponse);
}

// Para usar desde consola del navegador o Node.js
if (typeof window !== 'undefined') {
  // Disponible en el navegador
  (window as any).sdkExamples = {
    ejecutarTodosLosEjemplos,
    testearTusRespuestas,
    ejemplo1_BackendActual,
    ejemplo2_LaravelSanctum,
    ejemplo3_AutoDeteccion,
    ejemplo4_ConfiguracionPersonalizada,
    ejemplo5_DebuggingAvanzado,
    ejemplo6_MigracionDatos,
    ejemplo7_TestingCompleto
  };
  
  // console.log('🚀 Ejemplos disponibles en window.sdkExamples');
}

export default {
  ejecutarTodosLosEjemplos,
  testearTusRespuestas,
  ejemplo1_BackendActual,
  ejemplo2_LaravelSanctum,
  ejemplo3_AutoDeteccion,
  ejemplo4_ConfiguracionPersonalizada,
  ejemplo5_DebuggingAvanzado,
  ejemplo6_MigracionDatos,
  ejemplo7_TestingCompleto
};
