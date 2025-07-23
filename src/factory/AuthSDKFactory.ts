import { AuthSDK } from '../core/AuthSDK';
import { AuthConfig } from '../types';
import { EnhancedAuthConfig, BACKEND_PRESETS, ResponseAnalysis, BackendPresets } from '../types/enhanced_types';

/**
 * Factory para crear instancias de AuthSDK configuradas para diferentes backends
 */
export class AuthSDKFactory {
  /**
   * Crear AuthSDK para backend específico
   */
  static create(backendType: keyof typeof BACKEND_PRESETS, customConfig: Partial<EnhancedAuthConfig> = {}): AuthSDK {
    const preset = BACKEND_PRESETS[backendType];
    
    if (!preset) {
      throw new Error(`Backend preset '${backendType}' not found. Available: ${Object.keys(BACKEND_PRESETS).join(', ')}`);
    }

    // Convertir BackendFieldMappings a Record<string, string[]>
    const convertFieldMappings = (mappings: any): Record<string, string[]> => {
      const result: Record<string, string[]> = {};
      for (const [key, value] of Object.entries(mappings || {})) {
        if (Array.isArray(value)) {
          result[key] = value;
        }
      }
      return result;
    };

    const config: AuthConfig = {
      authServiceUrl: customConfig.authServiceUrl || 'http://localhost:3000',
      ...customConfig,
      backend: {
        type: backendType,
        userSearchPaths: customConfig.backend?.userSearchPaths || preset.userSearchPaths,
        fieldMappings: convertFieldMappings(customConfig.backend?.fieldMappings || preset.fieldMappings),
        preserveOriginalData: customConfig.backend?.preserveOriginalData ?? preset.preserveOriginalData,
      },
    };

    console.log(`🏭 Creating AuthSDK for backend: ${backendType}`);
    console.log(`🔧 Configuration:`, config);

    return new AuthSDK(config);
  }

  /**
   * Crear AuthSDK con configuración completamente personalizada
   */
  static createCustom(config: AuthConfig): AuthSDK {
    console.log('🏭 Creating custom AuthSDK');
    console.log('🔧 Custom configuration:', config);
    
    return new AuthSDK(config);
  }

  /**
   * Analizar respuesta de API para detectar estructura
   */
  static analyzeResponse(response: any): ResponseAnalysis {
    console.log('🔍 Analyzing API response structure...');
    
    const analysis: ResponseAnalysis = {
      backendType: 'unknown',
      structure: {
        hasUser: false,
        hasTokens: false,
        userPath: null,
        tokenFields: [],
        userFields: []
      },
      extraction: {
        tokensExtracted: false,
        userExtracted: false,
        missingFields: []
      },
      recommendations: []
    };

    // Detectar tipo de backend
    if (response.resultado?.data) {
      analysis.backendType = 'laravel-sanctum';
    } else if (response.data?.user || response.success !== undefined) {
      analysis.backendType = 'node-express';
    } else if (response.access_token || response.token) {
      analysis.backendType = 'jwt-standard';
    }

    // Analizar estructura
    const allKeys = this.getAllKeys(response);
    
    analysis.structure.tokenFields = allKeys.filter(key => 
      ['token', 'access', 'bearer', 'jwt', 'auth'].some(term => 
        key.toLowerCase().includes(term)
      )
    );
    
    analysis.structure.userFields = allKeys.filter(key => 
      ['user', 'data', 'profile', 'account', 'me'].some(term => 
        key.toLowerCase().includes(term)
      )
    );

    analysis.structure.hasTokens = analysis.structure.tokenFields.length > 0;
    analysis.structure.hasUser = analysis.structure.userFields.length > 0;

    // Determinar path de usuario más probable
    if (analysis.structure.userFields.length > 0) {
      analysis.structure.userPath = analysis.structure.userFields[0];
    }

    // Intentar extracción real
    try {
      const { TokenExtractor } = require('../core/TokenManager');
      TokenExtractor.extractTokens(response);
      analysis.extraction.tokensExtracted = true;
    } catch (error) {
      analysis.extraction.missingFields.push('accessToken');
    }

    try {
      const { TokenExtractor } = require('../core/TokenManager');
      const user = TokenExtractor.extractUser(response);
      analysis.extraction.userExtracted = !!user;
    } catch (error) {
      analysis.extraction.missingFields.push('user');
    }

    // Generar recomendaciones
    analysis.recommendations = this.generateRecommendations(analysis);

    console.log('📊 Analysis completed:', analysis);
    return analysis;
  }

  /**
   * Test automático de extracción para todos los presets
   */
  static testAllPresets(response: any): Record<string, { success: boolean; error?: string; extracted?: any }> {
    console.log('🧪 Testing response with all available presets...');
    
    const results: Record<string, { success: boolean; error?: string; extracted?: any }> = {};
    
    for (const [backendType, preset] of Object.entries(BACKEND_PRESETS)) {
      console.log(`\n🔧 Testing with ${backendType} preset...`);
      
      try {
        // Usar el TokenExtractor directamente para testing
        const { TokenExtractor } = require('../core/TokenManager');
        
        const tokens = TokenExtractor.extractTokens(response);
        const user = TokenExtractor.extractUser(response);
        
        results[backendType] = {
          success: true,
          extracted: { tokens, user }
        };
        
        console.log(`✅ ${backendType} preset works!`);
        
      } catch (error) {
        results[backendType] = {
          success: false,
          error: error instanceof Error ? error.message : 'Unknown error'
        };
        
        console.log(`❌ ${backendType} preset failed:`, error);
      }
    }
    
    return results;
  }

  /**
   * Generar configuración custom basada en análisis de respuesta
   */
  static generateCustomConfig(response: any, baseUrl: string): AuthConfig {
    const analysis = this.analyzeResponse(response);
    
    console.log('🏗️ Generating custom configuration based on analysis...');
    
    const config: AuthConfig = {
      authServiceUrl: baseUrl,
      backend: {
        type: 'custom',
        userSearchPaths: analysis.structure.userPath ? [analysis.structure.userPath] : [''],
        fieldMappings: {
          token: analysis.structure.tokenFields.slice(0, 3), // Top 3 candidates
          userId: ['id', '_id', 'user_id'],
          email: ['email', 'correo'],
          name: ['name', 'nombre', 'full_name']
        },
        preserveOriginalData: true
      }
    };
    
    console.log('🔧 Generated config:', config);
    return config;
  }

  private static getAllKeys(obj: any, prefix = ''): string[] {
    const keys: string[] = [];
    
    if (obj && typeof obj === 'object') {
      for (const [key, value] of Object.entries(obj)) {
        const fullKey = prefix ? `${prefix}.${key}` : key;
        keys.push(fullKey);
        
        if (value && typeof value === 'object' && !Array.isArray(value)) {
          keys.push(...this.getAllKeys(value, fullKey));
        }
      }
    }
    
    return keys;
  }

  private static generateRecommendations(analysis: ResponseAnalysis): string[] {
    const recommendations: string[] = [];

    if (!analysis.extraction.tokensExtracted) {
      recommendations.push(`⚠️ Configure token extraction. Found possible fields: ${analysis.structure.tokenFields.join(', ')}`);
    }

    if (!analysis.extraction.userExtracted) {
      recommendations.push(`⚠️ Configure user extraction. Found possible fields: ${analysis.structure.userFields.join(', ')}`);
    }

    if (analysis.backendType === 'unknown') {
      recommendations.push('💡 Consider using custom backend configuration');
      recommendations.push('🔧 Use AuthSDKFactory.generateCustomConfig() for automatic setup');
    } else {
      recommendations.push(`✅ Use '${analysis.backendType}' preset: AuthSDKFactory.create('${analysis.backendType}')`);
    }

    if (analysis.extraction.tokensExtracted && analysis.extraction.userExtracted) {
      recommendations.push('🎉 Response is fully compatible! No additional configuration needed.');
    }

    return recommendations;
  }
}

// ==============================================
// FUNCIONES HELPER PARA USO FÁCIL
// ==============================================

/**
 * Crear AuthSDK para Node.js/Express (tu sistema actual)
 */
export function createNodeExpressAuth(baseUrl: string = 'http://localhost:3000', customConfig?: Partial<AuthConfig>): AuthSDK {
  return AuthSDKFactory.create('node-express', {
    authServiceUrl: baseUrl,
    ...customConfig
  });
}

/**
 * Crear AuthSDK para Laravel Sanctum
 */
export function createLaravelSanctumAuth(baseUrl: string = 'http://localhost:8000/api', customConfig?: Partial<AuthConfig>): AuthSDK {
  return AuthSDKFactory.create('laravel-sanctum', {
    authServiceUrl: baseUrl,
    ...customConfig
  });
}

/**
 * Crear AuthSDK para JWT estándar
 */
export function createJWTStandardAuth(baseUrl: string, customConfig?: Partial<AuthConfig>): AuthSDK {
  return AuthSDKFactory.create('jwt-standard', {
    authServiceUrl: baseUrl,
    ...customConfig
  });
}

/**
 * Auto-detectar y crear AuthSDK basado en una respuesta de ejemplo
 */
export function createAutoDetectAuth(sampleResponse: any, baseUrl: string): AuthSDK {
  console.log('🤖 Auto-detecting backend type from sample response...');
  
  const analysis = AuthSDKFactory.analyzeResponse(sampleResponse);
  
  if (analysis.backendType !== 'unknown') {
    console.log(`🎯 Detected: ${analysis.backendType}`);
    return AuthSDKFactory.create(analysis.backendType as keyof BackendPresets, {
      authServiceUrl: baseUrl
    });
  } else {
    console.log('🔧 Generating custom configuration...');
    const customConfig = AuthSDKFactory.generateCustomConfig(sampleResponse, baseUrl);
    return AuthSDKFactory.createCustom(customConfig);
  }
}

// ==============================================
// FUNCIONES DE TESTING Y DEBUGGING
// ==============================================

/**
 * Función helper para testear diferentes respuestas de backend
 */
export function testBackendResponse(response: any, verbose: boolean = true): void {
  console.group('🧪 Testing Backend Response');
  
  if (verbose) {
    console.log('📥 Original Response:', response);
  }
  
  // Analizar respuesta
  const analysis = AuthSDKFactory.analyzeResponse(response);
  console.log('📊 Analysis Results:', analysis);
  
  // Mostrar recomendaciones
  console.log('\n💡 Recommendations:');
  analysis.recommendations.forEach(rec => console.log(`  ${rec}`));
  
  // Testear con todos los presets
  const testResults = AuthSDKFactory.testAllPresets(response);
  
  console.log('\n🏆 Best Compatible Presets:');
  Object.entries(testResults)
    .filter(([_, result]) => result.success)
    .forEach(([preset, _]) => console.log(`  ✅ ${preset}`));
  
  console.groupEnd();
}

/**
 * Crear configuración de desarrollo con logging extendido
 */
export function createDevAuth(backendType: keyof typeof BACKEND_PRESETS = 'node-express', baseUrl: string = 'http://localhost:3000'): AuthSDK {
  console.log('🛠️ Creating development AuthSDK with extended logging...');
  
  const auth = AuthSDKFactory.create(backendType, {
    authServiceUrl: baseUrl
  });

  // Agregar listeners para debugging
  auth.onAuthStateChanged((state) => {
    console.log('🔄 [DEV] Auth State Changed:', {
      isAuthenticated: state.isAuthenticated,
      user: state.user?.email || state.user?.name,
      backendType: state.backendType,
      loading: state.loading,
      error: state.error
    });
  });

  return auth;
}

/**
 * Testear con datos mock de diferentes backends
 */
export function runMockTests(): void {
  console.group('🧪 Running Comprehensive Mock Tests');

  // Mock response Node.js/Express (tu formato actual)
  const nodeResponse = {
    success: true,
    message: "Inicio de sesión exitoso",
    data: {
      user: {
        _id: '687fd4d0b0b1db461b716dbc',
        email: 'test@test.com',
        firstName: 'Test',
        lastName: 'User',
        role: 'admin',
        permissions: ['*'],
        isActive: true,
        profile: {},
        createdAt: '2025-07-22T18:06:29.082Z',
        lastLogin: '2025-07-22T18:06:29.082Z'
      },
      accessToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
      refreshToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
      expiresIn: 3600
    }
  };

  // Mock response Laravel Sanctum (formato del ejemplo que proporcionaste)
  const sanctumResponse = {
    status: 'success',
    code: 200,
    message: 'Inicio de sesión exitoso.',
    resultado: {
      status: 'success',
      code: 200,
      message: 'Inicio de sesión exitoso.',
      data: {
        token: '539|S1O3LzUcTVyjE0UQVMc15RquzYXyvpPP1ktrGbYPe65008ec',
        expires_at: '2025-07-22 15:20:27',
        refresh_token: '540|9AP2QMCXKhzDt3u6YHzPq6tE3eT8jdsk50X6dtoV6b8dc0b4',
        rt_expires_at: '2025-07-23 14:20:27',
        token_type: 'Bearer',
        name: 'olivio',
        full_name: 'Olivio Subelza',
        sucursales: [
          {
            id: 1,
            sucursal: 'CENTRAL',
            sigla: 'T01',
            nombre_comercial: null,
            rol: 'Administrador'
          },
          {
            id: 2,
            sucursal: 'Sucursal 2',
            sigla: 'T02', 
            nombre_comercial: null,
            rol: 'Administrador'
          }
        ]
      }
    }
  };

  // Mock response JWT estándar
  const jwtResponse = {
    access_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
    refresh_token: 'refresh_token_here',
    expires_in: 3600,
    token_type: 'Bearer',
    name: 'John Doe',
    email: 'john@example.com'
  };

  console.log('\n=== TESTING NODE.JS/EXPRESS RESPONSE ===');
  testBackendResponse(nodeResponse, false);

  console.log('\n=== TESTING LARAVEL SANCTUM RESPONSE ===');
  testBackendResponse(sanctumResponse, false);

  console.log('\n=== TESTING JWT STANDARD RESPONSE ===');
  testBackendResponse(jwtResponse, false);

  console.groupEnd();
}

/**
 * Comparar extracción entre presets para una respuesta
 */
export function compareExtractionMethods(response: any): void {
  console.group('🔍 Comparing Extraction Methods');
  
  const results = AuthSDKFactory.testAllPresets(response);
  
  console.table(
    Object.entries(results).map(([preset, result]) => ({
      Preset: preset,
      Success: result.success ? '✅' : '❌',
      Error: result.error || 'N/A',
      'Tokens Extracted': result.extracted?.tokens ? '✅' : '❌',
      'User Extracted': result.extracted?.user ? '✅' : '❌'
    }))
  );
  
  console.groupEnd();
}

export default AuthSDKFactory;
