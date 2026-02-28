import { AuthTokens, AuthUser } from '../types';
import { Logger } from './Logger';

/**
 * Enhanced TokenExtractor with flexible data preservation
 * Mantiene todos los datos originales del backend sin pérdida de información
 */
export class TokenExtractor {
  private static readonly TOKEN_KEYS = [
    'accessToken', 'access_token', 'token', 'authToken', 'auth_token',
    'bearerToken', 'bearer_token', 'jwt', 'jwtToken', 'jwt_token'
  ];

  private static readonly REFRESH_TOKEN_KEYS = [
    'refreshToken', 'refresh_token', 'renewToken', 'renew_token',
    'rt_expires_at' // Para manejar casos donde el refresh viene con metadata
  ];

  private static readonly EXPIRES_KEYS = [
    'expiresIn', 'expires_in', 'exp', 'expiration', 'expires_at', 'expiresAt',
    'expiry', 'expiry_time', 'expiryTime', 'valid_until', 'validUntil',
    'rt_expires_at' // Para Sanctum Laravel
  ];

  private static readonly TOKEN_TYPE_KEYS = [
    'tokenType', 'token_type', 'type', 'authType', 'auth_type'
  ];

  private static readonly USER_SEARCH_PATHS = [
    'data.user',           // Node.js/Express estándar
    'resultado.data',      // Laravel Sanctum
    'user',               // JWT o respuesta directa
    'data',               // Respuesta con data wrapper
    'profile',            // Algunos sistemas usan profile
    'userInfo',           // Otros usan userInfo
    'account',            // Account-based systems
    ''                    // Raíz del objeto
  ];

  // Cache mejorado con TTL
  private static searchCache = new Map<string, { value: any; timestamp: number }>();
  private static readonly CACHE_TTL = 5000;

  /**
   * Búsqueda profunda optimizada con paths específicos
   */
  private static deepSearchByPaths(obj: any, searchPaths: string[]): any {
    if (!obj || typeof obj !== 'object') return null;

    // Generar cache key único
    const cacheKey = `paths_${JSON.stringify(searchPaths)}_${this.generateObjectSignature(obj)}`;
    const cached = this.searchCache.get(cacheKey);
    
    if (cached && Date.now() - cached.timestamp < this.CACHE_TTL) {
      return cached.value;
    }

    for (const path of searchPaths) {
      if (path === '') {
        // Buscar en la raíz
        const result = this.extractFromRoot(obj);
        if (result) {
          this.searchCache.set(cacheKey, { value: result, timestamp: Date.now() });
          return result;
        }
        continue;
      }

      const value = this.getNestedValue(obj, path);
      if (value && typeof value === 'object') {
        this.searchCache.set(cacheKey, { value, timestamp: Date.now() });
        return value;
      }
    }

    this.searchCache.set(cacheKey, { value: null, timestamp: Date.now() });
    return null;
  }

  /**
   * Extrae datos de usuario desde la raíz del objeto
   */
  private static extractFromRoot(obj: any): any {
    // Verificar si el objeto raíz tiene campos de usuario válidos
    const userFields = ['id', '_id', 'email', 'name', 'firstName', 'usuario'];
    const hasUserField = userFields.some(field => obj[field] !== undefined);
    
    if (hasUserField) {
      return obj;
    }
    
    return null;
  }

  /**
   * Obtiene valor anidado usando dot notation
   */
  private static getNestedValue(obj: any, path: string): any {
    return path.split('.').reduce((current, key) => {
      return current && current[key] !== undefined ? current[key] : null;
    }, obj);
  }

  /**
   * Genera una signatura única del objeto para cache
   */
  private static generateObjectSignature(obj: any): string {
    try {
      const keys = Object.keys(obj).sort().slice(0, 10); // Primeras 10 keys para performance
      return keys.join(',');
    } catch {
      return 'unknown';
    }
  }

  /**
   * Búsqueda mejorada de campos específicos
   */
  private static enhancedDeepSearch(obj: any, keys: string[], maxDepth = 5): any {
    if (!obj || typeof obj !== 'object' || maxDepth <= 0) return null;

    // Búsqueda en nivel actual (caso más común)
    for (const key of keys) {
      if (obj.hasOwnProperty(key) && obj[key] !== null && obj[key] !== undefined) {
        return obj[key];
      }
    }

    // Búsqueda en niveles anidados
    const queue: Array<{ obj: any; depth: number }> = [];
    
    for (const [key, value] of Object.entries(obj)) {
      if (value && typeof value === 'object' && !Array.isArray(value)) {
        queue.push({ obj: value, depth: 1 });
      }
    }

    while (queue.length > 0) {
      const { obj: currentObj, depth } = queue.shift()!;
      
      if (depth >= maxDepth) continue;

      for (const key of keys) {
        if (currentObj.hasOwnProperty(key) && currentObj[key] !== null && currentObj[key] !== undefined) {
          return currentObj[key];
        }
      }

      for (const [key, value] of Object.entries(currentObj)) {
        if (value && typeof value === 'object' && !Array.isArray(value)) {
          queue.push({ obj: value, depth: depth + 1 });
        }
      }
    }

    return null;
  }

  /**
   * Normalización mejorada de tiempo de expiración con soporte para múltiples formatos
   */
  private static normalizeExpirationTime(expiresValue: any): number | undefined {
    if (!expiresValue) return undefined;

    // Número: puede ser timestamp o segundos relativos
    if (typeof expiresValue === 'number') {
      // Si es un timestamp (mayor a 1609459200 = 1 Jan 2021)
      if (expiresValue > 1609459200) {
        const now = Math.floor(Date.now() / 1000);
        return Math.max(0, expiresValue - now);
      }
      // Si no, son segundos relativos
      return Math.max(0, expiresValue);
    }

    // String: intentar parsear como fecha o timestamp
    if (typeof expiresValue === 'string') {
      // Formato de fecha (ISO, Laravel Sanctum, etc.)
      if (expiresValue.includes('T') || expiresValue.includes('-') || expiresValue.includes('/')) {
        const date = new Date(expiresValue);
        if (!isNaN(date.getTime())) {
          const now = Date.now();
          const expiresMs = date.getTime();
          const secondsUntilExpiry = Math.floor((expiresMs - now) / 1000);
          return Math.max(0, secondsUntilExpiry);
        }
      }

      // Timestamp como string
      const timestampSeconds = parseInt(expiresValue);
      if (!isNaN(timestampSeconds)) {
        if (timestampSeconds > 1609459200) {
          const now = Math.floor(Date.now() / 1000);
          return Math.max(0, timestampSeconds - now);
        }
        return Math.max(0, timestampSeconds);
      }
    }

    Logger.warn('Could not parse expiration time:', expiresValue, typeof expiresValue);
    return undefined;
  }

  /**
   * Extracción mejorada de tokens con soporte para múltiples formatos
   */
  static extractTokens(response: any): AuthTokens & { _originalTokenResponse?: any } {
    const accessToken = this.enhancedDeepSearch(response, this.TOKEN_KEYS);
    const refreshToken = this.enhancedDeepSearch(response, this.REFRESH_TOKEN_KEYS);
    const tokenType = this.enhancedDeepSearch(response, this.TOKEN_TYPE_KEYS);

    if (!accessToken) {
      throw new Error('No access token found in response');
    }

    // Extraer múltiples formatos de expiración
    const expiresIn = this.extractExpirationTime(response);
    const expiresAt = this.enhancedDeepSearch(response, ['expires_at', 'expiresAt', 'rt_expires_at']);

    const tokens: AuthTokens & { _originalTokenResponse?: any } = {
      accessToken,
      refreshToken,
      expiresIn,
      expiresAt,
      tokenType: tokenType || 'Bearer',
      // NUEVO: Preservar respuesta original para debugging
      _originalTokenResponse: response
    };

    return tokens;
  }

  /**
   * Extracción de tiempo de expiración mejorada
   */
  private static extractExpirationTime(response: any): number | undefined {
    const expiresValue = this.enhancedDeepSearch(response, this.EXPIRES_KEYS);
    return this.normalizeExpirationTime(expiresValue);
  }

  /**
   * Extracción flexible de usuario con preservación completa de datos
   */
  static extractUser(response: any): (AuthUser & { _originalUserResponse?: any; _backendType?: string }) | null {
    // Buscar datos de usuario usando paths específicos
    const userData = this.deepSearchByPaths(response, this.USER_SEARCH_PATHS);

    if (!userData || typeof userData !== 'object') {
      // Fallback: intentar construir desde campos dispersos
      return this.buildUserFromScatteredFields(response);
    }

    // Detectar tipo de backend basado en estructura
    const backendType = this.detectBackendType(response, userData);

    // Extraer campos estándar con mapeo flexible
    const standardUser = this.mapToStandardUser(userData);

    // CLAVE: Preservar TODOS los datos originales
    const enhancedUser: AuthUser & { _originalUserResponse?: any; _backendType?: string } = {
      ...standardUser,
      // Preservar campos originales que no están en el mapping
      ...this.preserveUnmappedFields(userData, standardUser),
      // Metadatos para debugging y flexibilidad
      _originalUserResponse: response,
      _backendType: backendType
    };

    return enhancedUser;
  }

  /**
   * Mapea campos de usuario a formato estándar
   */
  private static mapToStandardUser(userData: any): AuthUser {
    return {
      id: this.findUserField(userData, ['_id', 'id', 'user_id', 'userId']) || 'unknown',
      email: this.findUserField(userData, ['email', 'user_email', 'userEmail', 'correo']),
      name: this.buildUserName(userData),
      // Campos adicionales comunes
      firstName: this.findUserField(userData, ['firstName', 'first_name', 'nombre']),
      lastName: this.findUserField(userData, ['lastName', 'last_name', 'apellido']),
      role: this.findUserField(userData, ['role', 'rol', 'roles', 'authorities']),
      permissions: this.extractPermissions(userData),
      isActive: this.findUserField(userData, ['isActive', 'is_active', 'active', 'activo']),
      profile: this.findUserField(userData, ['profile', 'perfil', 'profileData'])
    };
  }

  /**
   * Construye el nombre completo del usuario
   */
  private static buildUserName(userData: any): string {
    const firstName = this.findUserField(userData, ['firstName', 'first_name', 'nombre']);
    const lastName = this.findUserField(userData, ['lastName', 'last_name', 'apellido']);
    const fullName = this.findUserField(userData, ['name', 'fullName', 'full_name', 'nombreCompleto']);
    const email = this.findUserField(userData, ['email', 'correo']);

    if (fullName) return fullName;
    if (firstName && lastName) return `${firstName} ${lastName}`;
    if (firstName) return firstName;
    if (email) return email;
    
    return 'Usuario';
  }

  /**
   * Busca un campo usando múltiples nombres posibles
   */
  private static findUserField(userData: any, fieldNames: string[]): any {
    for (const field of fieldNames) {
      if (userData[field] !== undefined && userData[field] !== null) {
        return userData[field];
      }
    }
    return undefined;
  }

  /**
   * Extrae permisos en formato array
   */
  private static extractPermissions(userData: any): string[] {
    const perms = this.findUserField(userData, ['permissions', 'permisos', 'authorities', 'roles']);
    
    if (Array.isArray(perms)) return perms;
    if (typeof perms === 'string') return [perms];
    
    return [];
  }

  /**
   * Preserva campos que no están en el mapping estándar
   */
  private static preserveUnmappedFields(originalData: any, mappedData: any): Record<string, any> {
    const preserved: Record<string, any> = {};
    const standardFields = new Set(Object.keys(mappedData));
    
    for (const [key, value] of Object.entries(originalData)) {
      // Preservar si no está en campos estándar y no es un campo interno
      if (!standardFields.has(key) && !key.startsWith('_')) {
        preserved[key] = value;
      }
    }
    
    return preserved;
  }

  /**
   * Detecta el tipo de backend basado en la estructura de respuesta
   */
  private static detectBackendType(response: any, userData: any): string {
    // Laravel Sanctum
    if (response.resultado?.data || response.token?.includes?.('|')) {
      return 'laravel-sanctum';
    }
    
    // Node.js/Express estándar
    if (response.data?.user || response.success !== undefined) {
      return 'node-express';
    }
    
    // JWT puro
    if (response.accessToken && !response.data) {
      return 'jwt-standard';
    }
    
    return 'unknown';
  }

  /**
   * Construye usuario desde campos dispersos cuando no hay estructura clara
   */
  private static buildUserFromScatteredFields(response: any): (AuthUser & { _originalUserResponse?: any; _backendType?: string }) | null {
    const id = this.enhancedDeepSearch(response, ['id', '_id', 'user_id', 'userId']);
    const email = this.enhancedDeepSearch(response, ['email', 'user_email', 'userEmail']);
    const name = this.enhancedDeepSearch(response, ['name', 'username', 'user_name', 'fullName']);

    if (!id && !email && !name) {
      // Último recurso: extraer desde JWT token
      const token = this.enhancedDeepSearch(response, this.TOKEN_KEYS);
      if (token) {
        const userFromToken = this.parseUserFromToken(token);
        if (userFromToken) {
          return {
            ...userFromToken,
            _originalUserResponse: response,
            _backendType: 'jwt-parsed'
          };
        }
      }
      return null;
    }

    return {
      id: id || 'unknown',
      email,
      name: name || email || 'Usuario',
      _originalUserResponse: response,
      _backendType: 'scattered-fields'
    };
  }

  /**
   * Parsea información de usuario desde JWT token
   */
  private static parseUserFromToken(token: string): AuthUser | null {
    try {
      // Skip tokens de Sanctum (contienen |)
      if (token.includes('|')) return null;

      const parts = token.split('.');
      if (parts.length !== 3) return null;

      const base64Payload = parts[1];
      const paddedBase64 = base64Payload.padEnd(
        base64Payload.length + (4 - (base64Payload.length % 4)) % 4,
        '='
      );
      
      const payload = JSON.parse(atob(paddedBase64));

      return {
        id: payload.sub || payload.user_id || payload.id || payload.userId || 'unknown',
        name: payload.name || payload.username || payload.firstName || payload.email || 'Usuario',
        email: payload.email,
        firstName: payload.firstName || payload.first_name,
        lastName: payload.lastName || payload.last_name,
        role: payload.role || payload.roles?.[0],
        permissions: payload.permissions || payload.authorities || [],
        // Preservar todos los campos del JWT
        ...payload
      };
    } catch (error) {
      Logger.warn('Error parsing user from JWT:', error);
      return null;
    }
  }

  /**
   * Método de debug mejorado con más información
   */
  static debugResponse(response: any, depth: number = 0): void {
    const indent = '  '.repeat(depth);
    console.group(`${indent}🔍 Enhanced Response Analysis (depth: ${depth})`);

    if (response && typeof response === 'object') {
      console.log(`${indent}📊 Object keys:`, Object.keys(response));

      // Analizar estructura para diferentes backends
      const backendType = this.detectBackendType(response, response);
      console.log(`${indent}🔧 Detected backend type:`, backendType);

      // Tokens detectados
      const possibleTokens = Object.keys(response).filter(key => 
        this.TOKEN_KEYS.some(tokenKey => 
          key.toLowerCase().includes(tokenKey.toLowerCase())
        )
      );
      if (possibleTokens.length > 0) {
        console.log(`${indent}🔑 Possible token fields:`, possibleTokens);
      }

      // Usuarios detectados
      const possibleUsers = Object.keys(response).filter(key => 
        ['user', 'data', 'profile', 'account'].some(userKey => 
          key.toLowerCase().includes(userKey.toLowerCase())
        )
      );
      if (possibleUsers.length > 0) {
        console.log(`${indent}👤 Possible user fields:`, possibleUsers);
      }

      // Paths de búsqueda
      console.log(`${indent}🔍 Searching in paths:`, this.USER_SEARCH_PATHS);

      if (depth < 2) {
        for (const [key, value] of Object.entries(response)) {
          if (value && typeof value === 'object' && !Array.isArray(value)) {
            console.log(`${indent}📂 Analyzing nested object: ${key}`);
            this.debugResponse(value, depth + 1);
          }
        }
      }
    } else {
      console.log(`${indent}📝 Primitive value:`, typeof response, response);
    }

    console.groupEnd();
  }

  /**
   * Limpiar cache (llamar periódicamente para evitar memory leaks)
   */
  static clearCache(): void {
    this.searchCache.clear();
  }

  /**
   * Test de extracción con diferentes formatos
   */
  static testExtraction(response: any): void {
    console.group('🧪 Testing Token and User Extraction');
    
    try {
      console.log('📥 Original response:', response);
      
      // Test token extraction
      console.log('🔑 Testing token extraction...');
      const tokens = this.extractTokens(response);
      console.log('✅ Extracted tokens:', tokens);
      
      // Test user extraction
      console.log('👤 Testing user extraction...');
      const user = this.extractUser(response);
      console.log('✅ Extracted user:', user);
      
      console.log('🎉 Extraction test completed successfully!');
      
    } catch (error) {
      console.error('❌ Extraction test failed:', error);
    }
    
    console.groupEnd();
  }
}
