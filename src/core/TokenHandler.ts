import { AuthTokens, AuthUser } from "../types";

export class TokenHandler {
  public static detectTokenType(token: string): 'jwt' | 'sanctum' | 'opaque' {
    if (!token || typeof token !== 'string') {
      return 'opaque';
    }

    // Token de Sanctum: contiene pipe (|)
    if (token.includes('|')) {
      return 'sanctum';
    }

    // Token JWT: tiene 3 partes separadas por puntos
    const parts = token.split('.');
    if (parts.length === 3) {
      try {
        // Verificar que la segunda parte se puede decodificar
        const base64Payload = parts[1];
        const paddedBase64 = base64Payload.padEnd(
          base64Payload.length + (4 - (base64Payload.length % 4)) % 4,
          '='
        );
        atob(paddedBase64);
        return 'jwt';
      } catch {
        return 'opaque';
      }
    }

    return 'opaque';
  }

  /**
   * Extrae información del token según su tipo
   */
  static parseToken(token: string): {
    type: 'jwt' | 'sanctum' | 'opaque';
    payload?: any;
    exp?: number;
    tokenId?: string;
    isValid: boolean;
  } {
    const type = this.detectTokenType(token);

    switch (type) {
      case 'jwt':
        return this.parseJWTToken(token);
      case 'sanctum':
        return this.parseSanctumToken(token);
      default:
        return this.parseOpaqueToken(token);
    }
  }

  private static parseJWTToken(token: string) {
    try {
      const parts = token.split('.');
      const base64Payload = parts[1];
      const paddedBase64 = base64Payload.padEnd(
        base64Payload.length + (4 - (base64Payload.length % 4)) % 4,
        '='
      );
      
      const decodedPayload = atob(paddedBase64);
      const payload = JSON.parse(decodedPayload);
      
      return {
        type: 'jwt' as const,
        payload,
        exp: payload.exp,
        isValid: payload.exp ? payload.exp > Math.floor(Date.now() / 1000) : true
      };
    } catch (error) {
      console.error('Error parsing JWT token:', error);
      return {
        type: 'jwt' as const,
        isValid: false
      };
    }
  }

  private static parseSanctumToken(token: string) {
    const parts = token.split('|');
    return {
      type: 'sanctum' as const,
      tokenId: parts[0],
      payload: {
        tokenId: parts[0],
        hash: parts[1]
      },
      isValid: true // Los tokens de Sanctum no contienen info de expiración
    };
  }

  private static parseOpaqueToken(_: string) {
    return {
      type: 'opaque' as const,
      isValid: true // Tokens opacos requieren validación externa
    };
  }
}