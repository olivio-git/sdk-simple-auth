import { AuthTokens, AuthUser } from "../types"; 
import ExpirationHandler from "./ExpirationHandler";

// TokenExtractor actualizado para manejar mejor los diferentes formatos
class TokenExtractor {
  // ... (mantener los arrays de claves existentes)
  private static readonly TOKEN_KEYS = [
    'accessToken', 'access_token', 'token', 'authToken', 'auth_token',
    'bearerToken', 'bearer_token', 'jwt', 'jwtToken', 'jwt_token'
  ];

  private static readonly REFRESH_TOKEN_KEYS = [
    'refreshToken', 'refresh_token', 'renewToken', 'renew_token'
  ];

  private static readonly EXPIRES_KEYS = [
    'expiresIn', 'expires_in', 'exp', 'expiration', 'expires_at', 'expiresAt',
    'expiry', 'expiry_time', 'expiryTime', 'valid_until', 'validUntil'
  ];

  private static readonly EXPIRES_AT_KEYS = [
    'expires_at', 'expiresAt', 'expiration', 'expiry_time', 'expiryTime',
    'valid_until', 'validUntil', 'rt_expires_at', 'rtExpiresAt'
  ];

  private static readonly TOKEN_TYPE_KEYS = [
    'tokenType', 'token_type', 'type', 'authType', 'auth_type'
  ];

  private static readonly USER_KEYS = [
    'user', 'userData', 'user_data', 'profile', 'userProfile', 'user_profile',
    'data', 'userInfo', 'user_info', 'account', 'accountData', 'account_data',
    'name', 'username', 'userName', 'email', 'userEmail', 'user_email', 
    'userId', 'id', 'full_name', 'fullName'
  ];

  private static deepSearch(obj: any, keys: string[]): any {
    if (!obj || typeof obj !== 'object') return null;

    for (const key of keys) {
      if (obj.hasOwnProperty(key) && obj[key] !== null && obj[key] !== undefined) {
        return obj[key];
      }
    }

    for (const value of Object.values(obj)) {
      if (value && typeof value === 'object') {
        const result = this.deepSearch(value, keys);
        if (result) return result;
      }
    }

    return null;
  }

  static extractTokens(response: any): AuthTokens {
    const accessToken = this.deepSearch(response, this.TOKEN_KEYS);
    const refreshToken = this.deepSearch(response, this.REFRESH_TOKEN_KEYS);
    const tokenType = this.deepSearch(response, this.TOKEN_TYPE_KEYS);
    
    // Buscar diferentes tipos de información de expiración
    const expiresIn = this.deepSearch(response, this.EXPIRES_KEYS);
    const expiresAt = this.deepSearch(response, this.EXPIRES_AT_KEYS);

    if (!accessToken) {
      throw new Error('No access token found in response');
    }

    // Calcular expiración usando el nuevo handler
    const calculatedExpiresIn = ExpirationHandler.calculateExpiration(
      accessToken,
      expiresIn,
      expiresAt
    );

    return {
      accessToken,
      refreshToken,
      expiresIn: calculatedExpiresIn,
      expiresAt, // Mantener el valor original también
      tokenType: tokenType || 'Bearer',
    };
  }

  static extractUser(response: any): AuthUser | null {
    const userData = this.deepSearch(response, this.USER_KEYS);

    if (userData && typeof userData === 'object') {
      return {
        id: userData.id || userData.user_id || userData.userId || 'unknown',
        name: userData.name || userData.username || userData.full_name || userData.email || 'User',
        email: userData.email || userData.userEmail,
        ...userData // Incluir campos adicionales como sucursales
      };
    }

    // Buscar campos de usuario en el nivel raíz
    const name = this.deepSearch(response, ['name', 'username', 'full_name', 'email']);
    if (name) {
      return {
        id: this.deepSearch(response, ['id', 'user_id', 'userId']) || 'unknown',
        name,
        email: this.deepSearch(response, ['email', 'user_email', 'userEmail']),
        // Buscar campos adicionales como sucursales
        sucursales: this.deepSearch(response, ['sucursales', 'branches', 'offices'])
      };
    }

    return null;
  }
}
export default TokenExtractor;