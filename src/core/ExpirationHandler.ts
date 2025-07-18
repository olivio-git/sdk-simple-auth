import {TokenHandler} from "./TokenHandler";

// Clase para normalizar fechas de expiración
class ExpirationHandler {
  /**
   * Normaliza diferentes formatos de fecha de expiración a segundos desde ahora
   */
  static normalizeExpiration(expiresValue: any): number | undefined {
    if (!expiresValue) return undefined;

    // Si ya es un número, asumimos que son segundos
    if (typeof expiresValue === 'number') {
      return expiresValue;
    }

    if (typeof expiresValue === 'string') {
      // Intentar parsear como fecha ISO (formato de Sanctum)
      if (expiresValue.includes('T') || expiresValue.includes('-')) {
        const date = new Date(expiresValue);
        if (!isNaN(date.getTime())) {
          const now = Date.now();
          const expiresMs = date.getTime();
          const secondsUntilExpiry = Math.floor((expiresMs - now) / 1000);
          return Math.max(0, secondsUntilExpiry);
        }
      }

      // Intentar parsear como timestamp Unix
      const timestampSeconds = parseInt(expiresValue);
      if (!isNaN(timestampSeconds) && timestampSeconds > 1000000000) {
        const now = Math.floor(Date.now() / 1000);
        return Math.max(0, timestampSeconds - now);
      }

      // Intentar parsear como número en string
      const numberValue = parseInt(expiresValue);
      if (!isNaN(numberValue)) {
        return numberValue;
      }
    }

    console.warn('Could not parse expiration time:', expiresValue);
    return undefined;
  }

  /**
   * Calcula cuándo expira un token basándose en múltiples fuentes
   */
  static calculateExpiration(
    token: string, 
    expiresIn?: number, 
    expiresAt?: string | number,
    storedAt?: number
  ): number | undefined {
    // 1. Priorizar expiresAt si está disponible
    if (expiresAt) {
      return this.normalizeExpiration(expiresAt);
    }

    // 2. Usar expiresIn si está disponible
    if (expiresIn) {
      return this.normalizeExpiration(expiresIn);
    }

    // 3. Intentar extraer del token mismo (JWT)
    const tokenInfo = TokenHandler.parseToken(token);
    if (tokenInfo.type === 'jwt' && tokenInfo.exp) {
      const now = Math.floor(Date.now() / 1000);
      return Math.max(0, tokenInfo.exp - now);
    }

    // 4. Si es un token almacenado con timestamp, calcular basándose en tiempo transcurrido
    if (storedAt && expiresIn) {
      const now = Math.floor(Date.now() / 1000);
      const timeElapsed = now - storedAt;
      return Math.max(0, expiresIn - timeElapsed);
    }

    return undefined;
  }
}
export default ExpirationHandler;