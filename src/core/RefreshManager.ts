import { AuthConfig, AuthTokens, HttpClient } from '../types';
import ExpirationHandler from './ExpirationHandler';
import { Logger } from './Logger';
import { StorageManager } from './StorageManager';
import TokenExtractor from './TokenExtractor';
import { TokenHandler } from './TokenHandler';

/**
 * Enhanced RefreshManager with automatic session renewal and retry logic
 */
export class RefreshManager {
  private config: Required<AuthConfig>;
  private storageManager: StorageManager;
  private httpClient: HttpClient;

  // Refresh state management
  private refreshTimer: ReturnType<typeof setTimeout> | null = null;
  private isRefreshing = false;
  private refreshPromise: Promise<AuthTokens> | null = null;
  private refreshAttempts = 0;
  private lastRefreshTime = 0;

  // Callbacks
  private onTokenRefresh?: (tokens: AuthTokens) => void;
  private onRefreshError?: (error: Error) => void;
  private onSessionRenewed?: (tokens: AuthTokens) => void;
  private logger: Logger;

  constructor(
    config: Required<AuthConfig>,
    storageManager: StorageManager,
    httpClient: HttpClient,
    callbacks?: {
      onTokenRefresh?: (tokens: AuthTokens) => void;
      onRefreshError?: (error: Error) => void;
      onSessionRenewed?: (tokens: AuthTokens) => void;
    },
    logger?: Logger
  ) {
    this.config = config;
    this.storageManager = storageManager;
    this.httpClient = httpClient;
    this.onTokenRefresh = callbacks?.onTokenRefresh;
    this.onRefreshError = callbacks?.onRefreshError;
    this.onSessionRenewed = callbacks?.onSessionRenewed;
    this.logger = logger ?? new Logger();
  }

  /**
   * Schedule automatic token refresh based on expiration time
   */
  scheduleTokenRefresh(tokens: AuthTokens): void {
    if (!this.config.tokenRefresh.enabled || !tokens.refreshToken) {
      this.logger.debug('Token refresh disabled or no refresh token available');
      return;
    }

    this.clearRefreshTimer();

    const expiresInSeconds = ExpirationHandler.calculateExpiration(
      tokens.accessToken,
      tokens.expiresIn,
      tokens.expiresAt
    );

    if (!expiresInSeconds) {
      this.logger.warn('No expiration info available, using default scheduling');
      // Use default scheduling based on token type
      const tokenInfo = TokenHandler.parseToken(tokens.accessToken);
      const defaultExpiration = tokenInfo.type === 'sanctum' ? 24 * 60 * 60 : 60 * 60;
      const bufferMs = this.config.tokenRefresh.bufferTime ?? 900 * 1000;
      const timeUntilRefresh = (defaultExpiration * 1000) - bufferMs;

      if (timeUntilRefresh > 0) {
        this.scheduleRefreshTimer(timeUntilRefresh);
      }
      return;
    }

    // NUEVO: Validación de tiempo mínimo para evitar refresh inmediato
    const minimumLifetime = this.config.tokenRefresh.minimumTokenLifetime || 300;
    if (expiresInSeconds < minimumLifetime) {
      this.logger.warn(`Token expires in ${expiresInSeconds}s (less than minimum ${minimumLifetime}s), using grace period`);

      // Usar período de gracia para tokens de corta duración
      const gracePeriod = (this.config.tokenRefresh.gracePeriod || 60) * 1000;
      this.scheduleRefreshTimer(gracePeriod);
      this.logger.debug(`Token refresh scheduled with grace period in ${gracePeriod / 1000}s`);
      return;
    }

    const bufferMs = this.config.tokenRefresh.bufferTime ?? 900 * 1000;
    const expiresMs = expiresInSeconds * 1000;
    const timeUntilRefresh = expiresMs - bufferMs;

    // NUEVO: Tiempo mínimo de espera para evitar refresh inmediato
    const minimumWaitTime = 30000; // 30 segundos mínimo
    const actualWaitTime = Math.max(timeUntilRefresh, minimumWaitTime);

    if (actualWaitTime > 0) {
      this.scheduleRefreshTimer(actualWaitTime);
      // console.debug(`Token refresh scheduled in ${Math.floor(actualWaitTime / 1000)}s`);
    } else {
      this.logger.warn('Token expires very soon, but skipping immediate refresh to avoid loops');
    }
  }

  /**
   * Perform token refresh with enhanced session management
   */
  async refreshTokens(): Promise<AuthTokens> {
    if (!this.config.tokenRefresh.enabled) {
      throw new Error('Token refresh is disabled');
    }

    // Prevent multiple simultaneous refreshes
    if (this.isRefreshing && this.refreshPromise) {
      this.logger.debug('Refresh already in progress, waiting for completion');
      return this.refreshPromise;
    }

    // Check rate limiting
    const now = Date.now();
    if (this.lastRefreshTime > 0 && now - this.lastRefreshTime < 5000) { // 5 second minimum between refreshes
      throw new Error('Refresh rate limit exceeded');
    }

    // Reset attempts if enough time has passed since the LAST ATTEMPT (success or failure)
    const timeSinceLastAttempt = this.lastRefreshTime > 0 ? now - this.lastRefreshTime : Infinity;
    if (timeSinceLastAttempt > 60000) { // 1 minute
      this.refreshAttempts = 0;
    }

    // Record attempt time immediately so rate limit and attempt window work correctly
    // even when the refresh fails (lastRefreshTime must not stay at 0 after a failure)
    this.lastRefreshTime = now;

    // Check retry limit
    if (this.refreshAttempts >= (this.config.tokenRefresh.maxRetries ?? 3)) {
      this.logger.error('Maximum refresh attempts exceeded, stopping automatic refresh');
      this.refreshAttempts = 0;
      throw new Error('Maximum refresh attempts exceeded');
    }

    this.isRefreshing = true;
    this.refreshAttempts++;
    this.refreshPromise = this.performRefresh();

    try {
      const tokens = await this.refreshPromise;
      this.refreshAttempts = 0; // Reset on success
      return tokens;
    } catch (error) {
      this.logger.error(`Refresh attempt ${this.refreshAttempts} failed:`, error);

      // NUEVO: Only schedule retry if we haven't exceeded max retries
      if (this.refreshAttempts < (this.config.tokenRefresh.maxRetries ?? 3)) {
        const baseDelay = Math.min(2000 * this.refreshAttempts, 30000); // Cap at 30s
        const retryDelay = baseDelay + Math.random() * 1000; // Add up to 1s jitter to prevent thundering herd
        this.logger.debug(`Scheduling retry ${this.refreshAttempts + 1}/${this.config.tokenRefresh.maxRetries ?? 3} in ${retryDelay}ms`);

        setTimeout(() => {
          // Only retry if we still have a refresh token
          this.storageManager.getStoredTokens().then(tokens => {
            if (tokens?.refreshToken) {
              this.refreshTokens().catch((err) => this.logger.error('Retry refresh failed:', err));
            } else {
              this.logger.warn('No refresh token available for retry, stopping attempts');
              this.refreshAttempts = 0;
            }
          });
        }, retryDelay);
      } else {
        this.logger.error('Max retries exceeded, stopping refresh attempts');
        this.refreshAttempts = 0;
        this.onRefreshError?.(error as Error);
      }

      throw error;
    } finally {
      this.isRefreshing = false;
      this.refreshPromise = null;
    }
  }

  /**
   * Check if token should be refreshed based on expiration
   */
  shouldRefreshToken(token: string): boolean {
    if (!this.config.tokenRefresh.enabled) {
      return false;
    }

    const tokenInfo = TokenHandler.parseToken(token);

    if (tokenInfo.type === 'jwt' && tokenInfo.exp) {
      const now = Math.floor(Date.now() / 1000);
      const timeUntilExpiry = tokenInfo.exp - now;
      return timeUntilExpiry < (this.config.tokenRefresh.bufferTime ?? 900);
    }

    // For non-JWT tokens, we can't determine synchronously without stored metadata
    // Return false to avoid automatic refresh, manual refresh can still be triggered
    return false;
  }

  /**
   * Async version to check if token should be refreshed (for non-JWT tokens)
   */
  async shouldRefreshTokenAsync(token: string): Promise<boolean> {
    if (!this.config.tokenRefresh.enabled) {
      return false;
    }

    const tokenInfo = TokenHandler.parseToken(token);

    if (tokenInfo.type === 'jwt' && tokenInfo.exp) {
      const now = Math.floor(Date.now() / 1000);
      const timeUntilExpiry = tokenInfo.exp - now;
      return timeUntilExpiry < (this.config.tokenRefresh.bufferTime ?? 900);
    }

    // For non-JWT tokens, check stored metadata
    return this.shouldRefreshBasedOnMetadata();
  }

  /**
   * Clear refresh timer
   */
  clearRefreshTimer(): void {
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
      this.refreshTimer = null;
      this.logger.debug('Refresh timer cleared');
    }
  }

  /**
   * Get refresh status information
   */
  getRefreshStatus(): {
    isRefreshing: boolean;
    refreshAttempts: number;
    lastRefreshTime: number;
    nextRefreshScheduled: boolean;
  } {
    return {
      isRefreshing: this.isRefreshing,
      refreshAttempts: this.refreshAttempts,
      lastRefreshTime: this.lastRefreshTime,
      nextRefreshScheduled: this.refreshTimer !== null
    };
  }

  /**
   * Force refresh regardless of timing
   */
  async forceRefresh(): Promise<AuthTokens> {
    this.clearRefreshTimer();
    this.refreshAttempts = 0; // Reset attempts for forced refresh
    return this.refreshTokens();
  }

  /**
   * Detect if error is an authentication error (401, 403, etc)
   */
  private isAuthenticationError(error: any): boolean {
    // Check for Axios error format
    if (error?.response?.status) {
      const status = error.response.status;
      return status === 401 || status === 403;
    }

    // Check for Fetch error (our default httpClient)
    if (error?.message) {
      const msg = error.message.toLowerCase();
      return msg.includes('401') ||
             msg.includes('403') ||
             msg.includes('unauthorized') ||
             msg.includes('unauthenticated');
    }

    return false;
  }

  /**
   * Private method to perform the actual refresh
   */
  private async performRefresh(): Promise<AuthTokens> {
    const storedTokens = await this.storageManager.getStoredTokens();
    const refreshToken = storedTokens?.refreshToken;

    if (!refreshToken) {
      throw new Error('No refresh token available');
    }

    this.logger.debug('Performing token refresh...');

    try {
      const url = `${this.config.authServiceUrl}${this.config.endpoints.refresh}`;
      const tokenInfo = TokenHandler.parseToken(refreshToken);

      this.logger.debug('Refresh token info:', {
        type: tokenInfo.type,
        url,
        hasRefreshToken: !!refreshToken,
        refreshTokenLength: refreshToken.length
      });

      let response: any;

      if (tokenInfo.type === 'sanctum') {
        // For Sanctum tokens, send in Authorization header
        this.logger.debug('Using Sanctum refresh method (Authorization header)');
        response = await this.httpClient.post(url, {
          refresh_token: refreshToken,
          refreshToken: refreshToken
        }, {
          headers: {
            Authorization: `Bearer ${refreshToken}`
          }
        });
      } else {
        // For JWT and other tokens, send in body
        this.logger.debug('Using JWT refresh method (body only)');
        response = await this.httpClient.post(url, {
          refresh_token: refreshToken,
          refreshToken: refreshToken
        });
      }

      const newTokens = this.processRefreshResponse(response, refreshToken);

      // Store updated tokens with session renewal
      await this.storageManager.storeTokens(newTokens);
      await this.storageManager.updateLastRefreshTime();

      // Schedule next refresh
      this.scheduleTokenRefresh(newTokens);

      // Notify callbacks
      this.onTokenRefresh?.(newTokens);
      this.onSessionRenewed?.(newTokens);

      this.logger.debug('Token refresh completed successfully');

      return newTokens;

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Token refresh failed';
      this.logger.error('Token refresh failed:', errorMessage);

      // Detectar si es un error de autenticación (401, 403)
      const isAuthError = this.isAuthenticationError(error);

      // Si el servidor rechaza el refresh token, o la respuesta tiene formato inválido
      // (no retryable — el mismo endpoint siempre devolverá el mismo formato),
      // limpiar storage y detener reintentos
      const lowerMessage = errorMessage.toLowerCase();
      const isNonRetryable =
        isAuthError ||
        lowerMessage.includes('invalid') ||
        lowerMessage.includes('expired') ||
        lowerMessage.includes('unauthorized') ||
        lowerMessage.includes('unauthenticated') ||
        lowerMessage.includes('inválidos') ||
        lowerMessage.includes('requerido');

      if (isNonRetryable) {
        this.logger.warn('Non-retryable refresh error, clearing authentication data');
        await this.storageManager.clearAll();
        // Max out attempts to prevent any scheduled retry from firing
        this.refreshAttempts = this.config.tokenRefresh.maxRetries ?? 3;
      }

      this.onRefreshError?.(error instanceof Error ? error : new Error(errorMessage));
      throw error;
    }
  }

  /**
   * Process refresh response and extract tokens
   */
  private processRefreshResponse(response: any, originalRefreshToken: string): AuthTokens {
    try {
      const tokens = TokenExtractor.extractTokens(response);

      // Preserve original refresh token if no new one is provided
      if (!tokens.refreshToken) {
        tokens.refreshToken = originalRefreshToken;
        this.logger.debug('Using original refresh token (no new token provided)');
      }

      return tokens;

    } catch (error) {
      this.logger.error('Error processing refresh response:', error);
      throw new Error('Invalid refresh response format');
    }
  }

  /**
   * Schedule refresh timer with error handling
   */
  private scheduleRefreshTimer(timeUntilRefresh: number): void {
    try {
      this.refreshTimer = setTimeout(() => {
        this.logger.debug('Automatic refresh triggered by timer');
        this.refreshTokens().catch((error) => {
          this.logger.error('Automatic refresh failed:', error);
          this.onRefreshError?.(error);
        });
      }, timeUntilRefresh);
    } catch (error) {
      this.logger.error('Error scheduling refresh timer:', error);
    }
  }

  /**
   * Check if token should be refreshed based on stored metadata
   */
  private async shouldRefreshBasedOnMetadata(): Promise<boolean> {
    try {
      const metadata = await this.storageManager.getTokenMetadata();
      const storedTokens = await this.storageManager.getStoredTokens();

      if (!metadata?.storedAt || !storedTokens?.expiresIn) {
        return false;
      }

      const now = Math.floor(Date.now() / 1000);
      const timeElapsed = now - metadata.storedAt;
      const timeUntilExpiry = storedTokens.expiresIn - timeElapsed;

      return timeUntilExpiry < (this.config.tokenRefresh.bufferTime ?? 900);

    } catch (error) {
      this.logger.error('Error checking refresh metadata:', error);
      return false;
    }
  }

  /**
   * Reset refresh state (useful for logout)
   */
  reset(): void {
    this.clearRefreshTimer();
    this.isRefreshing = false;
    this.refreshPromise = null;
    this.refreshAttempts = 0;
    this.lastRefreshTime = 0;
    this.logger.debug('Refresh manager reset');
  }

  /**
   * Check if refresh is currently possible
   */
  async canRefresh(): Promise<boolean> {
    try {
      const storedTokens = await this.storageManager.getStoredTokens();
      return !!(
        this.config.tokenRefresh.enabled &&
        storedTokens?.refreshToken &&
        !this.isRefreshing
      );
    } catch {
      return false;
    }
  }
}
