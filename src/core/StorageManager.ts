import { IndexedDBAdapter } from '../storage/IndexedDBAdapter';
import { LocalStorageAdapter } from '../storage/LocalStorageAdapter';
import { StorageAdapter } from '../storage/StorageAdapter';
import { AuthConfig, AuthTokens, AuthUser } from '../types';
import { Logger } from './Logger';
import { version as SDK_VERSION } from '../../package.json';

/**
 * Enhanced StorageManager with session persistence and automatic cleanup
 */
export class StorageManager {
  private storageAdapter: StorageAdapter;
  private config: Required<AuthConfig>['storage'];

  constructor(config: Required<AuthConfig>['storage']) {
    this.config = config;
    this.storageAdapter = this.createStorageAdapter();
  }

  private createStorageAdapter(): StorageAdapter {
    const storageType = this.config.type || 'indexedDB';

    if (storageType === 'localStorage') {
      return new LocalStorageAdapter();
    } else {
      return new IndexedDBAdapter(
        this.config.dbName,
        this.config.dbVersion,
        this.config.storeName
      );
    }
  }

  /**
   * Store tokens with enhanced metadata for session management
   */
  async storeTokens(tokens: AuthTokens): Promise<void> {
    try {
      const now = Math.floor(Date.now() / 1000);
      const tokenData = {
        ...tokens,
        storedAt: now,
        lastRefreshed: now,
        version: SDK_VERSION,
        sessionId: this.generateSessionId()
      };

      await this.storageAdapter.setItem(
        this.config.tokenKey!,
        JSON.stringify(tokenData)
      );

      // Store refresh token separately for security
      if (tokens.refreshToken) {
        await this.storageAdapter.setItem(
          this.config.refreshTokenKey!,
          tokens.refreshToken
        );
      }

      Logger.debug('Tokens stored successfully with session metadata');
    } catch (error) {
      Logger.error('Error storing tokens:', error);
      throw new Error('Failed to store authentication tokens');
    }
  }

  /**
   * Store user information with session tracking
   */
  async storeUser(user: AuthUser): Promise<void> {
    try {
      const userData = {
        ...user,
        lastUpdated: Math.floor(Date.now() / 1000),
        sessionId: await this.getCurrentSessionId()
      };

      await this.storageAdapter.setItem(
        this.config.userKey!,
        JSON.stringify(userData)
      );

      Logger.debug('User data stored successfully');
    } catch (error) {
      Logger.error('Error storing user:', error);
      throw new Error('Failed to store user information');
    }
  }

  /**
   * Retrieve stored tokens with validation and cleanup
   */
  async getStoredTokens(): Promise<AuthTokens | null> {
    try {
      const tokenDataStr = await this.storageAdapter.getItem(this.config.tokenKey!);
      
      if (!tokenDataStr) {
        return null;
      }

      let tokenData: any;
      try {
        tokenData = JSON.parse(tokenDataStr);
      } catch {
        // Handle legacy string-only tokens
        Logger.warn('Legacy token format detected, migrating...');
        const refreshToken = await this.storageAdapter.getItem(this.config.refreshTokenKey!);
        return {
          accessToken: tokenDataStr,
          refreshToken: refreshToken || undefined,
        };
      }

      // Validate token data structure
      if (!tokenData.accessToken) {
        Logger.warn('Invalid token data structure, clearing storage');
        await this.clearTokens();
        return null;
      }

      // Calculate remaining time for tokens with expiration
      if (tokenData.expiresIn && tokenData.storedAt) {
        const now = Math.floor(Date.now() / 1000);
        const timeElapsed = now - tokenData.storedAt;
        const remainingTime = Math.max(0, tokenData.expiresIn - timeElapsed);
        
        tokenData.expiresIn = remainingTime;
      }

      // Get refresh token from separate storage
      const refreshToken = await this.storageAdapter.getItem(this.config.refreshTokenKey!);
      
      return {
        accessToken: tokenData.accessToken,
        refreshToken: refreshToken || tokenData.refreshToken,
        expiresIn: tokenData.expiresIn,
        expiresAt: tokenData.expiresAt,
        tokenType: tokenData.tokenType,
      };

    } catch (error) {
      Logger.error('Error retrieving stored tokens:', error);
      await this.clearTokens(); // Clean up corrupted data
      return null;
    }
  }

  /**
   * Retrieve stored user information
   */
  async getStoredUser(): Promise<AuthUser | null> {
    try {
      const userData = await this.storageAdapter.getItem(this.config.userKey!);
      
      if (!userData) {
        return null;
      }

      try {
        const user = JSON.parse(userData);
        
        // Validate basic user structure
        if (!user.id && !user.email) {
          Logger.warn('Invalid user data structure, clearing storage');
          await this.clearUser();
          return null;
        }

        return user;
      } catch {
        Logger.warn('Corrupted user data, clearing storage');
        await this.clearUser();
        return null;
      }

    } catch (error) {
      Logger.error('Error retrieving stored user:', error);
      return null;
    }
  }

  /**
   * Get token metadata for validation and session management
   */
  async getTokenMetadata(): Promise<{
    storedAt?: number;
    lastRefreshed?: number;
    sessionId?: string;
    version?: string;
  } | null> {
    try {
      const tokenDataStr = await this.storageAdapter.getItem(this.config.tokenKey!);
      
      if (!tokenDataStr) {
        return null;
      }

      const tokenData = JSON.parse(tokenDataStr);
      
      return {
        storedAt: tokenData.storedAt,
        lastRefreshed: tokenData.lastRefreshed,
        sessionId: tokenData.sessionId,
        version: tokenData.version
      };

    } catch (error) {
      Logger.error('Error getting token metadata:', error);
      return null;
    }
  }

  /**
   * Update last refresh timestamp when tokens are renewed
   */
  async updateLastRefreshTime(): Promise<void> {
    try {
      const tokenDataStr = await this.storageAdapter.getItem(this.config.tokenKey!);
      
      if (tokenDataStr) {
        const tokenData = JSON.parse(tokenDataStr);
        tokenData.lastRefreshed = Math.floor(Date.now() / 1000);
        
        await this.storageAdapter.setItem(
          this.config.tokenKey!,
          JSON.stringify(tokenData)
        );
      }
    } catch (error) {
      Logger.error('Error updating last refresh time:', error);
    }
  }

  /**
   * Clear only token storage
   */
  async clearTokens(): Promise<void> {
    try {
      await Promise.all([
        this.storageAdapter.removeItem(this.config.tokenKey!),
        this.storageAdapter.removeItem(this.config.refreshTokenKey!)
      ]);
      Logger.debug('Tokens cleared successfully');
    } catch (error) {
      Logger.error('Error clearing tokens:', error);
    }
  }

  /**
   * Clear only user storage
   */
  async clearUser(): Promise<void> {
    try {
      await this.storageAdapter.removeItem(this.config.userKey!);
      Logger.debug('User data cleared successfully');
    } catch (error) {
      Logger.error('Error clearing user data:', error);
    }
  }

  /**
   * Clear all authentication storage
   */
  async clearAll(): Promise<void> {
    try {
      await Promise.all([
        this.clearTokens(),
        this.clearUser()
      ]);
      Logger.debug('All authentication data cleared successfully');
    } catch (error) {
      Logger.error('Error clearing all storage:', error);
    }
  }

  /**
   * Check if storage contains valid session data
   */
  async hasValidSession(): Promise<boolean> {
    try {
      const tokens = await this.getStoredTokens();
      const user = await this.getStoredUser();
      
      return !!(tokens?.accessToken && user?.id);
    } catch {
      return false;
    }
  }

  /**
   * Generate unique session ID
   */
  private generateSessionId(): string {
    return `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Get current session ID
   */
  private async getCurrentSessionId(): Promise<string | null> {
    try {
      const metadata = await this.getTokenMetadata();
      return metadata?.sessionId || null;
    } catch {
      return null;
    }
  }

  /**
   * Migrate from old storage format to new format
   */
  async migrateStorage(): Promise<void> {
    try {
      const metadata = await this.getTokenMetadata();
      
      // If no version info, this is legacy storage
      if (!metadata?.version) {
        Logger.debug('Migrating legacy storage format...');
        
        const tokens = await this.getStoredTokens();
        const user = await this.getStoredUser();
        
        if (tokens && user) {
          // Re-store with new format
          await this.storeTokens(tokens);
          await this.storeUser(user);
          Logger.debug('Storage migration completed successfully');
        }
      }
    } catch (error) {
      Logger.error('Error during storage migration:', error);
    }
  }

  /**
   * Get storage adapter for advanced operations
   */
  getAdapter(): StorageAdapter {
    return this.storageAdapter;
  }

  /**
   * Get storage configuration
   */
  getConfig(): Required<AuthConfig>['storage'] {
    return this.config;
  }
}
