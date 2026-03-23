import { AuthState } from '../types';
import { TokenHandler } from './TokenHandler';
import { TokenExtractor } from './TokenManager';

type RefreshStatus = {
  isRefreshing: boolean;
  refreshAttempts: number;
  lastRefreshTime: number;
  nextRefreshScheduled: boolean;
};

/**
 * Encapsulates all debug/introspection methods for AuthSDK.
 * Keeps AuthSDK surface area focused on auth operations.
 * All methods are no-ops when debug=false.
 */
export class AuthDebugger {
  private readonly isEnabled: boolean;
  private readonly getState: () => AuthState;
  private readonly getRefreshStatus: () => RefreshStatus;

  constructor(
    isEnabled: boolean,
    getState: () => AuthState,
    getRefreshStatus: () => RefreshStatus
  ) {
    this.isEnabled = isEnabled;
    this.getState = getState;
    this.getRefreshStatus = getRefreshStatus;
  }

  debugToken(token?: string): void {
    if (!this.isEnabled) return;

    const targetToken = token || this.getState().tokens?.accessToken;
    if (!targetToken) return;

    console.group('🔍 Token Debug Information');
    const tokenInfo = TokenHandler.parseToken(targetToken);
    console.log('Token type:', tokenInfo.type);
    console.log('Token info:', tokenInfo);

    if (tokenInfo.type === 'jwt' && tokenInfo.payload) {
      console.log('JWT Payload:', tokenInfo.payload);
      if (tokenInfo.exp) {
        const expiryDate = new Date(tokenInfo.exp * 1000);
        const now = new Date();
        const timeLeft = Math.max(0, Math.floor((expiryDate.getTime() - now.getTime()) / 1000));
        console.log('Expires at:', expiryDate.toISOString());
        console.log('Time left:', `${Math.floor(timeLeft / 60)}m ${timeLeft % 60}s`);
      }
    }

    console.log('Refresh status:', this.getRefreshStatus());
    console.groupEnd();
  }

  debugResponse(response: any): void {
    if (!this.isEnabled) return;

    console.group('🔍 API Response Debug');
    TokenExtractor.debugResponse(response);

    try {
      const tokens = TokenExtractor.extractTokens(response);
      console.log('✅ Extracted tokens:', tokens);
    } catch (error) {
      console.log('❌ Token extraction failed:', error);
    }

    try {
      const user = TokenExtractor.extractUser(response);
      console.log('✅ Extracted user:', user);
    } catch (error) {
      console.log('❌ User extraction failed:', error);
    }

    console.groupEnd();
  }

  testExtraction(response: any): void {
    if (!this.isEnabled) return;

    console.group('🧪 Testing Token and User Extraction');

    try {
      console.log('📥 Original response:', response);

      console.log('🔑 Testing token extraction...');
      const tokens = TokenExtractor.extractTokens(response);
      console.log('✅ Extracted tokens:', tokens);

      console.log('👤 Testing user extraction...');
      const user = TokenExtractor.extractUser(response);
      console.log('✅ Extracted user:', user);

      console.log('🎉 Extraction test completed successfully!');
    } catch (error) {
      console.error('❌ Extraction test failed:', error);
    }

    console.groupEnd();
  }

  debugSession(): void {
    if (!this.isEnabled) return;

    const state = this.getState();

    console.group('🔍 Enhanced Session Debug');
    console.log('📊 Current State:', state);

    if (state.tokens?.accessToken) {
      this.debugToken(state.tokens.accessToken);
    }

    if (state.user?._originalUserResponse) {
      console.log('📥 Original User Response:', state.user._originalUserResponse);
    }

    console.log('🔄 Refresh Status:', this.getRefreshStatus());
    console.groupEnd();
  }
}
