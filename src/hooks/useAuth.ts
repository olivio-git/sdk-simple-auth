import { useState, useEffect, useCallback, useRef } from 'react';
import { AuthSDK } from '../core/AuthSDK';
import { AuthState, LoginCredentials, RegisterData, AuthTokens } from '../types';

/**
 * Enhanced useAuth hook with better error handling and loading states
 */
export function useAuth(authSDK: AuthSDK) {
  const [authState, setAuthState] = useState<AuthState>(authSDK.getState());
  const [sessionInfo, setSessionInfo] = useState<{
    isValid: boolean;
    refreshAvailable: boolean;
    sessionId: string | null;
  } | null>(null);
  
  // Ref to track if component is mounted
  const isMountedRef = useRef(true);
  
  useEffect(() => {
    return () => {
      isMountedRef.current = false;
    };
  }, []);

  // Subscribe to auth state changes
  useEffect(() => {
    const unsubscribe = authSDK.onAuthStateChanged((newState: AuthState) => {
      if (isMountedRef.current) {
        setAuthState(newState);
      }
    });

    // Get initial session info
    const updateSessionInfo = async () => {
      try {
        const info = await authSDK.getSessionInfo();
        if (isMountedRef.current) {
          setSessionInfo({
            isValid: info.isValid,
            refreshAvailable: info.refreshAvailable,
            sessionId: info.sessionId,
          });
        }
      } catch (error) {
        console.error('Error getting session info:', error);
      }
    };

    updateSessionInfo();

    return unsubscribe;
  }, [authSDK]);

  // Enhanced login with better error handling
  const login = useCallback(
    async (credentials: LoginCredentials) => {
      try {
        const user = await authSDK.login(credentials);
        
        // Update session info after successful login
        const info = await authSDK.getSessionInfo();
        if (isMountedRef.current) {
          setSessionInfo({
            isValid: info.isValid,
            refreshAvailable: info.refreshAvailable,
            sessionId: info.sessionId,
          });
        }
        
        return user;
      } catch (error) {
        console.error('Login error in hook:', error);
        throw error;
      }
    },
    [authSDK]
  );

  // Enhanced register with session establishment support
  const register = useCallback(
    async (userData: RegisterData) => {
      try {
        const user = await authSDK.register(userData);
        
        // Update session info after registration (in case auto-login occurred)
        const info = await authSDK.getSessionInfo();
        if (isMountedRef.current) {
          setSessionInfo({
            isValid: info.isValid,
            refreshAvailable: info.refreshAvailable,
            sessionId: info.sessionId,
          });
        }
        
        return user;
      } catch (error) {
        console.error('Registration error in hook:', error);
        throw error;
      }
    },
    [authSDK]
  );

  // Enhanced logout with state cleanup
  const logout = useCallback(
    async () => {
      try {
        await authSDK.logout();
        
        if (isMountedRef.current) {
          setSessionInfo(null);
        }
      } catch (error) {
        console.error('Logout error in hook:', error);
        throw error;
      }
    },
    [authSDK]
  );

  // Enhanced refresh tokens with state updates
  const refreshTokens = useCallback(
    async () => {
      try {
        const tokens = await authSDK.refreshTokens();
        
        // Update session info after refresh
        const info = await authSDK.getSessionInfo();
        if (isMountedRef.current) {
          setSessionInfo({
            isValid: info.isValid,
            refreshAvailable: info.refreshAvailable,
            sessionId: info.sessionId,
          });
        }
        
        return tokens;
      } catch (error) {
        console.error('Token refresh error in hook:', error);
        throw error;
      }
    },
    [authSDK]
  );

  // Force refresh tokens
  const forceRefreshTokens = useCallback(
    async () => {
      try {
        const tokens = await authSDK.forceRefreshTokens();
        
        // Update session info after force refresh
        const info = await authSDK.getSessionInfo();
        if (isMountedRef.current) {
          setSessionInfo({
            isValid: info.isValid,
            refreshAvailable: info.refreshAvailable,
            sessionId: info.sessionId,
          });
        }
        
        return tokens;
      } catch (error) {
        console.error('Force refresh error in hook:', error);
        throw error;
      }
    },
    [authSDK]
  );

  // Get auth headers for API calls
  const getAuthHeaders = useCallback(
    async () => {
      try {
        return await authSDK.getAuthHeaders();
      } catch (error) {
        console.error('Error getting auth headers:', error);
        throw error;
      }
    },
    [authSDK]
  );

  // Get valid access token
  const getValidAccessToken = useCallback(
    async () => {
      try {
        return await authSDK.getValidAccessToken();
      } catch (error) {
        console.error('Error getting valid access token:', error);
        throw error;
      }
    },
    [authSDK]
  );

  // Check authentication status
  const checkAuthStatus = useCallback(
    async () => {
      try {
        const isAuth = await authSDK.isAuthenticated();
        const info = await authSDK.getSessionInfo();
        
        if (isMountedRef.current) {
          setSessionInfo({
            isValid: info.isValid,
            refreshAvailable: info.refreshAvailable,
            sessionId: info.sessionId,
          });
        }
        
        return isAuth;
      } catch (error) {
        console.error('Error checking auth status:', error);
        return false;
      }
    },
    [authSDK]
  );

  // Debug utilities
  const debugToken = useCallback(
    (token?: string) => {
      authSDK.debugToken(token);
    },
    [authSDK]
  );

  const debugResponse = useCallback(
    (response: any) => {
      authSDK.debugResponse(response);
    },
    [authSDK]
  );

  // Return enhanced hook interface
  return {
    // Core state
    ...authState,
    
    // Session information
    sessionInfo,
    
    // Authentication methods
    login,
    register,
    logout,
    
    // Token management
    refreshTokens,
    forceRefreshTokens,
    getAuthHeaders,
    getValidAccessToken,
    
    // Utilities
    checkAuthStatus,
    debugToken,
    debugResponse,
    
    // Computed properties
    hasValidSession: authState.isAuthenticated && sessionInfo?.isValid,
    canRefresh: sessionInfo?.refreshAvailable || false,
    sessionId: sessionInfo?.sessionId || null,
  };
}
