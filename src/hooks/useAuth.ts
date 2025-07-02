import { useState, useEffect, useCallback } from 'react';
import { AuthSDK } from '../core/AuthSDK';
import { AuthState, LoginCredentials, RegisterData } from '../types';

export function useAuth(authSDK: AuthSDK) {
  const [authState, setAuthState] = useState<AuthState>(authSDK.getState());

  useEffect(() => {
    // Suscribirse a cambios de estado usando el nuevo método
    const unsubscribe = authSDK.onAuthStateChanged((newState: AuthState) => {
      setAuthState(newState);
    });

    // Cleanup: cancelar suscripción
    return unsubscribe;
  }, [authSDK]);

  const login = useCallback(
    async (credentials: LoginCredentials) => {
      return authSDK.login(credentials);
    },
    [authSDK]
  );

  const register = useCallback(
    async (userData: RegisterData) => {
      return authSDK.register(userData);
    },
    [authSDK]
  );

  const logout = useCallback(async () => {
    return authSDK.logout();
  }, [authSDK]);

  const refreshTokens = useCallback(async () => {
    try {
      return await authSDK.refreshTokens();
    } catch (error) {
      console.error('Error refreshing tokens:', error);
      throw error;
    }
  }, [authSDK]);

  return {
    ...authState,
    login,
    register,
    logout,
    refreshTokens,
    getAuthHeaders: authSDK.getAuthHeaders.bind(authSDK),
    getValidAccessToken: authSDK.getValidAccessToken.bind(authSDK),
  };
}