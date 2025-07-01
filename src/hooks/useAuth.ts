import { useState, useEffect, useCallback } from 'react';
import { AuthSDK } from '../core/AuthSDK';
import { AuthState, LoginCredentials, RegisterData } from '../types';

export function useAuth(authSDK: AuthSDK) {
  const [authState, setAuthState] = useState<AuthState>(authSDK.getState());

  useEffect(() => {
    // Suscribirse a cambios de estado
    const unsubscribe = (newState: AuthState) => {
      setAuthState(newState);
    };

    // Configurar callback
    const currentCallbacks = authSDK['callbacks'];
    const originalCallback = currentCallbacks.onAuthStateChanged;
    
    currentCallbacks.onAuthStateChanged = (state) => {
      unsubscribe(state);
      originalCallback?.(state);
    };

    // Cleanup
    return () => {
      currentCallbacks.onAuthStateChanged = originalCallback;
    };
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

  return {
    ...authState,
    login,
    register,
    logout,
    getAuthHeaders: authSDK.getAuthHeaders.bind(authSDK),
    getValidAccessToken: authSDK.getValidAccessToken.bind(authSDK),
  };
}