# AuthSDK

```
 █████╗ ██╗   ██╗████████╗██╗  ██╗    ███████╗██████╗ ██╗  ██╗
██╔══██╗██║   ██║╚══██╔══╝██║  ██║    ██╔════╝██╔══██╗██║ ██╔╝
███████║██║   ██║   ██║   ███████║    ███████╗██║  ██║█████╔╝ 
██╔══██║██║   ██║   ██║   ██╔══██║    ╚════██║██║  ██║██╔═██╗ 
██║  ██║╚██████╔╝   ██║   ██║  ██║    ███████║██████╔╝██║  ██╗
╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝    ╚══════╝╚═════╝ ╚═╝  ╚═╝
```

A comprehensive, lightweight authentication SDK for modern web applications with automatic token refresh, TypeScript support, React integration, and flexible storage options.

## 🚀 Features

- **🔐 Complete Authentication Flow**: Login, register, logout, and profile management
- **🔄 Automatic Token Refresh**: Smart token renewal with configurable buffer time
- **💾 Flexible Storage**: Support for both localStorage and IndexedDB with custom adapters
- **⚡ React Integration**: Built-in React hooks for seamless state management
- **🛡️ TypeScript Support**: Fully typed for better developer experience
- **🔧 Configurable**: Flexible configuration for different backend implementations
- **📦 Lightweight**: Minimal dependencies, maximum performance
- **🌐 Universal**: Works in browser and Node.js environments
- **🎯 State Management**: Observable state changes with subscription support

## 📦 Installation

```bash
npm install sdk-simple-auth
```

```bash
yarn add sdk-simple-auth
```

```bash
pnpm add sdk-simple-auth
```

## 🔧 Quick Start

### Basic Usage

```javascript
import { AuthSDK } from 'sdk-simple-auth';

const authSDK = new AuthSDK({
  authServiceUrl: 'https://your-api.com',
  storage: {
    type: 'localStorage', // or 'indexedDB'
  }
});

// Login
const user = await authSDK.login({
  email: 'user@example.com',
  password: 'password123'
});

// Check authentication status
const isAuthenticated = authSDK.isAuthenticated();

// Get current user
const currentUser = authSDK.getCurrentUser();

// Subscribe to auth state changes
const unsubscribe = authSDK.onAuthStateChanged((state) => {
  console.log('Auth state changed:', state);
});

// Logout
await authSDK.logout();
```

### React Integration with useAuth Hook

```jsx
import React from 'react';
import { AuthSDK, useAuth } from 'sdk-simple-auth';

const authSDK = new AuthSDK({
  authServiceUrl: 'https://your-api.com',
  storage: {
    type: 'localStorage',
  }
});

function AuthProvider({ children }) {
  return (
    <AuthContext.Provider value={authSDK}>
      {children}
    </AuthContext.Provider>
  );
}

function LoginComponent() {
  const {
    isAuthenticated,
    user,
    loading,
    error,
    login,
    logout
  } = useAuth(authSDK);

  const handleLogin = async () => {
    try {
      await login({
        email: 'user@example.com',
        password: 'password123'
      });
    } catch (error) {
      console.error('Login failed:', error);
    }
  };

  if (loading) return <div>Loading...</div>;
  
  return isAuthenticated ? (
    <div>
      <p>Welcome, {user?.email}!</p>
      <button onClick={logout}>Logout</button>
    </div>
  ) : (
    <button onClick={handleLogin}>Login</button>
  );
}
```

## ⚙️ Configuration

### Complete Configuration Options

```javascript
const authSDK = new AuthSDK({
  // Required: Your authentication service base URL
  authServiceUrl: 'https://your-api.com',
  
  // Optional: API endpoints configuration
  endpoints: {
    login: '/auth/login',           // POST endpoint for login
    register: '/auth/register',     // POST endpoint for registration
    refresh: '/auth/refreshToken',  // POST endpoint for token refresh
    logout: '/auth/logout',         // POST endpoint for logout
    profile: '/auth/profile'        // GET endpoint for user profile
  },
  
  // Optional: Storage configuration
  storage: {
    type: 'localStorage',               // 'localStorage' or 'indexedDB'
    // IndexedDB specific options
    dbName: 'AuthSDK',                  // IndexedDB database name
    dbVersion: 1,                       // IndexedDB database version
    storeName: 'auth_data',             // IndexedDB store name
    // Storage keys for both localStorage and IndexedDB
    tokenKey: 'auth_access_token',      // Key for access token
    refreshTokenKey: 'auth_refresh_token', // Key for refresh token
    userKey: 'auth_user'                // Key for user data
  },
  
  // Optional: Token refresh configuration
  tokenRefresh: {
    enabled: true,        // Enable automatic token refresh
    bufferTime: 900,      // Refresh token 15 minutes before expiry (in seconds)
    maxRetries: 3         // Maximum refresh retry attempts
  },
  
  // Optional: Custom HTTP client
  httpClient: customHttpClient
}, {
  // Optional: Event callbacks
  onLogin: (user, tokens) => {
    console.log('User logged in:', user);
  },
  onLogout: () => {
    console.log('User logged out');
  },
  onTokenRefresh: (tokens) => {
    console.log('Tokens refreshed');
  },
  onAuthStateChanged: (state) => {
    console.log('Auth state changed:', state);
  },
  onError: (error) => {
    console.error('Auth error:', error);
  }
});
```

### Storage Adapters

The SDK supports two storage adapters:

#### LocalStorage Adapter (Default)
```javascript
const authSDK = new AuthSDK({
  authServiceUrl: 'https://your-api.com',
  storage: {
    type: 'localStorage',
    tokenKey: 'my_access_token',
    refreshTokenKey: 'my_refresh_token',
    userKey: 'my_user_data'
  }
});
```

#### IndexedDB Adapter
```javascript
const authSDK = new AuthSDK({
  authServiceUrl: 'https://your-api.com',
  storage: {
    type: 'indexedDB',
    dbName: 'MyAppAuth',
    dbVersion: 1,
    storeName: 'auth_storage',
    tokenKey: 'access_token',
    refreshTokenKey: 'refresh_token',
    userKey: 'user_data'
  }
});
```

## 📚 API Reference

### AuthSDK Methods

#### `login(credentials: LoginCredentials): Promise<AuthUser>`
Authenticate user with email and password.

```javascript
const user = await authSDK.login({
  email: 'user@example.com',
  password: 'password123'
});
```

#### `register(userData: RegisterData): Promise<AuthUser>`
Register a new user account.

```javascript
const user = await authSDK.register({
  email: 'user@example.com',
  password: 'password123',
  name: 'John Doe'
});
```

#### `logout(): Promise<void>`
Log out the current user and clear all stored data.

```javascript
await authSDK.logout();
```

#### `refreshTokens(): Promise<AuthTokens>`
Manually refresh authentication tokens.

```javascript
const tokens = await authSDK.refreshTokens();
```

#### `onAuthStateChanged(listener: StateChangeListener): () => void`
Subscribe to authentication state changes.

```javascript
const unsubscribe = authSDK.onAuthStateChanged((state) => {
  console.log('Auth state:', state);
  console.log('Is authenticated:', state.isAuthenticated);
  console.log('Current user:', state.user);
  console.log('Loading:', state.loading);
  console.log('Error:', state.error);
});

// Unsubscribe when no longer needed
unsubscribe();
```

#### `getState(): AuthState`
Get the current authentication state.

```javascript
const state = authSDK.getState();
console.log(state.isAuthenticated, state.user, state.loading);
```

#### `getCurrentUser(): AuthUser | null`
Get the currently authenticated user.

```javascript
const user = authSDK.getCurrentUser();
```

#### `getAccessToken(): string | null`
Get the current access token.

```javascript
const token = authSDK.getAccessToken();
```

#### `getRefreshToken(): string | null`
Get the current refresh token.

```javascript
const refreshToken = authSDK.getRefreshToken();
```

#### `isAuthenticated(): boolean`
Check if user is currently authenticated.

```javascript
const isAuth = authSDK.isAuthenticated();
```

#### `getValidAccessToken(): Promise<string | null>`
Get a valid access token, refreshing if necessary.

```javascript
const token = await authSDK.getValidAccessToken();
```

#### `getAuthHeaders(): Promise<Record<string, string>>`
Get authorization headers for API requests.

```javascript
const headers = await authSDK.getAuthHeaders();
// Returns: { Authorization: 'Bearer <token>' }
```

### useAuth Hook

The `useAuth` hook provides a convenient way to integrate authentication into React components.

```typescript
const {
  isAuthenticated,
  user,
  tokens,
  loading,
  error,
  login,
  register,
  logout,
  refreshTokens,
  getAuthHeaders,
  getValidAccessToken
} = useAuth(authSDK);
```

#### Hook Return Values

- `isAuthenticated`: Boolean indicating if user is authenticated
- `user`: Current user object or null
- `tokens`: Current tokens object or null
- `loading`: Boolean indicating if an auth operation is in progress
- `error`: Error message string or null
- `login`: Function to login with credentials
- `register`: Function to register a new user
- `logout`: Function to logout the current user
- `refreshTokens`: Function to manually refresh tokens
- `getAuthHeaders`: Function to get authorization headers
- `getValidAccessToken`: Function to get a valid access token

### TypeScript Types

```typescript
interface AuthConfig {
  authServiceUrl: string;
  endpoints?: {
    login?: string;
    register?: string;
    refresh?: string;
    logout?: string;
    profile?: string;
  };
  storage?: {
    type?: 'localStorage' | 'indexedDB';
    dbName?: string;
    dbVersion?: number;
    storeName?: string;
    tokenKey?: string;
    refreshTokenKey?: string;
    userKey?: string;
  };
  tokenRefresh?: {
    enabled?: boolean;
    bufferTime?: number;
    maxRetries?: number;
  };
  httpClient?: HttpClient;
}

interface AuthUser {
  id: string;
  email?: string;
  name?: string;
  roles?: string[];
  [key: string]: any;
}

interface AuthTokens {
  accessToken: string;
  refreshToken?: string;
  expiresIn?: number;
  tokenType?: string;
}

interface AuthState {
  isAuthenticated: boolean;
  user: AuthUser | null;
  tokens: AuthTokens | null;
  loading: boolean;
  error: string | null;
}

interface LoginCredentials {
  email: string;
  password: string;
}

interface RegisterData {
  email: string;
  password: string;
  name?: string;
  [key: string]: any;
}

interface StorageAdapter {
  setItem(key: string, value: string): Promise<void>;
  getItem(key: string): Promise<string | null>;
  removeItem(key: string): Promise<void>;
  clear(): Promise<void>;
}
```

## 🔒 Security Features

- **Automatic Token Refresh**: Prevents token expiration issues
- **Flexible Storage**: Choose between localStorage and IndexedDB
- **Token Validation**: Validates JWT tokens before use
- **Error Handling**: Comprehensive error handling and recovery
- **Memory Management**: Prevents memory leaks with proper cleanup
- **State Synchronization**: Consistent state across components

## 🌐 Backend Integration

### Expected API Response Format

#### Login/Register Response
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 3600,
  "token_type": "Bearer",
  "user": {
    "id": "123",
    "email": "user@example.com",
    "name": "John Doe"
  }
}
```

#### Token Refresh Response
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 3600,
  "token_type": "Bearer"
}
```

## 🧪 Testing

### Basic Test Setup

```javascript
import { AuthSDK } from 'sdk-simple-auth';

describe('AuthSDK', () => {
  let authSDK;

  beforeEach(() => {
    authSDK = new AuthSDK({
      authServiceUrl: 'http://localhost:3000',
      storage: {
        type: 'localStorage',
        tokenKey: 'test_token',
        refreshTokenKey: 'test_refresh_token',
        userKey: 'test_user',
      },
      tokenRefresh: {
        enabled: true,
        bufferTime: 30,
      }
    });
    
    jest.clearAllMocks();
    localStorage.clear();
  });

  test('should initialize correctly', () => {
    expect(authSDK).toBeDefined();
    expect(authSDK.isAuthenticated()).toBe(false);
  });

  test('should login successfully', async () => {
    const mockResponse = {
      access_token: 'mock_access_token',
      refresh_token: 'mock_refresh_token',
      user: { id: '1', email: 'user@example.com' },
    };

    global.fetch = jest.fn().mockResolvedValueOnce({
      ok: true,
      json: async () => mockResponse,
    });

    const user = await authSDK.login({
      email: 'user@example.com',
      password: 'password123'
    });

    expect(user.email).toBe('user@example.com');
    expect(authSDK.isAuthenticated()).toBe(true);
  });
});
```

### Testing with React Hook

```javascript
import { renderHook, act } from '@testing-library/react';
import { useAuth } from 'sdk-simple-auth';

test('useAuth hook works correctly', async () => {
  const { result } = renderHook(() => useAuth(authSDK));

  expect(result.current.isAuthenticated).toBe(false);

  await act(async () => {
    await result.current.login({
      email: 'user@example.com',
      password: 'password123'
    });
  });

  expect(result.current.isAuthenticated).toBe(true);
});
```

## 📖 Migration Guide

### From v1.0.3 to v1.1.0

#### New Features
- Added `onAuthStateChanged` method for state subscriptions
- Added `useAuth` React hook
- Added flexible storage adapters (localStorage and IndexedDB)
- Added `getRefreshToken` method

#### Breaking Changes
- Storage configuration structure changed to support multiple adapters
- State change callbacks now use the subscription model

#### Migration Steps

1. **Update storage configuration**:
```javascript
// Old
const authSDK = new AuthSDK({
  authServiceUrl: 'https://api.example.com',
  // storage keys were direct properties
});

// New
const authSDK = new AuthSDK({
  authServiceUrl: 'https://api.example.com',
  storage: {
    type: 'localStorage', // or 'indexedDB'
    tokenKey: 'auth_access_token',
    refreshTokenKey: 'auth_refresh_token',
    userKey: 'auth_user'
  }
});
```

2. **Update state change handling**:
```javascript
// Old - using callbacks
const authSDK = new AuthSDK(config, {
  onAuthStateChanged: (state) => {
    console.log('State changed:', state);
  }
});

// New - using subscription (recommended)
const unsubscribe = authSDK.onAuthStateChanged((state) => {
  console.log('State changed:', state);
});
```

3. **Use the new React hook**:
```javascript
// Old - manual state management
const [user, setUser] = useState(null);
const [loading, setLoading] = useState(false);

useEffect(() => {
  const unsubscribe = authSDK.onAuthStateChanged((state) => {
    setUser(state.user);
    setLoading(state.loading);
  });
  return unsubscribe;
}, []);

// New - using useAuth hook
const { user, loading, login, logout } = useAuth(authSDK);
```

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🐛 Issues

If you encounter any issues, please file them on our [GitHub Issues](https://github.com/olivio-git/auth-sdk/issues) page.

## 📖 Changelog

### v1.1.3
- Added `onAuthStateChanged` method for state subscriptions
- Added `useAuth` React hook for seamless React integration
- Added flexible storage adapters (localStorage and IndexedDB)
- Added `getRefreshToken` method
- Improved state management and synchronization
- Enhanced TypeScript support

### v1.0.0
- Initial release
- Complete authentication flow
- Automatic token refresh
- Basic React integration
- TypeScript support

---

Made with ❤️ by [olivio-git](https://github.com/olivio-git)