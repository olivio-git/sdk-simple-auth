# AuthSDK

```
 █████╗ ██╗   ██╗████████╗██╗  ██╗    ███████╗██████╗ ██╗  ██╗
██╔══██╗██║   ██║╚══██╔══╝██║  ██║    ██╔════╝██╔══██╗██║ ██╔╝
███████║██║   ██║   ██║   ███████║    ███████╗██║  ██║█████╔╝ 
██╔══██║██║   ██║   ██║   ██╔══██║    ╚════██║██║  ██║██╔═██╗ 
██║  ██║╚██████╔╝   ██║   ██║  ██║    ███████║██████╔╝██║  ██╗
╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝    ╚══════╝╚═════╝ ╚═╝  ╚═╝
```

A comprehensive, lightweight authentication SDK for modern web applications with automatic token refresh, TypeScript support, and React integration.

## 🚀 Features

- **🔐 Complete Authentication Flow**: Login, register, logout, and profile management
- **🔄 Automatic Token Refresh**: Smart token renewal with configurable buffer time
- **💾 Persistent Storage**: Automatic localStorage integration with customizable keys
- **⚡ React Integration**: Built-in React hooks for seamless state management
- **🛡️ TypeScript Support**: Fully typed for better developer experience
- **🔧 Configurable**: Flexible configuration for different backend implementations
- **📦 Lightweight**: Minimal dependencies, maximum performance
- **🌐 Universal**: Works in browser and Node.js environments

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
  authServiceUrl: 'https://your-api.com'
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

// Logout
await authSDK.logout();
```

### React Integration

```jsx
import React from 'react';
import { AuthSDK } from 'sdk-simple-auth';

const authSDK = new AuthSDK({
  authServiceUrl: 'https://your-api.com'
});

function LoginComponent() {
  const [user, setUser] = React.useState(authSDK.getCurrentUser());
  const [loading, setLoading] = React.useState(false);

  React.useEffect(() => {
    // Listen to auth state changes
    const unsubscribe = authSDK.onAuthStateChanged((state) => {
      setUser(state.user);
      setLoading(state.loading);
    });

    return unsubscribe;
  }, []);

  const handleLogin = async () => {
    try {
      await authSDK.login({
        email: 'user@example.com',
        password: 'password123'
      });
    } catch (error) {
      console.error('Login failed:', error);
    }
  };

  if (loading) return <div>Loading...</div>;
  
  return user ? (
    <div>Welcome, {user.email}!</div>
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
    tokenKey: 'auth_access_token',       // localStorage key for access token
    refreshTokenKey: 'auth_refresh_token', // localStorage key for refresh token
    userKey: 'auth_user'                 // localStorage key for user data
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

## 📚 API Reference

### AuthSDK Methods

#### `login(credentials: LoginCredentials): Promise<AuthUser>`
Authenticate user with email/username and password.

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
  email: string;
  name?: string;
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
```

## 🔒 Security Features

- **Automatic Token Refresh**: Prevents token expiration issues
- **Secure Storage**: Uses localStorage with configurable keys
- **Token Validation**: Validates JWT tokens before use
- **Error Handling**: Comprehensive error handling and recovery
- **Memory Management**: Prevents memory leaks with proper cleanup

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

```javascript
// Mock the AuthSDK for testing
const mockAuthSDK = {
  login: jest.fn(),
  logout: jest.fn(),
  isAuthenticated: jest.fn(() => true),
  getCurrentUser: jest.fn(() => ({ id: '1', email: 'test@example.com' }))
};
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

### v1.0.1
- Initial release
- Complete authentication flow
- Automatic token refresh
- React integration
- TypeScript support

---

Made with ❤️ by [olivio-git](https://github.com/olivio-git)