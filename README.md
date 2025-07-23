# 🔐 SDK Simple Auth

**Universal JavaScript/TypeScript authentication library with multi-backend support**

[![NPM Version](https://img.shields.io/npm/v/sdk-simple-auth.svg)](https://www.npmjs.com/package/sdk-simple-auth)
[![License](https://img.shields.io/npm/l/sdk-simple-auth.svg)](https://github.com/olivio-git/sdk-simple-auth/blob/main/LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg)](https://www.typescriptlang.org/)

## 🚀 **Key Features**

- ✅ **Multi-Backend**: Compatible with Node.js/Express, Laravel Sanctum, standard JWT
- ✅ **TypeScript**: Full type support and native compatibility
- ✅ **React Ready**: Hooks and components ready to use
- ✅ **Auto-detection**: Automatically detects backend type
- ✅ **Data Preservation**: Maintains all original backend data
- ✅ **Auto Refresh**: Intelligent token management
- ✅ **Flexible Storage**: LocalStorage, IndexedDB, memory
- ✅ **Zero Dependencies**: No heavy external dependencies

## 📦 **Installation**

```bash
npm install sdk-simple-auth
```

## 🎯 **Quick Start**

### **Basic Configuration**

```typescript
import { AuthSDK } from 'sdk-simple-auth';

const auth = new AuthSDK({
  authServiceUrl: 'http://localhost:3000'
});

// Login
const user = await auth.login({
  email: 'user@example.com',
  password: 'my-password'
});

console.log('Authenticated user:', user);
```

### **With React**

```jsx
import React, { useEffect, useState } from 'react';
import { AuthSDK } from 'sdk-simple-auth';

function App() {
  const [auth] = useState(() => new AuthSDK({
    authServiceUrl: process.env.REACT_APP_API_URL
  }));
  const [user, setUser] = useState(null);

  useEffect(() => {
    // Check existing session
    auth.isAuthenticated().then(isAuth => {
      if (isAuth) {
        setUser(auth.getCurrentUser());
      }
    });

    // Listen to auth changes
    const unsubscribe = auth.onAuthStateChanged((state) => {
      setUser(state.user);
    });

    return unsubscribe;
  }, [auth]);

  const handleLogin = async () => {
    try {
      const user = await auth.login({
        email: 'user@example.com',
        password: 'password'
      });
      console.log('Login successful:', user);
    } catch (error) {
      console.error('Login error:', error);
    }
  };

  return (
    <div>
      {user ? (
        <div>
          <h1>Hello, {user.name}!</h1>
          <button onClick={() => auth.logout()}>
            Logout
          </button>
        </div>
      ) : (
        <button onClick={handleLogin}>
          Login
        </button>
      )}
    </div>
  );
}
```

## 🛠️ **Backend Configuration**

### **Node.js/Express**

```typescript
import { createQuickNodeAuth } from 'sdk-simple-auth';

const auth = createQuickNodeAuth('http://localhost:3000');

// Your backend should return:
// {
//   "success": true,
//   "data": {
//     "user": { "id": 1, "email": "user@test.com", "name": "User" },
//     "token": "jwt-token-here",
//     "refreshToken": "refresh-token-here"
//   }
// }
```

### **Laravel Sanctum**

```typescript
import { createQuickSanctumAuth } from 'sdk-simple-auth';

const auth = createQuickSanctumAuth('http://localhost:8000/api');

const user = await auth.login({
  email: 'user@example.com',
  password: 'password',
  device_name: 'my-web-app'
});

// Compatible with Sanctum responses:
// {
//   "user": { "id": 1, "email": "user@test.com", "created_at": "..." },
//   "token": "1|sanctum-token-here"
// }
```

### **Standard JWT**

```typescript
import { AuthSDK } from 'sdk-simple-auth';

const auth = new AuthSDK({
  authServiceUrl: 'http://localhost:3000',
  backend: {
    type: 'jwt-standard',
    userSearchPaths: ['user', 'data.user'],
    fieldMappings: {
      userId: ['sub', 'id'],
      email: ['email'],
      name: ['name', 'username']
    }
  }
});
```

## 🔧 **Core API**

### **Authentication Methods**

```typescript
// Login
const user = await auth.login(credentials);

// Register
const user = await auth.register(userData);

// Logout
await auth.logout();

// Check authentication
const isAuth = await auth.isAuthenticated();

// Get current user
const user = auth.getCurrentUser();

// Get valid token (with auto refresh)
const token = await auth.getValidAccessToken();

// Authorization headers
const headers = await auth.getAuthHeaders();
// { Authorization: 'Bearer jwt-token' }
```

### **Token Management**

```typescript
// Manual refresh
const newTokens = await auth.refreshTokens();

// Force refresh
const tokens = await auth.forceRefreshTokens();

// Session information
const sessionInfo = await auth.getExtendedSessionInfo();
console.log({
  isValid: sessionInfo.isValid,
  expiresIn: sessionInfo.expiresIn,
  canRefresh: sessionInfo.canRefresh
});
```

### **Events and State**

```typescript
// Listen to state changes
const unsubscribe = auth.onAuthStateChanged((state) => {
  console.log('State:', state.isAuthenticated);
  console.log('User:', state.user);
  console.log('Loading:', state.loading);
  console.log('Error:', state.error);
});

// Get current state
const state = auth.getState();
```

## 🏗️ **Advanced Configuration**

### **Complete Configuration**

```typescript
const auth = new AuthSDK({
  authServiceUrl: 'http://localhost:3000',
  
  // Custom endpoints
  endpoints: {
    login: '/auth/login',
    register: '/auth/register',
    refresh: '/auth/refresh',
    logout: '/auth/logout',
    profile: '/auth/profile'
  },
  
  // Storage configuration
  storage: {
    type: 'localStorage', // 'localStorage' | 'indexedDB'
    tokenKey: 'access_token',
    refreshTokenKey: 'refresh_token',
    userKey: 'user_data'
  },
  
  // Auto refresh
  tokenRefresh: {
    enabled: true,
    bufferTime: 300, // Refresh 5 min before expiry
    maxRetries: 3
  },
  
  // Backend configuration
  backend: {
    type: 'node-express',
    userSearchPaths: ['user', 'data.user'],
    fieldMappings: {
      userId: ['id', 'user_id'],
      email: ['email'],
      name: ['name', 'full_name']
    },
    preserveOriginalData: true
  }
});
```

## 🧪 **Testing and Debugging**

### **Debug Mode**

```typescript
// Analyze your API response
auth.debugResponse(response);

// Debug current token
auth.debugToken();

// Debug complete session
auth.debugSession();

// Test data extraction
auth.testExtraction(mockResponse);
```

### **Backend Auto-detection**

```typescript
import { quickAnalyzeAndCreate } from 'sdk-simple-auth';

// Automatically analyzes response and creates SDK
const auth = quickAnalyzeAndCreate(
  responseFromYourAPI,
  'http://localhost:3000'
);
```

## 🔒 **Error Handling**

```typescript
try {
  const user = await auth.login(credentials);
} catch (error) {
  if (error.message.includes('credentials')) {
    console.log('Invalid credentials');
  } else if (error.message.includes('network')) {
    console.log('Network error');
  } else {
    console.log('Unknown error:', error.message);
  }
}

// Listen to global errors
auth.onAuthStateChanged((state) => {
  if (state.error) {
    console.error('Authentication error:', state.error);
  }
});
```

## 📱 **Compatibility**

- ✅ **Browsers**: Chrome, Firefox, Safari, Edge (ES2018+)
- ✅ **Node.js**: 14.x, 16.x, 18.x, 20.x
- ✅ **Frameworks**: React, Vue, Angular, Vanilla JS
- ✅ **Bundlers**: Webpack, Vite, Rollup, Parcel
- ✅ **TypeScript**: 4.5+

## 📚 **Documentation**

- 🚀 [Quick Start Guide](docs/getting-started.md)
- 🔧 [Advanced Configuration](docs/advanced-config.md)
- 📖 [API Reference](docs/api-reference.md)
- 🧪 [Complete Examples](examples/)
- 🐛 [Troubleshooting](docs/troubleshooting.md)

## 🤝 **Contributing**

1. Fork the repository
2. Create a branch: `git checkout -b feature/new-feature`
3. Commit: `git commit -am 'Add new feature'`
4. Push: `git push origin feature/new-feature`
5. Create Pull Request

## 📄 **License**

MIT License - see [LICENSE](LICENSE) for details.

## 🆘 **Support**

- 📚 [Complete documentation](docs/)
- 🐛 [Report bugs](https://github.com/olivio-git/sdk-simple-auth/issues)
- 💬 [Discussions](https://github.com/olivio-git/sdk-simple-auth/discussions)

---

**Developed by [olivio-git](https://github.com/olivio-git)**
