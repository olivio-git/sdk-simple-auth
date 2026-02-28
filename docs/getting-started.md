# 🚀 Quick Start Guide - SDK Simple Auth

## 📦 **Installation**

```bash
npm install sdk-simple-auth
```

## 🎯 **Setup in 3 Steps**

### **Step 1: Import and Configure**

```typescript
import { AuthSDK } from 'sdk-simple-auth';

const auth = new AuthSDK({
  authServiceUrl: 'http://localhost:3000' // Your authentication API
});
```

### **Step 2: User Login**

```typescript
async function loginUser() {
  try {
    const user = await auth.login({
      email: 'user@example.com',
      password: 'my-password'
    });
    
    console.log('✅ User authenticated:', user);
    // user = { id: 1, email: '...', name: '...', ... }
    
  } catch (error) {
    console.error('❌ Login error:', error.message);
  }
}
```

### **Step 3: Check State**

```typescript
// Check if authenticated
const isAuthenticated = await auth.isAuthenticated();

if (isAuthenticated) {
  const user = auth.getCurrentUser();
  console.log('Current user:', user);
} else {
  console.log('No active session');
}
```

## 🔧 **Configuration by Backend Type**

### **🟢 Node.js + Express**

If your backend is Node.js with Express and responds like this:

```json
{
  "success": true,
  "data": {
    "user": { "id": 1, "email": "user@test.com", "name": "User" },
    "token": "eyJhbGciOiJIUzI1NiIs...",
    "refreshToken": "refresh-token-here"
  }
}
```

**Use:**
```typescript
import { createQuickNodeAuth } from 'sdk-simple-auth';

const auth = createQuickNodeAuth('http://localhost:3000');
```

### **🟠 Laravel + Sanctum**

If your backend is Laravel with Sanctum:

```json
{
  "user": {
    "id": 1,
    "email": "user@test.com",
    "email_verified_at": "2025-01-01T00:00:00.000000Z",
    "created_at": "2025-01-01T00:00:00.000000Z"
  },
  "token": "1|sanctum-token-here"
}
```

**Use:**
```typescript
import { createQuickSanctumAuth } from 'sdk-simple-auth';

const auth = createQuickSanctumAuth('http://localhost:8000/api');

// Login with device_name (required by Sanctum)
const user = await auth.login({
  email: 'user@example.com',
  password: 'password',
  device_name: 'my-web-app'
});
```

### **🔵 Pure JWT**

If your backend returns standard JWT:

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "user": { "sub": "1", "email": "user@test.com", "name": "User" }
}
```

**Use:**
```typescript
import { AuthSDK } from 'sdk-simple-auth';

const auth = new AuthSDK({
  authServiceUrl: 'http://localhost:3000',
  backend: {
    type: 'jwt-standard'
  }
});
```

## ⚛️ **React Integration**

### **Basic Component**

```jsx
import React, { useState, useEffect } from 'react';
import { AuthSDK } from 'sdk-simple-auth';

// Create SDK instance (outside component)
const auth = new AuthSDK({
  authServiceUrl: process.env.REACT_APP_API_URL
});

function AuthExample() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Check existing session
    checkExistingSession();
    
    // Listen to state changes
    const unsubscribe = auth.onAuthStateChanged((state) => {
      setUser(state.user);
      setLoading(state.loading);
    });

    return unsubscribe; // Cleanup
  }, []);

  const checkExistingSession = async () => {
    const isAuth = await auth.isAuthenticated();
    if (isAuth) {
      setUser(auth.getCurrentUser());
    }
    setLoading(false);
  };

  const handleLogin = async () => {
    setLoading(true);
    try {
      const userData = await auth.login({
        email: 'user@example.com',
        password: 'password123'
      });
      // setUser updates automatically via onAuthStateChanged
    } catch (error) {
      alert('Login error: ' + error.message);
    }
    setLoading(false);
  };

  const handleLogout = () => {
    auth.logout();
    // setUser updates automatically via onAuthStateChanged
  };

  if (loading) {
    return <div>Loading...</div>;
  }

  return (
    <div>
      {user ? (
        <div>
          <h1>Hello, {user.name || user.email}!</h1>
          <p>ID: {user.id}</p>
          <button onClick={handleLogout}>Logout</button>
        </div>
      ) : (
        <div>
          <h1>You are not logged in</h1>
          <button onClick={handleLogin}>Login</button>
        </div>
      )}
    </div>
  );
}

export default AuthExample;
```

### **Custom Hook**

```jsx
import { useState, useEffect } from 'react';
import { AuthSDK } from 'sdk-simple-auth';

const auth = new AuthSDK({
  authServiceUrl: process.env.REACT_APP_API_URL
});

export function useAuth() {
  const [state, setState] = useState({
    user: null,
    loading: true,
    error: null,
    isAuthenticated: false
  });

  useEffect(() => {
    const unsubscribe = auth.onAuthStateChanged((authState) => {
      setState({
        user: authState.user,
        loading: authState.loading,
        error: authState.error,
        isAuthenticated: authState.isAuthenticated
      });
    });

    // Check initial session
    auth.isAuthenticated().then(isAuth => {
      if (isAuth) {
        setState(prev => ({
          ...prev,
          user: auth.getCurrentUser(),
          isAuthenticated: true,
          loading: false
        }));
      } else {
        setState(prev => ({
          ...prev,
          loading: false
        }));
      }
    });

    return unsubscribe;
  }, []);

  const login = async (credentials) => {
    try {
      const user = await auth.login(credentials);
      return user;
    } catch (error) {
      throw error;
    }
  };

  const logout = () => {
    auth.logout();
  };

  const getAuthHeaders = async () => {
    return await auth.getAuthHeaders();
  };

  return {
    ...state,
    login,
    logout,
    getAuthHeaders,
    auth // Direct access to SDK if needed
  };
}

// Use the hook
function MyComponent() {
  const { user, loading, login, logout, isAuthenticated } = useAuth();

  if (loading) return <div>Loading...</div>;

  return (
    <div>
      {isAuthenticated ? (
        <div>
          <p>Welcome, {user.name}</p>
          <button onClick={logout}>Logout</button>
        </div>
      ) : (
        <button onClick={() => login({ email: 'test@test.com', password: '123' })}>
          Login
        </button>
      )}
    </div>
  );
}
```

## 🔄 **Token Management**

### **Auto Refresh**

```typescript
// SDK automatically handles token refresh
const auth = new AuthSDK({
  authServiceUrl: 'http://localhost:3000',
  tokenRefresh: {
    enabled: true,
    bufferTime: 300, // Refresh 5 minutes before expiry
    maxRetries: 3
  }
});

// Get valid token (with auto refresh if needed)
const token = await auth.getValidAccessToken();

// Ready-to-use headers
const headers = await auth.getAuthHeaders();
// { Authorization: 'Bearer valid-token' }
```

### **Use with Fetch/Axios**

```typescript
// With native fetch
async function apiCall() {
  const headers = await auth.getAuthHeaders();
  
  const response = await fetch('/api/data', {
    headers: {
      'Content-Type': 'application/json',
      ...headers
    }
  });
  
  return response.json();
}

// With axios
import axios from 'axios';

// Interceptor to add token automatically
axios.interceptors.request.use(async (config) => {
  const headers = await auth.getAuthHeaders();
  config.headers = { ...config.headers, ...headers };
  return config;
});

// Interceptor to handle 401 errors
axios.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (error.response?.status === 401) {
      // Token expired, try refresh
      try {
        await auth.refreshTokens();
        // Retry original request
        const headers = await auth.getAuthHeaders();
        error.config.headers = { ...error.config.headers, ...headers };
        return axios.request(error.config);
      } catch (refreshError) {
        // Refresh failed, logout
        auth.logout();
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  }
);
```

## 🛠️ **Debug and Troubleshooting**

### **Analyze Your API Response**

```typescript
// If you don't know what format your backend uses
auth.debugResponse(responseFromYourAPI);

// This will print to console:
// 🔍 API Response Debug
// 📥 Original response: { ... }
// ✅ Extracted tokens: { ... }
// ✅ Extracted user: { ... }
```

### **Check Token State**

```typescript
// Debug current token
auth.debugToken();

// Detailed session information
const sessionInfo = await auth.getExtendedSessionInfo();
console.log({
  isValid: sessionInfo.isValid,
  tokenType: sessionInfo.tokenType,
  expiresIn: sessionInfo.expiresIn,
  canRefresh: sessionInfo.canRefresh
});
```

### **Backend Auto-detection**

```typescript
import { quickAnalyzeAndCreate } from 'sdk-simple-auth';

// Make manual login to your API and pass the response
const response = await fetch('/api/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email: 'test@test.com', password: '123' })
});

const data = await response.json();

// SDK will analyze and configure automatically
const auth = quickAnalyzeAndCreate(data, 'http://localhost:3000');
```

## ❌ **Common Errors and Solutions**

### **"No user information found"**

**Problem:** Your API doesn't return user data where the SDK expects it.

**Solution:**
```typescript
const auth = new AuthSDK({
  authServiceUrl: 'http://localhost:3000',
  backend: {
    userSearchPaths: ['user', 'data.user', 'profile'], // Where to search
    fieldMappings: {
      userId: ['id', 'user_id', 'userId'],
      email: ['email', 'mail'],
      name: ['name', 'username', 'full_name']
    }
  }
});
```

### **"Token invalid or expired"**

**Problem:** Invalid token or incorrect configuration.

**Solutions:**
```typescript
// 1. Check token format
auth.debugToken();

// 2. Check refresh capability
const sessionInfo = await auth.getExtendedSessionInfo();
console.log('Can refresh:', sessionInfo.canRefresh);

// 3. Configure refresh properly
const auth = new AuthSDK({
  // ...
  tokenRefresh: {
    enabled: true,
    bufferTime: 300
  }
});
```

### **CORS or Network Errors**

**Problem:** Connection errors with the API.

**Solution:**
```typescript
// Custom HTTP client with error handling
const auth = new AuthSDK({
  authServiceUrl: 'http://localhost:3000',
  httpClient: {
    async post(url, data, config) {
      try {
        const response = await fetch(url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            ...config?.headers
          },
          body: JSON.stringify(data)
        });
        
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        return await response.json();
      } catch (error) {
        console.error('HTTP Error:', error);
        throw error;
      }
    },
    // ... other methods similarly
  }
});
```

## 🎉 **Ready to Use!**

With these examples you have everything needed to integrate `sdk-simple-auth` into your application.

### **Next Steps:**

1. ✅ **Install**: `npm install sdk-simple-auth`
2. ✅ **Configure** according to your backend
3. ✅ **Integrate** into your application
4. ✅ **Test** login/logout
5. ✅ **Customize** as needed

### **Additional Resources:**

- 📚 [Complete examples](../examples/)
- 🔧 [Advanced configuration](./advanced-config.md)
- 🐛 [Troubleshooting](./troubleshooting.md)
- 📖 [API Reference](./api-reference.md)

Need help? [Open an issue](https://github.com/olivio-git/sdk-simple-auth/issues) in the repository.
