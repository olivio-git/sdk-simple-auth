# sdk-simple-auth

[![npm](https://img.shields.io/npm/v/sdk-simple-auth)](https://www.npmjs.com/package/sdk-simple-auth)
[![License](https://img.shields.io/npm/l/sdk-simple-auth)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-ready-blue)](https://www.typescriptlang.org/)

Universal JavaScript/TypeScript authentication SDK with multi-backend support, automatic token refresh, and React integration.

---

## Features

- **Multi-backend** — works out of the box with Node.js/Express, Laravel Sanctum, and standard JWT
- **Auto-detection** — analyzes your API response and configures itself automatically
- **React hook** — `useAuth()` with full state management
- **Auto token refresh** — refreshes tokens before they expire, configurable buffer time
- **Encrypted storage** — optional AES-GCM 256-bit encryption at rest
- **Axios interceptors** — drop-in `AxiosInterceptorManager` for automatic auth headers
- **Session validation** — `SessionValidator` with expiry tracking and session IDs
- **Multi-tab sync** — optional BroadcastChannel sync: login/logout/token-refresh propagated to all open tabs
- **Flexible storage** — `localStorage`, `IndexedDB`, or in-memory
- **TypeScript** — full types, tree-shakeable ESM + CJS + UMD builds

---

## Installation

```bash
npm install sdk-simple-auth
```

---

## Quick Start

### Node.js / Express

```typescript
import { createQuickNodeAuth } from 'sdk-simple-auth';

const auth = createQuickNodeAuth('http://localhost:3000');

const user = await auth.login({ email: 'user@example.com', password: 'secret' });
```

### Laravel Sanctum

```typescript
import { createQuickSanctumAuth } from 'sdk-simple-auth';

const auth = createQuickSanctumAuth('http://localhost:8000/api');

const user = await auth.login({ email: 'user@example.com', password: 'secret' });
```

### Auto-detect from response

```typescript
import { quickAnalyzeAndCreate } from 'sdk-simple-auth';

// Pass a sample response from your API and it configures itself
const auth = quickAnalyzeAndCreate(sampleApiResponse, 'http://localhost:3000');
```

### Manual configuration

```typescript
import { AuthSDK } from 'sdk-simple-auth';

const auth = new AuthSDK({
  authServiceUrl: 'http://localhost:3000',
  endpoints: {
    login: '/auth/login',
    register: '/auth/register',
    refresh: '/auth/refresh',
    logout: '/auth/logout',
  },
  backend: {
    type: 'node-express',       // 'node-express' | 'laravel-sanctum' | 'jwt-standard'
    userSearchPaths: ['user', 'data.user'],
    fieldMappings: {
      userId: ['id', 'user_id'],
      email: ['email'],
      name: ['name', 'full_name'],
    },
  },
  storage: {
    type: 'localStorage',       // 'localStorage' | 'indexedDB'
  },
  tokenRefresh: {
    enabled: true,
    bufferTime: 900,            // Refresh 15 min before expiry
    maxRetries: 3,
  },
});
```

---

## Core API

```typescript
// Auth
await auth.login(credentials)
await auth.register(userData)
await auth.logout()
await auth.isAuthenticated()
auth.getCurrentUser()

// Tokens
await auth.getValidAccessToken()
await auth.getAuthHeaders()       // { Authorization: 'Bearer ...' }
await auth.refreshTokens()
await auth.forceRefreshTokens()

// Session
await auth.getSessionInfo()       // { isValid, refreshAvailable, sessionId }
await auth.getExtendedSessionInfo()

// State
auth.getState()
auth.onAuthStateChanged((state) => { ... })

// Lifecycle
auth.destroy()                    // stop listeners/timers before discarding instance

// Debug
auth.debugToken()
auth.debugResponse(response)
auth.debugSession()
```

---

## React Hook

```tsx
import { AuthSDK, useAuth } from 'sdk-simple-auth';

const authSDK = new AuthSDK({ authServiceUrl: 'http://localhost:3000' });

function App() {
  const {
    isAuthenticated,
    user,
    loading,
    error,
    sessionInfo,
    login,
    logout,
    getAuthHeaders,
  } = useAuth(authSDK);

  if (loading) return <p>Loading...</p>;

  return isAuthenticated ? (
    <div>
      <p>Hello, {user?.name}</p>
      <button onClick={logout}>Logout</button>
    </div>
  ) : (
    <button onClick={() => login({ email: 'user@example.com', password: 'secret' })}>
      Login
    </button>
  );
}
```

---

## Axios Interceptors

Automatically attaches auth headers and handles 401 token refresh on every request:

```typescript
import axios from 'axios';
import { AuthSDK, AxiosInterceptorManager } from 'sdk-simple-auth';

const auth = new AuthSDK({ authServiceUrl: 'http://localhost:3000' });
const client = axios.create({ baseURL: 'http://localhost:3000' });

const interceptors = new AxiosInterceptorManager(auth, client);
interceptors.setup();

// All requests now include Authorization header automatically
// 401 responses trigger a token refresh and retry
```

---

## Encrypted Storage

Optional AES-GCM 256-bit encryption for tokens at rest:

```typescript
import { AuthSDK, EncryptedStorageAdapter, LocalStorageAdapter } from 'sdk-simple-auth';

const auth = new AuthSDK({
  authServiceUrl: 'http://localhost:3000',
  storage: {
    type: 'localStorage',
    encryption: {
      enabled: true,
      secret: 'your-unique-secret-key', // use a strong random value in production
    },
  },
});

// Or wrap any adapter manually:
const encrypted = new EncryptedStorageAdapter(new LocalStorageAdapter(), 'your-secret');
```

---

## Multi-Tab Sync

By default, each browser tab manages its auth state independently. Enable `tabSync` to synchronise login/logout/token-refresh events across all tabs of the same origin via the [BroadcastChannel API](https://developer.mozilla.org/en-US/docs/Web/API/BroadcastChannel):

```typescript
const auth = new AuthSDK({
  authServiceUrl: 'http://localhost:3000',
  tabSync: {
    enabled: true,           // disabled by default — must opt in
    channelName: 'myapp',    // optional, default: 'default'
  },
});
```

> **Note:** `tabSync` is **opt-in** (`enabled: false` by default). Without it, logging out in one tab will not affect other open tabs.

All tabs must use the same `channelName` for the sync to work. This feature is browser-only — it is automatically skipped in Node.js/SSR environments.

---

## Exports

| Export | Description |
|--------|-------------|
| `AuthSDK` | Main class |
| `useAuth` | React hook |
| `createQuickNodeAuth(url)` | Factory for Node.js/Express |
| `createQuickSanctumAuth(url)` | Factory for Laravel Sanctum |
| `quickAnalyzeAndCreate(response, url)` | Auto-detect backend from response |
| `AxiosInterceptorManager` | Axios integration |
| `EncryptedStorageAdapter` | AES-GCM encrypted storage |
| `LocalStorageAdapter` | localStorage adapter |
| `IndexedDBAdapter` | IndexedDB adapter |
| `SessionValidator` | Session validation |
| `TokenExtractor` | Token parsing utilities |
| `AuthDebugger` | Debug utilities (token inspection, response analysis) |
| `BACKEND_PRESETS` | Config presets for each backend type |

---

## Compatibility

| Environment | Support |
|-------------|---------|
| Browsers | Chrome, Firefox, Safari, Edge (ES2018+) |
| Node.js | 18+ (or provide `httpClient` for older versions) |
| React | 16.8+ (hooks) |
| TypeScript | 4.5+ |
| Bundlers | Webpack, Vite, Rollup, Parcel |
| Formats | ESM, CJS, UMD |

---

## License

MIT — see [LICENSE](LICENSE)

---

Developed by [Olivio Subelza](https://github.com/olivio-git)
