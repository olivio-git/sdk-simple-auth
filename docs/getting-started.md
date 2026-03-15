# Getting Started

## Installation

```bash
npm install sdk-simple-auth
```

---

## Choose your backend

### Node.js / Express

Your backend returns something like:
```json
{ "success": true, "data": { "user": { "id": 1, "email": "..." }, "token": "...", "refreshToken": "..." } }
```

```typescript
import { createQuickNodeAuth } from 'sdk-simple-auth';

const auth = createQuickNodeAuth('http://localhost:3000');
const user = await auth.login({ email: 'user@example.com', password: 'secret' });
```

### Laravel Sanctum

Your backend returns something like:
```json
{ "user": { "id": 1, "email": "..." }, "token": "1|sanctum-token" }
```

```typescript
import { createQuickSanctumAuth } from 'sdk-simple-auth';

const auth = createQuickSanctumAuth('http://localhost:8000/api');
const user = await auth.login({ email: 'user@example.com', password: 'secret' });
```

### Don't know your backend format?

```typescript
import { quickAnalyzeAndCreate } from 'sdk-simple-auth';

// Make a test login call, pass the response here
const auth = quickAnalyzeAndCreate(yourApiResponse, 'http://localhost:3000');
```

---

## Check authentication state

```typescript
const isAuth = await auth.isAuthenticated();

if (isAuth) {
  const user = auth.getCurrentUser();
  console.log(user); // { id, email, name, ... }
}
```

---

## Get auth headers for API calls

```typescript
const headers = await auth.getAuthHeaders();
// { Authorization: 'Bearer eyJ...' }

// Use with fetch
const res = await fetch('/api/data', { headers });

// Or with axios (manual)
axios.defaults.headers.common = headers;
```

---

## Automatic Axios integration

```typescript
import axios from 'axios';
import { AxiosInterceptorManager } from 'sdk-simple-auth';

const client = axios.create({ baseURL: 'http://localhost:3000' });
const interceptors = new AxiosInterceptorManager(auth, client);
interceptors.setup();

// Every request now has the Authorization header automatically
// 401 responses trigger a token refresh and the request retries
```

---

## React

```tsx
import { useAuth } from 'sdk-simple-auth';

function LoginPage() {
  const { isAuthenticated, user, loading, login, logout } = useAuth(auth);

  const handleLogin = async () => {
    await login({ email: 'user@example.com', password: 'secret' });
  };

  if (loading) return <p>Loading...</p>;

  return isAuthenticated ? (
    <div>
      <p>Welcome, {user?.name}</p>
      <button onClick={logout}>Logout</button>
    </div>
  ) : (
    <button onClick={handleLogin}>Login</button>
  );
}
```

The `useAuth` hook returns:

| Property | Type | Description |
|----------|------|-------------|
| `isAuthenticated` | `boolean` | Current auth status |
| `user` | `AuthUser \| null` | Current user data |
| `loading` | `boolean` | Operation in progress |
| `error` | `string \| null` | Last error message |
| `sessionInfo` | `object \| null` | `{ isValid, refreshAvailable, sessionId }` |
| `login` | `fn` | Login with credentials |
| `logout` | `fn` | Logout |
| `register` | `fn` | Register new user |
| `refreshTokens` | `fn` | Manually refresh tokens |
| `getAuthHeaders` | `fn` | Get `{ Authorization: '...' }` |
| `getValidAccessToken` | `fn` | Get current valid token |

---

## Encrypted storage

Enable AES-GCM 256-bit encryption for tokens stored in the browser:

```typescript
import { AuthSDK, EncryptedStorageAdapter } from 'sdk-simple-auth';

const auth = new AuthSDK({
  authServiceUrl: 'http://localhost:3000',
  storage: {
    adapter: new EncryptedStorageAdapter({ key: 'my-secret-key' }),
  },
});
```

---

## Token auto-refresh

By default the SDK refreshes tokens 15 minutes before expiry. Customize it:

```typescript
const auth = new AuthSDK({
  authServiceUrl: 'http://localhost:3000',
  tokenRefresh: {
    enabled: true,
    bufferTime: 300,   // Refresh 5 min before expiry
    maxRetries: 3,
  },
});
```

---

## Debugging

```typescript
auth.debugToken()              // Decode and log the current token
auth.debugResponse(response)   // Analyze a raw API response
auth.debugSession()            // Log full session state
```
