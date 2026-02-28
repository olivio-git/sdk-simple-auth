# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install dependencies
npm install

# Build all formats (ESM, CJS, UMD, minified ESM)
npm run build

# Watch mode during development
npm run dev

# Run all tests
npm test

# Run a single test file
npx jest tests/AuthSDK.test.ts --detectOpenHandles --forceExit

# Test with coverage
npm run test:coverage

# Type checking only (no emit)
npm run type-check

# Lint
npm run lint
npm run lint:fix

# Run all validations (type-check + lint + tests)
npm run validate

# Local development linking
npm link                          # From sdk root - creates global link
npm link sdk-simple-auth          # From consumer app - links to local build
```

## Architecture

This is a **published npm library** (`sdk-simple-auth`) — a universal JS/TS authentication SDK with multi-backend support. Source is in TypeScript (`src/`), compiled to `dist/` via Rollup into 4 formats: ESM, CJS, UMD, and minified ESM.

### Core Module Structure

**`src/core/AuthSDK.ts`** — Main class consumers instantiate. Orchestrates all managers:
- `StorageManager` — Handles token/user persistence (localStorage or IndexedDB)
- `RefreshManager` — Automatic token refresh with deduplication (prevents concurrent refreshes)
- `SessionValidator` — Browser-only; validates sessions on tab focus/visibility change
- `AxiosInterceptorManager` — Optional axios integration for auto-attaching Bearer tokens
- `TokenHandler` / `TokenExtractor` — JWT parsing and field extraction from varied backend shapes
- `ExpirationHandler` — Timer-based expiration scheduling
- `Logger` — Debug logging, enabled via `config.debug`

**`src/factory/AuthSDKFactory.ts`** — Factory with presets for `node-express`, `laravel-sanctum`, and `jwt-standard` backends. Also provides `quickAnalyzeAndCreate()` which auto-detects backend structure from a sample response.

**`src/hooks/useAuth.ts`** — React hook that wraps an `AuthSDK` instance, subscribes to state changes via `onAuthStateChanged` callback injection, and exposes `{ isAuthenticated, user, tokens, loading, error, login, register, logout, getAuthHeaders, getValidAccessToken }`.

**`src/storage/`** — `StorageAdapter` interface with two implementations: `LocalStorageAdapter` and `IndexedDBAdapter`.

**`src/types/index.ts`** and **`src/types/enhanced_types.ts`** — Type definitions. `enhanced_types.ts` contains `BACKEND_PRESETS`, `EnhancedAuthConfig`, and response analysis types.

### Key Behaviors

- **Token response normalization**: Accepts both snake_case (`access_token`, `refresh_token`) and camelCase (`accessToken`, `refreshToken`) from backends.
- **Concurrent refresh deduplication**: `RefreshManager` uses a single shared promise when multiple calls arrive during refresh.
- **Auto-logout on refresh failure**: If token refresh fails, `logout()` is called automatically to clean state.
- **State observers**: `onAuthStateChanged` callback is the primary state subscription mechanism. The React `useAuth` hook patches this callback on the `AuthSDK` instance directly (via `authSDK['callbacks']`).
- **SessionValidator** only activates in browser environments (`SessionValidator.isSupported()` guards SSR).

### Build Outputs

| File | Format | Purpose |
|------|--------|---------|
| `dist/index.esm.js` | ESM | Modern bundlers (Vite, Webpack) |
| `dist/index.cjs.js` | CJS | Node.js / `require()` |
| `dist/index.umd.js` | UMD + minified | CDN / browser `<script>` |
| `dist/index.esm.min.js` | ESM minified | Production bundles |

React and react-dom are `external` in all builds — they must be provided by the consumer.

### Testing

Tests live in `tests/`. Jest is configured with `jsdom` environment (for localStorage/DOM APIs). Test files:
- `tests/AuthSDK.test.ts` — Core SDK behavior
- `tests/AxiosInterceptors.test.ts` — Axios integration
- `tests/StartupValidation.test.ts` — Initialization and storage hydration

### Publishing Workflow

```bash
npm version patch   # or minor / major
npm run build
git push && git push --tags
npm publish         # triggers prepublishOnly → npm run build
```
