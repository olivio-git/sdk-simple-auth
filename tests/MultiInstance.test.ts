/**
 * Several SDK instances sharing one storage: browser tabs, or the windows of a
 * desktop app (Tauri/Electron) on the same origin.
 *
 * Each test drives real AuthSDK instances against a fake backend that rotates
 * refresh tokens (a refresh token can be used once), which is what turns two
 * simultaneous refreshes into a 401.
 */
import { AuthSDK } from '../src/core/AuthSDK';
import { AuthConfig, HttpClient } from '../src/types';

// ─── Shared environment ──────────────────────────────────────────────────────

class MemoryStorage {
  private map = new Map<string, string>();
  getItem(key: string) { return this.map.has(key) ? this.map.get(key)! : null; }
  setItem(key: string, value: string) { this.map.set(key, String(value)); }
  removeItem(key: string) { this.map.delete(key); }
  clear() { this.map.clear(); }
  get size() { return this.map.size; }
}

const storage = new MemoryStorage();
Object.defineProperty(window, 'localStorage', { value: storage, configurable: true });

/** Same-origin BroadcastChannel; delivery is async, like the real one. */
class FakeBroadcastChannel {
  static channels = new Map<string, Set<FakeBroadcastChannel>>();
  onmessage: ((event: MessageEvent) => void) | null = null;

  constructor(public readonly name: string) {
    const set = FakeBroadcastChannel.channels.get(name) ?? new Set();
    set.add(this);
    FakeBroadcastChannel.channels.set(name, set);
  }

  postMessage(data: unknown) {
    for (const channel of FakeBroadcastChannel.channels.get(this.name) ?? []) {
      if (channel === this) continue;
      Promise.resolve().then(() => channel.onmessage?.({ data } as MessageEvent));
    }
  }

  close() {
    FakeBroadcastChannel.channels.get(this.name)?.delete(this);
  }
}
(global as any).BroadcastChannel = FakeBroadcastChannel;

/** Web Locks API: one holder per name, FIFO, across every instance. */
class FakeLockManager {
  private tails = new Map<string, Promise<unknown>>();

  request(name: string, optionsOrCallback: any, maybeCallback?: any): Promise<unknown> {
    const callback = typeof optionsOrCallback === 'function' ? optionsOrCallback : maybeCallback;
    const previous = this.tails.get(name) ?? Promise.resolve();
    const run = previous.catch(() => undefined).then(() => callback({ name, mode: 'exclusive' }));
    this.tails.set(name, run.catch(() => undefined));
    return run;
  }
}

function setWebLocks(enabled: boolean) {
  Object.defineProperty(navigator, 'locks', {
    value: enabled ? new FakeLockManager() : undefined,
    configurable: true,
  });
}

// ─── Fake backend ────────────────────────────────────────────────────────────

const LIFETIME = 3600; // seconds
const USER = { id: 7, name: 'Caja 1', email: 'caja1@example.com' };

function jwt(exp: number, jti: number): string {
  const encode = (value: object) => btoa(JSON.stringify(value)).replace(/=+$/, '');
  return `${encode({ alg: 'HS256', typ: 'JWT' })}.${encode({ sub: USER.id, exp, jti })}.signature`;
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

function makeBackend() {
  let sequence = 0;
  const validRefreshTokens = new Set<string>();
  const backend = {
    online: true,
    responseDelay: 50,
    rejectionDelay: 80,
    calls: { login: 0, refresh: 0, refreshRejected: 0, logout: 0 },
    revokeAll() { validRefreshTokens.clear(); },
    http: null as unknown as HttpClient,
  };

  const issue = () => {
    sequence += 1;
    const refreshToken = `rt-${sequence}`;
    validRefreshTokens.add(refreshToken);
    return {
      access_token: jwt(Math.floor(Date.now() / 1000) + LIFETIME, sequence),
      refresh_token: refreshToken,
      expires_in: LIFETIME,
    };
  };

  backend.http = {
    async post(url: string, body?: any) {
      if (!backend.online) throw new TypeError('Failed to fetch');

      if (url.endsWith('/login')) {
        backend.calls.login += 1;
        const tokens = issue();
        await sleep(backend.responseDelay);
        return { ...tokens, user: USER };
      }

      if (url.endsWith('/refresh')) {
        // The server decides when the request arrives, the client learns later.
        const presented = body?.refresh_token;
        if (!validRefreshTokens.has(presented)) {
          backend.calls.refreshRejected += 1;
          await sleep(backend.rejectionDelay);
          throw Object.assign(new Error('Refresh token inválido'), { response: { status: 401 } });
        }
        validRefreshTokens.delete(presented); // rotation: single use
        backend.calls.refresh += 1;
        const tokens = issue();
        await sleep(backend.responseDelay);
        return tokens;
      }

      if (url.endsWith('/logout')) {
        backend.calls.logout += 1;
        return {};
      }

      throw new Error(`Unexpected POST ${url}`);
    },
    async get() { throw new Error('not used'); },
    async put() { throw new Error('not used'); },
    async delete() { throw new Error('not used'); },
  };

  return backend;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

const instances: AuthSDK[] = [];

function createInstance(http: HttpClient, extra: Partial<AuthConfig> = {}): AuthSDK {
  const sdk = new AuthSDK({
    authServiceUrl: 'http://api.test',
    endpoints: { login: '/login', logout: '/logout', refresh: '/refresh' },
    storage: { type: 'localStorage', tokenKey: 'app_token', refreshTokenKey: 'app_refresh', userKey: 'app_user' },
    httpClient: http,
    sessionValidation: { enabled: false, validateOnStartup: false },
    tabSync: { enabled: true, channelName: 'app' },
    ...extra,
  });
  instances.push(sdk);
  return sdk;
}

/** Secondary window as an app would configure it. */
function createSecondary(http: HttpClient): AuthSDK {
  return createInstance(http, { instanceRole: 'secondary', tokenRefresh: { enabled: false } } as any);
}

const MINUTE = 60_000;

/** Lets pending promises and zero-delay work settle. */
async function settle(ms = 0) {
  await jest.advanceTimersByTimeAsync(ms);
}

/** Time passes while the machine sleeps: timers do not run, the clock jumps. */
function sleepMachine(ms: number) {
  jest.setSystemTime(Date.now() + ms);
}

/**
 * Waking up: every overdue timer fires back to back, before any network
 * response or promise continuation can run in between.
 */
function wakeUpFiringOverdueTimers(ms: number) {
  jest.advanceTimersByTime(ms);
}

async function login(sdk: AuthSDK) {
  const loggingIn = sdk.login({ email: 'caja1@example.com', password: 'secret' });
  await settle(100);
  await loggingIn;
}

function storedSession() {
  return {
    token: storage.getItem('app_token'),
    refresh: storage.getItem('app_refresh'),
    user: storage.getItem('app_user'),
  };
}

beforeEach(() => {
  jest.useFakeTimers();
  jest.setSystemTime(new Date('2026-03-02T08:00:00Z'));
  storage.clear();
  FakeBroadcastChannel.channels.clear();
  setWebLocks(true);
  jest.spyOn(console, 'error').mockImplementation(() => {});
  jest.spyOn(console, 'warn').mockImplementation(() => {});
});

afterEach(() => {
  instances.splice(0).forEach((sdk) => sdk.destroy());
  jest.clearAllTimers();
  jest.useRealTimers();
  jest.restoreAllMocks();
});

// ─── Startup ─────────────────────────────────────────────────────────────────

describe('startup with an expired access token', () => {
  test('renews with the refresh token instead of clearing the session', async () => {
    const backend = makeBackend();
    const first = createInstance(backend.http);
    await login(first);
    first.destroy();

    // App closed (or PC asleep) longer than the access token lifetime.
    sleepMachine(2 * 60 * MINUTE);

    const reopened = createInstance(backend.http);
    const ready = reopened.ready;
    await settle(200);
    await ready;

    expect(reopened.getState().isAuthenticated).toBe(true);
    expect(reopened.getCurrentUser()?.id).toBe(USER.id);
    expect(await reopened.getValidAccessToken()).toBeTruthy();
    expect(backend.calls.refresh).toBe(1);
    expect(backend.calls.logout).toBe(0);
  });

  test('clears the session when the server rejects the refresh token', async () => {
    const backend = makeBackend();
    const first = createInstance(backend.http);
    await login(first);
    first.destroy();

    sleepMachine(2 * 60 * MINUTE);
    backend.revokeAll();

    const reopened = createInstance(backend.http);
    const ready = reopened.ready;
    await settle(200);
    await ready;

    expect(reopened.getState().isAuthenticated).toBe(false);
    expect(storedSession().token).toBeNull();
  });

  test('keeps the stored session when the network is down, to retry later', async () => {
    const backend = makeBackend();
    const first = createInstance(backend.http);
    await login(first);
    first.destroy();

    sleepMachine(2 * 60 * MINUTE);
    backend.online = false;

    const offline = createInstance(backend.http);
    const ready = offline.ready;
    await settle(200);
    await ready;
    expect(offline.getState().isAuthenticated).toBe(false);
    expect(storedSession().refresh).not.toBeNull();
    offline.destroy();

    backend.online = true;
    const online = createInstance(backend.http);
    const readyAgain = online.ready;
    await settle(200);
    await readyAgain;
    expect(online.getState().isAuthenticated).toBe(true);
  });
});

// ─── Several primaries (browser tabs) ────────────────────────────────────────

describe('two tabs refreshing at the same moment', () => {
  test('neither loses the session (Web Locks)', async () => {
    const backend = makeBackend();
    const tabA = createInstance(backend.http);
    await login(tabA);
    const tabB = createInstance(backend.http);
    await settle(10);
    await tabB.ready;

    // Both schedule the refresh from the same expiresAt, so the timers fire together.
    await settle(50 * MINUTE);

    expect(backend.calls.refreshRejected).toBe(0);
    expect(backend.calls.refresh).toBe(1);
    expect(backend.calls.logout).toBe(0);
    expect(tabA.getState().isAuthenticated).toBe(true);
    expect(tabB.getState().isAuthenticated).toBe(true);
    expect(tabA.getAccessToken()).toBe(tabB.getAccessToken());
    expect(storedSession().refresh).toBe('rt-2');
  });

  test('without Web Locks, a 401 for a token another tab just rotated does not clear the session', async () => {
    setWebLocks(false);
    const backend = makeBackend();
    const tabA = createInstance(backend.http);
    await login(tabA);
    const tabB = createInstance(backend.http);
    await settle(10);
    await tabB.ready;

    await settle(50 * MINUTE);

    expect(backend.calls.refresh).toBe(1);
    expect(backend.calls.logout).toBe(0);
    expect(tabA.getState().isAuthenticated).toBe(true);
    expect(tabB.getState().isAuthenticated).toBe(true);
    expect(storedSession().refresh).toBe('rt-2');
  });

  test('a refresh the server really rejects still ends the session everywhere', async () => {
    const backend = makeBackend();
    const tabA = createInstance(backend.http);
    await login(tabA);
    const tabB = createInstance(backend.http);
    await settle(10);
    await tabB.ready;

    backend.revokeAll();
    await settle(65 * MINUTE);

    expect(tabA.getState().isAuthenticated).toBe(false);
    expect(tabB.getState().isAuthenticated).toBe(false);
    expect(storedSession().token).toBeNull();
  });
});

// ─── Machine sleep ───────────────────────────────────────────────────────────

describe('waking up after the access token expired', () => {
  test('the refresh and expiration timers firing together do not log out', async () => {
    const backend = makeBackend();
    const sdk = createInstance(backend.http);
    await login(sdk);

    wakeUpFiringOverdueTimers(61 * MINUTE);
    await settle(1000);

    expect(backend.calls.logout).toBe(0);
    expect(backend.calls.refresh).toBe(1);
    expect(sdk.getState().isAuthenticated).toBe(true);
    expect(await sdk.getValidAccessToken()).toBeTruthy();
  });

  test('with the network still down, keeps the session and recovers when it comes back', async () => {
    const backend = makeBackend();
    const sdk = createInstance(backend.http);
    await login(sdk);

    backend.online = false; // Wi-Fi still reconnecting
    await settle(61 * MINUTE);

    expect(sdk.getState().isAuthenticated).toBe(true);
    expect(storedSession().refresh).not.toBeNull();

    backend.online = true;
    await settle(2 * MINUTE);
    const token = sdk.getValidAccessToken();
    await settle(100);

    expect(await token).toBeTruthy();
    expect(backend.calls.refresh).toBe(1);
    expect(backend.calls.logout).toBe(0);
  });
});

describe('getValidAccessToken', () => {
  test('returns the current token when an early refresh fails but it is still valid', async () => {
    const backend = makeBackend();
    const sdk = createInstance(backend.http);
    await login(sdk);
    const current = sdk.getAccessToken();

    backend.online = false;
    await settle(50 * MINUTE); // inside the 15 min refresh window, 10 min left

    const token = sdk.getValidAccessToken();
    await settle(100);
    expect(await token).toBe(current);
  });
});

// ─── Secondary windows ───────────────────────────────────────────────────────

describe('secondary instance (instanceRole: "secondary")', () => {
  test('opening with an expired stored token asks the primary instead of clearing', async () => {
    const backend = makeBackend();
    const main = createInstance(backend.http);
    await login(main);

    sleepMachine(2 * 60 * MINUTE); // main's timers have not run yet

    const secondary = createSecondary(backend.http);
    const ready = secondary.ready;
    await settle(500);
    await ready;

    expect(secondary.getState().isAuthenticated).toBe(true);
    expect(await secondary.getValidAccessToken()).toBeTruthy();
    expect(backend.calls.refresh).toBe(1); // done by the main window
    expect(backend.calls.logout).toBe(0);
    expect(storedSession().refresh).toBe('rt-2');
  });

  test('never refreshes on its own; follows the primary', async () => {
    const backend = makeBackend();
    const main = createInstance(backend.http);
    await login(main);
    const secondary = createSecondary(backend.http);
    await settle(10);
    await secondary.ready;

    await settle(3 * 60 * MINUTE);

    expect(backend.calls.refreshRejected).toBe(0);
    expect(backend.calls.logout).toBe(0);
    expect(secondary.getState().isAuthenticated).toBe(true);
    expect(secondary.getAccessToken()).toBe(main.getAccessToken());
  });

  test('sleeping with the secondary open: no one logs out', async () => {
    const backend = makeBackend();
    const main = createInstance(backend.http);
    await login(main);
    const secondary = createSecondary(backend.http);
    await settle(10);
    await secondary.ready;

    wakeUpFiringOverdueTimers(61 * MINUTE);
    await settle(1000);

    expect(backend.calls.logout).toBe(0);
    expect(backend.calls.refreshRejected).toBe(0);
    expect(main.getState().isAuthenticated).toBe(true);
    expect(secondary.getState().isAuthenticated).toBe(true);
    expect(await secondary.getValidAccessToken()).toBe(main.getAccessToken());
  });

  test('with no primary to answer, keeps the shared storage untouched', async () => {
    const backend = makeBackend();
    const main = createInstance(backend.http);
    await login(main);
    main.destroy();

    sleepMachine(2 * 60 * MINUTE);
    const before = storedSession();

    const orphan = createSecondary(backend.http);
    const ready = orphan.ready;
    await settle(10_000);
    await ready;

    expect(orphan.getState().isAuthenticated).toBe(false);
    expect(storedSession()).toEqual(before);
    expect(backend.calls.refresh).toBe(0);
  });

  test('an explicit logout from a secondary still logs out everywhere', async () => {
    const backend = makeBackend();
    const main = createInstance(backend.http);
    await login(main);
    const secondary = createSecondary(backend.http);
    await settle(10);
    await secondary.ready;

    const loggingOut = secondary.logout();
    await settle(10);
    await loggingOut;

    expect(backend.calls.logout).toBe(1);
    expect(storedSession().token).toBeNull();
    expect(main.getState().isAuthenticated).toBe(false);
  });
});

// ─── Axios interceptors in a secondary ───────────────────────────────────────

function makeFakeAxios() {
  const handlers: { request?: (config: any) => any; responseError?: (error: any) => any } = {};
  const axios = {
    interceptors: {
      request: { use: jest.fn((fulfilled) => { handlers.request = fulfilled; return 1; }), eject: jest.fn() },
      response: { use: jest.fn((_ok, rejected) => { handlers.responseError = rejected; return 1; }), eject: jest.fn() },
    },
    request: jest.fn(async (config: any) => ({ status: 200, config })),
  };
  /** An API call that answered 401. */
  const fail401 = () =>
    handlers.responseError!({ config: { headers: {} }, response: { status: 401 } });
  return { axios, fail401 };
}

describe('secondary instance with Axios interceptors', () => {
  test('a 401 asks the primary for the session and retries', async () => {
    const backend = makeBackend();
    const main = createInstance(backend.http);
    await login(main);
    const { axios, fail401 } = makeFakeAxios();
    const secondary = createInstance(backend.http, {
      instanceRole: 'secondary',
      interceptors: { enabled: true, axiosInstance: axios },
    });
    await settle(10);
    await secondary.ready;

    const retried = fail401();
    await settle(100);
    const response = await retried;

    expect(response.config.headers.Authorization).toBe(`Bearer ${main.getAccessToken()}`);
    expect(backend.calls.logout).toBe(0);
    expect(secondary.getState().isAuthenticated).toBe(true);
  });

  test('when nobody answers, it signs out only itself: the shared storage stays', async () => {
    const backend = makeBackend();
    const main = createInstance(backend.http);
    await login(main);
    const { axios, fail401 } = makeFakeAxios();
    const secondary = createInstance(backend.http, {
      instanceRole: 'secondary',
      interceptors: { enabled: true, axiosInstance: axios },
      tabSync: { enabled: true, channelName: 'app', sessionRequestTimeout: 1000 },
    });
    await settle(10);
    await secondary.ready;
    main.destroy(); // the main window is gone
    const before = storedSession();

    const failed = fail401().catch((error: unknown) => error);
    await settle(1500);
    await failed;

    expect(secondary.getState().isAuthenticated).toBe(false);
    expect(storedSession()).toEqual(before);
  });
});
