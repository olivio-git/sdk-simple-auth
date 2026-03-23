import { AuthDebugger } from '../src/core/AuthDebugger';

// ─── Helpers ─────────────────────────────────────────────────────────────────

const JWT_TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9' +
  '.eyJzdWIiOiIxMjMiLCJuYW1lIjoiVGVzdCIsImV4cCI6OTk5OTk5OTk5OX0' +
  '.signature';

const SANCTUM_TOKEN = '1|abcdefghijklmnopqrstuvwxyz';

const OPAQUE_TOKEN = 'opaque-token-no-dots';

function makeState(tokens: any = null, user: any = null) {
  return {
    isAuthenticated: !!tokens,
    user,
    tokens,
    loading: false,
    error: null,
  };
}

function makeRefreshStatus() {
  return {
    isRefreshing: false,
    refreshAttempts: 0,
    lastRefreshTime: 0,
    nextRefreshScheduled: false,
  };
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('AuthDebugger', () => {
  let consoleSpy: jest.SpyInstance;
  let consoleGroupSpy: jest.SpyInstance;
  let consoleGroupEndSpy: jest.SpyInstance;

  beforeEach(() => {
    consoleSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
    consoleGroupSpy = jest.spyOn(console, 'group').mockImplementation(() => {});
    consoleGroupEndSpy = jest.spyOn(console, 'groupEnd').mockImplementation(() => {});
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  // ─── debugToken ──────────────────────────────────────────────────────────

  describe('debugToken', () => {
    test('no imprime nada cuando debug=false', () => {
      const debugger_ = new AuthDebugger(false, () => makeState(), makeRefreshStatus);

      debugger_.debugToken(JWT_TOKEN);

      expect(consoleSpy).not.toHaveBeenCalled();
      expect(consoleGroupSpy).not.toHaveBeenCalled();
    });

    test('imprime info del token cuando debug=true', () => {
      const debugger_ = new AuthDebugger(true, () => makeState(), makeRefreshStatus);

      debugger_.debugToken(JWT_TOKEN);

      expect(consoleGroupSpy).toHaveBeenCalled();
      expect(consoleSpy).toHaveBeenCalled();
    });

    test('usa el token del estado si no se pasa token explícito', () => {
      const state = makeState({ accessToken: SANCTUM_TOKEN });
      const debugger_ = new AuthDebugger(true, () => state, makeRefreshStatus);

      debugger_.debugToken(); // sin argumento

      expect(consoleGroupSpy).toHaveBeenCalled();
    });

    test('no imprime nada si no hay token en estado ni argumento', () => {
      const debugger_ = new AuthDebugger(true, () => makeState(), makeRefreshStatus);

      debugger_.debugToken();

      expect(consoleGroupSpy).not.toHaveBeenCalled();
    });

    test('reconoce tokens JWT, Sanctum y opacos sin lanzar error', () => {
      const debugger_ = new AuthDebugger(true, () => makeState(), makeRefreshStatus);

      expect(() => debugger_.debugToken(JWT_TOKEN)).not.toThrow();
      expect(() => debugger_.debugToken(SANCTUM_TOKEN)).not.toThrow();
      expect(() => debugger_.debugToken(OPAQUE_TOKEN)).not.toThrow();
    });
  });

  // ─── debugResponse ───────────────────────────────────────────────────────

  describe('debugResponse', () => {
    test('no imprime nada cuando debug=false', () => {
      const debugger_ = new AuthDebugger(false, () => makeState(), makeRefreshStatus);

      debugger_.debugResponse({ access_token: 'tok', user: { id: '1' } });

      expect(consoleSpy).not.toHaveBeenCalled();
    });

    test('no lanza error con respuestas mal formadas', () => {
      const debugger_ = new AuthDebugger(true, () => makeState(), makeRefreshStatus);

      expect(() => debugger_.debugResponse(null)).not.toThrow();
      expect(() => debugger_.debugResponse({})).not.toThrow();
      expect(() => debugger_.debugResponse('string')).not.toThrow();
    });

    test('imprime tokens y usuario cuando la respuesta es válida', () => {
      const debugger_ = new AuthDebugger(true, () => makeState(), makeRefreshStatus);

      debugger_.debugResponse({
        access_token: JWT_TOKEN,
        user: { id: '1', email: 'test@example.com' },
      });

      expect(consoleGroupSpy).toHaveBeenCalled();
    });
  });

  // ─── testExtraction ──────────────────────────────────────────────────────

  describe('testExtraction', () => {
    test('no imprime nada cuando debug=false', () => {
      const debugger_ = new AuthDebugger(false, () => makeState(), makeRefreshStatus);

      debugger_.testExtraction({ access_token: 'tok' });

      expect(consoleSpy).not.toHaveBeenCalled();
    });

    test('imprime resultado de extracción cuando debug=true', () => {
      const debugger_ = new AuthDebugger(true, () => makeState(), makeRefreshStatus);

      debugger_.testExtraction({ access_token: JWT_TOKEN, user: { id: '1' } });

      expect(consoleGroupSpy).toHaveBeenCalled();
    });

    test('no lanza error cuando la extracción falla', () => {
      const debugger_ = new AuthDebugger(true, () => makeState(), makeRefreshStatus);

      // Respuesta sin tokens válidos
      expect(() => debugger_.testExtraction({ foo: 'bar' })).not.toThrow();
    });
  });

  // ─── debugSession ────────────────────────────────────────────────────────

  describe('debugSession', () => {
    test('no imprime nada cuando debug=false', () => {
      const state = makeState({ accessToken: JWT_TOKEN }, { id: '1' });
      const debugger_ = new AuthDebugger(false, () => state, makeRefreshStatus);

      debugger_.debugSession();

      expect(consoleSpy).not.toHaveBeenCalled();
    });

    test('imprime info de sesión completa cuando debug=true', () => {
      const state = makeState({ accessToken: JWT_TOKEN }, { id: '1', email: 'test@example.com' });
      const debugger_ = new AuthDebugger(true, () => state, makeRefreshStatus);

      debugger_.debugSession();

      expect(consoleGroupSpy).toHaveBeenCalled();
      expect(consoleSpy).toHaveBeenCalled();
    });

    test('no lanza error cuando no hay sesión activa', () => {
      const debugger_ = new AuthDebugger(true, () => makeState(), makeRefreshStatus);

      expect(() => debugger_.debugSession()).not.toThrow();
    });
  });
});
