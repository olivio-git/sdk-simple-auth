import { AuthTokens, AuthUser } from '../types';
import { Logger } from './Logger';

type TabSyncMessage =
  | { type: 'LOGIN'; tabId: string; user: AuthUser; tokens: AuthTokens }
  | { type: 'LOGOUT'; tabId: string }
  | { type: 'TOKEN_REFRESHED'; tabId: string; tokens: AuthTokens }
  | { type: 'SESSION_REQUEST'; tabId: string; requestId: string }
  | { type: 'SESSION_RESPONSE'; tabId: string; requestId: string; to: string; user: AuthUser; tokens: AuthTokens };

export interface SharedSession {
  user: AuthUser;
  tokens: AuthTokens;
}

export interface TabSyncCallbacks {
  onRemoteLogin: (user: AuthUser, tokens: AuthTokens) => void;
  onRemoteLogout: () => void;
  onRemoteTokenRefresh: (tokens: AuthTokens) => void;
  /**
   * Another instance asks for the current session (e.g. a secondary window
   * whose token expired). Resolve `null` to stay silent.
   */
  onSessionRequest?: () => Promise<SharedSession | null>;
}

/**
 * TabSyncManager — synchronises auth state across browser tabs on the same origin.
 *
 * Uses the BroadcastChannel API (browser-only). Each SDK instance gets a random
 * tabId so it can ignore messages it originally sent, preventing echo loops.
 *
 * Usage:
 *   const mgr = new TabSyncManager('myapp', callbacks, logger);
 *   mgr.start();           // open channel
 *   mgr.broadcastLogin();  // notify other tabs
 *   mgr.destroy();         // close channel (call from AuthSDK.destroy())
 */
export class TabSyncManager {
  private channel: BroadcastChannel | null = null;
  private readonly tabId: string;
  private readonly pendingRequests = new Map<string, (session: SharedSession | null) => void>();
  private readonly channelName: string;

  constructor(
    channelName: string,
    private readonly callbacks: TabSyncCallbacks,
    private readonly logger: Logger
  ) {
    this.channelName = `auth-sdk-${channelName}`;
    // Random per-instance ID used to filter self-originated messages.
    this.tabId = Math.random().toString(36).slice(2);
  }

  /** Open the BroadcastChannel and start listening for remote events. */
  start(): void {
    if (!TabSyncManager.isSupported() || this.channel) return;

    this.channel = new BroadcastChannel(this.channelName);
    this.channel.onmessage = (event: MessageEvent<TabSyncMessage>) => {
      this.handleMessage(event.data);
    };
    this.logger.debug(`TabSyncManager: listening on "${this.channelName}" (tab ${this.tabId})`);
  }

  /** Notify other tabs that this tab logged in. */
  broadcastLogin(user: AuthUser, tokens: AuthTokens): void {
    this.send({ type: 'LOGIN', tabId: this.tabId, user, tokens });
  }

  /** Notify other tabs that this tab logged out. */
  broadcastLogout(): void {
    this.send({ type: 'LOGOUT', tabId: this.tabId });
  }

  /** Notify other tabs that tokens were refreshed so they update in-memory state. */
  broadcastTokenRefresh(tokens: AuthTokens): void {
    this.send({ type: 'TOKEN_REFRESHED', tabId: this.tabId, tokens });
  }

  /**
   * Asks the other instances for the current session. Resolves with the first
   * answer, or `null` if nobody answers within `timeoutMs`.
   */
  requestSession(timeoutMs: number): Promise<SharedSession | null> {
    if (!this.channel) return Promise.resolve(null);

    const requestId = Math.random().toString(36).slice(2);
    return new Promise((resolve) => {
      const timer = setTimeout(() => settle(null), timeoutMs);
      const settle = (session: SharedSession | null) => {
        clearTimeout(timer);
        this.pendingRequests.delete(requestId);
        resolve(session);
      };
      this.pendingRequests.set(requestId, settle);
      this.send({ type: 'SESSION_REQUEST', tabId: this.tabId, requestId });
    });
  }

  /** Close the channel. Safe to call multiple times. */
  destroy(): void {
    for (const settle of [...this.pendingRequests.values()]) settle(null);
    if (this.channel) {
      this.channel.close();
      this.channel = null;
      this.logger.debug('TabSyncManager: channel closed');
    }
  }

  /** Returns true when the BroadcastChannel API is available (browser only). */
  static isSupported(): boolean {
    return typeof BroadcastChannel !== 'undefined';
  }

  private send(message: TabSyncMessage): void {
    this.channel?.postMessage(message);
  }

  private handleMessage(message: TabSyncMessage): void {
    // Discard messages originating from this same tab instance.
    if (message.tabId === this.tabId) return;

    this.logger.debug(`TabSyncManager: received ${message.type} from tab ${message.tabId}`);

    switch (message.type) {
      case 'LOGIN':
        this.callbacks.onRemoteLogin(message.user, message.tokens);
        break;
      case 'LOGOUT':
        this.callbacks.onRemoteLogout();
        break;
      case 'TOKEN_REFRESHED':
        this.callbacks.onRemoteTokenRefresh(message.tokens);
        break;
      case 'SESSION_REQUEST':
        void this.answerSessionRequest(message.tabId, message.requestId);
        break;
      case 'SESSION_RESPONSE':
        if (message.to !== this.tabId) return;
        this.pendingRequests.get(message.requestId)?.({ user: message.user, tokens: message.tokens });
        break;
    }
  }

  private async answerSessionRequest(requesterTabId: string, requestId: string): Promise<void> {
    if (!this.callbacks.onSessionRequest) return;
    try {
      const session = await this.callbacks.onSessionRequest();
      if (!session) return;
      this.send({
        type: 'SESSION_RESPONSE',
        tabId: this.tabId,
        requestId,
        to: requesterTabId,
        user: session.user,
        tokens: session.tokens,
      });
    } catch (error) {
      this.logger.warn('TabSyncManager: could not answer a session request', error);
    }
  }
}
