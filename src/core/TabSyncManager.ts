import { AuthTokens, AuthUser } from '../types';
import { Logger } from './Logger';

type TabSyncMessage =
  | { type: 'LOGIN'; tabId: string; user: AuthUser; tokens: AuthTokens }
  | { type: 'LOGOUT'; tabId: string }
  | { type: 'TOKEN_REFRESHED'; tabId: string; tokens: AuthTokens };

export interface TabSyncCallbacks {
  onRemoteLogin: (user: AuthUser, tokens: AuthTokens) => void;
  onRemoteLogout: () => void;
  onRemoteTokenRefresh: (tokens: AuthTokens) => void;
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

  /** Close the channel. Safe to call multiple times. */
  destroy(): void {
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
    }
  }
}
