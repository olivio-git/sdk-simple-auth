import { StorageAdapter } from "./StorageAdapter";

export class LocalStorageAdapter implements StorageAdapter {
  async setItem(key: string, value: string): Promise<void> {
    if (typeof window !== 'undefined') {
      try {
        localStorage.setItem(key, value);
      } catch {
        // Silently ignore QuotaExceededError, SecurityError (private mode), etc.
      }
    }
  }

  async getItem(key: string): Promise<string | null> {
    if (typeof window !== 'undefined') {
      try {
        return localStorage.getItem(key);
      } catch {
        return null;
      }
    }
    return null;
  }

  async removeItem(key: string): Promise<void> {
    if (typeof window !== 'undefined') {
      try {
        localStorage.removeItem(key);
      } catch {
        // Silently ignore storage errors
      }
    }
  }

  async clear(): Promise<void> {
    if (typeof window !== 'undefined') {
      try {
        localStorage.clear();
      } catch {
        // Silently ignore storage errors
      }
    }
  }
}
