import { StorageAdapter } from "./StorageAdapter";

export class LocalStorageAdapter implements StorageAdapter {
  async setItem(key: string, value: string): Promise<void> {
    if (typeof window !== 'undefined') {
      localStorage.setItem(key, value);
    }
  }

  async getItem(key: string): Promise<string | null> {
    if (typeof window !== 'undefined') {
      return localStorage.getItem(key);
    }
    return null;
  }
 
  async removeItem(key: string): Promise<void> {
    if (typeof window !== 'undefined') {
      localStorage.removeItem(key);
    }
  }

  async clear(): Promise<void> {
    if (typeof window !== 'undefined') {
      localStorage.clear();
    }
  }
}