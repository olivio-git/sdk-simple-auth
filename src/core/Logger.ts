/**
 * Logger utility for the SDK
 * Allows enabling/disabling debug logs globally
 */
export class Logger {
  private static debugMode = false;
  private static prefix = '[AuthSDK]';

  /**
   * Enable or disable debug mode
   */
  static setDebugMode(enabled: boolean) {
    this.debugMode = enabled;
  }

  /**
   * Log a debug message (only if debug mode is enabled)
   */
  static debug(message: string, ...args: any[]) {
    if (this.debugMode) {
      console.debug(`${this.prefix} [Debug] ${message}`, ...args);
    }
  }

  /**
   * Log an info message (only if debug mode is enabled)
   */
  static log(message: string, ...args: any[]) {
    if (this.debugMode) {
      console.log(`${this.prefix} ${message}`, ...args);
    }
  }

  /**
   * Log a warning message (always visible, but formatted)
   */
  static warn(message: string, ...args: any[]) {
    console.warn(`${this.prefix} [Warn] ${message}`, ...args);
  }

  /**
   * Log an error message (always visible, but formatted)
   */
  static error(message: string, ...args: any[]) {
    console.error(`${this.prefix} [Error] ${message}`, ...args);
  }
}
