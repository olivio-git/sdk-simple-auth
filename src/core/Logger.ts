/**
 * Logger utility for the SDK.
 * Can be used as an instance (injected per-manager) or via static
 * convenience methods that delegate to the global default instance.
 */
export class Logger {
  private debugMode: boolean;
  private readonly prefix: string;

  // Global default instance — used by static convenience methods and utility classes
  private static defaultInstance = new Logger(false);

  constructor(debug = false, prefix = '[AuthSDK]') {
    this.debugMode = debug;
    this.prefix = prefix;
  }

  debug(message: string, ...args: any[]) {
    if (this.debugMode) {
      console.debug(`${this.prefix} [Debug] ${message}`, ...args);
    }
  }

  log(message: string, ...args: any[]) {
    if (this.debugMode) {
      console.log(`${this.prefix} ${message}`, ...args);
    }
  }

  warn(message: string, ...args: any[]) {
    console.warn(`${this.prefix} [Warn] ${message}`, ...args);
  }

  error(message: string, ...args: any[]) {
    console.error(`${this.prefix} [Error] ${message}`, ...args);
  }

  // Static convenience methods — delegate to the global default instance.
  // Used by utility classes (TokenHandler, ExpirationHandler, etc.) that
  // don't participate in constructor injection.
  static setDebugMode(enabled: boolean) {
    Logger.defaultInstance.debugMode = enabled;
  }

  static debug(message: string, ...args: any[]) {
    Logger.defaultInstance.debug(message, ...args);
  }

  static log(message: string, ...args: any[]) {
    Logger.defaultInstance.log(message, ...args);
  }

  static warn(message: string, ...args: any[]) {
    Logger.defaultInstance.warn(message, ...args);
  }

  static error(message: string, ...args: any[]) {
    Logger.defaultInstance.error(message, ...args);
  }
}
