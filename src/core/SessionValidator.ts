import { AuthConfig } from '../types';
import { Logger } from './Logger';

/**
 * SessionValidator - Maneja la validación automática de sesiones
 * cuando la app regresa del background o se reactiva
 */
export class SessionValidator {
  private config: Required<AuthConfig>['sessionValidation'];
  private onValidationRequired: () => Promise<boolean>;
  private lastActivityTime: number = Date.now();
  private isListening: boolean = false;
  private logger: Logger;

  // Listeners para limpieza
  private visibilityListener?: () => void;
  private focusListener?: () => void;
  private pageShowListener?: (event: PageTransitionEvent) => void;

  constructor(
    config: Required<AuthConfig>['sessionValidation'],
    onValidationRequired: () => Promise<boolean>,
    logger?: Logger
  ) {
    this.config = {
      enabled: true,
      validateOnFocus: true,
      validateOnVisibility: true,
      maxInactivityTime: 300, // 5 minutos por defecto
      autoLogoutOnInvalid: true,
      ...config
    };
    this.onValidationRequired = onValidationRequired;
    this.logger = logger ?? new Logger();
  }

  /**
   * Iniciar listeners de eventos del DOM
   */
  startListening(): void {
    if (this.isListening || !this.config.enabled) {
      return;
    }

    // Solo funciona en entorno browser
    if (typeof window === 'undefined' || typeof document === 'undefined') {
      this.logger.debug('SessionValidator: Not a browser environment, skipping');
      return;
    }

    // 1. Listener de visibilitychange (cuando cambia de pestaña o minimiza)
    if (this.config.validateOnVisibility) {
      this.visibilityListener = () => this.handleVisibilityChange();
      document.addEventListener('visibilitychange', this.visibilityListener);
      this.logger.debug('SessionValidator: visibilitychange listener added');
    }

    // 2. Listener de focus (cuando la ventana obtiene foco)
    if (this.config.validateOnFocus) {
      this.focusListener = () => this.handleWindowFocus();
      window.addEventListener('focus', this.focusListener);
      this.logger.debug('SessionValidator: focus listener added');
    }

    // 3. Listener de pageshow (cuando la página se muestra desde caché)
    this.pageShowListener = (event: PageTransitionEvent) => this.handlePageShow(event);
    window.addEventListener('pageshow', this.pageShowListener);
    this.logger.debug('SessionValidator: pageshow listener added');

    this.isListening = true;
    this.logger.debug('SessionValidator: Started listening for app lifecycle events');
  }

  /**
   * Detener listeners de eventos
   */
  stopListening(): void {
    if (!this.isListening) {
      return;
    }

    if (typeof window === 'undefined' || typeof document === 'undefined') {
      return;
    }

    if (this.visibilityListener) {
      document.removeEventListener('visibilitychange', this.visibilityListener);
    }

    if (this.focusListener) {
      window.removeEventListener('focus', this.focusListener);
    }

    if (this.pageShowListener) {
      window.removeEventListener('pageshow', this.pageShowListener);
    }

    this.isListening = false;
    this.logger.debug('SessionValidator: Stopped listening for app lifecycle events');
  }

  /**
   * Manejar cambio de visibilidad (pestaña activa/inactiva)
   */
  private async handleVisibilityChange(): Promise<void> {
    if (document.visibilityState === 'visible') {
      this.logger.debug('SessionValidator: App became visible');
      await this.validateIfNeeded('visibility');
    } else {
      this.logger.debug('SessionValidator: App became hidden');
      // Actualizar tiempo de última actividad
      this.lastActivityTime = Date.now();
    }
  }

  /**
   * Manejar foco de ventana
   */
  private async handleWindowFocus(): Promise<void> {
    this.logger.debug('SessionValidator: Window gained focus');
    await this.validateIfNeeded('focus');
  }

  /**
   * Manejar pageshow (incluyendo back/forward cache)
   */
  private async handlePageShow(event: PageTransitionEvent): Promise<void> {
    if (event.persisted) {
      // Página restaurada desde cache (usuario usó back button)
      this.logger.debug('SessionValidator: Page restored from cache');
      await this.validateIfNeeded('pageshow-cached');
    } else {
      this.logger.debug('SessionValidator: Page loaded normally');
      this.lastActivityTime = Date.now();
    }
  }

  /**
   * Validar sesión si es necesario
   */
  private async validateIfNeeded(trigger: string): Promise<void> {
    const now = Date.now();
    const inactiveTime = (now - this.lastActivityTime) / 1000; // en segundos

    this.logger.debug(`SessionValidator: Validation triggered by ${trigger}`);
    this.logger.debug(`SessionValidator: Inactive for ${Math.floor(inactiveTime)}s (max: ${this.config.maxInactivityTime}s)`);

    // Solo validar si ha pasado suficiente tiempo de inactividad
    if (inactiveTime < this.config.maxInactivityTime!) {
      this.logger.debug('SessionValidator: Inactivity time below threshold, skipping validation');
      this.lastActivityTime = now;
      return;
    }

    this.logger.debug('SessionValidator: Performing session validation...');

    try {
      const isValid = await this.onValidationRequired();

      if (isValid) {
        this.logger.debug('SessionValidator: Session is valid');
        this.lastActivityTime = now;
      } else {
        this.logger.warn('SessionValidator: Session is invalid');
        // El callback ya manejará el logout si autoLogoutOnInvalid está habilitado
      }
    } catch (error) {
      this.logger.error('SessionValidator: Validation error:', error);
      // Update activity time to prevent hammering the server on consecutive
      // validation failures (e.g. network errors). Next trigger will retry
      // after the normal inactivity threshold.
      this.lastActivityTime = now;
    }
  }

  /**
   * Actualizar tiempo de última actividad manualmente
   */
  updateLastActivity(): void {
    this.lastActivityTime = Date.now();
  }

  /**
   * Obtener información de estado
   */
  getStatus(): {
    isListening: boolean;
    lastActivityTime: number;
    inactiveSeconds: number;
  } {
    const now = Date.now();
    return {
      isListening: this.isListening,
      lastActivityTime: this.lastActivityTime,
      inactiveSeconds: Math.floor((now - this.lastActivityTime) / 1000)
    };
  }

  /**
   * Forzar validación inmediata
   */
  async forceValidation(): Promise<boolean> {
    this.logger.debug('SessionValidator: Forcing immediate validation');
    try {
      const isValid = await this.onValidationRequired();
      if (isValid) {
        this.lastActivityTime = Date.now();
      }
      return isValid;
    } catch (error) {
      this.logger.error('SessionValidator: Force validation error:', error);
      return false;
    }
  }

  /**
   * Verificar si está disponible en el entorno actual
   */
  static isSupported(): boolean {
    return typeof window !== 'undefined' && typeof document !== 'undefined';
  }
}
