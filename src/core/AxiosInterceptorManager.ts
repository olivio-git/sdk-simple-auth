import { Logger } from './Logger';

/**
 * AxiosInterceptorManager - Gestiona interceptores de Axios para inyección automática
 * de tokens y manejo de errores de autenticación
 */
export class AxiosInterceptorManager {
  private axiosInstance: any;
  private requestInterceptorId: number | null = null;
  private responseInterceptorId: number | null = null;

  // Concurrency handling
  private isRefreshing = false;
  private failedQueue: Array<{
    resolve: (token: string | null) => void;
    reject: (error: Error) => void;
  }> = [];

  // Callbacks
  private getAccessToken: () => Promise<string | null>;
  private onSessionInvalid: () => void | Promise<void>;
  private onTokenRefresh?: () => Promise<void>;
  private logger: Logger;

  constructor(
    axiosInstance: any,
    callbacks: {
      getAccessToken: () => Promise<string | null>;
      onSessionInvalid: () => void | Promise<void>;
      onTokenRefresh?: () => Promise<void>;
    },
    logger?: Logger
  ) {
    this.axiosInstance = axiosInstance;
    this.getAccessToken = callbacks.getAccessToken;
    this.onSessionInvalid = callbacks.onSessionInvalid;
    this.onTokenRefresh = callbacks.onTokenRefresh;
    this.logger = logger ?? new Logger();
  }

  /**
   * Configurar interceptores de Axios
   */
  setup(options: {
    autoInjectToken?: boolean;
    handleAuthErrors?: boolean;
  } = {}): void {
    const {
      autoInjectToken = true,
      handleAuthErrors = true
    } = options;

    // Verificar que sea una instancia de Axios válida
    if (!this.isAxiosInstance(this.axiosInstance)) {
      this.logger.warn('AxiosInterceptorManager: Invalid Axios instance provided');
      return;
    }

    // Request interceptor - Inyectar token automáticamente
    if (autoInjectToken) {
      this.requestInterceptorId = this.axiosInstance.interceptors.request.use(
        async (config: any) => {
          try {
            const token = await this.getAccessToken();

            if (token) {
              // Solo inyectar si no hay Authorization header ya configurado
              if (!config.headers.Authorization) {
                config.headers.Authorization = `Bearer ${token}`;
                this.logger.debug('AxiosInterceptor: Token injected automatically');
              }
            }
          } catch (error) {
            this.logger.error('AxiosInterceptor: Error getting access token:', error);
          }

          return config;
        },
        (error: any) => {
          return Promise.reject(error);
        }
      );

      this.logger.debug('AxiosInterceptor: Request interceptor configured');
    }

    // Response interceptor - Manejar errores de autenticación
    if (handleAuthErrors) {
      this.responseInterceptorId = this.axiosInstance.interceptors.response.use(
        (response: any) => {
          return response;
        },
        async (error: any) => {
          const originalRequest = error.config;
          const status = error?.response?.status;

          // Detectar errores de autenticación (401)
          if (status === 401) {
            if (!this.onTokenRefresh) {
              await this.handleSessionInvalid(status);
              return Promise.reject(error);
            }

            if (this.isRefreshing) {
              // Si ya se está refrescando, encolar la petición
              this.logger.debug('AxiosInterceptor: Refresh in progress, queuing request');
              return new Promise((resolve, reject) => {
                this.failedQueue.push({ resolve, reject });
              })
                .then((token) => {
                  originalRequest.headers.Authorization = `Bearer ${token}`;
                  return this.axiosInstance.request(originalRequest);
                })
                .catch((err) => {
                  return Promise.reject(err);
                });
            }

            this.isRefreshing = true;
            this.logger.debug('AxiosInterceptor: Authentication error (401), starting refresh...');

            try {
              await this.onTokenRefresh();
              const newToken = await this.getAccessToken();

              if (!newToken) {
                throw new Error('No token available after refresh');
              }

              this.logger.debug('AxiosInterceptor: Token refreshed successfully');
              
              // Procesar cola con el nuevo token
              this.processQueue(null, newToken);
              
              // Reintentar la petición original
              originalRequest.headers.Authorization = `Bearer ${newToken}`;
              return this.axiosInstance.request(originalRequest);

            } catch (refreshError) {
              this.logger.error('AxiosInterceptor: Token refresh failed:', refreshError);
              this.processQueue(refreshError as Error, null);
              await this.handleSessionInvalid(status);
              return Promise.reject(refreshError);
            } finally {
              this.isRefreshing = false;
            }
          }

          // Otros errores de autenticación (403, 422) que no requieren refresh
          if (status === 422 || status === 403) {
             this.logger.warn(`AxiosInterceptor: Auth error (${status}), checking session...`);
             // Opcional: Podríamos validar sesión aquí también
          }

          return Promise.reject(error);
        }
      );

      this.logger.debug('AxiosInterceptor: Response interceptor configured');
    }

    this.logger.debug('Axios interceptors configured successfully');
  }

  /**
   * Procesar cola de peticiones fallidas
   */
  private processQueue(error: Error | null, token: string | null = null): void {
    this.logger.debug(`AxiosInterceptor: Processing queue (${this.failedQueue.length} requests)`);
    
    this.failedQueue.forEach((prom) => {
      if (error) {
        prom.reject(error);
      } else {
        prom.resolve(token);
      }
    });

    this.failedQueue = [];
  }

  /**
   * Manejar sesión inválida
   */
  private async handleSessionInvalid(status: number): Promise<void> {
    this.logger.warn(`AxiosInterceptor: Session invalid (HTTP ${status}), triggering logout`);
    await this.onSessionInvalid();
  }

  /**
   * Remover interceptores
   */
  remove(): void {
    if (!this.axiosInstance?.interceptors) {
      return;
    }

    if (this.requestInterceptorId !== null) {
      this.axiosInstance.interceptors.request.eject(this.requestInterceptorId);
      this.requestInterceptorId = null;
      this.logger.debug('AxiosInterceptor: Request interceptor removed');
    }

    if (this.responseInterceptorId !== null) {
      this.axiosInstance.interceptors.response.eject(this.responseInterceptorId);
      this.responseInterceptorId = null;
      this.logger.debug('AxiosInterceptor: Response interceptor removed');
    }

    this.logger.debug('Axios interceptors removed');
  }

  /**
   * Verificar si es una instancia válida de Axios
   */
  private isAxiosInstance(instance: any): boolean {
    return (
      instance &&
      instance.interceptors &&
      typeof instance.interceptors.request?.use === 'function' &&
      typeof instance.interceptors.response?.use === 'function' &&
      typeof instance.request === 'function'
    );
  }

  /**
   * Verificar si los interceptores están activos
   */
  isActive(): boolean {
    return this.requestInterceptorId !== null || this.responseInterceptorId !== null;
  }

  /**
   * Obtener información de estado
   */
  getStatus(): {
    isActive: boolean;
    hasRequestInterceptor: boolean;
    hasResponseInterceptor: boolean;
  } {
    return {
      isActive: this.isActive(),
      hasRequestInterceptor: this.requestInterceptorId !== null,
      hasResponseInterceptor: this.responseInterceptorId !== null
    };
  }
}
