"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthSDK = void 0;
var tslib_1 = require("tslib");
var AuthSDK = /** @class */ (function () {
    function AuthSDK(config, callbacks) {
        this.refreshTimer = null;
        this.isRefreshing = false;
        this.refreshPromise = null;
        // Configuración por defecto
        this.config = {
            authServiceUrl: config.authServiceUrl,
            endpoints: tslib_1.__assign({ login: '/auth/login', register: '/auth/register', refresh: '/auth/refresh', logout: '/auth/logout', profile: '/auth/profile' }, config.endpoints),
            storage: tslib_1.__assign({ tokenKey: 'auth_access_token', refreshTokenKey: 'auth_refresh_token', userKey: 'auth_user' }, config.storage),
            tokenRefresh: tslib_1.__assign({ enabled: true, bufferTime: 300, maxRetries: 3 }, config.tokenRefresh),
            httpClient: config.httpClient || this.createDefaultFetchClient(),
        };
        this.callbacks = callbacks || {};
        // Estado inicial
        this.state = {
            isAuthenticated: false,
            user: null,
            tokens: null,
            loading: false,
            error: null,
        };
        // Inicializar desde storage
        this.initializeFromStorage();
    }
    // Cliente HTTP por defecto usando fetch
    AuthSDK.prototype.createDefaultFetchClient = function () {
        return {
            post: function (url, data, config) {
                return tslib_1.__awaiter(this, void 0, void 0, function () {
                    var response, error;
                    return tslib_1.__generator(this, function (_a) {
                        switch (_a.label) {
                            case 0: return [4 /*yield*/, fetch(url, tslib_1.__assign({ method: 'POST', headers: tslib_1.__assign({ 'Content-Type': 'application/json' }, config === null || config === void 0 ? void 0 : config.headers), body: data ? JSON.stringify(data) : undefined }, config))];
                            case 1:
                                response = _a.sent();
                                if (!!response.ok) return [3 /*break*/, 3];
                                return [4 /*yield*/, response.json().catch(function () { return ({ message: 'Request failed' }); })];
                            case 2:
                                error = _a.sent();
                                throw new Error(error.message || "HTTP ".concat(response.status));
                            case 3: return [2 /*return*/, response.json()];
                        }
                    });
                });
            },
            get: function (url, config) {
                return tslib_1.__awaiter(this, void 0, void 0, function () {
                    var response, error;
                    return tslib_1.__generator(this, function (_a) {
                        switch (_a.label) {
                            case 0: return [4 /*yield*/, fetch(url, tslib_1.__assign({ method: 'GET', headers: tslib_1.__assign({ 'Content-Type': 'application/json' }, config === null || config === void 0 ? void 0 : config.headers) }, config))];
                            case 1:
                                response = _a.sent();
                                if (!!response.ok) return [3 /*break*/, 3];
                                return [4 /*yield*/, response.json().catch(function () { return ({ message: 'Request failed' }); })];
                            case 2:
                                error = _a.sent();
                                throw new Error(error.message || "HTTP ".concat(response.status));
                            case 3: return [2 /*return*/, response.json()];
                        }
                    });
                });
            },
            put: function (url, data, config) {
                return tslib_1.__awaiter(this, void 0, void 0, function () {
                    var response, error;
                    return tslib_1.__generator(this, function (_a) {
                        switch (_a.label) {
                            case 0: return [4 /*yield*/, fetch(url, tslib_1.__assign({ method: 'PUT', headers: tslib_1.__assign({ 'Content-Type': 'application/json' }, config === null || config === void 0 ? void 0 : config.headers), body: data ? JSON.stringify(data) : undefined }, config))];
                            case 1:
                                response = _a.sent();
                                if (!!response.ok) return [3 /*break*/, 3];
                                return [4 /*yield*/, response.json().catch(function () { return ({ message: 'Request failed' }); })];
                            case 2:
                                error = _a.sent();
                                throw new Error(error.message || "HTTP ".concat(response.status));
                            case 3: return [2 /*return*/, response.json()];
                        }
                    });
                });
            },
            delete: function (url, config) {
                return tslib_1.__awaiter(this, void 0, void 0, function () {
                    var response, error;
                    return tslib_1.__generator(this, function (_a) {
                        switch (_a.label) {
                            case 0: return [4 /*yield*/, fetch(url, tslib_1.__assign({ method: 'DELETE', headers: tslib_1.__assign({ 'Content-Type': 'application/json' }, config === null || config === void 0 ? void 0 : config.headers) }, config))];
                            case 1:
                                response = _a.sent();
                                if (!!response.ok) return [3 /*break*/, 3];
                                return [4 /*yield*/, response.json().catch(function () { return ({ message: 'Request failed' }); })];
                            case 2:
                                error = _a.sent();
                                throw new Error(error.message || "HTTP ".concat(response.status));
                            case 3: return [2 /*return*/, response.json()];
                        }
                    });
                });
            },
        };
    };
    // Inicializar desde localStorage
    AuthSDK.prototype.initializeFromStorage = function () {
        try {
            var storedTokens = this.getStoredTokens();
            var storedUser = this.getStoredUser();
            if (storedTokens && storedUser && this.isTokenValid(storedTokens.accessToken)) {
                this.state = {
                    isAuthenticated: true,
                    user: storedUser,
                    tokens: storedTokens,
                    loading: false,
                    error: null,
                };
                // Programar refresh automático
                if (this.config.tokenRefresh.enabled) {
                    this.scheduleTokenRefresh(storedTokens.accessToken);
                }
                this.notifyStateChange();
            }
            else {
                this.clearStorage();
            }
        }
        catch (error) {
            console.error('Error initializing from storage:', error);
            this.clearStorage();
        }
    };
    // Métodos públicos principales
    AuthSDK.prototype.login = function (credentials) {
        return tslib_1.__awaiter(this, void 0, void 0, function () {
            var url, response, tokens, user, error_1, errorMessage;
            var _a, _b, _c, _d;
            return tslib_1.__generator(this, function (_e) {
                switch (_e.label) {
                    case 0:
                        this.setLoading(true);
                        this.setError(null);
                        _e.label = 1;
                    case 1:
                        _e.trys.push([1, 3, 4, 5]);
                        url = "".concat(this.config.authServiceUrl).concat(this.config.endpoints.login);
                        return [4 /*yield*/, this.config.httpClient.post(url, credentials)];
                    case 2:
                        response = _e.sent();
                        tokens = {
                            accessToken: response.access_token || response.accessToken,
                            refreshToken: response.refresh_token || response.refreshToken,
                            expiresIn: response.expires_in || response.expiresIn,
                            tokenType: response.token_type || response.tokenType || 'Bearer',
                        };
                        user = response.user || this.parseTokenPayload(tokens.accessToken);
                        // Guardar en storage
                        this.storeTokens(tokens);
                        this.storeUser(user);
                        // Actualizar estado
                        this.state = {
                            isAuthenticated: true,
                            user: user,
                            tokens: tokens,
                            loading: false,
                            error: null,
                        };
                        // Programar refresh automático
                        if (this.config.tokenRefresh.enabled) {
                            this.scheduleTokenRefresh(tokens.accessToken);
                        }
                        this.notifyStateChange();
                        (_b = (_a = this.callbacks).onLogin) === null || _b === void 0 ? void 0 : _b.call(_a, user, tokens);
                        return [2 /*return*/, user];
                    case 3:
                        error_1 = _e.sent();
                        errorMessage = error_1 instanceof Error ? error_1.message : 'Login failed';
                        this.setError(errorMessage);
                        (_d = (_c = this.callbacks).onError) === null || _d === void 0 ? void 0 : _d.call(_c, errorMessage);
                        throw error_1;
                    case 4:
                        this.setLoading(false);
                        return [7 /*endfinally*/];
                    case 5: return [2 /*return*/];
                }
            });
        });
    };
    AuthSDK.prototype.register = function (userData) {
        return tslib_1.__awaiter(this, void 0, void 0, function () {
            var url, response, tokens, user, error_2, errorMessage;
            var _a, _b, _c, _d;
            return tslib_1.__generator(this, function (_e) {
                switch (_e.label) {
                    case 0:
                        this.setLoading(true);
                        this.setError(null);
                        _e.label = 1;
                    case 1:
                        _e.trys.push([1, 3, 4, 5]);
                        url = "".concat(this.config.authServiceUrl).concat(this.config.endpoints.register);
                        return [4 /*yield*/, this.config.httpClient.post(url, userData)];
                    case 2:
                        response = _e.sent();
                        // Después del registro, hacer login automático si se devuelven tokens
                        if (response.access_token || response.accessToken) {
                            tokens = {
                                accessToken: response.access_token || response.accessToken,
                                refreshToken: response.refresh_token || response.refreshToken,
                                expiresIn: response.expires_in || response.expiresIn,
                                tokenType: response.token_type || response.tokenType || 'Bearer',
                            };
                            user = response.user || this.parseTokenPayload(tokens.accessToken);
                            this.storeTokens(tokens);
                            this.storeUser(user);
                            this.state = {
                                isAuthenticated: true,
                                user: user,
                                tokens: tokens,
                                loading: false,
                                error: null,
                            };
                            if (this.config.tokenRefresh.enabled) {
                                this.scheduleTokenRefresh(tokens.accessToken);
                            }
                            this.notifyStateChange();
                            (_b = (_a = this.callbacks).onLogin) === null || _b === void 0 ? void 0 : _b.call(_a, user, tokens);
                            return [2 /*return*/, user];
                        }
                        return [2 /*return*/, response.user];
                    case 3:
                        error_2 = _e.sent();
                        errorMessage = error_2 instanceof Error ? error_2.message : 'Registration failed';
                        this.setError(errorMessage);
                        (_d = (_c = this.callbacks).onError) === null || _d === void 0 ? void 0 : _d.call(_c, errorMessage);
                        throw error_2;
                    case 4:
                        this.setLoading(false);
                        return [7 /*endfinally*/];
                    case 5: return [2 /*return*/];
                }
            });
        });
    };
    AuthSDK.prototype.logout = function () {
        return tslib_1.__awaiter(this, void 0, void 0, function () {
            var url;
            var _a, _b, _c;
            return tslib_1.__generator(this, function (_d) {
                switch (_d.label) {
                    case 0:
                        _d.trys.push([0, , 3, 4]);
                        if (!((_a = this.state.tokens) === null || _a === void 0 ? void 0 : _a.accessToken)) return [3 /*break*/, 2];
                        url = "".concat(this.config.authServiceUrl).concat(this.config.endpoints.logout);
                        return [4 /*yield*/, this.config.httpClient.post(url, {}, {
                                headers: {
                                    Authorization: "Bearer ".concat(this.state.tokens.accessToken),
                                },
                            }).catch(function () {
                                // Ignorar errores del servidor en logout
                            })];
                    case 1:
                        _d.sent();
                        _d.label = 2;
                    case 2: return [3 /*break*/, 4];
                    case 3:
                        // Limpiar estado local siempre
                        this.clearStorage();
                        this.clearRefreshTimer();
                        this.state = {
                            isAuthenticated: false,
                            user: null,
                            tokens: null,
                            loading: false,
                            error: null,
                        };
                        this.notifyStateChange();
                        (_c = (_b = this.callbacks).onLogout) === null || _c === void 0 ? void 0 : _c.call(_b);
                        return [7 /*endfinally*/];
                    case 4: return [2 /*return*/];
                }
            });
        });
    };
    AuthSDK.prototype.refreshTokens = function () {
        return tslib_1.__awaiter(this, void 0, void 0, function () {
            var tokens;
            return tslib_1.__generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        // Evitar múltiples refreshes simultáneos
                        if (this.isRefreshing && this.refreshPromise) {
                            return [2 /*return*/, this.refreshPromise];
                        }
                        this.isRefreshing = true;
                        this.refreshPromise = this.performTokenRefresh();
                        _a.label = 1;
                    case 1:
                        _a.trys.push([1, , 3, 4]);
                        return [4 /*yield*/, this.refreshPromise];
                    case 2:
                        tokens = _a.sent();
                        return [2 /*return*/, tokens];
                    case 3:
                        this.isRefreshing = false;
                        this.refreshPromise = null;
                        return [7 /*endfinally*/];
                    case 4: return [2 /*return*/];
                }
            });
        });
    };
    AuthSDK.prototype.performTokenRefresh = function () {
        return tslib_1.__awaiter(this, void 0, void 0, function () {
            var refreshToken, url, response, tokens, error_3;
            var _a, _b, _c;
            return tslib_1.__generator(this, function (_d) {
                switch (_d.label) {
                    case 0:
                        refreshToken = (_a = this.state.tokens) === null || _a === void 0 ? void 0 : _a.refreshToken;
                        if (!refreshToken) {
                            throw new Error('No refresh token available');
                        }
                        _d.label = 1;
                    case 1:
                        _d.trys.push([1, 3, , 5]);
                        url = "".concat(this.config.authServiceUrl).concat(this.config.endpoints.refresh);
                        return [4 /*yield*/, this.config.httpClient.post(url, {
                                refresh_token: refreshToken,
                            })];
                    case 2:
                        response = _d.sent();
                        tokens = {
                            accessToken: response.access_token || response.accessToken,
                            refreshToken: response.refresh_token || response.refreshToken || refreshToken,
                            expiresIn: response.expires_in || response.expiresIn,
                            tokenType: response.token_type || response.tokenType || 'Bearer',
                        };
                        // Actualizar storage y estado
                        this.storeTokens(tokens);
                        this.state.tokens = tokens;
                        // Programar próximo refresh
                        if (this.config.tokenRefresh.enabled) {
                            this.scheduleTokenRefresh(tokens.accessToken);
                        }
                        this.notifyStateChange();
                        (_c = (_b = this.callbacks).onTokenRefresh) === null || _c === void 0 ? void 0 : _c.call(_b, tokens);
                        return [2 /*return*/, tokens];
                    case 3:
                        error_3 = _d.sent();
                        // Si falla el refresh, hacer logout
                        return [4 /*yield*/, this.logout()];
                    case 4:
                        // Si falla el refresh, hacer logout
                        _d.sent();
                        throw error_3;
                    case 5: return [2 /*return*/];
                }
            });
        });
    };
    // Métodos de utilidad públicos
    AuthSDK.prototype.getState = function () {
        return tslib_1.__assign({}, this.state);
    };
    AuthSDK.prototype.getCurrentUser = function () {
        return this.state.user;
    };
    AuthSDK.prototype.getAccessToken = function () {
        var _a;
        return ((_a = this.state.tokens) === null || _a === void 0 ? void 0 : _a.accessToken) || null;
    };
    AuthSDK.prototype.isAuthenticated = function () {
        var _a;
        return this.state.isAuthenticated && this.isTokenValid((_a = this.state.tokens) === null || _a === void 0 ? void 0 : _a.accessToken);
    };
    AuthSDK.prototype.getValidAccessToken = function () {
        return tslib_1.__awaiter(this, void 0, void 0, function () {
            var tokens, error_4;
            var _a;
            return tslib_1.__generator(this, function (_b) {
                switch (_b.label) {
                    case 0:
                        if (!((_a = this.state.tokens) === null || _a === void 0 ? void 0 : _a.accessToken)) {
                            return [2 /*return*/, null];
                        }
                        if (!this.shouldRefreshToken(this.state.tokens.accessToken)) return [3 /*break*/, 4];
                        _b.label = 1;
                    case 1:
                        _b.trys.push([1, 3, , 4]);
                        return [4 /*yield*/, this.refreshTokens()];
                    case 2:
                        tokens = _b.sent();
                        return [2 /*return*/, tokens.accessToken];
                    case 3:
                        error_4 = _b.sent();
                        return [2 /*return*/, null];
                    case 4: return [2 /*return*/, this.state.tokens.accessToken];
                }
            });
        });
    };
    // Métodos para integración con otros clientes HTTP
    AuthSDK.prototype.getAuthHeaders = function () {
        return tslib_1.__awaiter(this, void 0, void 0, function () {
            var token;
            return tslib_1.__generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.getValidAccessToken()];
                    case 1:
                        token = _a.sent();
                        if (!token) {
                            throw new Error('No valid authentication token');
                        }
                        return [2 /*return*/, {
                                Authorization: "Bearer ".concat(token),
                            }];
                }
            });
        });
    };
    // Métodos privados de utilidad
    AuthSDK.prototype.isTokenValid = function (token) {
        if (!token)
            return false;
        try {
            var payload = this.parseTokenPayload(token);
            var now = Math.floor(Date.now() / 1000);
            return payload.exp > now;
        }
        catch (_a) {
            return false;
        }
    };
    AuthSDK.prototype.shouldRefreshToken = function (token) {
        try {
            var payload = this.parseTokenPayload(token);
            var now = Math.floor(Date.now() / 1000);
            return payload.exp - now < this.config.tokenRefresh.bufferTime;
        }
        catch (_a) {
            return false;
        }
    };
    AuthSDK.prototype.parseTokenPayload = function (token) {
        var base64Payload = token.split('.')[1];
        var payload = JSON.parse(atob(base64Payload));
        return payload;
    };
    AuthSDK.prototype.scheduleTokenRefresh = function (token) {
        var _this = this;
        this.clearRefreshTimer();
        try {
            var payload = this.parseTokenPayload(token);
            var now = Math.floor(Date.now() / 1000);
            var timeUntilRefresh = (payload.exp - now - this.config.tokenRefresh.bufferTime) * 1000;
            if (timeUntilRefresh > 0) {
                this.refreshTimer = setTimeout(function () {
                    _this.refreshTokens().catch(console.error);
                }, timeUntilRefresh);
            }
        }
        catch (error) {
            console.error('Error scheduling token refresh:', error);
        }
    };
    AuthSDK.prototype.clearRefreshTimer = function () {
        if (this.refreshTimer) {
            clearTimeout(this.refreshTimer);
            this.refreshTimer = null;
        }
    };
    // Métodos de storage
    AuthSDK.prototype.storeTokens = function (tokens) {
        if (typeof window !== 'undefined') {
            localStorage.setItem(this.config.storage.tokenKey || '', tokens.accessToken || '');
            if (tokens.refreshToken) {
                localStorage.setItem(this.config.storage.refreshTokenKey || '', tokens.refreshToken);
            }
        }
    };
    AuthSDK.prototype.storeUser = function (user) {
        if (typeof window !== 'undefined') {
            localStorage.setItem(this.config.storage.userKey || '', JSON.stringify(user));
        }
    };
    AuthSDK.prototype.getStoredTokens = function () {
        if (typeof window !== 'undefined') {
            var accessToken = localStorage.getItem(this.config.storage.tokenKey || '');
            var refreshToken = localStorage.getItem(this.config.storage.refreshTokenKey || '');
            if (accessToken) {
                return {
                    accessToken: accessToken,
                    refreshToken: refreshToken || undefined,
                };
            }
        }
        return null;
    };
    AuthSDK.prototype.getStoredUser = function () {
        if (typeof window !== 'undefined') {
            var userData = localStorage.getItem(this.config.storage.userKey || '');
            if (userData) {
                try {
                    return JSON.parse(userData);
                }
                catch (_a) {
                    return null;
                }
            }
        }
        return null;
    };
    AuthSDK.prototype.clearStorage = function () {
        if (typeof window !== 'undefined') {
            localStorage.removeItem(this.config.storage.tokenKey || '');
            localStorage.removeItem(this.config.storage.refreshTokenKey || '');
            localStorage.removeItem(this.config.storage.userKey || '');
        }
    };
    // Métodos de estado
    AuthSDK.prototype.setLoading = function (loading) {
        this.state.loading = loading;
        this.notifyStateChange();
    };
    AuthSDK.prototype.setError = function (error) {
        this.state.error = error;
        this.notifyStateChange();
    };
    AuthSDK.prototype.notifyStateChange = function () {
        var _a, _b;
        (_b = (_a = this.callbacks).onAuthStateChanged) === null || _b === void 0 ? void 0 : _b.call(_a, this.getState());
    };
    return AuthSDK;
}());
exports.AuthSDK = AuthSDK;
