"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.useAuth = useAuth;
var tslib_1 = require("tslib");
var react_1 = require("react");
function useAuth(authSDK) {
    var _this = this;
    var _a = (0, react_1.useState)(authSDK.getState()), authState = _a[0], setAuthState = _a[1];
    (0, react_1.useEffect)(function () {
        // Suscribirse a cambios de estado
        var unsubscribe = function (newState) {
            setAuthState(newState);
        };
        // Configurar callback
        var currentCallbacks = authSDK['callbacks'];
        var originalCallback = currentCallbacks.onAuthStateChanged;
        currentCallbacks.onAuthStateChanged = function (state) {
            unsubscribe(state);
            originalCallback === null || originalCallback === void 0 ? void 0 : originalCallback(state);
        };
        // Cleanup
        return function () {
            currentCallbacks.onAuthStateChanged = originalCallback;
        };
    }, [authSDK]);
    var login = (0, react_1.useCallback)(function (credentials) { return tslib_1.__awaiter(_this, void 0, void 0, function () {
        return tslib_1.__generator(this, function (_a) {
            return [2 /*return*/, authSDK.login(credentials)];
        });
    }); }, [authSDK]);
    var register = (0, react_1.useCallback)(function (userData) { return tslib_1.__awaiter(_this, void 0, void 0, function () {
        return tslib_1.__generator(this, function (_a) {
            return [2 /*return*/, authSDK.register(userData)];
        });
    }); }, [authSDK]);
    var logout = (0, react_1.useCallback)(function () { return tslib_1.__awaiter(_this, void 0, void 0, function () {
        return tslib_1.__generator(this, function (_a) {
            return [2 /*return*/, authSDK.logout()];
        });
    }); }, [authSDK]);
    return tslib_1.__assign(tslib_1.__assign({}, authState), { login: login, register: register, logout: logout, getAuthHeaders: authSDK.getAuthHeaders.bind(authSDK), getValidAccessToken: authSDK.getValidAccessToken.bind(authSDK) });
}
