"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.useAuth = exports.AuthSDK = void 0;
// Exportar todo lo público
var AuthSDK_1 = require("./core/AuthSDK");
Object.defineProperty(exports, "AuthSDK", { enumerable: true, get: function () { return AuthSDK_1.AuthSDK; } });
var useAuth_1 = require("./hooks/useAuth");
Object.defineProperty(exports, "useAuth", { enumerable: true, get: function () { return useAuth_1.useAuth; } });
