"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.analytics = exports.app = void 0;
const app_1 = require("firebase/app");
const analytics_1 = require("firebase/analytics");
const firebaseConfig = {
    apiKey: "AIzaSyC4wsZNO1mNe6XK-duwWAEa0qfA3BbTHF0",
    authDomain: "techificail.firebaseapp.com",
    projectId: "techificail",
    storageBucket: "techificail.appspot.com", // likely this, see note below
    messagingSenderId: "40821731391",
    appId: "1:40821731391:web:43d5422417cc1ec533888a",
    measurementId: "G-QDTTLMXJWB"
};
exports.app = (0, app_1.initializeApp)(firebaseConfig);
exports.analytics = (typeof globalThis !== "undefined" && typeof globalThis.window !== "undefined")
    ? await (async () => (await (0, analytics_1.isSupported)()) ? (0, analytics_1.getAnalytics)(exports.app) : undefined)()
    : undefined;
//# sourceMappingURL=firebase.js.map