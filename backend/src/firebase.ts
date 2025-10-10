import { initializeApp } from "firebase/app";
import { getAnalytics, isSupported } from "firebase/analytics";

const firebaseConfig = {
  apiKey: "AIzaSyC4wsZNO1mNe6XK-duwWAEa0qfA3BbTHF0",
  authDomain: "techificail.firebaseapp.com",
  projectId: "techificail",
  storageBucket: "techificail.appspot.com", // likely this, see note below
  messagingSenderId: "40821731391",
  appId: "1:40821731391:web:43d5422417cc1ec533888a",
  measurementId: "G-QDTTLMXJWB"
};
export const app = initializeApp(firebaseConfig);
export const analytics = (typeof globalThis !== "undefined" && typeof (globalThis as any).window !== "undefined")
  ? await (async () => (await isSupported()) ? getAnalytics(app) : undefined)()
  : undefined;