import { initializeApp } from "firebase/app";
import { getAnalytics, isSupported } from "firebase/analytics";

const firebaseConfig = {

  apiKey: "AIzaSyDOKNf--eUaYasLNeT4ZsmhXKZKr9utbSc",

  authDomain: "techificial-38f35.firebaseapp.com",

  projectId: "techificial-38f35",

  storageBucket: "techificial-38f35.firebasestorage.app",

  messagingSenderId: "646954665066",

  appId: "1:646954665066:web:d4e6b7ebdd0d2d4cf13613",

  measurementId: "G-9151ZF48W9"

};

export const app = initializeApp(firebaseConfig);
export const analytics = (typeof globalThis !== "undefined" && typeof (globalThis as any).window !== "undefined")
  ? await (async () => (await isSupported()) ? getAnalytics(app) : undefined)()
  : undefined;