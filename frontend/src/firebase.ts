import { initializeApp, type FirebaseApp } from 'firebase/app';
import { getAnalytics, isSupported } from 'firebase/analytics';

const firebaseConfig = {
  apiKey: 'AIzaSyBWdc6fPO6DxYC5dQG8lqUuMWlMW9LsA_s',
  authDomain: 'recon-app-e6d89.firebaseapp.com',
  projectId: 'recon-app-e6d89',
  storageBucket: 'recon-app-e6d89.firebasestorage.app',
  messagingSenderId: '174790385035',
  appId: '1:174790385035:web:5d9294af439d70d3f8a38e',
  measurementId: 'G-PV9EM2R7ZB',
};

const app: FirebaseApp = initializeApp(firebaseConfig);

// Only initialize Analytics when explicitly enabled
const enableAnalytics = (import.meta as any).env?.VITE_ENABLE_ANALYTICS === 'true'
if (enableAnalytics && typeof window !== 'undefined') {
  isSupported().then((ok) => { if (ok) getAnalytics(app); });
}

export { app };