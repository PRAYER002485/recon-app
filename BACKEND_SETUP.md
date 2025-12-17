# Backend Setup Guide

## 🚀 Quick Start

Your backend is ready to deploy! Follow these steps:

### Step 1: Deploy Backend (Choose one option)

#### Option A: Railway (Recommended - Free)
1. Go to [railway.app](https://railway.app)
2. Sign up with GitHub
3. Click "New Project" → "Deploy from GitHub repo"
4. Select your `recon-app` repository
5. Set **Root Directory** to `backend`
6. Add environment variable:
   - **Name**: `ALLOWED_ORIGINS`
   - **Value**: `https://techificail.web.app,https://techificail.firebaseapp.com`
7. Click "Deploy"
8. Copy the generated URL (e.g., `https://your-app-name.railway.app`)

#### Option B: Render (Alternative - Free)
1. Go to [render.com](https://render.com)
2. Sign up with GitHub
3. Click "New" → "Web Service"
4. Connect your GitHub repository
5. Configure:
   - **Root Directory**: `backend`
   - **Build Command**: `npm install && npm run build`
   - **Start Command**: `npm start`
6. Add environment variable:
   - **Name**: `ALLOWED_ORIGINS`
   - **Value**: `https://techificail.web.app,https://techificail.firebaseapp.com`
7. Deploy and copy the URL

#### Option C: Vercel (Alternative - Free)
1. Go to [vercel.com](https://vercel.com)
2. Sign up with GitHub
3. Import your GitHub repository
4. Configure:
   - **Root Directory**: `backend`
   - **Build Command**: `npm run build`
   - **Output Directory**: `dist`
5. Add environment variable:
   - **Name**: `ALLOWED_ORIGINS`
   - **Value**: `https://techificail.web.app,https://techificail.firebaseapp.com`
6. Deploy and copy the URL

### Step 2: Configure Frontend

Once you have your backend URL, run:

```bash
cd /root/Desktop/Internship/recon-app
./setup-backend.sh https://your-backend-url.railway.app
```

This will:
- Update your frontend environment variables
- Test the backend connection
- Show you the next steps

### Step 3: Deploy Frontend

```bash
cd frontend
npm run build
firebase deploy
```

### Step 4: Test Your App

Visit [https://techificail.web.app](https://techificail.web.app) and try a search!

## 🔧 Manual Configuration

If you prefer to configure manually:

1. **Update frontend environment**:
   ```bash
   echo "VITE_API_BASE=https://your-backend-url.railway.app" > frontend/.env.production
   ```

2. **Build and deploy frontend**:
   ```bash
   cd frontend
   npm run build
   firebase deploy
   ```

## 🐛 Troubleshooting

### CORS Errors
If you see CORS errors, make sure:
- Your backend URL is in the `ALLOWED_ORIGINS` environment variable
- The frontend URL matches exactly (including https://)

### Backend Not Responding
- Check the backend logs in your hosting platform
- Verify the health check endpoint: `https://your-backend-url/api/health`
- Make sure the build completed successfully

### Frontend Still Shows Old URL
- Clear your browser cache
- Make sure you rebuilt and redeployed the frontend
- Check that `.env.production` has the correct URL

## 📁 Project Structure

```
recon-app/
├── backend/           # Node.js/Express API
│   ├── src/
│   │   └── server.ts # Main server file
│   ├── package.json
│   └── deploy.sh     # Deployment helper
├── frontend/         # React frontend
│   ├── src/
│   │   └── App.tsx   # Main app component
│   └── package.json
└── setup-backend.sh  # Configuration helper
```

## 🔗 API Endpoints

Your backend provides these endpoints:
- `GET /api/health` - Health check
- `POST /api/recon` - Subdomain discovery
- `POST /api/ports` - Port scanning
- `POST /api/nmap` - Nmap scanning
- `POST /api/js-scan` - JavaScript file scanning

All endpoints expect JSON with `{ "target": "domain.com", "mode": "fast" }`
