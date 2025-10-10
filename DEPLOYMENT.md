# Backend Deployment Guide

## Option 1: Railway (Recommended - Free)

### Step 1: Create Railway Account
1. Go to [railway.app](https://railway.app)
2. Sign up with GitHub
3. Connect your GitHub account

### Step 2: Deploy Backend
1. In Railway dashboard, click "New Project"
2. Select "Deploy from GitHub repo"
3. Choose your repository: `recon-app`
4. Select the `backend` folder as the root directory
5. Railway will automatically detect it's a Node.js project
6. Set environment variables:
   - `ALLOWED_ORIGINS`: `https://techificail.web.app,https://techificail.firebaseapp.com`
7. Deploy!

### Step 3: Get Backend URL
After deployment, Railway will give you a URL like: `https://your-app-name.railway.app`

## Option 2: Render (Alternative - Free)

### Step 1: Create Render Account
1. Go to [render.com](https://render.com)
2. Sign up with GitHub

### Step 2: Deploy Backend
1. Click "New" → "Web Service"
2. Connect your GitHub repository
3. Configure:
   - **Root Directory**: `backend`
   - **Build Command**: `npm install && npm run build`
   - **Start Command**: `npm start`
4. Set environment variables:
   - `ALLOWED_ORIGINS`: `https://techificail.web.app,https://techificail.firebaseapp.com`
5. Deploy!

## Option 3: Vercel (Alternative - Free)

### Step 1: Create Vercel Account
1. Go to [vercel.com](https://vercel.com)
2. Sign up with GitHub

### Step 2: Deploy Backend
1. Import your GitHub repository
2. Configure:
   - **Root Directory**: `backend`
   - **Build Command**: `npm run build`
   - **Output Directory**: `dist`
3. Set environment variables in Vercel dashboard
4. Deploy!

## After Deployment

Once you have your backend URL (e.g., `https://your-backend.railway.app`), you need to:

1. Update your frontend environment variables
2. Redeploy your frontend to Firebase

See the next steps in the main README.
