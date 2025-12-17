#!/bin/bash

echo "🚀 Backend Deployment Script"
echo "=============================="
echo ""

echo "📦 Building the project..."
npm run build

if [ $? -ne 0 ]; then
    echo "❌ Build failed!"
    exit 1
fi

echo "✅ Build successful!"
echo ""

echo "🌐 Deployment Options:"
echo "1. Railway (Recommended)"
echo "2. Render"
echo "3. Vercel"
echo ""

echo "For Railway deployment:"
echo "1. Go to https://railway.app"
echo "2. Sign up with GitHub"
echo "3. Click 'New Project' → 'Deploy from GitHub repo'"
echo "4. Select your 'recon-app' repository"
echo "5. Set root directory to 'backend'"
echo "6. Add environment variable: ALLOWED_ORIGINS=https://techificail.web.app,https://techificail.firebaseapp.com"
echo "7. Deploy!"
echo ""

echo "For Render deployment:"
echo "1. Go to https://render.com"
echo "2. Sign up with GitHub"
echo "3. Click 'New' → 'Web Service'"
echo "4. Connect your GitHub repository"
echo "5. Set root directory to 'backend'"
echo "6. Set build command: npm install && npm run build"
echo "7. Set start command: npm start"
echo "8. Add environment variable: ALLOWED_ORIGINS=https://techificail.web.app,https://techificail.firebaseapp.com"
echo "9. Deploy!"
echo ""

echo "For Vercel deployment:"
echo "1. Go to https://vercel.com"
echo "2. Sign up with GitHub"
echo "3. Import your GitHub repository"
echo "4. Set root directory to 'backend'"
echo "5. Set build command: npm run build"
echo "6. Set output directory to 'dist'"
echo "7. Add environment variable: ALLOWED_ORIGINS=https://techificail.web.app,https://techificail.firebaseapp.com"
echo "8. Deploy!"
echo ""

echo "After deployment, you'll get a URL like: https://your-app-name.railway.app"
echo "Copy this URL - you'll need it for the frontend configuration!"
