#!/bin/bash

# Recon App Deployment Script
# This script helps you deploy the recon-app step by step

set -e

echo "🚀 Recon App Deployment Helper"
echo "=============================="
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if backend URL is provided
if [ -z "$1" ]; then
    echo -e "${YELLOW}⚠️  No backend URL provided${NC}"
    echo ""
    echo "Usage: ./deploy.sh <backend-url>"
    echo "Example: ./deploy.sh https://your-app-name.railway.app"
    echo ""
    echo "If you haven't deployed your backend yet:"
    echo "1. Follow the instructions in DEPLOYMENT_GUIDE.md"
    echo "2. Deploy backend to Railway/Render/Vercel"
    echo "3. Get your backend URL"
    echo "4. Run this script again with the URL"
    exit 1
fi

BACKEND_URL="$1"

# Validate URL format
if [[ ! "$BACKEND_URL" =~ ^https?:// ]]; then
    echo -e "${RED}❌ Invalid URL format. Must start with http:// or https://${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Backend URL: $BACKEND_URL${NC}"
echo ""

# Step 1: Update frontend environment
echo "📝 Step 1: Updating frontend environment..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/frontend/.env.production"

echo "VITE_API_BASE=$BACKEND_URL" > "$ENV_FILE"
echo -e "${GREEN}✅ Created/Updated: $ENV_FILE${NC}"
echo ""

# Step 2: Test backend connection
echo "🔍 Step 2: Testing backend connection..."
HEALTH_URL="$BACKEND_URL/api/health"
HEALTH_CHECK=$(curl -s "$HEALTH_URL" 2>/dev/null || echo "")

if [ $? -eq 0 ] && echo "$HEALTH_CHECK" | grep -q "ok"; then
    echo -e "${GREEN}✅ Backend is responding correctly!${NC}"
else
    echo -e "${YELLOW}⚠️  Backend health check failed${NC}"
    echo "   URL: $HEALTH_URL"
    echo "   Response: $HEALTH_CHECK"
    echo "   This might be okay if the backend is still deploying..."
    echo ""
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi
echo ""

# Step 3: Build frontend
echo "🔨 Step 3: Building frontend..."
cd "$SCRIPT_DIR/frontend"

if [ ! -d "node_modules" ]; then
    echo "📦 Installing dependencies..."
    npm install
fi

echo "🏗️  Building production bundle..."
npm run build

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Frontend built successfully!${NC}"
else
    echo -e "${RED}❌ Frontend build failed!${NC}"
    exit 1
fi
echo ""

# Step 4: Check Firebase login
echo "🔐 Step 4: Checking Firebase authentication..."
if ! firebase projects:list &>/dev/null; then
    echo -e "${YELLOW}⚠️  Not logged in to Firebase${NC}"
    echo "   Please run: firebase login"
    echo ""
    read -p "Login to Firebase now? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        firebase login
    else
        echo "Skipping Firebase deployment. You can deploy manually later with:"
        echo "  firebase deploy --only hosting"
        exit 0
    fi
fi
echo ""

# Step 5: Deploy to Firebase
echo "🚀 Step 5: Deploying to Firebase Hosting..."
cd "$SCRIPT_DIR"

read -p "Deploy to Firebase now? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    firebase deploy --only hosting
    if [ $? -eq 0 ]; then
        echo ""
        echo -e "${GREEN}🎉 Deployment successful!${NC}"
        echo ""
        echo "Your app should be live at:"
        echo "  - https://techificail.web.app"
        echo "  - https://techificail.firebaseapp.com"
        echo ""
        echo "Backend URL: $BACKEND_URL"
    else
        echo -e "${RED}❌ Firebase deployment failed!${NC}"
        exit 1
    fi
else
    echo ""
    echo "Skipping Firebase deployment."
    echo "You can deploy manually later with:"
    echo "  firebase deploy --only hosting"
fi

echo ""
echo "✅ Deployment process complete!"
echo ""
echo "Next steps:"
echo "1. Test your app at https://techificail.web.app"
echo "2. Check browser console for any errors"
echo "3. If you see CORS errors, verify ALLOWED_ORIGINS in backend environment"

