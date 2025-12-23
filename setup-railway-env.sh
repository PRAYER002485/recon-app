#!/bin/bash

# Script to set Railway environment variables via CLI
# Requires Railway CLI to be installed and authenticated
# Install: npm i -g @railway/cli
# Login: railway login

echo "🚀 Setting up Railway environment variables for reputation API..."

# Check if Railway CLI is installed
if ! command -v railway &> /dev/null; then
    echo "❌ Railway CLI not found. Install it with: npm i -g @railway/cli"
    echo "   Then login with: railway login"
    exit 1
fi

# Check if logged in
if ! railway whoami &> /dev/null; then
    echo "❌ Not logged in to Railway. Run: railway login"
    exit 1
fi

echo ""
echo "📝 Setting VIRUSTOTAL_API_KEY..."
railway variables set VIRUSTOTAL_API_KEY=413f56941af6e94c585694b70ff0c670f8aa9383d51553ab149a4019df3fd7c1

echo ""
echo "📝 Setting GSB_API_KEY..."
railway variables set GSB_API_KEY=AIzaSyBd8wbNBwd0hTh7UuyL8mn6Jd5sipWIoJY

echo ""
echo "✅ Environment variables set successfully!"
echo ""
echo "🔄 Railway will automatically redeploy your service."
echo "⏳ Wait 1-2 minutes for the deployment to complete."
echo ""
echo "🧪 Test the reputation feature after deployment completes."

