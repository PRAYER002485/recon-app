#!/bin/bash

echo "🔧 Backend Setup Script"
echo "======================="
echo ""

# Check if backend URL is provided
if [ -z "$1" ]; then
    echo "❌ Please provide your backend URL as an argument"
    echo "Usage: ./setup-backend.sh https://your-backend-url.railway.app"
    echo ""
    echo "If you haven't deployed yet, follow these steps:"
    echo "1. Go to https://railway.app"
    echo "2. Sign up with GitHub"
    echo "3. Deploy your backend (see DEPLOYMENT.md for details)"
    echo "4. Copy the backend URL and run this script again"
    exit 1
fi

BACKEND_URL="$1"

echo "✅ Backend URL: $BACKEND_URL"
echo ""

# Update frontend environment
echo "📝 Updating frontend environment..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "VITE_API_BASE=$BACKEND_URL" > "$SCRIPT_DIR/frontend/.env.production"

echo "✅ Frontend environment updated!"
echo ""

# Test backend connection
echo "🔍 Testing backend connection..."
HEALTH_CHECK=$(curl -s "$BACKEND_URL/api/health" 2>/dev/null)

if [ $? -eq 0 ] && echo "$HEALTH_CHECK" | grep -q "ok"; then
    echo "✅ Backend is responding correctly!"
else
    echo "⚠️  Backend health check failed. Please verify your URL is correct."
    echo "   Expected response: {\"status\":\"ok\"}"
    echo "   Got: $HEALTH_CHECK"
fi

echo ""
echo "🚀 Next steps:"
echo "1. Build and deploy your frontend:"
echo "   cd frontend && npm run build"
echo "   firebase deploy"
echo ""
echo "2. Test your app at https://techificail.web.app"
echo ""
echo "3. If you see CORS errors, make sure your backend URL is added to ALLOWED_ORIGINS"
echo "   in your backend environment variables"
