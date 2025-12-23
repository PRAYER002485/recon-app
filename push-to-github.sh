#!/bin/bash

# Script to push changes to GitHub after SSH key is added

cd "$(dirname "$0")"

echo "🔑 Testing SSH connection to GitHub..."
if ssh -T git@github.com 2>&1 | grep -q "successfully authenticated"; then
    echo "✅ SSH authentication successful!"
else
    echo "❌ SSH authentication failed. Please add your SSH key to GitHub first:"
    echo "   1. Go to: https://github.com/settings/keys"
    echo "   2. Click 'New SSH key'"
    echo "   3. Paste this key:"
    echo ""
    cat ~/.ssh/id_ed25519.pub
    echo ""
    exit 1
fi

echo ""
echo "📦 Checking git status..."
git status

echo ""
echo "🚀 Pushing to GitHub..."
git push origin main

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Successfully pushed to GitHub!"
    echo "🔄 Railway should automatically detect and deploy the changes."
else
    echo ""
    echo "❌ Push failed. Check the error above."
    exit 1
fi

