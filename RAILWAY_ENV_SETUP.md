# Railway Environment Variables Setup

This guide explains how to add API keys for the reputation functionality on Railway.

## Required API Keys

The reputation feature requires the following API keys:

1. **VIRUSTOTAL_API_KEY** - VirusTotal API key for domain reputation checks
2. **GSB_API_KEY** - Google Safe Browsing API key for threat detection

## How to Add Environment Variables in Railway

### ⚠️ Important: Service Variables vs Shared Variables

**If you set variables as "Shared Variables"**, they won't automatically be available to your service. You need to set them as **Service Variables** instead.

### Method 1: Railway Dashboard (Recommended)

1. Go to your Railway project: https://railway.app
2. **Select your service** (not the environment/project level)
3. Click on the **Variables** tab (this should show "Service Variables", not "Shared Variables")
4. Click **+ New Variable** for each key:

   **Variable 1:**
   - Name: `VIRUSTOTAL_API_KEY`
   - Value: `413f56941af6e94c585694b70ff0c670f8aa9383d51553ab149a4019df3fd7c1`
   - Click **Add**

   **Variable 2:**
   - Name: `GSB_API_KEY`
   - Value: `AIzaSyBd8wbNBwd0hTh7UuyL8mn6Jd5sipWIoJY`
   - Click **Add**

5. Railway will automatically redeploy your service after adding variables

### If You Already Set Them as Shared Variables

If you already added them as "Shared Variables", you have two options:

**Option A: Move to Service Variables (Recommended)**
1. Go to your service (not the environment)
2. Click **Variables** tab
3. Add the variables again as **Service Variables** (not shared)
4. You can delete the shared ones if you want

**Option B: Reference Shared Variables**
1. In your service's Variables tab
2. Add a new variable with name `VIRUSTOTAL_API_KEY`
3. For the value, use: `${{Shared.VIRUSTOTAL_API_KEY}}`
4. Repeat for `GSB_API_KEY` using `${{Shared.GSB_API_KEY}}`

### Method 2: Railway CLI

If you have Railway CLI installed:

```bash
railway variables set VIRUSTOTAL_API_KEY=413f56941af6e94c585694b70ff0c670f8aa9383d51553ab149a4019df3fd7c1
railway variables set GSB_API_KEY=AIzaSyBd8wbNBwd0hTh7UuyL8mn6Jd5sipWIoJY
```

## Verification

After setting the variables:

1. Wait for Railway to redeploy (usually takes 1-2 minutes)
2. **Debug check**: Visit `https://your-railway-url.railway.app/api/debug/env` to verify the variables are loaded
   - You should see `hasVtKey: true` and `hasGsbKey: true`
3. Visit your deployed app
4. Go to the **Reputation** section
5. Enter a domain (e.g., `21wickets.com`)
6. You should now see results from VirusTotal and Google Safe Browsing instead of the "No API keys configured" message

## Current API Keys

- **VirusTotal API Key**: `413f56941af6e94c585694b70ff0c670f8aa9383d51553ab149a4019df3fd7c1`
- **Google Safe Browsing API Key**: `AIzaSyBd8wbNBwd0hTh7UuyL8mn6Jd5sipWIoJY`

## Notes

- Environment variables are encrypted and secure in Railway
- Changes take effect after the service redeploys
- You can verify variables are set by checking the Variables tab in Railway dashboard

