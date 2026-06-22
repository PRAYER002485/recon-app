# Recon App (subfinder + httpx + naabu + katana)

Full-stack app: Node/Express backend shells out to `subfinder`, `httpx`, `naabu`, and `katana`; React frontend shows an interactive dashboard with sections for Subdomains, Port Scan, and JavaScript scan.

## Prereqs
- Linux with the following tools installed and on `$PATH`:
  - `subfinder`
  - `httpx`
  - `naabu`
  - `katana`
  - `curl` (used for lightweight JS content fetch)
  - Install via Go or project releases.
  - Example:
    ```bash
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest
    ```
    Ensure `~/go/bin` is in your PATH.

## Run backend
```bash
cd backend
npm run dev
# listens on http://localhost:4000
```  FRONTEND_ORIGIN=http://localhost:5173 npm run dev

## Run frontend
```bash
cd frontend
npm run dev
# open the Vite URL (default http://localhost:5173)
```

## Garak (LLM vulnerability scan)

This app exposes `POST /api/garak-scan` which runs [`garak`](https://github.com/NVIDIA/garak) on the **backend** (so your browser never talks to the target chatbot directly, avoiding CORS/`NetworkError`). The recommended way to scan a custom chatbot endpoint is to use garak’s REST generator (`rest.RestGenerator`) and provide:

- the target URL (e.g. `https://hacktheagent.com/api/chat`)
- required headers (cookies/session tokens, content-type, etc.)
- a request JSON template containing `"$INPUT"` where garak should inject probe prompts
- a response JSONPath like `$.bot_response.response` to extract the chatbot’s answer

### Lightweight local install (no Torch/Transformers)

`garak`’s full dependency set can be large. If you only need the REST generator for black-box HTTP endpoint testing, you can install a minimal copy into the repo and run via `PYTHONPATH`:

```bash
cd backend
mkdir -p tools/garak_py
python3 -m pip install --break-system-packages --no-deps --target tools/garak_py garak==0.13.3
python3 -m pip install --break-system-packages --target tools/garak_py xdg-base-dirs==6.0.2 lorem==0.1.1 langdetect==1.0.9
```

The backend auto-detects `backend/tools/garak_py/` and sets garak’s HOME/XDG dirs into `backend/.garak_state/` so it can write reports safely.

## AI Red Teaming (product workflow)

If your goal is to **red team AI systems end-to-end** (inventory → attack coverage → financial impact → blue-team fixes + regression), see:
- `AI_RED_TEAMING_ROADMAP.md`

## Usage
- Enter domain like `example.com` and choose a section in the sidebar.
- Subdomains runs:
  ```bash
  subfinder -silent -d <target> | httpx -silent -json -title -status-code -tech-detect
  ```
- Port Scan runs:
  ```bash
  naabu -host <target> -silent -json -ports 80,443,8080,8000,8443
  # then probes discovered web ports with httpx
  ```
- JavaScript Scan runs:
  ```bash
  katana -u https://<target> -d 3 -jc | grep \.js$
  # live check with httpx -mc 200, then light keyword grep via curl
  ```

## Environment Variables

For Railway deployment, you need to set the following environment variables:

- `VIRUSTOTAL_API_KEY` - VirusTotal API key for reputation checks
- `GSB_API_KEY` - Google Safe Browsing API key for threat detection

See [RAILWAY_ENV_SETUP.md](./RAILWAY_ENV_SETUP.md) for detailed setup instructions.

## Notes
- Long operations are capped at ~2 minutes. Adjust in `backend/src/server.ts` if needed.
- If `httpx`/`naabu` output changes, parsing may need tweaks.
- Security:
  - Backend runs tools without a shell and validates `target` as a domain.
  - Helmet, CORS (configurable `FRONTEND_ORIGIN`), JSON body limit, and per-route rate limiting are enabled.
  - Output is capped and processes time out. Container runs as non-root with a healthcheck.

## Snyk
- Authenticate once: `npx snyk auth`
- Scan backend: `cd backend && npm run snyk:test`
- Monitor backend over time: `npm run snyk:monitor`
- Scan frontend: `cd ../frontend && npm run snyk:test`
- Container scan (Dockerfile): `cd ../backend && npm run snyk:container`

Set CI to run these on pull requests and on a nightly schedule.
# recon-app
