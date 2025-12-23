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
