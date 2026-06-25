#!/usr/bin/env bash
set -euo pipefail

# Smoke-test garak REST generator end-to-end against a local stub endpoint.
# This validates:
# - garak is runnable (python -m garak)
# - rest.RestGenerator can POST JSON and extract response via JSONPath
# - report JSONL is produced
#
# Requirements:
# - python3
# - garak available either system-wide OR via backend/tools/garak_py (PYTHONPATH install)
#
# Usage:
#   cd backend
#   ./scripts/garak_rest_smoketest.sh

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .garak_state/home .garak_state/cache .garak_state/runs
export HOME="$ROOT_DIR/.garak_state/home"
export XDG_CONFIG_HOME="$ROOT_DIR/.garak_state/home"
export XDG_CACHE_HOME="$ROOT_DIR/.garak_state/cache"

if [[ -d "$ROOT_DIR/tools/garak_py" ]]; then
  export PYTHONPATH="$ROOT_DIR/tools/garak_py${PYTHONPATH:+:$PYTHONPATH}"
fi

PORT=5123
STUB_URL="http://127.0.0.1:${PORT}/"

node -e "
  const http = require('http');
  http.createServer((req,res) => {
    let body='';
    req.on('data', c => body += c);
    req.on('end', () => {
      res.writeHead(200, {'Content-Type':'application/json'});
      // Keep the response shape compatible with the default UI JSONPath: $.bot_response.response
      res.end(JSON.stringify({ bot_response: { response: 'ok' }, raw: body }));
    });
  }).listen(${PORT}, '127.0.0.1', () => console.log('stub chat listening on ${PORT}'));
" &
STUB_PID="$!"

cleanup() {
  kill "$STUB_PID" >/dev/null 2>&1 || true
}
trap cleanup EXIT

GEN_OPTS_FILE="$(mktemp)"
cat > "$GEN_OPTS_FILE" <<EOF
{
  "rest": {
    "RestGenerator": {
      "uri": "${STUB_URL}",
      "method": "post",
      "headers": { "Content-Type": "application/json" },
      "req_template_json_object": { "message": "\$INPUT" },
      "response_json": true,
      "response_json_field": "\$.bot_response.response",
      "request_timeout": 5,
      "verify_ssl": true
    }
  }
}
EOF

REPORT_PREFIX="$ROOT_DIR/.garak_state/runs/rest-smoke-$(date +%s)"

python3 -m garak \
  --target_type rest \
  --probes test.Blank \
  --detectors always.Pass \
  --generations 1 \
  --report_prefix "$REPORT_PREFIX" \
  --generator_option_file "$GEN_OPTS_FILE"

echo
echo "Report JSONL: ${REPORT_PREFIX}.report.jsonl"
echo "Report HTML : ${REPORT_PREFIX}.report.html"


