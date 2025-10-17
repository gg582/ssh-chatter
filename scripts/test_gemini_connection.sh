#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${GEMINI_API_KEY:-}" ]]; then
  echo "GEMINI_API_KEY is not set. Please export your Gemini API key before running this check." >&2
  exit 2
fi

BASE_URL="${GEMINI_API_BASE:-${GEMINI_BASE_URL:-https://generativelanguage.googleapis.com/v1beta}}"
MODEL="${GEMINI_MODEL:-gemini-2.5-flash}"

URL_SUFFIX="models/${MODEL}:generateContent"
if [[ "${BASE_URL}" != */ ]]; then
  URL="${BASE_URL}/${URL_SUFFIX}?key=${GEMINI_API_KEY}"
else
  URL="${BASE_URL}${URL_SUFFIX}?key=${GEMINI_API_KEY}"
fi

PAYLOAD=$(cat <<'JSON'
{
  "system_instruction": {
    "parts": [
      {
        "text": "You are a translation engine that echoes connectivity status as JSON."
      }
    ]
  },
  "contents": [
    {
      "parts": [
        {
          "text": "Respond with a JSON object that includes a key connectivity_test whose value is ok if you received this message."
        }
      ]
    }
  ],
  "generationConfig": {
    "responseMimeType": "application/json"
  }
}
JSON
)

HTTP_CODE=$(curl -sS -o /tmp/gemini_test_response.json -w "%{http_code}" \
  -H "Content-Type: application/json" \
  -H "x-goog-api-key: ${GEMINI_API_KEY}" \
  "${URL}" \
  -d "${PAYLOAD}" || true)

if [[ -f /tmp/gemini_test_response.json ]]; then
  cat /tmp/gemini_test_response.json
  printf '\n'
  rm -f /tmp/gemini_test_response.json
else
  echo "(no response body)"
fi

echo "HTTP status: ${HTTP_CODE}"

if [[ "${HTTP_CODE}" != 2* ]]; then
  echo "Gemini connectivity test failed with status ${HTTP_CODE}." >&2
  exit 1
fi
