# ADR 0005: The reference bridge is TypeScript on Node 22, with no runtime dependencies

**Status:** accepted, 2026-11-03

## Question

Issue #21 leaves the bridge's stack open: TypeScript on Node 22 LTS, or Python 3.12. Which one, and with which
dependencies? The bridge is small (two routes for WordPress, one callback route for the verifier, one FireFly call
per decision) but it is the component that sees credentials and holds the WordPress token, so what it pulls in
matters more than what it does.

## Comparison

| | TypeScript on Node 22 | Python 3.12 |
|---|---|---|
| HTTP server in the standard library | `node:http`, production-grade behind a reverse proxy | `http.server` is documented as not for production; a real server means FastAPI/uvicorn or aiohttp |
| HTTP client with timeouts | global `fetch` with `AbortSignal.timeout()` | `urllib` blocks; `httpx` or `aiohttp` are dependencies |
| SHA-256, constant-time compare, randomness | `node:crypto` | `hashlib`, `hmac`, `secrets` |
| Test runner | `node:test`, built in | `unittest` built in; `pytest` is the convention |
| Static types | TypeScript, checked when the image is built | type hints plus `mypy` as a dependency |
| Runtime packages needed for the above | none | at least a web framework and its tree |
| Already in this repository | `package.json` (QR encoder vendoring), `assets/js/login.js` | nothing |

## Decision

TypeScript, compiled by `tsc` to plain ES2022 modules and run on Node 22 LTS, with **no runtime dependencies**.
The only packages are development-time: `typescript` and `@types/node`. Tests use `node:test` against the compiled
output, which is what the container runs.

## Consequences

- The container image holds the compiled JavaScript and nothing from `node_modules`; reviewing the bridge means
  reading `bridge/src`.
- No framework: routing is a few patterns in `server.ts`, JSON bodies are size-limited by hand, and there is no
  dependency to keep patched.
- Contributors need Node 22 (`npm ci && npm test` in `bridge/`); the plugin's PHP toolchain is untouched.
- The contract in [BRIDGE-API.md](../BRIDGE-API.md) is language-neutral, so a second bridge in Python (for
  example around a different verifier) stays possible without touching the plugin.
