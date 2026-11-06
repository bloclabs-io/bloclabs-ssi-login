/**
 * HTTP surface. Two routes for WordPress (docs/BRIDGE-API.md) behind the static
 * bearer token, one callback route for the verifier behind a per-request token
 * (addressed by verifier session id: a request has one or two), and a health
 * check. Everything else is 404.
 */

import { createServer as createHttpServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';

import type { Bridge } from './bridge.js';
import { HttpError } from './bridge.js';
import { constantTimeEqual } from './crypto.js';
import type { Logger } from './log.js';

const MAX_JSON_BODY = 16 * 1024;
const ID_PATTERN = '([A-Za-z0-9_.-]{1,128})';
const CREATE_ROUTE = /^\/v1\/presentation-requests\/?$/;
const RESULT_ROUTE = new RegExp(`^/v1/presentation-requests/${ID_PATTERN}/result/?$`);
const CALLBACK_ROUTE = new RegExp(`^/v1/verifier-callbacks/${ID_PATTERN}/?$`);

export function createServer(bridge: Bridge, auth: { authToken: string }, log: Logger): Server {
  const expectedAuthorization = `Bearer ${auth.authToken}`;

  return createHttpServer((req, res) => {
    const started = process.hrtime.bigint();
    const path = (req.url ?? '/').split('?', 1)[0] ?? '/';
    res.on('finish', () => {
      const ms = Number(process.hrtime.bigint() - started) / 1e6;
      const fields = { method: req.method ?? '', path, status: res.statusCode, ms: Math.round(ms) };
      if (path === '/healthz') {
        log.debug('request', fields);
      } else {
        log.info('request', fields);
      }
    });

    handle(req, res, path).catch((error: unknown) => {
      if (error instanceof HttpError) {
        send(res, error.status, error.body());
        return;
      }
      log.error('request failed', { path, error: (error as Error).message });
      if (!res.headersSent) {
        send(res, 500, { error: 'internal' });
      } else {
        res.destroy();
      }
    });
  });

  async function handle(req: IncomingMessage, res: ServerResponse, path: string): Promise<void> {
    const method = req.method ?? 'GET';

    if (path === '/healthz') {
      await drain(req);
      send(res, method === 'GET' ? 200 : 405, { status: 'ok' });
      return;
    }

    if (CREATE_ROUTE.test(path)) {
      if (method !== 'POST') {
        await drain(req);
        send(res, 405, { error: 'method_not_allowed' }, { Allow: 'POST' });
        return;
      }
      if (!authorized(req)) {
        await drain(req);
        unauthorized(res);
        return;
      }
      const body = await readJson(req);
      send(res, 201, await bridge.createRequest(body));
      return;
    }

    const resultMatch = RESULT_ROUTE.exec(path);
    if (resultMatch) {
      await drain(req);
      if (method !== 'GET') {
        send(res, 405, { error: 'method_not_allowed' }, { Allow: 'GET' });
        return;
      }
      if (!authorized(req)) {
        unauthorized(res);
        return;
      }
      const result = bridge.getResult(decodeURIComponent(resultMatch[1]!));
      send(res, result.status, result.body);
      return;
    }

    const callbackMatch = CALLBACK_ROUTE.exec(path);
    if (callbackMatch) {
      // The posted session is not read: the bridge re-reads it from the verifier.
      await drain(req);
      if (method !== 'POST') {
        send(res, 405, { error: 'method_not_allowed' }, { Allow: 'POST' });
        return;
      }
      const outcome = bridge.handleCallback(decodeURIComponent(callbackMatch[1]!), req.headers.authorization);
      if (outcome === 'accepted') {
        send(res, 202, { status: 'accepted' });
      } else if (outcome === 'unauthorized') {
        unauthorized(res);
      } else {
        send(res, 404, { error: 'not_found' });
      }
      return;
    }

    await drain(req);
    send(res, 404, { error: 'not_found' });
  }

  function authorized(req: IncomingMessage): boolean {
    const header = req.headers.authorization;
    return typeof header === 'string' && constantTimeEqual(header, expectedAuthorization);
  }
}

function unauthorized(res: ServerResponse): void {
  send(res, 401, { error: 'unauthorized' }, { 'WWW-Authenticate': 'Bearer realm="bloclabs-ssi-bridge"' });
}

function send(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  const payload = JSON.stringify(body ?? null);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(payload),
    'Cache-Control': 'no-store',
    ...headers,
  });
  res.end(payload);
}

async function readJson(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buffer = chunk as Buffer;
    size += buffer.length;
    if (size > MAX_JSON_BODY) {
      throw new HttpError(413, 'payload_too_large');
    }
    chunks.push(buffer);
  }
  const text = Buffer.concat(chunks).toString('utf8');
  if (text.trim() === '') {
    throw new HttpError(400, 'invalid_json', 'The body must be JSON');
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new HttpError(400, 'invalid_json', 'The body must be JSON');
  }
}

/** Consumes and discards a request body, so the connection can be reused. */
async function drain(req: IncomingMessage): Promise<void> {
  for await (const _chunk of req) {
    // discard
  }
}
