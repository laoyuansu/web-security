import { createServer } from 'node:http';
import { createHmac, timingSafeEqual } from 'node:crypto';

const host = '127.0.0.1';
const port = 8102;
const cookieName = 'local_target_session';
const tokenEnvironment = new Map([
  ['user-a', 'NODE_TARGET_USER_A_TOKEN'],
  ['user-b', 'NODE_TARGET_USER_B_TOKEN'],
  ['admin', 'NODE_TARGET_ADMIN_TOKEN'],
]);

function configuredToken(principal) {
  return process.env[tokenEnvironment.get(principal)] ?? '';
}

function sameToken(candidate, expected) {
  const candidateBuffer = Buffer.from(candidate);
  const expectedBuffer = Buffer.from(expected);
  return candidateBuffer.length === expectedBuffer.length && timingSafeEqual(candidateBuffer, expectedBuffer);
}

function principalForToken(candidate) {
  if (!candidate) return null;
  for (const principal of tokenEnvironment.keys()) {
    const expected = configuredToken(principal);
    if (expected && sameToken(candidate, expected)) return principal;
  }
  return null;
}

function cookieSignature(principal) {
  return createHmac('sha256', configuredToken(principal)).update(principal).digest('hex');
}

function bearerToken(request) {
  const authorization = request.headers.authorization ?? '';
  const [scheme, token] = authorization.split(/\s+/, 2);
  return scheme?.toLowerCase() === 'bearer' && token ? token : null;
}

function cookieValue(request, name) {
  const pairs = (request.headers.cookie ?? '').split(';');
  const prefix = `${name}=`;
  const pair = pairs.map((value) => value.trim()).find((value) => value.startsWith(prefix));
  if (!pair) return null;
  try {
    return decodeURIComponent(pair.slice(prefix.length));
  } catch {
    return null;
  }
}

function cookiePrincipal(request) {
  const session = cookieValue(request, cookieName);
  if (!session) return null;
  const separator = session.indexOf('|');
  if (separator <= 0) return null;
  const principal = session.slice(0, separator);
  const signature = session.slice(separator + 1);
  const expected = tokenEnvironment.has(principal) ? configuredToken(principal) : '';
  return expected && signature && sameToken(signature, cookieSignature(principal)) ? principal : null;
}

function authenticatedPrincipal(request) {
  return principalForToken(bearerToken(request)) ?? cookiePrincipal(request);
}

function send(response, statusCode, body = null, headers = {}) {
  const output = body === null ? '' : JSON.stringify(body);
  response.writeHead(statusCode, {
    'cache-control': 'no-store',
    ...(body === null ? {} : { 'content-type': 'application/json; charset=utf-8' }),
    ...headers,
  });
  response.end(output);
}

function requireOwnerOrAdmin(request, response, owner) {
  const principal = authenticatedPrincipal(request);
  if (!principal) {
    send(response, 401, { detail: 'Authentication required' });
    return null;
  }
  if (principal !== owner && principal !== 'admin') {
    send(response, 403, { detail: 'Access denied' });
    return null;
  }
  return principal;
}

const server = createServer((request, response) => {
  const url = new URL(request.url, `http://${host}:${port}`);
  if (request.method === 'GET' && url.pathname === '/health') return send(response, 200, { status: 'ok' });

  if (request.method === 'POST' && url.pathname === '/test-login') {
    const principal = principalForToken(bearerToken(request));
    if (!principal) return send(response, 401, { detail: 'Authentication required' });
    const session = encodeURIComponent(`${principal}|${cookieSignature(principal)}`);
    return send(response, 204, null, { 'set-cookie': `${cookieName}=${session}; HttpOnly; SameSite=Strict; Path=/` });
  }

  const profileMatch = /^\/api\/profiles\/(user-a|user-b)$/.exec(url.pathname);
  if (request.method === 'GET' && profileMatch) {
    if (!requireOwnerOrAdmin(request, response, profileMatch[1])) return;
    return send(response, 200, { profile: profileMatch[1] });
  }

  const orderMatch = /^\/api\/orders\/(user-a|user-b)$/.exec(url.pathname);
  if (request.method === 'POST' && orderMatch) {
    if (!requireOwnerOrAdmin(request, response, orderMatch[1])) return;
    return send(response, 204);
  }

  if (request.method === 'GET' && url.pathname === '/api/admin/stats') {
    const principal = authenticatedPrincipal(request);
    if (!principal) return send(response, 401, { detail: 'Authentication required' });
    if (principal !== 'admin') return send(response, 403, { detail: 'Access denied' });
    return send(response, 200, { active_test_accounts: 3 });
  }

  return send(response, 404, { detail: 'Not found' });
});

server.listen(port, host, () => {
  console.log(`Local Node permission target listening on http://${host}:${port}`);
});
