const http = require('http');
const path = require('path');
const fs = require('fs');
const fsp = require('fs/promises');
const crypto = require('crypto');
const { getCollection } = require('./db');
let generateRegistrationOptions = null;
let verifyRegistrationResponse = null;
let generateAuthenticationOptions = null;
let verifyAuthenticationResponse = null;
let passkeyServerLoadError = null;

try {
  const passkeyServer = require('@simplewebauthn/server');
  generateRegistrationOptions = passkeyServer.generateRegistrationOptions;
  verifyRegistrationResponse = passkeyServer.verifyRegistrationResponse;
  generateAuthenticationOptions = passkeyServer.generateAuthenticationOptions;
  verifyAuthenticationResponse = passkeyServer.verifyAuthenticationResponse;
} catch (error) {
  passkeyServerLoadError = error;
  console.warn(`Modulo passkey non disponibile all'avvio: ${error.message}`);
}

const ROOT_DIR = __dirname;
loadEnvFile(path.join(ROOT_DIR, '.env'));
const SERVER_VERSION = '2026-02-26.1';

const PORT = Number(process.env.PORT) || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'change_this_session_secret';
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'change_this_password';
const WEBAUTHN_RP_NAME = process.env.WEBAUTHN_RP_NAME || 'Macerata FotoMap';
const WEBAUTHN_RP_ID = process.env.WEBAUTHN_RP_ID || 'localhost';
const WEBAUTHN_ORIGIN = process.env.WEBAUTHN_ORIGIN || `http://localhost:${PORT}`;

const PUBLIC_DIR = path.join(ROOT_DIR, 'public');
const DATA_DIR = path.join(ROOT_DIR, 'data');
// paths below are kept for reference but the app now persists to MongoDB instead of JSON files
const PINS_PATH = path.join(DATA_DIR, 'pins.json');
const AUTH_PATH = path.join(DATA_DIR, 'auth.json');
const TRACKING_PATH = path.join(DATA_DIR, 'tracking.log');
const UPLOADS_DIR = path.join(ROOT_DIR, 'uploads');

const MAX_IMAGE_SIZE_BYTES = 12 * 1024 * 1024;
const JSON_BODY_LIMIT_BYTES = 30 * 1024 * 1024;
const SESSION_COOKIE_NAME = 'macerata.sid';
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 7;
const AUTH_FLOW_TTL_MS = 1000 * 60 * 5;
const TRACKING_MAX_EVENTS = Math.max(200, Number.parseInt(process.env.TRACKING_MAX_EVENTS || '5000', 10) || 5000);

const ALLOWED_IMAGE_MIME_TYPES = new Set(['image/jpeg', 'image/png', 'image/webp']);
const MIME_TO_EXTENSION = {
  'image/jpeg': 'jpg',
  'image/png': 'png',
  'image/webp': 'webp',
};

const STATIC_MIME_TYPES = {
  '.css': 'text/css; charset=utf-8',
  '.html': 'text/html; charset=utf-8',
  '.ico': 'image/x-icon',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8',
  '.webp': 'image/webp',
};

const DEFAULT_MACERATA_CENTER = [13.4541, 43.3002];
const DEFAULT_MACERATA_BOUNDS = [
  [13.3307, 43.2355],
  [13.5856, 43.3664],
];
const DEFAULT_MACERATA_GEOMETRY = {
  type: 'Polygon',
  coordinates: [[
    [DEFAULT_MACERATA_BOUNDS[0][0], DEFAULT_MACERATA_BOUNDS[0][1]],
    [DEFAULT_MACERATA_BOUNDS[1][0], DEFAULT_MACERATA_BOUNDS[0][1]],
    [DEFAULT_MACERATA_BOUNDS[1][0], DEFAULT_MACERATA_BOUNDS[1][1]],
    [DEFAULT_MACERATA_BOUNDS[0][0], DEFAULT_MACERATA_BOUNDS[1][1]],
    [DEFAULT_MACERATA_BOUNDS[0][0], DEFAULT_MACERATA_BOUNDS[0][1]],
  ]],
};

const macerataGeo = {
  center: DEFAULT_MACERATA_CENTER,
  bounds: DEFAULT_MACERATA_BOUNDS,
  geometry: DEFAULT_MACERATA_GEOMETRY,
  sourceLabel: 'fallback',
};

const authUsers = loadAuthUsersFromEnv();
const webauthnExpectedOrigins = parseDelimitedValues(WEBAUTHN_ORIGIN);
const webauthnExpectedRpIDs = parseDelimitedValues(WEBAUTHN_RP_ID);
const webauthnRpID = webauthnExpectedRpIDs[0] || 'localhost';
let authStore = { users: {} };
let nextPinId = 1; // counter for numeric pin ids stored in Mongo
let initPromise = null;
let boundaryInitPromise = null;
let trackingWriteQueue = Promise.resolve();

class HttpError extends Error {
  constructor(statusCode, message) {
    super(message);
    this.statusCode = statusCode;
  }
}

function loadEnvFile(filePath) {
  if (!fs.existsSync(filePath)) {
    return;
  }

  const content = fs.readFileSync(filePath, 'utf8');
  const lines = content.split(/\r?\n/);

  lines.forEach((line) => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) {
      return;
    }

    const separatorIndex = trimmed.indexOf('=');
    if (separatorIndex <= 0) {
      return;
    }

    const key = trimmed.slice(0, separatorIndex).trim();
    let value = trimmed.slice(separatorIndex + 1).trim();

    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }

    if (!(key in process.env)) {
      process.env[key] = value;
    }
  });
}

function parseDelimitedValues(rawValue) {
  return String(rawValue || '')
    .split(/[,\s;]+/)
    .map((value) => value.trim())
    .filter(Boolean);
}

function parseEnvBoolean(rawValue, defaultValue = false) {
  if (rawValue === undefined || rawValue === null || rawValue === '') {
    return defaultValue;
  }

  const normalized = String(rawValue).trim().toLowerCase();
  if (['1', 'true', 'yes', 'y', 'si', 's', 'on'].includes(normalized)) {
    return true;
  }
  if (['0', 'false', 'no', 'n', 'off'].includes(normalized)) {
    return false;
  }

  return defaultValue;
}



function getEnvValueCaseInsensitive(targetKey) {
  const normalizedTarget = String(targetKey || '').trim().toLowerCase();
  if (!normalizedTarget) {
    return undefined;
  }

  const directValue = process.env[targetKey];
  if (directValue !== undefined) {
    return directValue;
  }

  for (const [entryKey, entryValue] of Object.entries(process.env)) {
    if (String(entryKey).toLowerCase() === normalizedTarget) {
      return entryValue;
    }
  }

  return undefined;
}

function normalizeUsername(username) {
  return String(username || '').trim().toLowerCase();
}

function envUserKeyFromUsername(username) {
  return String(username || '')
    .trim()
    .replace(/[^a-zA-Z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toUpperCase();
}

function loadAuthUsersFromEnv() {
  const usersMap = new Map();
  const configuredUsers = parseDelimitedValues(getEnvValueCaseInsensitive('AUTH_USERS'));

  const resolveUserConfig = (username, alias) => {
    const candidates = new Set();
    const usernameText = String(username || '').trim();
    const aliasText = String(alias || '').trim();

    if (aliasText) {
      candidates.add(aliasText);
      candidates.add(envUserKeyFromUsername(aliasText));
      candidates.add(normalizeUsername(aliasText));
    }

    if (usernameText) {
      candidates.add(usernameText);
      candidates.add(envUserKeyFromUsername(usernameText));
      candidates.add(normalizeUsername(usernameText));
    }

    let password = '';
    let requiresPasskey = false;

    for (const keyCandidate of candidates) {
      const rawPassword = getEnvValueCaseInsensitive(`AUTH_USER_${keyCandidate}_PASSWORD`);
      if (rawPassword !== undefined && String(rawPassword).trim()) {
        password = String(rawPassword).trim();
        break;
      }
    }

    for (const keyCandidate of candidates) {
      const rawPasskey = getEnvValueCaseInsensitive(`AUTH_USER_${keyCandidate}_PASSKEY`);
      if (rawPasskey !== undefined) {
        requiresPasskey = parseEnvBoolean(rawPasskey, false);
        break;
      }
    }

    return { password, requiresPasskey };
  };

  const registerUser = (usernameValue, aliasValue) => {
    const username = String(usernameValue || '').trim();
    const normalizedUsername = normalizeUsername(username);
    if (!normalizedUsername) {
      return;
    }

    const resolved = resolveUserConfig(username, aliasValue || username);
    if (!resolved.password) {
      const aliasText = String(aliasValue || username || '').trim();
      console.warn(`Utente "${username}" ignorato: password mancante (AUTH_USER_${aliasText}_PASSWORD).`);
      return;
    }

    usersMap.set(normalizedUsername, {
      username,
      normalizedUsername,
      password: resolved.password,
      requiresPasskey: resolved.requiresPasskey,
    });
  };

  configuredUsers.forEach((usernameRaw) => {
    registerUser(usernameRaw, usernameRaw);
  });

  Object.entries(process.env).forEach(([envKey, envValue]) => {
    const match = String(envKey).match(/^AUTH_USERS_(.+)$/i);
    if (!match) {
      return;
    }

    const alias = String(match[1] || '').trim();
    if (!alias) {
      return;
    }

    const username = String(envValue || '').trim() || alias;
    registerUser(username, alias);
  });

  if (usersMap.size === 0) {
    const fallbackUsername = String(ADMIN_USERNAME || '').trim() || 'admin';
    const fallbackNormalized = normalizeUsername(fallbackUsername);
    usersMap.set(fallbackNormalized, {
      username: fallbackUsername,
      normalizedUsername: fallbackNormalized,
      password: String(ADMIN_PASSWORD || '').trim() || 'change_this_password',
      requiresPasskey: parseEnvBoolean(getEnvValueCaseInsensitive('AUTH_ADMIN_PASSKEY'), false),
    });
  }

  return usersMap;
}

function listAuthUsers() {
  return Array.from(authUsers.values()).map((user) => user.username);
}

function findAuthUser(username) {
  const normalized = normalizeUsername(username);
  if (!normalized) {
    return null;
  }
  return authUsers.get(normalized) || null;
}

function hashText(value) {
  return crypto.createHash('sha256').update(String(value)).digest();
}

function safeEqualText(left, right) {
  const leftHash = hashText(left);
  const rightHash = hashText(right);
  return crypto.timingSafeEqual(leftHash, rightHash);
}

function verifyUserPassword(user, password) {
  if (!user) {
    return false;
  }
  return safeEqualText(user.password, password);
}

function ensurePasskeyServerAvailable() {
  if (
    typeof generateRegistrationOptions === 'function'
    && typeof verifyRegistrationResponse === 'function'
    && typeof generateAuthenticationOptions === 'function'
    && typeof verifyAuthenticationResponse === 'function'
  ) {
    return;
  }

  const details = passkeyServerLoadError && passkeyServerLoadError.message
    ? `: ${passkeyServerLoadError.message}`
    : '';
  throw new HttpError(503, `Passkey temporaneamente non disponibile${details}`);
}

function encodeBase64Url(value) {
  return Buffer.from(value)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function decodeBase64Url(value) {
  const normalized = String(value || '').replace(/-/g, '+').replace(/_/g, '/');
  const padding = '='.repeat((4 - (normalized.length % 4)) % 4);
  return Buffer.from(normalized + padding, 'base64');
}

function signTokenPayload(payload, scope) {
  const serializedPayload = JSON.stringify(payload);
  const payloadBase64 = encodeBase64Url(serializedPayload);
  const signature = crypto
    .createHmac('sha256', `${SESSION_SECRET}:${scope}`)
    .update(payloadBase64)
    .digest();
  const signatureBase64 = encodeBase64Url(signature);
  return `v1.${payloadBase64}.${signatureBase64}`;
}

function verifyTokenPayload(token, scope) {
  const rawToken = String(token || '').trim();
  const parts = rawToken.split('.');
  if (parts.length !== 3 || parts[0] !== 'v1') {
    return null;
  }

  const payloadBase64 = parts[1];
  const signatureBase64 = parts[2];
  const expectedSignature = crypto
    .createHmac('sha256', `${SESSION_SECRET}:${scope}`)
    .update(payloadBase64)
    .digest();
  const providedSignature = decodeBase64Url(signatureBase64);

  if (providedSignature.length !== expectedSignature.length) {
    return null;
  }

  if (!crypto.timingSafeEqual(expectedSignature, providedSignature)) {
    return null;
  }

  try {
    const rawPayload = decodeBase64Url(payloadBase64).toString('utf8');
    const parsed = JSON.parse(rawPayload);
    return parsed && typeof parsed === 'object' ? parsed : null;
  } catch (_error) {
    return null;
  }
}

function createAuthFlow(flowData) {
  const payload = {
    ...flowData,
    createdAt: Date.now(),
    expiresAt: Date.now() + AUTH_FLOW_TTL_MS,
  };
  return signTokenPayload(payload, 'auth-flow');
}

function getAuthFlow(token) {
  const flow = verifyTokenPayload(token, 'auth-flow');
  if (!flow || flow.expiresAt <= Date.now()) {
    return null;
  }
  return {
    ...flow,
    token,
  };
}

function destroyAuthFlow(_token) {
  // Stateless auth flow token: invalidazione tramite expiry/cookie clear.
}

function base64UrlToBuffer(value) {
  const text = String(value || '').trim();
  if (!text) {
    return Buffer.alloc(0);
  }
  return decodeBase64Url(text);
}

function bufferToBase64Url(value) {
  return Buffer.from(value)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function normalizeStoredAuth(raw) {
  const users = raw && raw.users && typeof raw.users === 'object' ? raw.users : {};
  const normalizedUsers = {};

  Object.entries(users).forEach(([usernameKey, userValue]) => {
    const normalizedUsername = normalizeUsername(usernameKey);
    if (!normalizedUsername || !userValue || typeof userValue !== 'object') {
      return;
    }

    const passkeys = Array.isArray(userValue.passkeys) ? userValue.passkeys : [];
    const normalizedPasskeys = passkeys
      .map((entry) => {
        if (!entry || typeof entry !== 'object') {
          return null;
        }

        const id = String(entry.id || '').trim();
        const publicKey = String(entry.publicKey || '').trim();
        if (!id || !publicKey) {
          return null;
        }

        return {
          id,
          publicKey,
          counter: Number.isFinite(entry.counter) ? Number(entry.counter) : 0,
          transports: Array.isArray(entry.transports)
            ? entry.transports.map((value) => String(value)).filter(Boolean)
            : [],
          deviceType: String(entry.deviceType || ''),
          backedUp: Boolean(entry.backedUp),
          createdAt: typeof entry.createdAt === 'string' ? entry.createdAt : new Date().toISOString(),
          updatedAt: typeof entry.updatedAt === 'string' ? entry.updatedAt : new Date().toISOString(),
        };
      })
      .filter(Boolean);

    normalizedUsers[normalizedUsername] = { passkeys: normalizedPasskeys };
  });

  return { users: normalizedUsers };
}

async function ensureLocalDataPaths() {
  await fsp.mkdir(DATA_DIR, { recursive: true });
  await fsp.mkdir(UPLOADS_DIR, { recursive: true });
}

async function initializeAuthStore() {
  const col = await getCollection('auth_store');
  // ensure index on _id maybe not needed

  // try to load existing document
  const doc = await col.findOne({ _id: 1 });
  if (!doc) {
    // migrate from legacy file if present
    let parsed = { users: {} };
    try {
      const raw = await fsp.readFile(AUTH_PATH, 'utf8');
      parsed = JSON.parse(raw);
    } catch (_e) {
      parsed = { users: {} };
    }
    authStore = normalizeStoredAuth(parsed);
    await col.insertOne({ _id: 1, data: authStore });
  } else {
    authStore = normalizeStoredAuth(doc.data || { users: {} });
  }
}

async function persistAuthStore() {
  const col = await getCollection('auth_store');
  await col.updateOne({ _id: 1 }, { $set: { data: authStore } }, { upsert: true });
}

function getUserAuthRecord(normalizedUsername) {
  if (!authStore.users[normalizedUsername]) {
    authStore.users[normalizedUsername] = { passkeys: [] };
  }
  return authStore.users[normalizedUsername];
}

function getUserPasskeys(normalizedUsername) {
  const userRecord = getUserAuthRecord(normalizedUsername);
  return Array.isArray(userRecord.passkeys) ? userRecord.passkeys : [];
}

function getWebAuthnCredentialFromStoredPasskey(storedPasskey) {
  return {
    id: storedPasskey.id,
    publicKey: base64UrlToBuffer(storedPasskey.publicKey),
    counter: Number.isFinite(storedPasskey.counter) ? Number(storedPasskey.counter) : 0,
    transports: Array.isArray(storedPasskey.transports) ? storedPasskey.transports : [],
  };
}

function getUserIdForWebAuthn(normalizedUsername) {
  return Buffer.from(`user:${normalizedUsername}`, 'utf8');
}

function buildPasskeyRegistrationOptions(user, passkeys, rpIDOverride) {
  ensurePasskeyServerAvailable();
  const rpIDToUse = rpIDOverride || webauthnRpID;
  return generateRegistrationOptions({
    rpName: WEBAUTHN_RP_NAME,
    rpID: rpIDToUse,
    userName: user.username,
    userID: getUserIdForWebAuthn(user.normalizedUsername),
    userDisplayName: user.username,
    attestationType: 'none',
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'preferred',
    },
    excludeCredentials: passkeys.map((passkey) => ({
      id: passkey.id,
      transports: Array.isArray(passkey.transports) ? passkey.transports : [],
    })),
  });
}

function buildPasskeyAuthenticationOptions(passkeys, rpIDOverride) {
  ensurePasskeyServerAvailable();
  const rpIDToUse = rpIDOverride || webauthnRpID;
  return generateAuthenticationOptions({
    rpID: rpIDToUse,
    allowCredentials: passkeys.map((passkey) => ({
      id: passkey.id,
      transports: Array.isArray(passkey.transports) ? passkey.transports : [],
    })),
    userVerification: 'preferred',
  });
}

function buildLoginSuccessPayload(username) {
  return {
    ok: true,
    authenticated: true,
    username,
  };
}

function formatItalianDate(isoDate) {
  return new Intl.DateTimeFormat('it-IT', {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(new Date(isoDate));
}

function pinRowToResponse(pin) {
  return {
    id: pin.id,
    lat: pin.lat,
    lng: pin.lng,
    address: pin.address,
    imageUrl: `/uploads/${pin.image_path}`,
    createdAt: pin.created_at,
    createdAtFormatted: formatItalianDate(pin.created_at),
    updatedAt: pin.updated_at,
  };
}

function sortPinsByLatest(pins) {
  return [...pins].sort((a, b) => {
    const byDate = new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
    if (byDate !== 0) {
      return byDate;
    }
    return b.id - a.id;
  });
}

function parseCoordinate(value) {
  const parsed = Number.parseFloat(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function parseCookies(rawCookieHeader) {
  if (!rawCookieHeader) {
    return {};
  }

  return rawCookieHeader
    .split(';')
    .map((part) => part.trim())
    .filter(Boolean)
    .reduce((acc, cookiePart) => {
      const index = cookiePart.indexOf('=');
      if (index <= 0) {
        return acc;
      }

      const key = cookiePart.slice(0, index).trim();
      const value = cookiePart.slice(index + 1).trim();
      acc[key] = decodeURIComponent(value);
      return acc;
    }, {});
}

function getSessionFromRequest(req) {
  const cookies = parseCookies(req.headers.cookie || '');
  const sid = cookies[SESSION_COOKIE_NAME];
  if (!sid) {
    return null;
  }

  const payload = verifyTokenPayload(sid, 'session');
  if (!payload || typeof payload.username !== 'string') {
    return null;
  }

  if (!Number.isFinite(payload.expiresAt) || payload.expiresAt <= Date.now()) {
    return null;
  }

  return {
    id: sid,
    username: payload.username,
  };
}

function createSession(username) {
  return signTokenPayload({
    username: String(username || '').trim(),
    createdAt: Date.now(),
    expiresAt: Date.now() + SESSION_TTL_MS,
    nonce: crypto.randomBytes(8).toString('hex'),
  }, 'session');
}

function destroySession(_sid) {
  // Sessione stateless: invalidazione tramite cancellazione cookie client.
}

function getRequestIp(req) {
  const forwarded = String(
    req.headers['x-forwarded-for']
      || req.headers['x-nf-client-connection-ip']
      || req.headers['client-ip']
      || '',
  ).trim();

  if (forwarded) {
    return forwarded.split(',')[0].trim();
  }

  const remote = req.socket && req.socket.remoteAddress ? String(req.socket.remoteAddress) : '';
  return remote.trim();
}

function queueTrackingWrite(task) {
  trackingWriteQueue = trackingWriteQueue
    .then(task)
    .catch((error) => {
      console.warn('Tracking non disponibile:', error.message);
    });

  return trackingWriteQueue;
}

function normalizeTrackingEntry(entry) {
  return {
    id: String(entry.id || `${Date.now()}-${crypto.randomBytes(3).toString('hex')}`),
    at: typeof entry.at === 'string' ? entry.at : new Date().toISOString(),
    action: String(entry.action || 'unknown'),
    username: entry.username ? String(entry.username) : null,
    authenticated: Boolean(entry.authenticated),
    ip: String(entry.ip || ''),
    userAgent: String(entry.userAgent || ''),
    method: String(entry.method || ''),
    path: String(entry.path || ''),
    details: entry.details && typeof entry.details === 'object' ? entry.details : {},
  };
}

async function initializeTrackingStore() {
  const col = await getCollection('tracking');
  // migrate existing log entries if collection empty
  try {
    const count = await col.countDocuments();
    if (count === 0) {
      const raw = await fsp.readFile(TRACKING_PATH, 'utf8');
      const lines = raw.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
      for (const line of lines) {
        try {
          const entry = JSON.parse(line);
          await appendTrackingEntry(entry);
        } catch (_e) {
          // ignore malformed lines
        }
      }
    }
  } catch (_e) {
    // ignore if file missing or db error
  }
}

async function appendTrackingEntry(entry) {
  const n = normalizeTrackingEntry(entry);
  const col = await getCollection('tracking');
  // store as-is; ensure authenticated boolean is stored
  await col.insertOne(n);
}

function trackEvent(req, session, action, details = {}) {
  const entry = {
    action,
    username: session && session.username ? session.username : null,
    authenticated: Boolean(session && session.username),
    ip: getRequestIp(req),
    userAgent: String(req.headers['user-agent'] || ''),
    method: String(req.method || ''),
    path: String(req.url || ''),
    details,
  };

  return queueTrackingWrite(() => appendTrackingEntry(entry));
}

async function readTrackingEntries(limit = 200) {
  const safeLimit = Math.max(1, Math.min(Number.parseInt(limit, 10) || 200, 2000));
  const col = await getCollection('tracking');
  const rows = await col.find({}).sort({ at: -1 }).limit(safeLimit).toArray();
  return rows.map(normalizeTrackingEntry);
}

function sessionCookieValue(sid) {
  const maxAgeSeconds = Math.floor(SESSION_TTL_MS / 1000);
  return `${SESSION_COOKIE_NAME}=${encodeURIComponent(sid)}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${maxAgeSeconds}`;
}

function clearSessionCookieValue() {
  return `${SESSION_COOKIE_NAME}=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0`;
}

function jsonResponse(res, statusCode, payload, extraHeaders = {}) {
  const body = JSON.stringify(payload);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
    ...extraHeaders,
  });
  res.end(body);
}

function noContentResponse(res, statusCode = 204) {
  res.writeHead(statusCode);
  res.end();
}

async function fetchWithTimeout(url, options = {}, timeoutMs = 10000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    return await fetch(url, {
      ...options,
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
  }
}

async function readJsonBody(req, maxBytes = JSON_BODY_LIMIT_BYTES) {
  const contentType = req.headers['content-type'] || '';
  if (!contentType.includes('application/json')) {
    throw new HttpError(415, 'Content-Type non supportato, usa application/json');
  }

  const chunks = [];
  let totalBytes = 0;

  for await (const chunk of req) {
    totalBytes += chunk.length;
    if (totalBytes > maxBytes) {
      throw new HttpError(413, 'Body troppo grande');
    }
    chunks.push(chunk);
  }

  const raw = Buffer.concat(chunks).toString('utf8').trim();
  if (!raw) {
    return {};
  }

  try {
    return JSON.parse(raw);
  } catch (_error) {
    throw new HttpError(400, 'JSON non valido');
  }
}

function resolveSafePath(baseDir, requestPath) {
  const normalized = requestPath.replace(/\\/g, '/');
  const resolvedPath = path.resolve(baseDir, `.${normalized}`);

  if (!resolvedPath.startsWith(baseDir)) {
    return null;
  }

  return resolvedPath;
}

function buildBoundaryFeature() {
  return {
    type: 'Feature',
    properties: {
      source: macerataGeo.sourceLabel,
    },
    geometry: macerataGeo.geometry,
  };
}

function pointInRing(lng, lat, ring) {
  let inside = false;

  for (let i = 0, j = ring.length - 1; i < ring.length; j = i, i += 1) {
    const xi = ring[i][0];
    const yi = ring[i][1];
    const xj = ring[j][0];
    const yj = ring[j][1];

    const intersects = ((yi > lat) !== (yj > lat))
      && (lng < ((xj - xi) * (lat - yi)) / ((yj - yi) || Number.EPSILON) + xi);

    if (intersects) {
      inside = !inside;
    }
  }

  return inside;
}

function pointInPolygonCoordinates(lng, lat, polygonCoordinates) {
  if (!Array.isArray(polygonCoordinates) || polygonCoordinates.length === 0) {
    return false;
  }

  const [outerRing, ...holes] = polygonCoordinates;
  if (!pointInRing(lng, lat, outerRing)) {
    return false;
  }

  for (const hole of holes) {
    if (pointInRing(lng, lat, hole)) {
      return false;
    }
  }

  return true;
}

function pointInGeometry(lng, lat, geometry) {
  if (!geometry || !geometry.type) {
    return false;
  }

  if (geometry.type === 'Polygon') {
    return pointInPolygonCoordinates(lng, lat, geometry.coordinates);
  }

  if (geometry.type === 'MultiPolygon') {
    return geometry.coordinates.some((polygon) => pointInPolygonCoordinates(lng, lat, polygon));
  }

  return false;
}

function isPointInsideMacerata(lat, lng) {
  try {
    if (pointInGeometry(lng, lat, macerataGeo.geometry)) {
      return true;
    }
  } catch (_error) {
    // Fallback alla bbox.
  }

  const [westSouth, eastNorth] = macerataGeo.bounds;
  return (
    lng >= westSouth[0] &&
    lng <= eastNorth[0] &&
    lat >= westSouth[1] &&
    lat <= eastNorth[1]
  );
}

async function reverseGeocode(lat, lng) {
  const url = new URL('https://nominatim.openstreetmap.org/reverse');
  url.searchParams.set('format', 'jsonv2');
  url.searchParams.set('lat', String(lat));
  url.searchParams.set('lon', String(lng));
  url.searchParams.set('zoom', '18');
  url.searchParams.set('addressdetails', '1');

  try {
    const response = await fetchWithTimeout(url, {
      headers: {
        'User-Agent': 'sito-macerata-map/1.0 (local setup)',
      },
    }, 8000);

    if (!response.ok) {
      return 'Indirizzo non disponibile';
    }

    const payload = await response.json();
    return payload.display_name || 'Indirizzo non disponibile';
  } catch (_error) {
    return 'Indirizzo non disponibile';
  }
}

async function searchAddressCandidates(addressInput, limit = 8) {
  const query = `${addressInput}, Macerata, Marche, Italia`;
  const url = new URL('https://nominatim.openstreetmap.org/search');
  url.searchParams.set('format', 'jsonv2');
  url.searchParams.set('q', query);
  url.searchParams.set('limit', String(limit));
  url.searchParams.set('addressdetails', '1');
  url.searchParams.set('countrycodes', 'it');

  const response = await fetchWithTimeout(url, {
    headers: {
      'User-Agent': 'sito-macerata-map/1.0 (local setup)',
    },
  }, 10000);

  if (!response.ok) {
    throw new HttpError(502, 'Impossibile geocodificare questo indirizzo adesso');
  }

  const results = await response.json();

  const uniqueMap = new Map();
  const normalized = results
    .map((item) => ({
      lat: Number.parseFloat(item.lat),
      lng: Number.parseFloat(item.lon),
      address: item.display_name,
    }))
    .filter((item) => Number.isFinite(item.lat) && Number.isFinite(item.lng) && isPointInsideMacerata(item.lat, item.lng));

  normalized.forEach((item) => {
    const key = `${item.lat.toFixed(6)}:${item.lng.toFixed(6)}:${String(item.address || '').toLowerCase()}`;
    if (!uniqueMap.has(key)) {
      uniqueMap.set(key, item);
    }
  });

  return Array.from(uniqueMap.values());
}

async function geocodeAddress(addressInput) {
  const results = await searchAddressCandidates(addressInput, 8);
  return results[0] || null;
}

async function initializeMacerataBoundary() {
  const structuredUrl = new URL('https://nominatim.openstreetmap.org/search');
  structuredUrl.searchParams.set('format', 'jsonv2');
  structuredUrl.searchParams.set('city', 'Macerata');
  structuredUrl.searchParams.set('state', 'Marche');
  structuredUrl.searchParams.set('country', 'Italia');
  structuredUrl.searchParams.set('addressdetails', '1');
  structuredUrl.searchParams.set('limit', '8');
  structuredUrl.searchParams.set('polygon_geojson', '1');

  const fallbackUrl = new URL('https://nominatim.openstreetmap.org/search');
  fallbackUrl.searchParams.set('format', 'jsonv2');
  fallbackUrl.searchParams.set('q', 'Macerata, Marche, Italia');
  fallbackUrl.searchParams.set('addressdetails', '1');
  fallbackUrl.searchParams.set('limit', '8');
  fallbackUrl.searchParams.set('polygon_geojson', '1');

  try {
    const fetchCandidates = async (url, timeoutMs) => {
      const response = await fetchWithTimeout(url, {
        headers: {
          'User-Agent': 'sito-macerata-map/1.0 (boundary bootstrap)',
        },
      }, timeoutMs);

      if (!response.ok) {
        throw new Error(`Nominatim HTTP ${response.status}`);
      }

      const data = await response.json();
      return Array.isArray(data) ? data : [];
    };

    const requests = await Promise.allSettled([
      fetchCandidates(structuredUrl, 8000),
      fetchCandidates(fallbackUrl, 9000),
    ]);

    const structuredCandidates = requests[0].status === 'fulfilled' ? requests[0].value : [];
    const fallbackCandidates = requests[1].status === 'fulfilled' ? requests[1].value : [];

    const seen = new Set();
    const validResults = [...structuredCandidates, ...fallbackCandidates]
      .filter((item) => item && item.geojson && Array.isArray(item.boundingbox))
      .filter((item) => ['Polygon', 'MultiPolygon'].includes(item.geojson.type))
      .filter((item) => {
        const key = `${item.osm_type || 'x'}:${item.osm_id || 'x'}:${item.place_id || 'x'}`;
        if (seen.has(key)) {
          return false;
        }
        seen.add(key);
        return true;
      });

    if (!validResults.length) {
      throw new Error('Boundary di Macerata non trovata');
    }

    const selectBestCandidate = (items) => items
      .map((item) => {
        const south = Number.parseFloat(item.boundingbox[0]);
        const north = Number.parseFloat(item.boundingbox[1]);
        const west = Number.parseFloat(item.boundingbox[2]);
        const east = Number.parseFloat(item.boundingbox[3]);
        const placeRank = Number.parseInt(item.place_rank, 10);
        const area = (north - south) * (east - west);

        const addresstype = String(item.addresstype || '').toLowerCase();
        const category = String(item.category || '').toLowerCase();
        const boundaryType = String(item.type || '').toLowerCase();
        const display = String(item.display_name || '').toLowerCase();

        let score = 0;
        if (category === 'boundary') score += 8;
        if (boundaryType === 'administrative') score += 10;
        if (addresstype === 'town' || addresstype === 'city' || addresstype === 'municipality') score += 26;

        if (Number.isFinite(placeRank)) {
          score += Math.max(0, 8 - Math.abs(16 - placeRank) * 2);
          if (placeRank < 14) {
            score -= 20;
          }
        }

        if (display.includes('provincia') || display.includes('province') || display.includes('county')) {
          score -= 35;
        }
        if (display.includes('macerata')) score += 4;
        if (display.includes('marche')) score += 2;

        if (area > 0.08) {
          score -= 30;
        }

        return {
          item,
          area: Number.isFinite(area) ? area : Number.POSITIVE_INFINITY,
          score,
        };
      })
      .filter((entry) => Number.isFinite(entry.area))
      .sort((a, b) => (b.score - a.score) || (a.area - b.area))[0]?.item || null;

    const result = selectBestCandidate(validResults);

    if (!result || !result.geojson || !Array.isArray(result.boundingbox)) {
      throw new Error('Boundary di Macerata non trovata');
    }

    if (!['Polygon', 'MultiPolygon'].includes(result.geojson.type)) {
      throw new Error(`GeoJSON non supportato: ${result.geojson.type}`);
    }

    const south = Number.parseFloat(result.boundingbox[0]);
    const north = Number.parseFloat(result.boundingbox[1]);
    const west = Number.parseFloat(result.boundingbox[2]);
    const east = Number.parseFloat(result.boundingbox[3]);
    const centerLng = Number.parseFloat(result.lon);
    const centerLat = Number.parseFloat(result.lat);

    if (![south, north, west, east, centerLng, centerLat].every(Number.isFinite)) {
      throw new Error('Coordinate boundary non valide');
    }

    macerataGeo.center = [centerLng, centerLat];
    macerataGeo.bounds = [[west, south], [east, north]];
    macerataGeo.geometry = result.geojson;
    macerataGeo.sourceLabel = `nominatim:${result.osm_type || 'x'}:${result.osm_id || 'x'}`;

    console.log('Boundary di Macerata caricata da Nominatim.');
  } catch (error) {
    macerataGeo.center = DEFAULT_MACERATA_CENTER;
    macerataGeo.bounds = DEFAULT_MACERATA_BOUNDS;
    macerataGeo.geometry = DEFAULT_MACERATA_GEOMETRY;
    macerataGeo.sourceLabel = 'fallback';
    console.warn('Impossibile caricare boundary reale, uso fallback bbox:', error.message);
  }
}

function normalizeStoredPin(raw) {
  if (!raw) {
    return null;
  }

  let id = raw.id;
  if (typeof id === 'string' && /^\d+$/.test(id)) {
    id = Number(id);
  }

  if (!Number.isInteger(id)) {
    return null;
  }

  const lat = Number(raw.lat);
  const lng = Number(raw.lng);
  if (!Number.isFinite(lat) || !Number.isFinite(lng)) {
    return null;
  }

  const createdAt = typeof raw.created_at === 'string' ? raw.created_at : new Date().toISOString();
  const updatedAt = typeof raw.updated_at === 'string' ? raw.updated_at : createdAt;

  return {
    id: raw.id,
    lat,
    lng,
    address: typeof raw.address === 'string' ? raw.address : 'Indirizzo non disponibile',
    image_path: typeof raw.image_path === 'string' ? raw.image_path : '',
    created_at: createdAt,
    updated_at: updatedAt,
  };
}

async function initializePinStore() {
  const col = await getCollection('pins');
  // ensure an index on id for fast lookup
  await col.createIndex({ id: 1 }, { unique: true });

  // compute nextPinId based on existing documents
  const last = await col.find({}).sort({ id: -1 }).limit(1).toArray();
  if (last && last.length > 0 && typeof last[0].id === 'number') {
    nextPinId = last[0].id + 1;
  } else {
    nextPinId = 1;
  }

  // migrate from legacy JSON file if collection empty
  try {
    const count = await col.countDocuments();
    if (count === 0) {
      const raw = await fsp.readFile(PINS_PATH, 'utf8');
      const arr = JSON.parse(raw);
      if (Array.isArray(arr)) {
        for (const rawPin of arr) {
          const pin = normalizeStoredPin(rawPin);
          if (pin && pin.image_path) {
            await col.insertOne(pin);
            if (typeof pin.id === 'number' && pin.id >= nextPinId) {
              nextPinId = pin.id + 1;
            }
          }
        }
      }
    }
  } catch (e) {
    // ignore migration errors
  }
}

// persistence is now handled by individual queries rather than writing the
// entire collection to a file; the old function has been removed.

async function findPinById(pinId) {
  const col = await getCollection('pins');
  const doc = await col.findOne({ id: pinId });
  return doc ? normalizeStoredPin(doc) : null;
}

// helper: return all pins sorted by creation date (newest first)
async function getAllPins() {
  const col = await getCollection('pins');
  const rows = await col.find({}).sort({ created_at: -1 }).toArray();
  return rows.map(normalizeStoredPin);
}

async function createPinInDb(pin) {
  const col = await getCollection('pins');
  pin.id = nextPinId++;
  await col.insertOne(pin);
  return pin;
}

async function updatePinInDb(pin) {
  const col = await getCollection('pins');
  await col.updateOne(
    { id: pin.id },
    { $set: { lat: pin.lat, lng: pin.lng, address: pin.address, image_path: pin.image_path, updated_at: pin.updated_at } }
  );
}

async function deletePinInDb(id) {
  const col = await getCollection('pins');
  await col.deleteOne({ id });
}

async function safeDeleteFileByName(filename) {
  if (!filename) {
    return;
  }

  const safeName = path.basename(filename);
  const fullPath = path.join(UPLOADS_DIR, safeName);

  try {
    await fsp.unlink(fullPath);
  } catch (error) {
    if (error.code !== 'ENOENT') {
      console.error('Errore durante cancellazione file:', error);
    }
  }
}

function validateImagePayload(imagePayload) {
  if (!imagePayload || typeof imagePayload !== 'object') {
    throw new HttpError(400, 'Immagine mancante');
  }

  const mimeType = String(imagePayload.type || '').toLowerCase();
  if (!ALLOWED_IMAGE_MIME_TYPES.has(mimeType)) {
    throw new HttpError(400, 'Formato file non supportato. Usa JPG, PNG o WEBP.');
  }

  const rawBase64 = String(imagePayload.base64 || '').trim();
  if (!rawBase64) {
    throw new HttpError(400, 'Contenuto immagine mancante');
  }

  const cleanedBase64 = rawBase64.replace(/^data:[^;]+;base64,/, '');
  const buffer = Buffer.from(cleanedBase64, 'base64');

  if (!buffer.length) {
    throw new HttpError(400, 'Immagine non valida');
  }

  if (buffer.length > MAX_IMAGE_SIZE_BYTES) {
    throw new HttpError(400, `Immagine troppo grande. Limite ${Math.floor(MAX_IMAGE_SIZE_BYTES / (1024 * 1024))} MB`);
  }

  const extension = MIME_TO_EXTENSION[mimeType];
  return { buffer, extension, mimeType };
}

async function saveImagePayload(imagePayload) {
  const { buffer, extension, mimeType } = validateImagePayload(imagePayload);
  const randomSuffix = crypto.randomBytes(4).toString('hex');
  const filename = `${Date.now()}-${randomSuffix}.${extension}`;

  const fullPath = path.join(UPLOADS_DIR, filename);
  await fsp.writeFile(fullPath, buffer);
  return filename;
}

async function handleApiRequest(req, res, pathname, searchParams, session) {
  if (req.method === 'GET' && pathname === '/api/health') {
    jsonResponse(res, 200, {
      ok: true,
      version: SERVER_VERSION,
      boundarySource: macerataGeo.sourceLabel,
    });
    return;
  }

  if (req.method === 'GET' && pathname === '/api/auth/session') {
    if (!session) {
      jsonResponse(res, 200, { authenticated: false });
      return;
    }

    jsonResponse(res, 200, {
      authenticated: true,
      username: session.username,
    });
    return;
  }

  if (req.method === 'POST' && pathname === '/api/auth/login') {
    const body = await readJsonBody(req);
    const username = String(body.username || '').trim();
    const password = String(body.password || '').trim();
    const user = findAuthUser(username);

    if (!user || !verifyUserPassword(user, password)) {
      await trackEvent(req, null, 'auth_login_failed', { usernameAttempt: username });
      throw new HttpError(401, 'Credenziali non valide');
    }

    const userPasskeys = getUserPasskeys(user.normalizedUsername);

    if (user.requiresPasskey) {
      ensurePasskeyServerAvailable();

      if (!webauthnExpectedOrigins.length || !webauthnExpectedRpIDs.length) {
        throw new HttpError(500, 'Configurazione passkey non valida sul server');
      }

      // ricava host/origine dalla richiesta per forzare il corretto rpID/origin
      const hostHeader = String(req.headers.host || '').split(':')[0];
      const proto = String(req.headers['x-forwarded-proto'] || 'http').split(',')[0];
      const originFromReq = `${proto}://${hostHeader}`;
      // se mancano nelle liste attese, aggiungili
      if (hostHeader && !webauthnExpectedRpIDs.includes(hostHeader)) {
        webauthnExpectedRpIDs.push(hostHeader);
      }
      if (originFromReq && !webauthnExpectedOrigins.includes(originFromReq)) {
        webauthnExpectedOrigins.push(originFromReq);
      }

      const rpIDOverride = hostHeader || undefined;

      if (!userPasskeys.length) {
        const options = await buildPasskeyRegistrationOptions(user, userPasskeys, rpIDOverride);
        const token = createAuthFlow({
          stage: 'passkey-setup',
          normalizedUsername: user.normalizedUsername,
          challenge: options.challenge,
        });
        await trackEvent(req, null, 'auth_passkey_setup_required', { username: user.username });

        jsonResponse(res, 200, {
          ok: false,
          step: 'passkey_setup',
          token,
          options,
        });
        return;
      }

      const options = await buildPasskeyAuthenticationOptions(userPasskeys, rpIDOverride);
      const token = createAuthFlow({
        stage: 'passkey-auth',
        normalizedUsername: user.normalizedUsername,
        challenge: options.challenge,
      });
      await trackEvent(req, null, 'auth_passkey_required', { username: user.username });

      jsonResponse(res, 200, {
        ok: false,
        step: 'passkey',
        token,
        options,
      });
      return;
    }

    const sid = createSession(user.username);
    await trackEvent(req, { username: user.username }, 'auth_login_success');
    jsonResponse(res, 200, buildLoginSuccessPayload(user.username), {
      'Set-Cookie': sessionCookieValue(sid),
    });
    return;
  }

  if (req.method === 'POST' && pathname === '/api/auth/passkey/register/verify') {
    const body = await readJsonBody(req);
    const token = String(body.token || '').trim();
    const credentialResponse = body.credential;
    const flow = getAuthFlow(token);

    if (!flow || flow.stage !== 'passkey-setup') {
      throw new HttpError(401, 'Sessione login passkey scaduta. Riprova il login.');
    }

    const user = authUsers.get(flow.normalizedUsername);
    if (!user) {
      destroyAuthFlow(token);
      throw new HttpError(401, 'Utente non disponibile');
    }

    ensurePasskeyServerAvailable();

    let verification;
    try {
      // aggiungi host/origine della richiesta alla lista attesa, se necessario
      const hostHeader = String(req.headers.host || '').split(':')[0];
      const proto = String(req.headers['x-forwarded-proto'] || 'http').split(',')[0];
      const originFromReq = `${proto}://${hostHeader}`;
      const expectedOrigins = [...webauthnExpectedOrigins];
      const expectedRpIDs = [...webauthnExpectedRpIDs];
      if (hostHeader && !expectedRpIDs.includes(hostHeader)) expectedRpIDs.push(hostHeader);
      if (originFromReq && !expectedOrigins.includes(originFromReq)) expectedOrigins.push(originFromReq);

      verification = await verifyRegistrationResponse({
        response: credentialResponse,
        expectedChallenge: flow.challenge,
        expectedOrigin: expectedOrigins,
        expectedRPID: expectedRpIDs,
        requireUserVerification: false,
      });
    } catch (error) {
      throw new HttpError(400, `Registrazione passkey non valida: ${error.message}`);
    }

    if (!verification.verified || !verification.registrationInfo) {
      throw new HttpError(401, 'Registrazione passkey non verificata');
    }

    const credential = verification.registrationInfo.credential;
    const passkeys = getUserPasskeys(user.normalizedUsername);
    const storedCredential = {
      id: credential.id,
      publicKey: bufferToBase64Url(credential.publicKey),
      counter: credential.counter,
      transports: Array.isArray(credential.transports) ? credential.transports : [],
      deviceType: verification.registrationInfo.credentialDeviceType || '',
      backedUp: Boolean(verification.registrationInfo.credentialBackedUp),
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    const existingIndex = passkeys.findIndex((item) => item.id === storedCredential.id);
    if (existingIndex >= 0) {
      passkeys[existingIndex] = {
        ...passkeys[existingIndex],
        ...storedCredential,
      };
    } else {
      passkeys.push(storedCredential);
    }

    await persistAuthStore();

    destroyAuthFlow(flow.token);
    const sid = createSession(user.username);
    await trackEvent(req, { username: user.username }, 'auth_passkey_registered_login_success');
    jsonResponse(res, 200, buildLoginSuccessPayload(user.username), {
      'Set-Cookie': sessionCookieValue(sid),
    });
    return;
  }

  if (req.method === 'POST' && pathname === '/api/auth/passkey/authenticate/verify') {
    const body = await readJsonBody(req);
    const token = String(body.token || '').trim();
    const credentialResponse = body.credential;
    const flow = getAuthFlow(token);

    if (!flow || flow.stage !== 'passkey-auth') {
      throw new HttpError(401, 'Sessione login passkey scaduta. Riprova il login.');
    }

    const user = authUsers.get(flow.normalizedUsername);
    if (!user) {
      destroyAuthFlow(token);
      throw new HttpError(401, 'Utente non disponibile');
    }

    const passkeys = getUserPasskeys(user.normalizedUsername);
    const credentialId = String(credentialResponse && credentialResponse.id ? credentialResponse.id : '').trim();
    const storedPasskey = passkeys.find((item) => item.id === credentialId);
    if (!storedPasskey) {
      throw new HttpError(401, 'Passkey non riconosciuta per questo utente');
    }

    ensurePasskeyServerAvailable();

    let verification;
    try {
      const hostHeader = String(req.headers.host || '').split(':')[0];
      const proto = String(req.headers['x-forwarded-proto'] || 'http').split(',')[0];
      const originFromReq = `${proto}://${hostHeader}`;
      const expectedOrigins = [...webauthnExpectedOrigins];
      const expectedRpIDs = [...webauthnExpectedRpIDs];
      if (hostHeader && !expectedRpIDs.includes(hostHeader)) expectedRpIDs.push(hostHeader);
      if (originFromReq && !expectedOrigins.includes(originFromReq)) expectedOrigins.push(originFromReq);

      verification = await verifyAuthenticationResponse({
        response: credentialResponse,
        expectedChallenge: flow.challenge,
        expectedOrigin: expectedOrigins,
        expectedRPID: expectedRpIDs,
        credential: getWebAuthnCredentialFromStoredPasskey(storedPasskey),
        requireUserVerification: false,
      });
    } catch (error) {
      throw new HttpError(401, `Verifica passkey fallita: ${error.message}`);
    }

    if (!verification.verified) {
      throw new HttpError(401, 'Autenticazione passkey non verificata');
    }

    storedPasskey.counter = verification.authenticationInfo.newCounter;
    storedPasskey.deviceType = verification.authenticationInfo.credentialDeviceType || storedPasskey.deviceType;
    storedPasskey.backedUp = Boolean(verification.authenticationInfo.credentialBackedUp);
    storedPasskey.updatedAt = new Date().toISOString();
    await persistAuthStore();

    destroyAuthFlow(flow.token);
    const sid = createSession(user.username);
    await trackEvent(req, { username: user.username }, 'auth_passkey_login_success');
    jsonResponse(res, 200, buildLoginSuccessPayload(user.username), {
      'Set-Cookie': sessionCookieValue(sid),
    });
    return;
  }

  if (req.method === 'POST' && pathname === '/api/auth/logout') {
    if (!session) {
      throw new HttpError(401, 'Non autorizzato');
    }

    destroySession(session.id);
    await trackEvent(req, session, 'auth_logout');
    jsonResponse(res, 200, { ok: true }, {
      'Set-Cookie': clearSessionCookieValue(),
    });
    return;
  }

  if (req.method === 'GET' && pathname === '/api/config') {
    await trackEvent(req, session, 'map_view_loaded');
    jsonResponse(res, 200, {
      maxImageSizeMb: Math.floor(MAX_IMAGE_SIZE_BYTES / (1024 * 1024)),
      macerata: {
        center: macerataGeo.center,
        bounds: macerataGeo.bounds,
        boundary: buildBoundaryFeature(),
      },
    });
    return;
  }

  if (req.method === 'GET' && pathname === '/api/pins') {
    await trackEvent(req, session, 'pins_list_view');
    const all = await getAllPins();
    jsonResponse(res, 200, sortPinsByLatest(all).map(pinRowToResponse));
    return;
  }

  if (!session) {
    await trackEvent(req, null, 'auth_required_denied', { pathname });
    throw new HttpError(401, 'Non autorizzato');
  }

  if (req.method === 'GET' && pathname === '/api/tracking') {
    const requestedLimit = searchParams.get('limit') || '200';
    const events = await readTrackingEntries(requestedLimit);
    jsonResponse(res, 200, { items: events, total: events.length });
    return;
  }

  if (req.method === 'POST' && pathname === '/api/pins') {
    const body = await readJsonBody(req);
    const lat = parseCoordinate(body.lat);
    const lng = parseCoordinate(body.lng);

    if (lat === null || lng === null) {
      throw new HttpError(400, 'Coordinate non valide');
    }

    if (!isPointInsideMacerata(lat, lng)) {
      throw new HttpError(400, 'Puoi inserire pin solo nel comune di Macerata');
    }

    let imageFilename = null;

    try {
      imageFilename = await saveImagePayload(body.image);
      const address = await reverseGeocode(lat, lng);
      const nowIso = new Date().toISOString();

      const createdPin = {
        lat,
        lng,
        address,
        image_path: imageFilename,
        created_at: nowIso,
        updated_at: nowIso,
      };

      await createPinInDb(createdPin);
      await trackEvent(req, session, 'pin_created', {
        pinId: createdPin.id,
        lat: createdPin.lat,
        lng: createdPin.lng,
        address: createdPin.address,
      });

      jsonResponse(res, 201, pinRowToResponse(createdPin));
      return;
    } catch (error) {
      if (imageFilename) {
        await safeDeleteFileByName(imageFilename);
      }
      throw error;
    }
  }

  const pinMatch = pathname.match(/^\/api\/pins\/(\d+)$/);
  if (pinMatch) {
    const pinId = Number.parseInt(pinMatch[1], 10);
    const pin = await findPinById(pinId);

    if (!pin) {
      throw new HttpError(404, 'Pin non trovato');
    }

    if (req.method === 'PATCH') {
      const body = await readJsonBody(req);
      const hasLat = Object.prototype.hasOwnProperty.call(body, 'lat');
      const hasLng = Object.prototype.hasOwnProperty.call(body, 'lng');
      const hasImage = Object.prototype.hasOwnProperty.call(body, 'image');

      if ((hasLat && !hasLng) || (!hasLat && hasLng)) {
        throw new HttpError(400, 'Per aggiornare posizione servono lat e lng insieme');
      }

      let newImageFilename = null;
      let committedImageSwap = false;

      try {
        if (hasImage) {
          newImageFilename = await saveImagePayload(body.image);
        }

        if (hasLat && hasLng) {
          const lat = parseCoordinate(body.lat);
          const lng = parseCoordinate(body.lng);

          if (lat === null || lng === null) {
            throw new HttpError(400, 'Coordinate non valide');
          }

          if (!isPointInsideMacerata(lat, lng)) {
            throw new HttpError(400, 'Puoi inserire pin solo nel comune di Macerata');
          }

          pin.lat = lat;
          pin.lng = lng;
          pin.address = await reverseGeocode(lat, lng);
        }

        const changed = hasLat || hasLng || hasImage;
        if (!changed) {
          throw new HttpError(400, 'Nessun campo da aggiornare');
        }

        if (newImageFilename) {
          const oldImageFilename = pin.image_path;
          pin.image_path = newImageFilename;
          committedImageSwap = true;
          await safeDeleteFileByName(oldImageFilename);
        }

        pin.updated_at = new Date().toISOString();
        await updatePinInDb(pin);
        await trackEvent(req, session, 'pin_updated', {
          pinId: pin.id,
          changedPosition: hasLat && hasLng,
          changedImage: hasImage,
        });

        jsonResponse(res, 200, pinRowToResponse(pin));
        return;
      } catch (error) {
        if (newImageFilename && !committedImageSwap) {
          await safeDeleteFileByName(newImageFilename);
        }
        throw error;
      }
    }

    if (req.method === 'DELETE') {
      await deletePinInDb(pinId);
      await safeDeleteFileByName(pin.image_path);
      await trackEvent(req, session, 'pin_deleted', { pinId });
      jsonResponse(res, 200, { ok: true });
      return;
    }

    throw new HttpError(405, 'Metodo non consentito');
  }

  if (req.method === 'GET' && pathname === '/api/geocode/suggest') {
    const query = String(searchParams.get('q') || '').trim();
    const rawLimit = Number.parseInt(searchParams.get('limit') || '7', 10);
    const limit = Number.isInteger(rawLimit) ? Math.max(1, Math.min(rawLimit, 10)) : 7;

    if (query.length < 2) {
      jsonResponse(res, 200, []);
      return;
    }

    const results = await searchAddressCandidates(query, limit);
    jsonResponse(res, 200, results);
    return;
  }

  if (req.method === 'POST' && pathname === '/api/geocode') {
    const body = await readJsonBody(req);
    const address = String(body.address || '').trim();

    if (!address) {
      throw new HttpError(400, 'Inserisci un indirizzo');
    }

    const result = await geocodeAddress(address);
    if (!result) {
      throw new HttpError(404, 'Nessun risultato a Macerata per questo indirizzo');
    }

    jsonResponse(res, 200, result);
    return;
  }

  if (req.method === 'GET' && pathname === '/api/location-check') {
    const lat = parseCoordinate(searchParams.get('lat'));
    const lng = parseCoordinate(searchParams.get('lng'));

    if (lat === null || lng === null) {
      throw new HttpError(400, 'Coordinate non valide');
    }

    const inside = isPointInsideMacerata(lat, lng);
    if (!inside) {
      jsonResponse(res, 200, { inside: false });
      return;
    }

    const address = await reverseGeocode(lat, lng);
    jsonResponse(res, 200, {
      inside: true,
      address,
    });
    return;
  }

  throw new HttpError(404, 'Endpoint non trovato');
}

async function serveUploadRequest(req, res, pathname) {
  const rawFilename = pathname.slice('/uploads/'.length);
  const safeName = path.basename(rawFilename);
  if (!safeName) {
    throw new HttpError(404, 'Risorsa non trovata');
  }

  const localPath = path.join(UPLOADS_DIR, safeName);
  let stat;
  try {
    stat = await fsp.stat(localPath);
  } catch (_error) {
    throw new HttpError(404, 'Risorsa non trovata');
  }

  if (!stat.isFile()) {
    throw new HttpError(404, 'Risorsa non trovata');
  }

  const extension = path.extname(localPath).toLowerCase();
  const contentType = STATIC_MIME_TYPES[extension] || 'application/octet-stream';
  res.writeHead(200, {
    'Content-Type': contentType,
    'Content-Length': stat.size,
    'Cache-Control': 'private, no-store',
    Pragma: 'no-cache',
    Expires: '0',
  });

  if (req.method === 'HEAD') {
    res.end();
    return;
  }

  const fileStream = fs.createReadStream(localPath);
  fileStream.on('error', () => {
    if (!res.headersSent) {
      res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
    }
    res.end('Errore lettura file');
  });
  fileStream.pipe(res);
}

async function serveStaticRequest(req, res, pathname) {
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    throw new HttpError(405, 'Metodo non consentito');
  }

  let filePath;

  if (pathname.startsWith('/uploads/')) {
    await trackEvent(req, getSessionFromRequest(req), 'pin_image_view', { filename: path.basename(pathname) });
    await serveUploadRequest(req, res, pathname);
    return;
  }

  const targetPath = pathname === '/' ? '/index.html' : pathname;
  filePath = resolveSafePath(PUBLIC_DIR, targetPath);

  if (!filePath) {
    throw new HttpError(404, 'Risorsa non trovata');
  }

  let stat;
  try {
    stat = await fsp.stat(filePath);
  } catch (_error) {
    throw new HttpError(404, 'Risorsa non trovata');
  }

  if (!stat.isFile()) {
    throw new HttpError(404, 'Risorsa non trovata');
  }

  const extension = path.extname(filePath).toLowerCase();
  const contentType = STATIC_MIME_TYPES[extension] || 'application/octet-stream';
  const isUploadFile = pathname.startsWith('/uploads/');
  if (isUploadFile) {
    await trackEvent(req, getSessionFromRequest(req), 'pin_image_view', { filename: path.basename(pathname) });
  }

  res.writeHead(200, {
    'Content-Type': contentType,
    'Content-Length': stat.size,
    'Cache-Control': isUploadFile ? 'private, no-store' : 'no-store, no-cache, must-revalidate',
    Pragma: 'no-cache',
    Expires: '0',
  });

  if (req.method === 'HEAD') {
    res.end();
    return;
  }

  const fileStream = fs.createReadStream(filePath);
  fileStream.on('error', () => {
    if (!res.headersSent) {
      res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
    }
    res.end('Errore lettura file');
  });
  fileStream.pipe(res);
}

function isApiPath(pathname) {
  return pathname.startsWith('/api/');
}

function normalizeIncomingPath(pathname) {
  return String(pathname || '/');
}

function initializeBoundaryInBackground() {
  if (!boundaryInitPromise) {
    boundaryInitPromise = initializeMacerataBoundary()
      .catch((error) => {
        console.warn(`Boundary background fallita: ${error.message}`);
      });
  }
}

async function initializeRuntime() {
  if (!initPromise) {
    initPromise = Promise.all([
      initializePinStore(),
      initializeAuthStore(),
      initializeTrackingStore(),
    ]).catch((error) => {
      initPromise = null;
      throw error;
    });
  }

  await initPromise;
  initializeBoundaryInBackground();
}

async function requestHandler(req, res) {
  try {
    await initializeRuntime();

    const baseUrl = `http://${req.headers.host || `localhost:${PORT}`}`;
    const url = new URL(req.url || '/', baseUrl);
    const pathname = normalizeIncomingPath(decodeURIComponent(url.pathname));
    const session = getSessionFromRequest(req);

    if (isApiPath(pathname)) {
      await handleApiRequest(req, res, pathname, url.searchParams, session);
    } else {
      await serveStaticRequest(req, res, pathname);
    }
  } catch (error) {
    if (error instanceof HttpError) {
      jsonResponse(res, error.statusCode, { error: error.message });
      return;
    }

    console.error('Errore server:', error);
    jsonResponse(res, 500, { error: 'Errore interno del server' });
  }
}

async function startServer() {
  await initializeRuntime();

  const server = http.createServer((req, res) => {
    requestHandler(req, res);
  });

  server.listen(PORT, () => {
    console.log(`Server attivo su http://localhost:${PORT}`);
    console.log(`Boundary source: ${macerataGeo.sourceLabel}`);
    console.log(`Using database at: ${process.env.MONGODB_URI || process.env.DATABASE_URL || process.env.MONGO_URL || process.env.MYSQL_URL || '<not configured>'}`);
    console.log(`Utenti auth: ${listAuthUsers().join(', ')}`);
  });
}

module.exports = {
  requestHandler,
  initializeRuntime,
  startServer,
};

if (require.main === module) {
  startServer().catch((error) => {
    console.error('Avvio server fallito:', error);
    process.exit(1);
  });
}
