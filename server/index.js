import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import cors from 'cors';
import { exec as execCallback, spawn } from 'child_process';
import { promisify } from 'util';
import path from 'path';
import fs from 'fs';
import http from 'http';
import os from 'os';
import crypto from 'crypto';
import { pipeline } from 'stream';
import { fileURLToPath } from 'url';
import { PrismaClient } from '@prisma/client';
import { load as loadHtml } from 'cheerio';
import axios from 'axios';
import { wrapper as wrapAxiosCookieJar } from 'axios-cookiejar-support';
import { CookieJar } from 'tough-cookie';
import extractZip from 'extract-zip';
import multer from 'multer';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import { OAuth2Client } from 'google-auth-library';
import { WebSocketServer, WebSocket } from 'ws';
import pty from 'node-pty';
import pino from 'pino';
import pinoHttp from 'pino-http';
import morgan from 'morgan';

const exec = promisify(execCallback);
const streamPipeline = promisify(pipeline);
const app = express();
const prisma = new PrismaClient();
const LOG_LEVEL = process.env.LOG_LEVEL ?? 'info';
const logger = pino({
  level: LOG_LEVEL,
  base: undefined,
});
const httpLogger = pinoHttp({
  logger,
  customLogLevel(res, err) {
    if (err || res.statusCode >= 500) return 'error';
    if (res.statusCode >= 400) return 'warn';
    return 'info';
  },
});
const HTTP_LOG_FORMAT = (() => {
  const raw = process.env.HTTP_LOG_FORMAT;
  if (raw === undefined) return 'combined';
  return raw;
})();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = process.env.CLI_BASE_DIR
  ? path.resolve(process.env.CLI_BASE_DIR)
  : path.resolve(__dirname, '..');
const FILE_STORAGE_DIR = path.join(ROOT_DIR, 'storage', 'ctf-files');
fs.mkdirSync(FILE_STORAGE_DIR, { recursive: true });
const CLI_WS_PATH = process.env.CLI_WS_PATH ?? '/ws/codex';
const CLI_INTERACTIVE_COMMAND = process.env.CLI_INTERACTIVE_COMMAND ?? 'codex';
const CLI_MAX_SESSIONS = Number(process.env.CLI_MAX_SESSIONS ?? 8);
const CLI_MAX_SESSIONS_PER_USER = Number(process.env.CLI_MAX_SESSIONS_PER_USER ?? 4);
const CLI_SESSION_IDLE_TTL_MS = Number(process.env.CLI_SESSION_IDLE_TTL_MS ?? 30 * 60 * 1000);
const IDA_MCP_SHARE_DIR = process.env.IDA_MCP_SHARE_DIR || '/mnt/c/ctf-hunter/ida-mirror';
if (IDA_MCP_SHARE_DIR) {
  try {
    fs.mkdirSync(IDA_MCP_SHARE_DIR, { recursive: true });
  } catch (error) {
    logger.warn({ err: error }, '[IDA MCP] Failed to initialize share directory');
  }
}
const MANUAL_UPLOAD_MAX_BYTES = Number(process.env.MANUAL_UPLOAD_MAX_BYTES ?? 3 * 1024 * 1024 * 1024);
const manualUploadStorage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, os.tmpdir()),
  filename: (_req, file, cb) => {
    const ext = path.extname(file?.originalname ?? '');
    const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
    cb(null, `manual-upload-${uniqueSuffix}${ext || ''}`);
  },
});
const manualUploadMiddleware = multer({
  storage: manualUploadStorage,
  limits: {
    fileSize: MANUAL_UPLOAD_MAX_BYTES,
  },
});
const manualArchiveUpload = manualUploadMiddleware.single('archive');

const parseArgsString = (value) => {
  if (!value || typeof value !== 'string') return [];
  const result = [];
  let current = '';
  let quote = null;
  let escapeNext = false;

  for (const char of value.trim()) {
    if (escapeNext) {
      current += char;
      escapeNext = false;
      continue;
    }

    if (char === '\\') {
      escapeNext = true;
      continue;
    }

    if (quote) {
      if (char === quote) {
        quote = null;
      } else {
        current += char;
      }
      continue;
    }

    if (char === '"' || char === "'") {
      quote = char;
      continue;
    }

    if (/\s/.test(char)) {
      if (current) {
        result.push(current);
        current = '';
      }
      continue;
    }

    current += char;
  }

  if (current) {
    result.push(current);
  }

  return result;
};

const CLI_INTERACTIVE_ARGS = (() => {
  const rawArgs = process.env.CLI_INTERACTIVE_ARGS;
  if (typeof rawArgs === 'string' && rawArgs.trim().length > 0) {
    return parseArgsString(rawArgs);
  }

  const approvalPolicy = process.env.CLI_APPROVAL_POLICY ?? 'never';
  const sandboxMode = process.env.CLI_SANDBOX_MODE ?? 'danger-full-access';
  return ['--ask-for-approval', approvalPolicy, '--sandbox', sandboxMode];
})();
// eslint-disable-next-line no-control-regex
const ANSI_CSI_REGEX = /\u001b\[[0-9;?]*[ -/]*[@-~]/g;
// eslint-disable-next-line no-control-regex
const ANSI_OSC_REGEX = /\u001b\][^\u0007]*\u0007/g;
const stripAnsi = (value) => {
  if (typeof value !== 'string') return '';
  return value.replace(ANSI_CSI_REGEX, '').replace(ANSI_OSC_REGEX, '');
};
const CLI_AUTO_APPROVE = (process.env.CLI_AUTO_APPROVE ?? 'true').toLowerCase() !== 'false';
const CLI_AUTO_APPROVE_CHOICE = process.env.CLI_AUTO_APPROVE_CHOICE === '2' ? '2\n' : '1\n';
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL
  ? process.env.PUBLIC_BASE_URL.replace(/\/$/, '')
  : null;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || process.env.VITE_GOOGLE_CLIENT_ID || null;
const parseAllowedEmails = () => {
  const raw = process.env.AUTH_ALLOWED_EMAILS;
  if (!raw) return [];
  return raw
    .split(',')
    .map((email) => email.trim().toLowerCase())
    .filter(Boolean);
};
const allowedAuthEmails = parseAllowedEmails();
const isEmailAllowed = (email) => {
  if (!email) return false;
  if (allowedAuthEmails.length === 0) return true;
  return allowedAuthEmails.includes(email.trim().toLowerCase());
};
const LEGACY_OWNER_PLACEHOLDER = 'unowned';
const isLegacyOwnerValue = (value) => !value || value === LEGACY_OWNER_PLACEHOLDER;
const getRequestUserEmail = (req) => req?.authUser?.email ?? null;
const AUTH_COOKIE_NAME = process.env.AUTH_COOKIE_NAME || 'ctf_hunter_auth';
const AUTH_JWT_SECRET = process.env.AUTH_JWT_SECRET || process.env.JWT_SECRET || 'ctf-hunter-dev-secret';
if (!process.env.AUTH_JWT_SECRET && !process.env.JWT_SECRET) {
  logger.warn('[auth] AUTH_JWT_SECRET is not set. Using fallback secret; configure AUTH_JWT_SECRET for production.');
}
const AUTH_TOKEN_TTL_SECONDS = Number(process.env.AUTH_TOKEN_TTL_SECONDS ?? 12 * 60 * 60);
const authCookieSecureEnv = (process.env.AUTH_COOKIE_SECURE ?? '').toLowerCase();
const AUTH_COOKIE_SECURE = authCookieSecureEnv === 'true'
  ? true
  : authCookieSecureEnv === 'false'
    ? false
    : (process.env.NODE_ENV ?? '').toLowerCase() === 'production';
const authCookieSameSiteEnv = (process.env.AUTH_COOKIE_SAMESITE ?? 'lax').toLowerCase();
const AUTH_COOKIE_SAMESITE = ['lax', 'strict', 'none'].includes(authCookieSameSiteEnv)
  ? authCookieSameSiteEnv
  : 'lax';
const AUTH_COOKIE_OPTIONS = {
  httpOnly: true,
  secure: AUTH_COOKIE_SECURE,
  sameSite: AUTH_COOKIE_SAMESITE,
  path: '/',
  maxAge: AUTH_TOKEN_TTL_SECONDS * 1000,
};
const googleOAuthClient = GOOGLE_CLIENT_ID ? new OAuth2Client(GOOGLE_CLIENT_ID) : null;
const decodeAuthToken = (token) => {
  if (!token) return null;
  try {
    return jwt.verify(token, AUTH_JWT_SECRET);
  } catch {
    return null;
  }
};
const buildUserFromPayload = (payload) => {
  if (!payload?.email) return null;
  return {
    email: payload.email.toLowerCase(),
    name: payload.name ?? payload.email,
    picture: payload.picture ?? null,
  };
};
const ensureCompetitionOwnership = async (competition, req, prismaArgs = undefined) => {
  if (!competition) return null;
  const userEmail = getRequestUserEmail(req);
  if (!userEmail) {
    return competition;
  }
  if (competition.ownerEmail === userEmail) {
    return competition;
  }
  if (!isLegacyOwnerValue(competition.ownerEmail)) {
    return competition;
  }
  try {
    return await prisma.competition.update({
      where: { id: competition.id },
      data: {
        ownerEmail: userEmail,
        ownerName: req.authUser?.name ?? competition.ownerName ?? null,
      },
      ...(prismaArgs ?? {}),
    });
  } catch (error) {
    void error;
    try {
      return await prisma.competition.findUnique({
        where: { id: competition.id },
        ...(prismaArgs ?? {}),
      });
    } catch {
      return competition;
    }
  }
};
const loadCompetitionForRequest = async (req, competitionId) => {
  const competition = await prisma.competition.findUnique({ where: { id: competitionId } });
  if (!competition) {
    return { competition: null, error: 'not_found' };
  }
  const normalized = await ensureCompetitionOwnership(competition, req);
  const userEmail = getRequestUserEmail(req);
  if (!normalized || !userEmail) {
    return { competition: null, error: 'forbidden' };
  }

  // Allow access if:
  // - the user owns the competition, or
  // - the competition is marked as shared, or
  // - the competition still has a legacy/unowned owner placeholder
  if (
    normalized.ownerEmail === userEmail ||
    normalized.isShared === true ||
    isLegacyOwnerValue(normalized.ownerEmail)
  ) {
    return { competition: normalized, error: null };
  }

  return { competition: null, error: 'forbidden' };
};
const respondCompetitionAccessError = (res, error) => {
  if (error === 'forbidden') {
    return res.status(403).json({ ok: false, error: 'Forbidden' });
  }
  return res.status(404).json({ ok: false, error: 'Competition not found' });
};
const requireCompetitionAccess = async (req, res, competitionId) => {
  const { competition, error } = await loadCompetitionForRequest(req, competitionId);
  if (!competition) {
    respondCompetitionAccessError(res, error);
    return null;
  }
  return competition;
};
const getTokenFromHeaders = (headers = {}) => {
  const authHeader = headers.authorization || headers.Authorization;
  if (typeof authHeader === 'string' && authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7);
  }
  const cookieHeader = headers.cookie || headers.Cookie;
  if (typeof cookieHeader === 'string' && cookieHeader.includes(`${AUTH_COOKIE_NAME}=`)) {
    const parts = cookieHeader.split(';').map((part) => part.trim());
    for (const part of parts) {
      if (!part) continue;
      const [key, ...rest] = part.split('=');
      if (key === AUTH_COOKIE_NAME) {
        return decodeURIComponent(rest.join('='));
      }
    }
  }
  return null;
};
const getTokenFromRequest = (req) => {
  if (req.cookies?.[AUTH_COOKIE_NAME]) {
    return req.cookies[AUTH_COOKIE_NAME];
  }
  return getTokenFromHeaders(req.headers ?? {});
};
const authenticateUserFromRequest = (req) => {
  const token = getTokenFromRequest(req);
  const payload = decodeAuthToken(token);
  return buildUserFromPayload(payload);
};
const respondUnauthorized = (req, res) => {
  if (req.path?.startsWith('/files')) {
    return res.status(401).end('Unauthorized');
  }
  return res.status(401).json({ ok: false, error: 'Unauthorized' });
};
const shouldEnforceAuth = (req) => {
  if (req.method === 'OPTIONS') return false;
  const pathLower = (req.path || req.originalUrl || '').toLowerCase();
  if (pathLower.startsWith('/api/auth')) return false;
  if (pathLower === '/api/healthz') return false;
  if (pathLower.startsWith('/api')) return true;
  if (pathLower.startsWith('/files')) return true;
  return false;
};
const setSessionCookie = (res, payload) => {
  const token = jwt.sign(payload, AUTH_JWT_SECRET, { expiresIn: AUTH_TOKEN_TTL_SECONDS });
  res.cookie(AUTH_COOKIE_NAME, token, AUTH_COOKIE_OPTIONS);
  return token;
};
const clearSessionCookie = (res) => {
  res.clearCookie(AUTH_COOKIE_NAME, { ...AUTH_COOKIE_OPTIONS, maxAge: 0 });
};

// Origin allowlist (default: localhost/127.0.0.1 and primary domain)
const DEFAULT_ALLOWED_HOSTS = ['localhost', '127.0.0.1', 'dooly.life'];

const parseAllowedOrigins = () => {
  const raw = process.env.ALLOWED_ORIGINS;
  if (!raw) return null; // use default localhost rules
  return raw.split(',').map((s) => s.trim()).filter(Boolean);
};
const isOriginAllowed = (origin) => {
  if (!origin) return true; // non-browser or same-origin
  try {
    const url = new URL(origin);
    const allowed = parseAllowedOrigins();
    if (!allowed) {
      return DEFAULT_ALLOWED_HOSTS.includes(url.hostname);
    }
    // Strict match by origin if full URL provided; allow hostname-only entries
    return allowed.some((pattern) => {
      try {
        const p = new URL(pattern);
        return p.origin === url.origin;
      } catch {
        return url.hostname === pattern;
      }
    });
  } catch {
    return false;
  }
};
app.use(httpLogger);
if (HTTP_LOG_FORMAT && !['off', 'none'].includes(HTTP_LOG_FORMAT.toLowerCase())) {
  app.use(morgan(HTTP_LOG_FORMAT, {
    stream: {
      write: (message) => logger.info({ msg: message.trim(), source: 'morgan' }),
    },
  }));
}
app.use(cors({
  origin: (origin, callback) => {
    if (isOriginAllowed(origin)) return callback(null, true);
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
}));
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());
app.use((req, _res, next) => {
  req.authUser = authenticateUserFromRequest(req);
  next();
});
app.use((req, res, next) => {
  if (!shouldEnforceAuth(req)) {
    return next();
  }
  if (req.authUser) {
    return next();
  }
  return respondUnauthorized(req, res);
});
app.use('/files', express.static(FILE_STORAGE_DIR));

// Track a single active ida-mcp process globally
let activeIdaProcess = null; // { child, startedAt, exePath, host, port, file, problemId, ownerEmail }

const resolveCwd = (inputDir) => {
  if (!inputDir) {
    return ROOT_DIR;
  }

  const resolved = path.resolve(ROOT_DIR, inputDir);

  if (!resolved.startsWith(ROOT_DIR)) {
    throw new Error('CWD must stay inside project root');
  }

  return resolved;
};

const CLI_INTERACTIVE_CWD = (() => {
  const value = process.env.CLI_INTERACTIVE_CWD;
  if (!value) {
    return ROOT_DIR;
  }
  return resolveCwd(value);
})();

app.get('/api/healthz', (_req, res) => {
  res.json({ ok: true, cwd: ROOT_DIR });
});

app.get('/api/auth/me', (req, res) => {
  if (!req.authUser) {
    return res.status(401).json({ ok: false, error: 'Unauthorized' });
  }
  return res.json({ ok: true, user: req.authUser });
});

app.post('/api/auth/logout', (req, res) => {
  clearSessionCookie(res);
  res.json({ ok: true });
});

app.post('/api/auth/google', async (req, res) => {
  if (!googleOAuthClient || !GOOGLE_CLIENT_ID) {
    return res.status(500).json({ ok: false, error: 'Google SSO is not configured.' });
  }

  const credential = req.body?.credential;
  if (!credential || typeof credential !== 'string') {
    return res.status(400).json({ ok: false, error: 'credential is required.' });
  }

  try {
    const ticket = await googleOAuthClient.verifyIdToken({
      idToken: credential,
      audience: GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    if (!payload?.email) {
      return res.status(400).json({ ok: false, error: '이메일 정보를 확인할 수 없습니다.' });
    }
    if (payload.email_verified === false) {
      return res.status(403).json({ ok: false, error: '이메일이 검증되지 않았습니다.' });
    }
    if (!isEmailAllowed(payload.email)) {
      return res.status(403).json({ ok: false, error: '허용되지 않은 이메일입니다.' });
    }

    const user = {
      email: payload.email.toLowerCase(),
      name: payload.name ?? payload.email,
      picture: payload.picture ?? null,
    };
    setSessionCookie(res, user);
    return res.json({ ok: true, user });
  } catch (error) {
    logger.error({ err: error }, '[auth] Failed to verify Google credential');
    return res.status(401).json({ ok: false, error: 'Google 인증에 실패했습니다.' });
  }
});

const getFileNameFromPath = (input) => {
  if (!input) return '첨부파일';
  try {
    return path.basename(decodeURIComponent(input));
  } catch {
    return path.basename(input);
  }
};

const normalizeStoredFile = (file) => {
  if (!file) return null;
  if (typeof file === 'string') {
    return {
      name: getFileNameFromPath(file),
      url: file,
    };
  }
  if (typeof file === 'object' && typeof file.url === 'string') {
    return {
      name: typeof file.name === 'string' && file.name.trim()
        ? file.name
        : getFileNameFromPath(file.url),
      url: file.url,
    };
  }
  return null;
};

const parseFilesRaw = (filesRaw) => {
  if (!filesRaw) return [];
  try {
    const parsed = JSON.parse(filesRaw);
    if (!Array.isArray(parsed)) return [];
    return parsed
      .map(normalizeStoredFile)
      .filter((file) => Boolean(file));
  } catch {
    return [];
  }
};

const encodePathSegment = (value) => encodeURIComponent(String(value));
const normalizeRelativePath = (value) =>
  (value ?? '')
    .split(/[\\/]+/g)
    .filter(Boolean)
    .join('/');
const decodeRelativePath = (value) =>
  (value ?? '')
    .split('/')
    .filter(Boolean)
    .map((segment) => {
      try {
        return decodeURIComponent(segment);
      } catch {
        return segment;
      }
    });

const buildPublicFileUrl = (competitionId, challengeId, relativePath) => {
  const encodedRelative = normalizeRelativePath(relativePath)
    .split('/')
    .filter(Boolean)
    .map(encodePathSegment)
    .join('/');
  const base = `/files/${encodePathSegment(competitionId)}/${encodePathSegment(challengeId)}`;
  return encodedRelative ? `${base}/${encodedRelative}` : base;
};

const toPosixPath = (value) => value.split(path.sep).join('/');

const ensureIdaAccessiblePath = async (linuxPath, competitionId, problemId) => {
  if (!linuxPath || linuxPath.startsWith('/mnt/')) {
    return linuxPath;
  }
  if (!IDA_MCP_SHARE_DIR) {
    return linuxPath;
  }
  const relativeFromStorage = (() => {
    const relative = path.relative(FILE_STORAGE_DIR, linuxPath);
    if (relative && !relative.startsWith('..')) {
      return relative;
    }
    return path.basename(linuxPath);
  })();
  const destinationPath = path.join(
    IDA_MCP_SHARE_DIR,
    competitionId,
    problemId,
    relativeFromStorage,
  );
  await fs.promises.mkdir(path.dirname(destinationPath), { recursive: true });
  await fs.promises.copyFile(linuxPath, destinationPath);
  return destinationPath;
};

const getFsErrorCode = (error) => {
  if (error && typeof error === 'object' && 'code' in error) {
    const code = error.code;
    if (typeof code === 'string') {
      return code;
    }
  }
  return null;
};

const createUniqueDirectory = async (basePath) => {
  let attempt = basePath;
  let counter = 1;
  while (true) {
    try {
      await fs.promises.mkdir(attempt, { recursive: false });
      return attempt;
    } catch (error) {
      const code = getFsErrorCode(error);
      if (code === 'EEXIST') {
        attempt = `${basePath}-${counter}`;
        counter += 1;
        continue;
      }
      if (code === 'ENOENT') {
        await fs.promises.mkdir(path.dirname(attempt), { recursive: true });
        continue;
      }
      throw error;
    }
  }
};

const collectFilesRecursively = async (dir) => {
  const entries = await fs.promises.readdir(dir, { withFileTypes: true }).catch(() => []);
  const files = [];
  for (const entry of entries) {
    const entryPath = path.join(dir, entry.name);
    if (entry.isSymbolicLink?.()) {
      continue;
    }
    if (entry.isDirectory()) {
      const nested = await collectFilesRecursively(entryPath);
      files.push(...nested);
    } else if (entry.isFile()) {
      files.push(entryPath);
    }
  }
  return files;
};

const isZipArchive = (filename, contentType) => {
  const ext = path.extname(filename ?? '').toLowerCase();
  if (ext === '.zip') return true;
  if (typeof contentType === 'string' && contentType.toLowerCase().includes('zip')) {
    return true;
  }
  return false;
};

const extractZipArchive = async ({ zipPath, archiveLabel, challengeDir, competitionId, challengeId }) => {
  const baseLabel = archiveLabel || path.basename(zipPath, path.extname(zipPath)) || 'archive';
  const extractBaseDir = path.join(challengeDir, `${baseLabel}-extracted`);
  let extractDir;
  try {
    extractDir = await createUniqueDirectory(extractBaseDir);
  } catch (error) {
    logger.warn({ err: error }, '[CTFd Import] 압축 해제 디렉터리를 만들지 못했습니다.');
    return [];
  }

  try {
    await extractZip(zipPath, { dir: extractDir });
  } catch (error) {
    logger.warn({ err: error }, '[CTFd Import] ZIP 파일을 해제하지 못했습니다.');
    return [];
  }

  const extractedPaths = await collectFilesRecursively(extractDir);
  if (extractedPaths.length === 0) {
    return [];
  }

  const files = [];
  for (const filePath of extractedPaths) {
    const relativeToChallenge = path.relative(challengeDir, filePath);
    if (relativeToChallenge.startsWith('..')) {
      continue;
    }
    const relativeInsideArchive = path.relative(extractDir, filePath) || path.basename(filePath);
    files.push({
      name: `${baseLabel}/${toPosixPath(relativeInsideArchive)}`,
      url: buildPublicFileUrl(competitionId, challengeId, toPosixPath(relativeToChallenge)),
    });
  }
  return files;
};

const normalizeProblemKeyPart = (value) => (typeof value === 'string' ? value.trim().toLowerCase() : '');

const buildProblemMatchKey = (title, source) => {
  const normalizedTitle = normalizeProblemKeyPart(title);
  if (!normalizedTitle) return null;
  const normalizedSource = normalizeProblemKeyPart(source);
  return `${normalizedSource}::${normalizedTitle}`;
};

const mergeProblemsTx = async (tx, competitionId, incomingProblems) => {
  const existingProblems = await tx.problem.findMany({
    where: { competitionId },
  });
  const existingMap = new Map();
  for (const problem of existingProblems) {
    const key = buildProblemMatchKey(problem.title, problem.source);
    if (key) {
      existingMap.set(key, problem);
    }
  }

  const created = [];
  const updated = [];

  for (const incoming of incomingProblems) {
    const key = buildProblemMatchKey(incoming.title, incoming.source);
    const match = key ? existingMap.get(key) : null;
    if (match) {
      const updatedProblem = await tx.problem.update({
        where: { id: match.id },
        data: {
          description: incoming.description,
          filesRaw: incoming.filesRaw ?? null,
        },
      });
      updated.push(updatedProblem);
    } else {
      const createdProblem = await tx.problem.create({
        data: incoming,
      });
      created.push(createdProblem);
    }
  }

  return { created, updated };
};

// Resolve a public file URL (served at /files/...) to a local disk path inside FILE_STORAGE_DIR
const resolvePublicFileUrlToLocalPath = (fileUrl) => {
  if (!fileUrl || typeof fileUrl !== 'string') return null;
  try {
    // Accept absolute URLs as well as path-only values
    const base = 'http://local';
    const parsed = new URL(fileUrl, base);
    const pathname = parsed.pathname || '';
    const PREFIX = '/files/';
    if (pathname.startsWith(PREFIX)) {
      const relative = pathname.slice(PREFIX.length); // <competitionId>/<problemId>/<filename>
      const decodedSegments = decodeRelativePath(relative);
      return path.join(FILE_STORAGE_DIR, ...decodedSegments);
    }
  } catch {
    // If URL parsing fails, try raw prefix check
    const PREFIX = '/files/';
    if (fileUrl.startsWith(PREFIX)) {
      const relative = fileUrl.slice(PREFIX.length);
      const decodedSegments = decodeRelativePath(relative);
      return path.join(FILE_STORAGE_DIR, ...decodedSegments);
    }
  }
  return null;
};

const collectCompetitionStorageDirsFromFiles = (competitionId, filesRaw) => {
  if (!competitionId || !filesRaw) return [];
  const files = parseFilesRaw(filesRaw);
  if (!files.length) return [];
  const competitionDir = path.join(FILE_STORAGE_DIR, competitionId);
  const dirs = new Set();
  for (const file of files) {
    if (!file?.url) continue;
    const localPath = resolvePublicFileUrlToLocalPath(file.url);
    if (!localPath) continue;
    if (!isPathInside(competitionDir, localPath)) continue;
    const relative = path.relative(competitionDir, localPath);
    if (!relative || relative.startsWith('..')) continue;
    const [storageKey] = relative.split(path.sep);
    if (!storageKey) continue;
    dirs.add(path.join(competitionDir, storageKey));
  }
  return Array.from(dirs);
};

const parseBooleanField = (value) => {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'number') return value !== 0;
  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase();
    return ['1', 'true', 'yes', 'y', 'on'].includes(normalized);
  }
  return false;
};

const sanitizeManualSourceLabel = (value, fallback = 'manual-upload') => {
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (trimmed) {
      return trimmed.slice(0, 120);
    }
  }
  return fallback;
};

const safeRelativeSegments = (value) => {
  if (typeof value !== 'string') return null;
  const rawSegments = value
    .split(/[\\/]+/g)
    .map((segment) => segment.trim())
    .filter(Boolean);
  if (rawSegments.length === 0) {
    return null;
  }
  if (rawSegments.some((segment) => segment === '.' || segment === '..')) {
    return null;
  }
  return rawSegments;
};

const sanitizeArchiveRelativePath = (value) => {
  const segments = safeRelativeSegments(value);
  if (!segments) return null;
  return segments.join('/');
};

const isPathInside = (parent, target) => {
  if (!parent || !target) return false;
  const relative = path.relative(parent, target);
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
};

const MANUAL_MANIFEST_FILES = ['manifest.json', 'problems.json', 'challenges.json', 'tasks.json', 'metadata.json'];

const findManualManifestFile = async (rootDir) => {
  if (!rootDir) return null;
  const allFiles = await collectFilesRecursively(rootDir);
  if (allFiles.length === 0) return null;
  const jsonFiles = allFiles.filter((filePath) => path.extname(filePath).toLowerCase() === '.json');
  if (jsonFiles.length === 0) return null;
  for (const preferred of MANUAL_MANIFEST_FILES) {
    const match = jsonFiles.find((filePath) => path.basename(filePath).toLowerCase() === preferred);
    if (match) {
      return match;
    }
  }
  return jsonFiles[0];
};

const manualDifficultyFromValue = (value, fallbackPoints = 0) => {
  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase();
    if (['easy', 'beginner', 'trivial'].includes(normalized)) return 'Easy';
    if (['medium', 'normal'].includes(normalized)) return 'Medium';
    if (['hard', 'insane', 'advanced'].includes(normalized)) return 'Hard';
  }
  if (typeof value === 'number' && Number.isFinite(value)) {
    if (value <= 150) return 'Easy';
    if (value <= 300) return 'Medium';
    return 'Hard';
  }
  if (typeof fallbackPoints === 'number' && Number.isFinite(fallbackPoints)) {
    if (fallbackPoints <= 150) return 'Easy';
    if (fallbackPoints <= 300) return 'Medium';
    if (fallbackPoints > 0) return 'Hard';
  }
  return 'Medium';
};

const parsePointsValue = (value) => {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return Math.max(0, Math.round(value));
  }
  if (typeof value === 'string') {
    const parsed = Number(value.trim());
    if (Number.isFinite(parsed)) {
      return Math.max(0, Math.round(parsed));
    }
  }
  return 0;
};

const normalizeProblemDescription = (rawProblem) => {
  const textCandidates = [rawProblem?.description, rawProblem?.body, rawProblem?.prompt, rawProblem?.text];
  const main = textCandidates.find((candidate) => typeof candidate === 'string' && candidate.trim());
  const connection = rawProblem?.connection_info || rawProblem?.connection || rawProblem?.host;
  const parts = [];
  if (typeof main === 'string') {
    parts.push(main.trim());
  }
  if (typeof connection === 'string' && connection.trim()) {
    parts.push(`[접속 정보]\n${connection.trim()}`);
  }
  return parts.join('\n\n');
};

const normalizeHints = (rawHints) => {
  if (!Array.isArray(rawHints)) return [];
  return rawHints
    .map((hint) => (typeof hint === 'string' ? hint.trim() : null))
    .filter((hint) => Boolean(hint));
};

const manualFileEntryFromValue = (value) => {
  if (!value) return null;
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!trimmed) return null;
    if (isAbsoluteUrl(trimmed)) {
      return { kind: 'url', value: trimmed, name: null };
    }
    return { kind: 'path', value: trimmed, name: null };
  }
  if (typeof value === 'object') {
    if (typeof value.url === 'string' && value.url.trim()) {
      return {
        kind: 'url',
        value: value.url.trim(),
        name: typeof value.name === 'string' && value.name.trim() ? value.name.trim() : null,
      };
    }
    const pathCandidate = value.path || value.file || value.location;
    if (typeof pathCandidate === 'string' && pathCandidate.trim()) {
      return {
        kind: 'path',
        value: pathCandidate.trim(),
        name: typeof value.name === 'string' && value.name.trim() ? value.name.trim() : null,
      };
    }
  }
  return null;
};

const collectManualFileEntries = (rawProblem) => {
  const collections = [rawProblem?.files, rawProblem?.attachments, rawProblem?.resources];
  for (const collection of collections) {
    if (Array.isArray(collection) && collection.length > 0) {
      return collection
        .map((entry) => manualFileEntryFromValue(entry))
        .filter((entry) => Boolean(entry));
    }
  }
  return [];
};

const parseManualProblemsPayload = (payload, { defaultSource }) => {
  const extractArray = (input) => {
    if (Array.isArray(input)) return input;
    if (input && typeof input === 'object') {
      if (Array.isArray(input.problems)) return input.problems;
      if (Array.isArray(input.challenges)) return input.challenges;
      if (Array.isArray(input.tasks)) return input.tasks;
      if (Array.isArray(input.items)) return input.items;
    }
    return null;
  };

  const array = extractArray(payload);
  if (!array || array.length === 0) {
    throw new Error('업로드 파일에서 problems/challenges 목록을 찾지 못했습니다.');
  }

  const parsed = [];
  const skipped = [];

  array.forEach((rawProblem, index) => {
    const title = typeof rawProblem?.title === 'string'
      ? rawProblem.title.trim()
      : typeof rawProblem?.name === 'string'
        ? rawProblem.name.trim()
        : '';
    const description = normalizeProblemDescription(rawProblem);
    if (!title) {
      skipped.push({ index, reason: '제목이 없어 건너뛰었습니다.' });
      return;
    }
    if (!description) {
      skipped.push({ index, title, reason: '설명이 없어 건너뛰었습니다.' });
      return;
    }

    const points = parsePointsValue(rawProblem?.points ?? rawProblem?.score ?? rawProblem?.value);
    const fileEntries = collectManualFileEntries(rawProblem);
    parsed.push({
      index,
      storageKey: `manual-${crypto.randomUUID()}`,
      title,
      description,
      category: sanitizeCategoryLabel(rawProblem?.category ?? rawProblem?.type ?? 'Misc'),
      difficulty: manualDifficultyFromValue(rawProblem?.difficulty ?? rawProblem?.level, points),
      points,
      hints: normalizeHints(rawProblem?.hints),
      fileEntries,
      source: sanitizeManualSourceLabel(rawProblem?.source, defaultSource),
    });
  });

  return { problems: parsed, skipped };
};

const buildManualImportError = (message, statusCode = 400) => Object.assign(new Error(message), {
  statusCode,
  isUserError: true,
});

const copyManualProblemFiles = async ({ problem, manifestDir, extractedRoot, competitionId }) => {
  const warnings = [];
  if (!Array.isArray(problem.fileEntries) || problem.fileEntries.length === 0) {
    return { files: [], warnings };
  }

  let challengeDir = null;
  const ensureChallengeDir = async () => {
    if (challengeDir) return challengeDir;
    const dir = path.join(FILE_STORAGE_DIR, competitionId, problem.storageKey);
    await fs.promises.rm(dir, { recursive: true, force: true }).catch(() => {});
    await fs.promises.mkdir(dir, { recursive: true });
    challengeDir = dir;
    return dir;
  };

  const storedFiles = [];

  const addStoredFile = async ({ sourcePath, relativePathSegments, displayName }) => {
    const baseDir = await ensureChallengeDir();
    const destinationPath = path.join(baseDir, ...relativePathSegments);
    await fs.promises.mkdir(path.dirname(destinationPath), { recursive: true });
    await fs.promises.copyFile(sourcePath, destinationPath);
    const relativeForUrl = toPosixPath(path.relative(baseDir, destinationPath));
    storedFiles.push({
      name: displayName ?? relativeForUrl,
      url: buildPublicFileUrl(competitionId, problem.storageKey, relativeForUrl),
    });
  };

  for (const entry of problem.fileEntries) {
    if (entry.kind === 'url') {
      const normalized = normalizeStoredFile({
        name: entry.name,
        url: entry.value,
      });
      if (normalized) {
        storedFiles.push(normalized);
      }
      continue;
    }

    if (!manifestDir || !extractedRoot) {
      warnings.push(`'${entry.value}' 파일을 찾을 수 없어 건너뛰었습니다. ZIP 안에 첨부 파일을 포함하세요.`);
      continue;
    }

    const sanitizedRelative = sanitizeArchiveRelativePath(entry.value);
    if (!sanitizedRelative) {
      warnings.push(`'${entry.value}' 경로가 올바르지 않아 건너뛰었습니다.`);
      continue;
    }

    const absolutePath = path.resolve(manifestDir, sanitizedRelative);
    if (!isPathInside(extractedRoot, absolutePath)) {
      warnings.push(`'${entry.value}' 경로가 ZIP 루트 밖에 있어 건너뛰었습니다.`);
      continue;
    }

    const stat = await fs.promises.stat(absolutePath).catch(() => null);
    if (!stat) {
      warnings.push(`'${entry.value}' 파일을 ZIP 안에서 찾지 못했습니다.`);
      continue;
    }

    if (stat.isDirectory()) {
      const nestedFiles = await collectFilesRecursively(absolutePath);
      if (nestedFiles.length === 0) {
        warnings.push(`'${entry.value}' 폴더가 비어 있어 건너뛰었습니다.`);
        continue;
      }
      for (const nested of nestedFiles) {
        const nestedRelative = path.relative(manifestDir, nested);
        const nestedSanitized = sanitizeArchiveRelativePath(nestedRelative);
        if (!nestedSanitized) {
          warnings.push(`'${nestedRelative}' 경로가 올바르지 않아 건너뛰었습니다.`);
          continue;
        }
        const segments = nestedSanitized.split('/');
        await addStoredFile({
          sourcePath: nested,
          relativePathSegments: segments,
          displayName: entry.name ? `${entry.name}/${path.basename(nested)}` : null,
        });
      }
      continue;
    }

    const segments = sanitizedRelative.split('/');
    await addStoredFile({
      sourcePath: absolutePath,
      relativePathSegments: segments,
      displayName: entry.name ?? null,
    });
  }

  return { files: storedFiles, warnings };
};

const sanitizeUploadedFilename = (value, fallback = 'attachment') => {
  if (typeof value !== 'string') {
    return fallback;
  }
  const replaced = value.replace(/[\\/:]+/g, '_').trim();
  return replaced || fallback;
};

const deriveProblemTitleFromUpload = (uploadedFile) => {
  const originalName = uploadedFile?.originalname ?? uploadedFile?.filename ?? '';
  if (originalName) {
    const base = path.basename(originalName, path.extname(originalName)).trim();
    if (base) {
      return base.slice(0, 120);
    }
  }
  return '직접 업로드한 문제';
};

const copyExtractedFilesToChallengeDir = async ({
  sourceDir,
  challengeDir,
  competitionId,
  storageKey,
  warnings = [],
}) => {
  const files = [];
  const extractedFiles = await collectFilesRecursively(sourceDir);
  for (const absolutePath of extractedFiles) {
    const relative = path.relative(sourceDir, absolutePath);
    if (!relative || relative.startsWith('..')) {
      continue;
    }
    const normalized = sanitizeArchiveRelativePath(relative);
    if (!normalized) {
      warnings.push(`'${relative}' 경로가 올바르지 않아 건너뛰었습니다.`);
      continue;
    }
    const destinationPath = path.join(challengeDir, ...normalized.split('/'));
    await fs.promises.mkdir(path.dirname(destinationPath), { recursive: true });
    await fs.promises.copyFile(absolutePath, destinationPath);
    files.push({
      name: normalized,
      url: buildPublicFileUrl(competitionId, storageKey, normalized),
    });
  }
  return files;
};

const copyUploadedFileToChallengeDir = async ({
  uploadedFile,
  challengeDir,
  competitionId,
  storageKey,
}) => {
  const filename = sanitizeUploadedFilename(
    uploadedFile?.originalname ?? uploadedFile?.filename ?? `attachment-${Date.now()}`,
    `attachment-${Date.now()}`,
  );
  const destinationPath = path.join(challengeDir, filename);
  await fs.promises.copyFile(uploadedFile.path, destinationPath);
  return [{
    name: filename,
    url: buildPublicFileUrl(competitionId, storageKey, filename),
  }];
};

const buildSingleUploadProblemSpec = async ({
  competitionId,
  uploadedFile,
  extractedRoot,
  providedTitle,
  providedDescription = '',
  sourceLabel,
  category,
  warnings = [],
}) => {
  const storageKey = `manual-${crypto.randomUUID()}`;
  const challengeDir = path.join(FILE_STORAGE_DIR, competitionId, storageKey);
  await fs.promises.rm(challengeDir, { recursive: true, force: true }).catch(() => {});
  await fs.promises.mkdir(challengeDir, { recursive: true });

  let storedFiles = [];
  if (extractedRoot) {
    storedFiles = await copyExtractedFilesToChallengeDir({
      sourceDir: extractedRoot,
      challengeDir,
      competitionId,
      storageKey,
      warnings,
    });
  } else {
    storedFiles = await copyUploadedFileToChallengeDir({
      uploadedFile,
      challengeDir,
      competitionId,
      storageKey,
    });
  }

  if (!storedFiles.length) {
    warnings?.push('첨부 파일 없이 문제를 저장했습니다.');
    await fs.promises.rm(challengeDir, { recursive: true, force: true }).catch(() => {});
  }

  const fallbackTitle = deriveProblemTitleFromUpload(uploadedFile);
  const resolvedTitle = providedTitle?.trim() ? providedTitle.trim().slice(0, 200) : fallbackTitle;
  const resolvedDescription = providedDescription?.trim()
    ? providedDescription.trim().slice(0, 5000)
    : '업로드된 첨부 파일을 확인하세요.';

  return {
    competitionId,
    title: resolvedTitle,
    description: resolvedDescription,
    category: category ?? 'Misc',
    difficulty: 'Medium',
    points: 0,
    hintsRaw: null,
    filesRaw: JSON.stringify(storedFiles),
    solved: false,
    source: sourceLabel,
  };
};

const buildMetadataOnlyProblemSpec = ({
  competitionId,
  providedTitle,
  providedDescription,
  sourceLabel,
  category,
}) => {
  const resolvedTitle = providedTitle?.trim() ? providedTitle.trim().slice(0, 200) : '수동 등록 문제';
  const resolvedDescription = providedDescription?.trim();
  if (!resolvedDescription) {
    throw buildManualImportError('문제 설명을 입력해주세요.');
  }
  return {
    competitionId,
    title: resolvedTitle,
    description: resolvedDescription,
    category: category ?? 'Misc',
    difficulty: 'Medium',
    points: 0,
    hintsRaw: null,
    filesRaw: null,
    solved: false,
    source: sourceLabel,
  };
};

// No port probing — enforce a single global MCP port (default 8744)

// PowerShell path resolver (WSL interop)
const getPowerShellPath = () => {
  const candidate = '/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe';
  try {
    if (fs.existsSync(candidate)) return candidate;
  } catch {}
  return 'powershell.exe';
};

// Kill all idalib-mcp/ida_mcp processes on Windows (best-effort)
const killAllIdaMcpProcesses = async () => {
  const ps = getPowerShellPath();
  const cmd = `${JSON.stringify(ps)} -NoProfile -ExecutionPolicy Bypass -Command `
    + JSON.stringify(
      [
        "try {",
        "  Get-Process -Name 'idalib-mcp','ida_mcp' -ErrorAction SilentlyContinue |",
        "    Stop-Process -Force -ErrorAction SilentlyContinue",
        "} catch {}",
      ].join(' ')
    );
  try {
    await exec(cmd, {
      cwd: ROOT_DIR,
      timeout: Number(process.env.CLI_TIMEOUT_MS) || 10000,
      maxBuffer: Number(process.env.CLI_MAX_BUFFER) || 1024 * 1024 * 2,
      shell: process.env.CLI_SHELL || '/bin/bash',
    });
  } catch {
    // ignore
  }
};

const extractFilenameFromDisposition = (value) => {
  if (!value || typeof value !== 'string') return null;
  const match = value.match(/filename\*=UTF-8''([^;]+)|filename="?([^";]+)"?/i);
  if (match) {
    return decodeURIComponent(match[1] ?? match[2]);
  }
  return null;
};

const downloadChallengeFiles = async ({ client, fileUrls, competitionId, challengeId }) => {
  if (!client || typeof client.downloadFile !== 'function') return [];
  if (!Array.isArray(fileUrls) || fileUrls.length === 0) return [];

  const challengeDir = path.join(FILE_STORAGE_DIR, competitionId, String(challengeId));
  await fs.promises.rm(challengeDir, { recursive: true, force: true }).catch(() => {});
  await fs.promises.mkdir(challengeDir, { recursive: true });

  const downloaded = [];
  for (const fileUrl of fileUrls) {
    if (!fileUrl || typeof fileUrl !== 'string') continue;
    try {
      const response = await client.downloadFile(fileUrl);
      const disposition = response.headers?.['content-disposition'];
      const fromHeader = extractFilenameFromDisposition(disposition);
      const fallbackName = getFileNameFromPath(fileUrl);
      const baseFilename = (fromHeader || fallbackName || `attachment-${downloaded.length + 1}`).trim();
      const extension = path.extname(baseFilename);
      const nameWithoutExt = path.basename(baseFilename, extension);
      let filename = baseFilename;
      let suffix = 1;
      while (fs.existsSync(path.join(challengeDir, filename))) {
        filename = `${nameWithoutExt}-${suffix}${extension}`;
        suffix += 1;
      }
      const targetPath = path.join(challengeDir, filename);
      await streamPipeline(response.data, fs.createWriteStream(targetPath));
      downloaded.push({
        name: filename,
        url: buildPublicFileUrl(competitionId, challengeId, filename),
      });
      const contentType = response.headers?.['content-type'];
      if (isZipArchive(filename, contentType)) {
        const extractedFiles = await extractZipArchive({
          zipPath: targetPath,
          archiveLabel: nameWithoutExt || filename,
          challengeDir,
          competitionId,
          challengeId,
        });
        if (extractedFiles.length) {
          downloaded.push(...extractedFiles);
        }
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      logger.warn({ err: error, challengeId, fileUrl }, `[CTFd Import] 파일 다운로드 실패: ${message}`);
    }
  }

  return downloaded;
};

const removeCompetitionFiles = async (competitionId) => {
  const dir = path.join(FILE_STORAGE_DIR, competitionId);
  await fs.promises.rm(dir, { recursive: true, force: true }).catch(() => {});
};

const backupCompetitionFiles = async (competitionId) => {
  const competitionDir = path.join(FILE_STORAGE_DIR, competitionId);
  try {
    await fs.promises.access(competitionDir, fs.constants.F_OK);
  } catch {
    return null;
  }

  const backupDir = `${competitionDir}.bak-${Date.now()}`;
  await fs.promises.rm(backupDir, { recursive: true, force: true }).catch(() => {});
  await fs.promises.rename(competitionDir, backupDir);
  return backupDir;
};

const restoreCompetitionFilesFromBackup = async (competitionId, backupDir) => {
  if (!backupDir) return;
  const competitionDir = path.join(FILE_STORAGE_DIR, competitionId);
  try {
    await fs.promises.rm(competitionDir, { recursive: true, force: true });
    await fs.promises.rename(backupDir, competitionDir);
  } catch (error) {
    logger.error({ err: error }, '[Import] Failed to restore competition files');
  }
};

const CATEGORY_ALIASES = {
  rev: 'Reversing',
  reverse: 'Reversing',
  'reverse engineering': 'Reversing',
  reversing: 'Reversing',
  pwn: 'Pwnable',
  pwnable: 'Pwnable',
  pwnables: 'Pwnable',
  for: 'Forensics',
  forensic: 'Forensics',
  forensics: 'Forensics',
  dfir: 'Forensics',
  web: 'Web',
  'web hacking': 'Web',
  webhacking: 'Web',
  crypto: 'Crypto',
  cryptography: 'Crypto',
  misc: 'Misc',
  miscellaneous: 'Misc',
};

const sanitizeCategoryLabel = (value) => {
  if (typeof value !== 'string') {
    return 'Misc';
  }
  const trimmed = value.trim();
  return trimmed || 'Misc';
};

const normalizeCategory = (value) => {
  const label = sanitizeCategoryLabel(value);
  const canonical = CATEGORY_ALIASES[label.toLowerCase()];
  return canonical ?? 'Misc';
};

const mapProblem = (problem) => {
  const category = sanitizeCategoryLabel(problem.category);
  const normalizedCategory = normalizeCategory(category);

  return {
    id: problem.id,
    title: problem.title,
    description: problem.description,
    category,
    normalizedCategory,
    difficulty: problem.difficulty,
    points: problem.points,
    hints: problem.hintsRaw ? JSON.parse(problem.hintsRaw) : [],
    files: parseFilesRaw(problem.filesRaw),
    solved: problem.solved,
    source: problem.source ?? '',
    flag: problem.flag ?? '',
    writeup: problem.writeup ?? '',
    writeupUpdatedAt: problem.writeupUpdatedAt,
    createdAt: problem.createdAt,
  };
};

const isAbsoluteUrl = (value) => typeof value === 'string' && /^[a-z][a-z\d+\-.]*:\/\//i.test(value);

const getPublicBaseUrl = (req) => {
  if (PUBLIC_BASE_URL) return PUBLIC_BASE_URL;
  if (!req || typeof req.get !== 'function') return '';
  const host = req.get('host');
  if (!host) return '';
  const protocol = req.protocol ?? 'http';
  return `${protocol}://${host}`;
};

const mapProblemForResponse = (problem, req) => {
  const mapped = mapProblem(problem);
  if (!Array.isArray(mapped.files) || mapped.files.length === 0) {
    return mapped;
  }

  const baseUrl = getPublicBaseUrl(req);
  if (!baseUrl) {
    return mapped;
  }

  mapped.files = mapped.files.map((file) => {
    if (!file || !file.url) {
      return file;
    }
    if (isAbsoluteUrl(file.url)) {
      return {
        ...file,
        downloadUrl: file.url,
      };
    }
    return {
      ...file,
      downloadUrl: `${baseUrl}${file.url}`,
    };
  });

  return mapped;
};

const normalizeBaseUrl = (value) => {
  if (typeof value !== 'string' || !value.trim()) {
    throw new Error('CTFd URL is required');
  }
  const trimmed = value.trim();
  if (!/^https?:\/\//i.test(trimmed)) {
    throw new Error('CTFd URL must start with http:// or https://');
  }
  const url = new URL(trimmed);
  const serialized = url.toString();
  return serialized.endsWith('/') ? serialized : `${serialized}/`;
};

const extractTagStrings = (tags) => {
  if (!Array.isArray(tags)) return [];
  return tags
    .map(tag => {
      if (!tag) return null;
      if (typeof tag === 'string') return tag;
      if (typeof tag === 'object') return tag.value ?? tag.name ?? null;
      return null;
    })
    .filter((tag) => typeof tag === 'string');
};

const inferDifficulty = (challenge, detail) => {
  const tags = [
    ...extractTagStrings(challenge?.tags),
    ...extractTagStrings(detail?.tags),
  ].map(tag => tag.toLowerCase());

  if (tags.includes('easy')) return 'Easy';
  if (tags.includes('medium')) return 'Medium';
  if (tags.includes('hard')) return 'Hard';

  const value = challenge?.value ?? detail?.value;
  if (typeof value === 'number') {
    if (value <= 150) return 'Easy';
    if (value <= 300) return 'Medium';
    return 'Hard';
  }

  return 'Medium';
};

const parseCtfdResponse = (response, requestPath) => {
  const contentType = response.headers?.['content-type'] ?? '';
  const isJson = contentType.includes('application/json');
  if (!isJson && typeof response.data !== 'object') {
    throw new Error(
      `CTFd가 JSON 대신 다른 응답을 반환했습니다 (path: ${requestPath}, content-type: ${contentType || 'unknown'})`
    );
  }

  if (typeof response.data === 'string') {
    try {
      return JSON.parse(response.data);
    } catch (error) {
      throw new Error(
        `CTFd 응답을 JSON으로 파싱하지 못했습니다 (path: ${requestPath}): ${
          error instanceof Error ? error.message : String(error)
        }`
      );
    }
  }

  return response.data;
};

const createCtfdTokenClient = (baseUrl, apiKey) => {
  if (!apiKey) {
    throw new Error('CTFd API Key가 필요합니다.');
  }

  const client = axios.create({
    baseURL: baseUrl,
    headers: {
      Authorization: `Token ${apiKey}`,
      Accept: 'application/json',
      'Content-Type': 'application/json',
    },
  });

  const resolveUrl = (inputPath) => new URL(inputPath, baseUrl).toString();

  const fetchJson = async (path) => {
    try {
      const response = await client.get(resolveUrl(path));
      return parseCtfdResponse(response, path);
    } catch (error) {
      const status = error?.response?.status;
      const location = error?.response?.headers?.location;
      if (status === 302 && location?.includes('/login')) {
        const redirectError = new Error('CTFd가 로그인 페이지로 리다이렉트했습니다. API Key가 유효한지 확인하세요.');
        redirectError.status = status;
        throw redirectError;
      }
      const wrappedError = new Error(
        `CTFd 요청 실패 (path: ${path}, status: ${status ?? 'network error'})`
      );
      wrappedError.status = status;
      throw wrappedError;
    }
  };

  const downloadFile = async (fileUrl) => {
    try {
      return await client.get(resolveUrl(fileUrl), { responseType: 'stream' });
    } catch (error) {
      const status = error?.response?.status;
      const wrappedError = new Error(
        `CTFd 파일 다운로드 실패 (url: ${fileUrl}, status: ${status ?? 'network error'})`
      );
      wrappedError.status = status;
      throw wrappedError;
    }
  };

  return { fetchJson, downloadFile };
};

const createCtfdSessionClient = async (baseUrl, username, password) => {
  if (!username || !password) {
    throw new Error('CTFd 아이디와 비밀번호가 필요합니다.');
  }

  const jar = new CookieJar();
  const axiosInstance = wrapAxiosCookieJar(
    axios.create({
      baseURL: baseUrl,
      jar,
      withCredentials: true,
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
      },
    })
  );

  const resolveUrl = (inputPath) => new URL(inputPath, baseUrl).toString();

  const loginPageResponse = await axiosInstance.get('/login', {
    headers: { Accept: 'text/html,application/xhtml+xml' },
  });
  const $ = loadHtml(loginPageResponse?.data ?? '');
  const nonce = $('input[name="nonce"]').attr('value');

  if (!nonce) {
    throw new Error('CTFd 로그인 nonce를 찾을 수 없습니다.');
  }

  const form = new URLSearchParams({
    name: username,
    password,
    nonce,
  });

  await axiosInstance.post('/login', form.toString(), {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    maxRedirects: 0,
    validateStatus: (status) => status === 302 || status === 200,
  });

  const fetchJson = async (path) => {
    try {
      const response = await axiosInstance.get(resolveUrl(path));
      return parseCtfdResponse(response, path);
    } catch (error) {
      const status = error?.response?.status;
      const wrappedError = new Error(
        `CTFd 요청 실패 (path: ${path}, status: ${status ?? 'network error'})`
      );
      wrappedError.status = status;
      throw wrappedError;
    }
  };

  const downloadFile = async (fileUrl) => {
    try {
      return await axiosInstance.get(resolveUrl(fileUrl), { responseType: 'stream' });
    } catch (error) {
      const status = error?.response?.status;
      const wrappedError = new Error(
        `CTFd 파일 다운로드 실패 (url: ${fileUrl}, status: ${status ?? 'network error'})`
      );
      wrappedError.status = status;
      throw wrappedError;
    }
  };

  return { fetchJson, downloadFile };
};

app.get('/api/competitions', async (req, res) => {
  try {
    const userEmail = getRequestUserEmail(req);
    if (!userEmail) {
      return res.status(401).json({ ok: false, error: 'Unauthorized' });
    }

    const competitions = await prisma.competition.findMany({
      where: {
        OR: [
          { ownerEmail: userEmail },
          { ownerEmail: LEGACY_OWNER_PLACEHOLDER },
          { isShared: true },
        ],
      },
      orderBy: { createdAt: 'desc' },
      include: { _count: { select: { problems: true } } },
    });

    const normalized = [];
    for (const competition of competitions) {
      if (competition.ownerEmail === userEmail) {
        normalized.push(competition);
        continue;
      }
      if (competition.isShared) {
        normalized.push(competition);
        continue;
      }
      if (isLegacyOwnerValue(competition.ownerEmail)) {
        const claimed = await ensureCompetitionOwnership(competition, req, {
          include: { _count: { select: { problems: true } } },
        });
        if (claimed && (claimed.ownerEmail === userEmail || claimed.isShared)) {
          normalized.push(claimed);
        }
      }
    }

    res.json({
      ok: true,
      competitions: normalized.map((competition) => ({
        id: competition.id,
        name: competition.name,
        description: competition.description ?? '',
        createdAt: competition.createdAt,
        updatedAt: competition.updatedAt,
        problemCount: competition._count?.problems ?? 0,
        isShared: Boolean(competition.isShared),
      })),
    });
  } catch (error) {
    logger.error({ err: error }, 'Failed to fetch competitions');
    res.status(500).json({ ok: false, error: 'Failed to fetch competitions' });
  }
});

app.post('/api/competitions', async (req, res) => {
  const { name, description, isShared } = req.body ?? {};
  const userEmail = getRequestUserEmail(req);

  if (!name || typeof name !== 'string') {
    return res.status(400).json({ ok: false, error: 'name is required' });
  }
  if (!userEmail) {
    return res.status(401).json({ ok: false, error: 'Unauthorized' });
  }

  try {
    const shared = parseBooleanField(isShared);
    const competition = await prisma.competition.create({
      data: {
        name,
        description,
        ownerEmail: userEmail,
        ownerName: req.authUser?.name ?? null,
        isShared: shared,
      },
    });

    res.status(201).json({
      ok: true,
      competition: {
        id: competition.id,
        name: competition.name,
        description: competition.description ?? '',
        createdAt: competition.createdAt,
        updatedAt: competition.updatedAt,
        problemCount: 0,
        isShared: Boolean(competition.isShared),
      },
    });
  } catch (error) {
    logger.error({ err: error }, 'Failed to create competition');
    res.status(500).json({ ok: false, error: 'Failed to create competition' });
  }
});

app.get('/api/competitions/:competitionId/settings', async (req, res) => {
  const { competitionId } = req.params;

  try {
    const competition = await requireCompetitionAccess(req, res, competitionId);
    if (!competition) {
      return;
    }

    res.json({
      ok: true,
      settings: {
        ctfUrl: competition.ctfUrl ?? '',
        databaseName: competition.databaseName ?? '',
        apiKey: competition.apiKey ?? '',
      },
    });
  } catch (error) {
    logger.error({ err: error }, 'Failed to fetch competition settings');
    res.status(500).json({ ok: false, error: 'Failed to fetch competition settings' });
  }
});

app.put('/api/competitions/:competitionId/settings', async (req, res) => {
  const { competitionId } = req.params;
  const { ctfUrl, databaseName, apiKey } = req.body ?? {};

  const normalizeNullable = (value) =>
    typeof value === 'string' && value.trim() ? value.trim() : null;
  const normalizedDbName = normalizeNullable(databaseName);

  try {
    if (!(await requireCompetitionAccess(req, res, competitionId))) {
      return;
    }

    if (normalizedDbName) {
      const existing = await prisma.competition.findFirst({
        where: {
          databaseName: normalizedDbName,
          ownerEmail: getRequestUserEmail(req),
          NOT: { id: competitionId },
        },
      });
      if (existing) {
        return res.status(409).json({ ok: false, error: '이미 사용 중인 데이터베이스 이름입니다.' });
      }
    }

    const updated = await prisma.competition.update({
      where: { id: competitionId },
      data: {
        ctfUrl: normalizeNullable(ctfUrl),
        databaseName: normalizedDbName,
        apiKey: normalizeNullable(apiKey),
      },
    });

    res.json({
      ok: true,
      settings: {
        ctfUrl: updated.ctfUrl ?? '',
        databaseName: updated.databaseName ?? '',
        apiKey: updated.apiKey ?? '',
      },
    });
  } catch (error) {
    logger.error({ err: error }, 'Failed to update competition settings');
    res.status(500).json({ ok: false, error: 'Failed to update competition settings' });
  }
});

app.get('/api/competitions/:competitionId/problems', async (req, res) => {
  const { competitionId } = req.params;

  try {
    if (!(await requireCompetitionAccess(req, res, competitionId))) {
      return;
    }

    const problems = await prisma.problem.findMany({
      where: { competitionId },
      orderBy: { createdAt: 'desc' },
    });

    res.json({
      ok: true,
      problems: problems.map((problem) => mapProblemForResponse(problem, req)),
    });
  } catch (error) {
    logger.error({ err: error }, 'Failed to fetch problems');
    res.status(500).json({ ok: false, error: 'Failed to fetch problems' });
  }
});

app.post('/api/competitions/:competitionId/problems/bulk', async (req, res) => {
  const { competitionId } = req.params;
  const { problems } = req.body ?? {};

  if (!Array.isArray(problems) || problems.length === 0) {
    return res.status(400).json({ ok: false, error: 'problems array is required' });
  }

  try {
    if (!(await requireCompetitionAccess(req, res, competitionId))) {
      return;
    }

    const preparedProblems = problems.map((problem) => {
      const normalizedFiles = Array.isArray(problem.files)
        ? problem.files.map((file) => normalizeStoredFile(file)).filter((file) => Boolean(file))
        : [];
      return {
        competitionId,
        title: typeof problem.title === 'string' ? problem.title : '',
        description: typeof problem.description === 'string' ? problem.description : '',
        category: sanitizeCategoryLabel(problem.category),
        difficulty: problem.difficulty,
        points: problem.points ?? 0,
        hintsRaw: Array.isArray(problem.hints) && problem.hints.length > 0 ? JSON.stringify(problem.hints) : null,
        filesRaw: normalizedFiles.length ? JSON.stringify(normalizedFiles) : null,
        solved: Boolean(problem.solved),
        source: typeof problem.source === 'string' ? problem.source : '',
      };
    });

    const { created, updated } = await prisma.$transaction((tx) =>
      mergeProblemsTx(tx, competitionId, preparedProblems)
    );

    const latestProblems = await prisma.problem.findMany({
      where: { competitionId },
      orderBy: { createdAt: 'desc' },
    });

    res.status(201).json({
      ok: true,
      created: created.length,
      updated: updated.length,
      problems: latestProblems.map((problem) => mapProblemForResponse(problem, req)),
    });
  } catch (error) {
    logger.error({ err: error }, 'Failed to store problems');
    res.status(500).json({ ok: false, error: 'Failed to store problems' });
  }
});

app.patch('/api/competitions/:competitionId/problems/:problemId', async (req, res) => {
  const { competitionId, problemId } = req.params;
  const { solved, flag, writeup } = req.body ?? {};

  const updateData = {};
  if (typeof solved === 'boolean') {
    updateData.solved = solved;
  }
  if (typeof flag === 'string') {
    updateData.flag = flag.trim();
  }
  if (typeof writeup === 'string') {
    updateData.writeup = writeup;
    updateData.writeupUpdatedAt = new Date();
  } else if (writeup === null) {
    updateData.writeup = null;
    updateData.writeupUpdatedAt = null;
  }

  if (Object.keys(updateData).length === 0) {
    return res.status(400).json({ ok: false, error: 'solved(boolean), flag(string), or writeup(string|null) is required' });
  }

  try {
    if (!(await requireCompetitionAccess(req, res, competitionId))) {
      return;
    }

    const problem = await prisma.problem.findFirst({
      where: { id: problemId, competitionId },
    });

    if (!problem) {
      return res.status(404).json({ ok: false, error: 'Problem not found' });
    }

    const updated = await prisma.problem.update({
      where: { id: problemId },
      data: updateData,
    });

    res.json({ ok: true, problem: mapProblemForResponse(updated, req) });
  } catch (error) {
    logger.error({ err: error }, 'Failed to update problem');
    res.status(500).json({ ok: false, error: 'Failed to update problem' });
  }
});

app.delete('/api/competitions/:competitionId', async (req, res) => {
  const { competitionId } = req.params;

  try {
    if (!(await requireCompetitionAccess(req, res, competitionId))) {
      return;
    }

    await removeCompetitionFiles(competitionId);
    await prisma.competition.delete({ where: { id: competitionId } });

    res.json({ ok: true });
  } catch (error) {
    logger.error({ err: error }, 'Failed to delete competition');
    res.status(500).json({ ok: false, error: 'Failed to delete competition' });
  }
});

app.post('/api/competitions/:competitionId/import/ctfd', async (req, res) => {
  const { competitionId } = req.params;
  const { baseUrl, apiKey, username, password, replaceExisting = true } = req.body ?? {};
  let filesBackupDir = null;

  const logStep = (...args) => logger.info({ args }, '[CTFd Import]');

  if (!baseUrl) {
    return res.status(400).json({ ok: false, error: 'baseUrl is required' });
  }
  if (!apiKey && !(username && password)) {
    return res.status(400).json({ ok: false, error: 'API key 또는 아이디/비밀번호가 필요합니다.' });
  }

  try {
    if (!(await requireCompetitionAccess(req, res, competitionId))) {
      return;
    }

    const normalizedBaseUrl = normalizeBaseUrl(baseUrl);

    const runImport = async (client) => {
      if (!client || typeof client.fetchJson !== 'function') {
        throw new Error('CTFd 클라이언트가 올바르게 초기화되지 않았습니다.');
      }

      const fetchJson = async (path) => {
        const result = await client.fetchJson(path);
        if (!result || result.success === false) {
          throw new Error(result?.message ?? result?.error ?? 'CTFd 요청 실패');
        }
        return result;
      };

      const challengesResponse = await fetchJson('/api/v1/challenges');
      const challenges = Array.isArray(challengesResponse?.data) ? challengesResponse.data : [];

      const preparedProblems = [];
      const failed = [];

      for (const challenge of challenges) {
        try {
          const detailResponse = await fetchJson(`/api/v1/challenges/${challenge.id}?preview=true`);
          const detail = detailResponse.data ?? {};

          const hints = [];
          const files = Array.isArray(detail.files) ? detail.files : [];
          const downloadedFiles = await downloadChallengeFiles({
            client,
            fileUrls: files,
            competitionId,
            challengeId: challenge.id,
          });
          const fallbackFiles = files
            .map((fileUrl) => normalizeStoredFile(fileUrl))
            .filter((file) => Boolean(file));
          const storedFiles = downloadedFiles.length ? downloadedFiles : fallbackFiles;
          const connectionInfo = detail.connection_info
            ? `\n\n[접속 정보]\n${detail.connection_info}`
            : '';

          preparedProblems.push({
            competitionId,
            title: challenge.name ?? detail.name ?? `Challenge #${challenge.id}`,
            description: `${detail.description ?? ''}${connectionInfo}`,
            category: sanitizeCategoryLabel(challenge.category ?? detail.category ?? 'Misc'),
            difficulty: inferDifficulty(challenge, detail),
            points: challenge.value ?? detail.value ?? 0,
            hintsRaw: hints.length ? JSON.stringify(hints) : null,
            filesRaw: storedFiles.length ? JSON.stringify(storedFiles) : null,
            solved: false,
            source: normalizedBaseUrl,
          });
        } catch (problemError) {
          logger.error({ err: problemError, challengeId: challenge.id }, 'Failed to import challenge');
          failed.push({
            id: challenge.id,
            name: challenge.name,
            reason: problemError instanceof Error ? problemError.message : 'Unknown error',
          });
        }
      }

      return { preparedProblems, failed };
    };

    let client = null;
    if (apiKey) {
      logStep('Trying token authentication...');
      client = createCtfdTokenClient(normalizedBaseUrl, apiKey);
    }
    if (!client) {
      logStep('Token skipped; using session login');
      client = await createCtfdSessionClient(normalizedBaseUrl, username, password);
    }

    if (replaceExisting) {
      filesBackupDir = await backupCompetitionFiles(competitionId);
    }

    let preparedProblems = [];
    let failed = [];

    try {
      const result = await runImport(client);
      preparedProblems = result.preparedProblems;
      failed = result.failed;
    } catch (error) {
      if (apiKey && username && password) {
        logger.warn({ err: error }, 'CTFd token request failed, retrying with session login...');
        client = await createCtfdSessionClient(normalizedBaseUrl, username, password);
        const result = await runImport(client);
        preparedProblems = result.preparedProblems;
        failed = result.failed;
      } else {
        throw error;
      }
    }

    let created = [];
    let updated = [];
    if (preparedProblems.length > 0) {
      const merged = await prisma.$transaction((tx) =>
        mergeProblemsTx(tx, competitionId, preparedProblems)
      );
      created = merged.created;
      updated = merged.updated;
    }

    if (filesBackupDir) {
      await fs.promises.rm(filesBackupDir, { recursive: true, force: true }).catch(() => {});
      filesBackupDir = null;
    }

    const latestProblems = await prisma.problem.findMany({
      where: { competitionId },
      orderBy: { createdAt: 'desc' },
    });

    res.json({
      ok: true,
      imported: created.length,
      updated: updated.length,
      failed,
      warnings: failed.length ? failed : undefined,
      problems: latestProblems.map((problem) => mapProblemForResponse(problem, req)),
    });
  } catch (error) {
    if (filesBackupDir) {
      await restoreCompetitionFilesFromBackup(competitionId, filesBackupDir);
      filesBackupDir = null;
    }
    logger.error({ err: error }, 'Failed to import CTFd data');
    res.status(500).json({ ok: false, error: error instanceof Error ? error.message : 'Failed to import from CTFd' });
  }
});

app.post('/api/competitions/:competitionId/import/manual', (req, res) => {
  manualArchiveUpload(req, res, async (uploadError) => {
    if (uploadError) {
      logger.warn({ err: uploadError }, 'Manual upload middleware failed');
      const status = uploadError?.code === 'LIMIT_FILE_SIZE' ? 413 : 400;
      const message = uploadError?.message ?? '파일을 업로드하지 못했습니다.';
      return res.status(status).json({ ok: false, error: message });
    }

    const { competitionId } = req.params;
    let extractedRoot = null;
    const replacedStorageDirs = new Set();

    const cleanupUploadedFile = async () => {
      if (req.file?.path) {
        await fs.promises.unlink(req.file.path).catch(() => {});
      }
      if (extractedRoot) {
        await fs.promises.rm(extractedRoot, { recursive: true, force: true }).catch(() => {});
      }
    };

    try {
      if (!(await requireCompetitionAccess(req, res, competitionId))) {
        await cleanupUploadedFile();
        return;
      }

      const hasUploadedFile = Boolean(req.file);
      const replaceExisting = parseBooleanField(req.body?.replaceExisting);
      const sourceLabel = sanitizeManualSourceLabel(req.body?.sourceLabel);
      const manualCategory = normalizeCategory(req.body?.category ?? 'Misc');
      const providedTitle = typeof req.body?.problemTitle === 'string' ? req.body.problemTitle.trim() : '';
      const providedDescription =
        typeof req.body?.problemDescription === 'string' ? req.body.problemDescription : '';
      if (!hasUploadedFile && !providedDescription.trim()) {
        throw buildManualImportError('문제 설명을 입력하거나 파일을 첨부해주세요.');
      }

      const isArchive = hasUploadedFile && isZipArchive(req.file.originalname, req.file.mimetype);
      const looksLikeJson = (() => {
        if (!hasUploadedFile) return false;
        const name = (req.file.originalname ?? '').toLowerCase();
        const mime = (req.file.mimetype ?? '').toLowerCase();
        return name.endsWith('.json') || mime.includes('json');
      })();

      let manifestPayload = null;
      let manifestDir = null;

      if (isArchive) {
        extractedRoot = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'manual-import-'));
        try {
          await extractZip(req.file.path, { dir: extractedRoot });
        } catch (error) {
          const reason = error instanceof Error ? error.message : '알 수 없는 오류';
          throw buildManualImportError(`ZIP 파일을 해제하지 못했습니다: ${reason}`);
        }
        const manifestPath = await findManualManifestFile(extractedRoot);
        if (manifestPath) {
          manifestDir = path.dirname(manifestPath);
          try {
            const rawJson = await fs.promises.readFile(manifestPath, 'utf8');
            manifestPayload = JSON.parse(rawJson);
          } catch (error) {
            const reason = error instanceof Error ? error.message : '알 수 없는 오류';
            throw buildManualImportError(`JSON 파일을 파싱하지 못했습니다: ${reason}`);
          }
        }
      } else if (looksLikeJson) {
        try {
          const rawJson = await fs.promises.readFile(req.file.path, 'utf8');
          manifestPayload = JSON.parse(rawJson);
        } catch (error) {
          const reason = error instanceof Error ? error.message : '알 수 없는 오류';
          throw buildManualImportError(`JSON 파일을 파싱하지 못했습니다: ${reason}`);
        }
      }

      const skipped = [];
      const warnings = [];
      let preparedProblems = [];

      let manualSpecs = null;
      let initialSkipped = [];
      if (manifestPayload) {
        try {
          const parsed = parseManualProblemsPayload(manifestPayload, {
            defaultSource: sourceLabel,
          });
          manualSpecs = parsed.problems;
          initialSkipped = parsed.skipped ?? [];
        } catch (parseError) {
          logger.warn(
            { err: parseError },
            'Manual manifest payload did not contain problems/challenges; falling back to single upload mode',
          );
          manualSpecs = null;
        }
      }

      if (manifestPayload && manualSpecs) {
        if (manualSpecs.length === 0) {
          throw buildManualImportError('유효한 문제가 없습니다. problems 배열을 확인하세요.');
        }
        skipped.push(...initialSkipped);

        for (const spec of manualSpecs) {
          try {
            const { files, warnings: fileWarnings } = await copyManualProblemFiles({
              problem: spec,
              manifestDir,
              extractedRoot,
              competitionId,
            });
            warnings.push(...fileWarnings);
            preparedProblems.push({
              competitionId,
              title: spec.title,
              description: spec.description,
              category: spec.category,
              difficulty: spec.difficulty,
              points: spec.points,
              hintsRaw: spec.hints.length ? JSON.stringify(spec.hints) : null,
              filesRaw: files.length ? JSON.stringify(files) : null,
              solved: false,
              source: spec.source,
            });
          } catch (problemError) {
            const reason = problemError instanceof Error ? problemError.message : '알 수 없는 오류';
            skipped.push({ title: spec.title, reason });
          }
        }
      } else if (hasUploadedFile) {
        const singleSpec = await buildSingleUploadProblemSpec({
          competitionId,
          uploadedFile: req.file,
          extractedRoot,
          providedTitle,
          providedDescription,
          sourceLabel,
          category: manualCategory,
          warnings,
        });
        preparedProblems = [singleSpec];
      } else {
        const metadataSpec = buildMetadataOnlyProblemSpec({
          competitionId,
          providedTitle,
          providedDescription,
          sourceLabel,
          category: manualCategory,
        });
        preparedProblems = [metadataSpec];
      }

      if (preparedProblems.length === 0) {
        throw buildManualImportError('저장할 수 있는 문제가 없습니다. 업로드 파일을 확인하세요.');
      }

      const replacementKeys = replaceExisting
        ? new Set(
            preparedProblems
              .map((problem) => buildProblemMatchKey(problem.title, problem.source))
              .filter((key) => Boolean(key))
          )
        : null;

      const result = await prisma.$transaction(async (tx) => {
        if (replaceExisting && replacementKeys && replacementKeys.size > 0) {
          const existingProblems = await tx.problem.findMany({
            where: { competitionId },
            select: { id: true, title: true, source: true, filesRaw: true },
          });
          const problemsToDelete = existingProblems.filter((problem) => {
            const key = buildProblemMatchKey(problem.title, problem.source);
            return key && replacementKeys.has(key);
          });
          if (problemsToDelete.length > 0) {
            const idsToDelete = problemsToDelete.map((problem) => problem.id);
            await tx.problem.deleteMany({
              where: { id: { in: idsToDelete } },
            });
            for (const problem of problemsToDelete) {
              const dirs = collectCompetitionStorageDirsFromFiles(competitionId, problem.filesRaw);
              for (const dir of dirs) {
                replacedStorageDirs.add(dir);
              }
            }
          }
          const created = [];
          for (const incoming of preparedProblems) {
            const createdProblem = await tx.problem.create({ data: incoming });
            created.push(createdProblem);
          }
          return { created, updated: [] };
        }

        return mergeProblemsTx(tx, competitionId, preparedProblems);
      });

      if (replacedStorageDirs.size > 0) {
        await Promise.all(
          Array.from(replacedStorageDirs).map((dir) =>
            fs.promises.rm(dir, { recursive: true, force: true }).catch(() => {}),
          ),
        );
      }

      const latestProblems = await prisma.problem.findMany({
        where: { competitionId },
        orderBy: { createdAt: 'desc' },
      });

      res.json({
        ok: true,
        imported: result.created.length,
        updated: result.updated.length,
        skipped,
        warnings: warnings.length ? warnings : undefined,
        problems: latestProblems.map((problem) => mapProblemForResponse(problem, req)),
      });
    } catch (error) {
      logger.error({ err: error }, 'Manual problem import failed');
      const statusCode = Number.isInteger(error?.statusCode) ? error.statusCode : 500;
      const message = error instanceof Error ? error.message : '문제 업로드 중 오류가 발생했습니다.';
      res.status(statusCode).json({ ok: false, error: message });
    } finally {
      await cleanupUploadedFile();
    }
  });
});

app.delete('/api/competitions/:competitionId/problems', async (req, res) => {
  const { competitionId } = req.params;

  try {
    if (!(await requireCompetitionAccess(req, res, competitionId))) {
      return;
    }

    await prisma.problem.deleteMany({ where: { competitionId } });
    res.json({ ok: true });
  } catch (error) {
    logger.error({ err: error }, 'Failed to delete problems');
    res.status(500).json({ ok: false, error: 'Failed to delete problems' });
  }
});

// Removed legacy /api/cli/execute endpoint (not used by UI)

const server = http.createServer(app);

// In-memory interactive session registry
// Each WebSocket connection can attach/detach; PTY lives until explicit termination
const sessions = new Map(); // id -> { id, pty, sockets:Set<WebSocket>, buffer:string, createdAt, lastActivity, cmd, args, owner }
const countSessionsForUser = (email) => {
  if (!email) return 0;
  let count = 0;
  for (const session of sessions.values()) {
    if (session.owner?.email === email) {
      count += 1;
    }
  }
  return count;
};

const generateSessionId = () =>
  Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);

const MAX_BUFFER_CHARS = 200_000; // keep last ~200 KB of output per session

// Simple list and terminate endpoints for sessions
// Removed sessions list endpoint (not used by UI)

app.delete('/api/cli/sessions/:id', (req, res) => {
  const { id } = req.params;
  const session = sessions.get(id);
  if (!session) {
    return res.status(404).json({ ok: false, error: 'Session not found' });
  }
  if (session.owner?.email && req.authUser?.email && session.owner.email !== req.authUser.email) {
    return res.status(403).json({ ok: false, error: 'Forbidden' });
  }
  try {
    session.pty?.kill();
  } catch {}
  sessions.delete(id);
  try {
    for (const ws of session.sockets) {
      try { ws.send(JSON.stringify({ type: 'exit', exitCode: null, signal: 'SIGTERM' })); } catch {}
      try { ws.close(); } catch {}
    }
  } catch {}
  return res.json({ ok: true, terminated: true });
});

const wss = new WebSocketServer({
  server,
  path: CLI_WS_PATH,
});

wss.on('connection', (socket, req) => {
  // Basic Origin allowlist for WS
  const reqOrigin = req.headers?.origin;
  if (!isOriginAllowed(reqOrigin)) {
    try { socket.close(1008, 'Origin not allowed'); } catch {}
    return;
  }
  const wsUser = buildUserFromPayload(decodeAuthToken(getTokenFromHeaders(req.headers ?? {})));
  if (!wsUser) {
    try { socket.close(4401, 'Unauthorized'); } catch {}
    return;
  }
  const connectionUrl = new URL(req.url ?? CLI_WS_PATH, 'http://localhost');
  const requestedSessionId = connectionUrl.searchParams.get('sid') || connectionUrl.searchParams.get('sessionId');
  const cols = Number(connectionUrl.searchParams.get('cols')) || 120;
  const rows = Number(connectionUrl.searchParams.get('rows')) || 30;

  const sendTo = (ws, payload) => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(payload));
    }
  };

  const broadcast = (session, payload) => {
    for (const ws of session.sockets) {
      sendTo(ws, payload);
    }
  };

  const attachToSession = (session) => {
    session.sockets.add(socket);
    // say hello and share session id
    sendTo(socket, {
      type: 'ready',
      sessionId: session.id,
      message: `Attached to session (${session.cmd})`,
    });
    // replay buffered output
    if (session.buffer) {
      sendTo(socket, { type: 'data', data: session.buffer });
    }

    socket.on('message', (raw) => {
      try {
        const parsed = JSON.parse(raw.toString());
        if (parsed?.type === 'input' && typeof parsed.data === 'string') {
          session.pty.write(parsed.data);
        } else if (parsed?.type === 'command' && typeof parsed.command === 'string') {
          const withNewline = parsed.appendNewline === false
            ? parsed.command
            : parsed.command.endsWith('\n')
              ? parsed.command
              : `${parsed.command}\n`;
          session.pty.write(withNewline);
        } else if (parsed?.type === 'resize') {
          const nextCols = Number(parsed.cols);
          const nextRows = Number(parsed.rows);
          if (Number.isFinite(nextCols) && Number.isFinite(nextRows)) {
            session.pty.resize(Math.max(1, nextCols), Math.max(1, nextRows));
          }
        } else if (parsed?.type === 'terminate') {
          try { session.pty.kill(); } catch {}
        }
      } catch (error) {
        void error;
        session.pty.write(raw.toString());
      }
    });

    socket.on('close', () => {
      session.sockets.delete(socket);
      // keep PTY alive; do not kill here
    });
    socket.on('error', (error) => {
      logger.error({ err: error }, 'CLI WebSocket error');
      session.sockets.delete(socket);
    });
  };

  // Try to reuse a session if requested
  if (requestedSessionId && sessions.has(requestedSessionId)) {
    const session = sessions.get(requestedSessionId);
    if (session.owner?.email && session.owner.email !== wsUser.email) {
      sendTo(socket, { type: 'error', message: '세션에 접근할 수 없습니다.' });
      try { socket.close(4403, 'Forbidden'); } catch {}
      return;
    }
    attachToSession(session);
    return;
  }

  // No reusable session: start a new one
  const initialCommand = CLI_INTERACTIVE_COMMAND;
  const commandArgs = [...CLI_INTERACTIVE_ARGS];
  let awaitingAutoApprove = CLI_AUTO_APPROVE;

  // Enforce max sessions
  if (Number.isFinite(CLI_MAX_SESSIONS) && sessions.size >= CLI_MAX_SESSIONS) {
    sendTo(socket, { type: 'error', message: 'Session limit reached' });
    try { socket.close(1013, 'Session limit'); } catch {}
    return;
  }
  if (
    Number.isFinite(CLI_MAX_SESSIONS_PER_USER)
    && CLI_MAX_SESSIONS_PER_USER >= 0
    && countSessionsForUser(wsUser.email) >= CLI_MAX_SESSIONS_PER_USER
  ) {
    sendTo(socket, { type: 'error', message: '너무 많은 리소스 사용으로 인해 사용이 제한되었습니다.' });
    try { socket.close(1013, 'User session limit'); } catch {}
    return;
  }

  let ptyProcess;
  try {
    ptyProcess = pty.spawn(initialCommand, commandArgs, {
      name: 'xterm-color',
      cols: Number.isFinite(cols) && cols > 0 ? cols : 120,
      rows: Number.isFinite(rows) && rows > 0 ? rows : 30,
      cwd: CLI_INTERACTIVE_CWD,
      env: {
        ...process.env,
        CLI_BASE_DIR: ROOT_DIR,
      },
    });
  } catch (error) {
    logger.error({ err: error }, 'Failed to start PTY session');
    const resourceLimited = Boolean(
      (error && typeof error === 'object' && ('code' in error) && ['EAGAIN', 'ENOMEM'].includes(error.code))
      || (error?.message && /resource/i.test(error.message))
    );
    sendTo(socket, {
      type: 'error',
      message: resourceLimited
        ? '너무 많은 리소스 사용으로 인해 사용이 제한되었습니다.'
        : (error instanceof Error ? error.message : 'Failed to start interactive session'),
    });
    socket.close();
    return;
  }

  const sessionId = generateSessionId();
  const session = {
    id: sessionId,
    pty: ptyProcess,
    sockets: new Set([socket]),
    buffer: '',
    createdAt: Date.now(),
    lastActivity: Date.now(),
    cmd: initialCommand,
    args: commandArgs,
    owner: wsUser,
  };
  sessions.set(sessionId, session);

  const maybeHandleAutoApprovePrompt = (rawChunk) => {
    if (!awaitingAutoApprove || !rawChunk) return;
    const asString = typeof rawChunk === 'string' ? rawChunk : rawChunk.toString('utf8');
    if (!asString) return;
    const plain = stripAnsi(asString);
    if (!plain) return;
    if (
      plain.includes('Allow Codex to work in this folder without asking for approval')
      || plain.includes('Require approval of edits and commands')
    ) {
      awaitingAutoApprove = false;
      setTimeout(() => {
        try {
          ptyProcess?.write(CLI_AUTO_APPROVE_CHOICE);
        } catch {
          // ignore
        }
      }, 10);
    }
  };

  // Announce session ready to the initial socket
  sendTo(socket, {
    type: 'ready',
    sessionId,
    message: `Interactive session started with command: ${initialCommand}`,
  });

  // Wire PTY events
  ptyProcess.onData((data) => {
    // guard cursor position report to avoid weird input state
    if (data && data.includes('\u001b[6n')) {
      try { ptyProcess.write('\u001b[1;1R'); } catch {}
    }
    maybeHandleAutoApprovePrompt(data);
    session.lastActivity = Date.now();
    const asString = typeof data === 'string' ? data : data.toString('utf8');
    if (asString) {
      session.buffer = (session.buffer + asString).slice(-MAX_BUFFER_CHARS);
    }
    broadcast(session, { type: 'data', data });
  });

  ptyProcess.onExit(({ exitCode, signal }) => {
    broadcast(session, { type: 'exit', exitCode, signal });
    // Clean up session once PTY exits
    sessions.delete(sessionId);
    try {
      for (const ws of session.sockets) {
        try { ws.close(); } catch {}
      }
    } catch {}
  });

  // Attach socket handlers for the first connection
  attachToSession(session);
});

// Periodic cleanup for idle sessions (no attached sockets)
if (Number.isFinite(CLI_SESSION_IDLE_TTL_MS) && CLI_SESSION_IDLE_TTL_MS > 0) {
  setInterval(() => {
    const now = Date.now();
    for (const [id, s] of sessions) {
      if (s.sockets.size === 0 && (now - (s.lastActivity || 0)) > CLI_SESSION_IDLE_TTL_MS) {
        try { s.pty?.kill(); } catch {}
        sessions.delete(id);
      }
    }
  }, 60 * 1000).unref();
}

const port = Number(process.env.PORT) || 4000;
const host = process.env.HOST || '127.0.0.1';

server.listen(port, host, () => {
  logger.info(`CLI bridge server listening on http://${host}:${port}`);
  logger.info(`Commands execute inside: ${ROOT_DIR}`);
  logger.info(`WebSocket CLI path: ${CLI_WS_PATH}`);
});

// IDA MCP integration (WSL -> Windows idalib-mcp.exe launcher)
// POST /api/competitions/:competitionId/problems/:problemId/ida-mcp
// Optional body: { fileUrl?: string, host?: string, port?: string|number, exePath?: string }
app.post('/api/competitions/:competitionId/problems/:problemId/ida-mcp', async (req, res) => {
  const { competitionId, problemId } = req.params;
  const { fileUrl, host: hostOverride, port: portOverride, exePath: exePathOverride } = req.body ?? {};

  const shQuote = (value) => `'${String(value).replace(/'/g, "'\\''")}'`;

  try {
    if (!(await requireCompetitionAccess(req, res, competitionId))) {
      return;
    }

    const problem = await prisma.problem.findFirst({ where: { id: problemId, competitionId } });
    if (!problem) {
      return res.status(404).json({ ok: false, error: 'Problem not found' });
    }

    // Resolve which file to use
    const files = parseFilesRaw(problem.filesRaw);
    let targetLocalPath = null;
    if (fileUrl && typeof fileUrl === 'string') {
      targetLocalPath = resolvePublicFileUrlToLocalPath(fileUrl);
    }
    if (!targetLocalPath) {
      for (const f of files) {
        const candidate = resolvePublicFileUrlToLocalPath(f?.url ?? '');
        if (candidate && fs.existsSync(candidate)) {
          targetLocalPath = candidate;
          break;
        }
      }
    }

    if (!targetLocalPath) {
      return res.status(404).json({ ok: false, error: '연결할 파일을 찾을 수 없습니다.' });
    }

    // Convert to absolute path (Linux) and ensure it exists
    const absLinuxPath = path.resolve(targetLocalPath);
    try {
      await fs.promises.access(absLinuxPath, fs.constants.R_OK);
    } catch {
      return res.status(404).json({ ok: false, error: '문제 파일이 존재하지 않거나 읽을 수 없습니다.' });
    }

    const hostAccessiblePath = await ensureIdaAccessiblePath(absLinuxPath, competitionId, problemId);

    // Convert Linux path to Windows path via wslpath
    const { stdout: winPathOut } = await exec(`wslpath -w ${shQuote(hostAccessiblePath)}`, {
      cwd: ROOT_DIR,
      shell: process.env.CLI_SHELL || '/bin/bash',
      timeout: Number(process.env.CLI_TIMEOUT_MS) || 15000,
      maxBuffer: Number(process.env.CLI_MAX_BUFFER) || 1024 * 1024 * 5,
      env: { ...process.env, CLI_BASE_DIR: ROOT_DIR },
    });
    const winPath = (winPathOut || '').trim();
    if (!winPath) {
      return res.status(500).json({ ok: false, error: 'wslpath 변환에 실패했습니다.' });
    }

    // Determine idalib-mcp.exe path (WSL path to Windows EXE)
    const requestedExe = typeof exePathOverride === 'string' ? exePathOverride.trim() : '';
    const exePath = requestedExe || process.env.IDA_MCP_EXE_PATH;

    if (!exePath || !fs.existsSync(exePath)) {
      return res.status(500).json({ ok: false, error: `idalib-mcp 실행 파일을 찾을 수 없습니다: ${exePath}` });
    }

    const host = (hostOverride || process.env.IDA_MCP_HOST || '192.168.35.105').toString();
    const chosenPort = Number(portOverride || process.env.IDA_MCP_PORT || 8744);

    const userEmail = getRequestUserEmail(req);
    // If other account is using ida-mcp, block takeover
    if (activeIdaProcess?.child && activeIdaProcess.ownerEmail && activeIdaProcess.ownerEmail !== userEmail) {
      return res.status(409).json({ ok: false, error: '다른 계정에서 IDA MCP를 사용 중입니다.' });
    }
    // If any ida-mcp process is already active for the same owner, kill it first (best-effort)
    if (activeIdaProcess?.child) {
      try { activeIdaProcess.child.kill(); } catch {}
      activeIdaProcess = null;
    }
    await killAllIdaMcpProcesses().catch(() => {});

    const args = ['--host', host, '--port', String(chosenPort), winPath];
    const child = spawn(exePath, args, {
      cwd: ROOT_DIR,
      env: {
        ...process.env,
        CLI_BASE_DIR: ROOT_DIR,
        ...(process.env.IDADIR ? { IDADIR: process.env.IDADIR } : {}),
      },
      stdio: ['ignore', 'ignore', 'ignore'],
      shell: false,
      detached: false,
    });

    activeIdaProcess = {
      child,
      startedAt: Date.now(),
      exePath,
      host,
      port: chosenPort,
      file: winPath,
      problemId,
      competitionId,
      ownerEmail: userEmail,
    };
    child.on('exit', (code, signal) => {
      logger.info({ code, signal }, '[IDA MCP] process exited');
      if (activeIdaProcess?.child === child) {
        activeIdaProcess = null;
      }
    });
    child.on('error', (childError) => {
      logger.error({ err: childError }, '[IDA MCP] failed to start process');
      if (activeIdaProcess?.child === child) {
        activeIdaProcess = null;
      }
    });

    return res.json({ ok: true, file: winPath, exe: exePath, host, port: chosenPort, started: true });
  } catch (error) {
    const message = error?.message || 'IDA MCP 연결 실행 실패';
    return res.status(500).json({ ok: false, error: message, stdout: error?.stdout ?? '', stderr: error?.stderr ?? '' });
  }
});

// Disconnect endpoint: kill active ida-mcp process for this problem if still running
app.delete('/api/competitions/:competitionId/problems/:problemId/ida-mcp', async (req, res) => {
  const { competitionId } = req.params;
  try {
    if (!(await requireCompetitionAccess(req, res, competitionId))) {
      return;
    }

    const userEmail = getRequestUserEmail(req);
    if (activeIdaProcess?.ownerEmail && activeIdaProcess.ownerEmail !== userEmail) {
      return res.status(403).json({ ok: false, error: '다른 계정의 IDA MCP 세션입니다.' });
    }

    if (activeIdaProcess?.child) {
      try { activeIdaProcess.child.kill(); } catch {}
      activeIdaProcess = null;
    }
    await killAllIdaMcpProcesses();
    return res.json({ ok: true, disconnected: true });
  } catch (error) {
    return res.status(500).json({ ok: false, error: error?.message ?? '연결 해제 실패' });
  }
});
