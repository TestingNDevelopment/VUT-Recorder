// server.js
// -----------------------------------------------------
// Express server with Google OAuth 2.0 (PKCE) + Drive upload
// -----------------------------------------------------

import express from 'express';
import fetch from 'node-fetch';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import cors from 'cors';
import { randomBytes, createHash } from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import dotenv from 'dotenv';

// Load .env (if present)
dotenv.config();

// -----------------------------------------------------
// Configuration & sanity checks
// -----------------------------------------------------
const {
  PORT = 8080,
  NODE_ENV = 'development',
  GOOGLE_CLIENT_ID,
  // GOOGLE_CLIENT_SECRET is NOT needed for PKCE, but keep for completeness
  // GOOGLE_CLIENT_SECRET,
} = process.env;

if (!GOOGLE_CLIENT_ID) {
  console.error('❌ FATAL: GOOGLE_CLIENT_ID env var is missing');
  process.exit(1);
}

const isProd = NODE_ENV === 'production';
const app = express();

// When running behind a reverse‑proxy (Railway, Render, Fly, …) we need to trust it
app.set('trust proxy', 1);

// -----------------------------------------------------
// Global middle‑wares
// -----------------------------------------------------
app.use(helmet());
app.use(
  cors({
    origin: true, // reflect request origin (adjust for your front‑end)
    credentials: true,
  })
);
app.use(express.static('public')); // optional static assets
app.use(cookieParser());

// ------------------------------------------------------------------
// Helper utilities
// ------------------------------------------------------------------
/** Wrap async route handlers so you don’t have to try/catch everywhere */
const asyncHandler = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

/** Base64‑URL encode a Buffer (PKCE) */
const base64urlEncode = (buf) =>
  buf
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

/** Generate a PKCE verifier/challenge pair */
const generatePKCE = () => {
  const verifier = base64urlEncode(randomBytes(32));
  const challenge = base64urlEncode(createHash('sha256').update(verifier).digest());
  return { verifier, challenge };
};

/** Build the redirect URI that Google should call back to */
const getRedirectUri = (req) => {
  const proto = req.headers['x-forwarded-proto'] || req.protocol;
  const host = req.headers['x-forwarded-host'] || req.get('host');
  return `${proto}://${host}/auth/callback`;
};

/** Common cookie options (HttpOnly + secure in prod) */
const cookieOpts = (maxAgeMs) => ({
  httpOnly: true,
  secure: isProd,
  sameSite: isProd ? 'lax' : 'none',
  maxAge: maxAgeMs,
});

/** Clear a cookie (used for logout & PKCE cleanup) */
const clearCookie = (res, name) => res.clearCookie(name, { path: '/' });

/** Simple logger – feel free to replace with Winston/pino */
const log = console;

// -----------------------------------------------------
// Routes
// -----------------------------------------------------

/* ---------- Health check ------------------------------------------------ */
app.get('/health', (req, res) => res.status(200).send('OK'));

/* ---------- Initiate OAuth login ---------------------------------------- */
app.get(
  '/auth/login',
  (req, res) => {
    const { verifier, challenge } = generatePKCE();

    // Store verifier in a short‑lived cookie
    res.cookie('pkce_verifier', verifier, cookieOpts(10 * 60 * 1000)); // 10 min

    const authUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
    authUrl.searchParams.set('client_id', GOOGLE_CLIENT_ID);
    authUrl.searchParams.set('redirect_uri', getRedirectUri(req));
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('scope', 'https://www.googleapis.com/auth/drive.file');
    authUrl.searchParams.set('code_challenge', challenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');
    authUrl.searchParams.set('access_type', 'offline'); // get refresh token
    authUrl.searchParams.set('prompt', 'consent');

    log.info('🔗 Redirecting to Google OAuth', authUrl.toString());
    res.redirect(authUrl);
  }
);

/* ---------- OAuth callback – exchange code for tokens ------------------- */
app.get(
  '/auth/callback',
  asyncHandler(async (req, res) => {
    const { code } = req.query;
    const verifier = req.cookies.pkce_verifier;

    if (!code || !verifier) {
      log.warn('OAuth callback missing code or verifier', { code, verifier });
      return res
        .status(400)
        .json({ error: 'invalid_request', message: 'Missing code or PKCE verifier' });
    }

    const tokenResp = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: GOOGLE_CLIENT_ID,
        grant_type: 'authorization_code',
        code,
        redirect_uri: getRedirectUri(req),
        code_verifier: verifier,
      }),
    });

    if (!tokenResp.ok) {
      const err = await tokenResp.json();
      log.error('Token exchange failed', err);
      return res.status(500).json({ error: 'token_exchange_failed', details: err });
    }

    const tokens = await tokenResp.json();

    // Store tokens in cookies
    res.cookie('access_token', tokens.access_token, cookieOpts(tokens.expires_in * 1000));
    if (tokens.refresh_token) {
      // Refresh tokens are long‑lived – keep for 30 days (adjust as needed)
      res.cookie('refresh_token', tokens.refresh_token, cookieOpts(30 * 24 * 60 * 60 * 1000));
    }

    // Clean up PKCE cookie
    clearCookie(res, 'pkce_verifier');

    log.info('✅ OAuth flow completed – tokens saved in cookies');
    // Send the user back to the SPA root (or a custom page)
    res.redirect('/');
  })
);

/* ---------- Refresh access token ---------------------------------------- */
app.get(
  '/auth/refresh',
  asyncHandler(async (req, res) => {
    const refreshToken = req.cookies.refresh_token;
    if (!refreshToken) {
      log.warn('Refresh attempted without refresh token');
      return res.status(401).json({ error: 'no_refresh_token' });
    }

    const refreshResp = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: GOOGLE_CLIENT_ID,
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
      }),
    });

    if (!refreshResp.ok) {
      const err = await refreshResp.json();
      log.error('Refresh token exchange failed', err);
      return res.status(500).json({ error: 'refresh_failed', details: err });
    }

    const newTokens = await refreshResp.json();
    res.cookie('access_token', newTokens.access_token, cookieOpts(newTokens.expires_in * 1000));
    log.info('🔄 Access token refreshed');
    res.json({ success: true });
  })
);

/* ---------- Video upload to Google Drive -------------------------------- */
app.post(
  '/upload',
  // Accept raw binary (any mime) up to 500 MB – tweak as needed
  express.raw({ type: '*/*', limit: '500mb' }),
  asyncHandler(async (req, res) => {
    const accessToken = req.cookies.access_token;
    if (!accessToken) {
      log.warn('Upload attempted without access token');
      return res.status(401).json({ error: 'unauthenticated' });
    }

    // Generate a temporary file name – you could also accept a name from the client
    const fileName = `upload-${Date.now()}.mp4`;

    // Initiate a **resumable** upload session (better for large files)
    const sessionResp = await fetch(
      `https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable`,
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'X-Upload-Content-Type': 'application/octet-stream',
          'X-Upload-Content-Length': req.body.length,
          'Content-Type': 'application/json; charset=UTF-8',
        },
        body: JSON.stringify({
          name: fileName,
          mimeType: 'application/octet-stream',
        }),
      }
    );

    if (!sessionResp.ok) {
      const err = await sessionResp.json();
      log.error('Failed to start resumable upload', err);
      return res.status(500).json({ error: 'upload_init_failed', details: err });
    }

    const uploadUrl = sessionResp.headers.get('Location');
    if (!uploadUrl) {
      log.error('Missing Location header for resumable upload');
      return res.status(500).json({ error: 'missing_upload_url' });
    }

    // Upload the whole file in a single PUT (still resumable – you could chunk it later)
    const putResp = await fetch(uploadUrl, {
      method: 'PUT',
      headers: {
        'Content-Length': req.body.length,
        'Content-Type': 'application/octet-stream',
      },
      body: req.body,
    });

    if (!putResp.ok) {
      const err = await putResp.json();
      log.error('Upload PUT failed', err);
      return res.status(500).json({ error: 'upload_failed', details: err });
    }

    const fileMeta = await putResp.json();
    log.info('✅ File uploaded to Drive', { fileId: fileMeta.id });
    res.json({ success: true, fileId: fileMeta.id });
  })
);

/* ---------- Logout – clear all auth cookies ----------------------------- */
app.post(
  '/auth/logout',
  (req, res) => {
    clearCookie(res, 'access_token');
    clearCookie(res, 'refresh_token');
    clearCookie(res, 'pkce_verifier');
    res.json({ success: true });
  }
);

/* ---------- Global error handler --------------------------------------- */
app.use((err, req, res, next) => {
  log.error('Unhandled error', err);
  const status = err.status || 500;
  res.status(status).json({
    error: err.message || 'Internal Server Error',
    ...(isProd ? {} : { stack: err.stack }),
  });
});

/* ---------- Start server ------------------------------------------------ */
app.listen(PORT, () => {
  log.info(`🚀 Server listening on http://0.0.0.0:${PORT} (${NODE_ENV})`);
});
