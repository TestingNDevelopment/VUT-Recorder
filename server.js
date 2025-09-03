// ---------------------------------------------------------------
//  server.js – Express backend for Google Drive PKCE OAuth + upload
// ---------------------------------------------------------------

import express from 'express';
import fetch from 'node-fetch';
import cookieParser from 'cookie-parser';
import { randomBytes, createHash } from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import dotenv from 'dotenv';
dotenv.config();

const app = express();

// ---------------------------------------------------------------
// 1️⃣ Configuration & validation
// ---------------------------------------------------------------
const PORT = process.env.PORT || 8080;
const NODE_ENV = process.env.NODE_ENV || 'development';
const IS_PROD = NODE_ENV === 'production';

const REQUIRED_VARS = ['GOOGLE_CLIENT_ID'];
for (const v of REQUIRED_VARS) {
  if (!process.env[v]) {
    console.error(`❌ Missing required env var: ${v}`);
    process.exit(1);
  }
}
const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;

// `BASE_URL` is optional – if not set we’ll build the redirect URI from the request.
let BASE_URL = process.env.BASE_URL?.replace(/\/+$/, ''); // strip trailing slash
if (BASE_URL) console.log(`🔧 Using BASE_URL from env: ${BASE_URL}`);

const COOKIE_OPTS = {
  httpOnly: true,
  secure: IS_PROD,               // only send over HTTPS in production
  sameSite: IS_PROD ? 'strict' : 'lax',
  // maxAge will be set per‑cookie
};

// ---------------------------------------------------------------
// 2️⃣ Express middleware
// ---------------------------------------------------------------
app.set('trust proxy', 1);               // needed when behind a reverse‑proxy
app.use(express.static('public'));
app.use(cookieParser());

// Helper to wrap async route handlers
const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

// ---------------------------------------------------------------
// 3️⃣ PKCE helpers
// ---------------------------------------------------------------
function base64urlEncode(buffer) {
  return buffer
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}
function generatePKCEPair() {
  const verifier = base64urlEncode(randomBytes(32));
  const challenge = base64urlEncode(
    createHash('sha256').update(verifier).digest()
  );
  return { verifier, challenge };
}

// ---------------------------------------------------------------
// 4️⃣ Utility: build redirect URI
// ---------------------------------------------------------------
function getRedirectUri(req) {
  // If BASE_URL is defined we use it, otherwise we infer from the request.
  const base = BASE_URL || `${req.protocol}://${req.get('host')}`;
  return `${base}/auth/callback`;
}

// ---------------------------------------------------------------
// 5️⃣ Health‑check (required by many PaaS)
// ---------------------------------------------------------------
app.get('/health', (req, res) => res.send('OK'));

// ---------------------------------------------------------------
// 6️⃣ Auth – Login
// ---------------------------------------------------------------
app.get('/auth/login', (req, res) => {
  const { verifier, challenge } = generatePKCEPair();

  // Store PKCE verifier in a short‑lived signed cookie
  res.cookie('pkce_verifier', verifier, {
    ...COOKIE_OPTS,
    maxAge: 10 * 60 * 1000, // 10 min
  });

  const redirectUri = getRedirectUri(req);

  const authUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
  authUrl.searchParams.set('client_id', CLIENT_ID);
  authUrl.searchParams.set('redirect_uri', redirectUri);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set(
    'scope',
    'https://www.googleapis.com/auth/drive.file'
  );
  authUrl.searchParams.set('code_challenge', challenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');
  authUrl.searchParams.set('access_type', 'offline'); // get refresh token
  authUrl.searchParams.set('prompt', 'consent'); // force consent on first login

  res.redirect(authUrl.toString());
});

// ---------------------------------------------------------------
// 7️⃣ Auth – Callback (exchange code for tokens)
// ---------------------------------------------------------------
app.get(
  '/auth/callback',
  asyncHandler(async (req, res) => {
    const code = req.query.code;
    const verifier = req.cookies.pkce_verifier;

    if (!code || !verifier) {
      return res.status(400).send('Missing code or PKCE verifier');
    }

    const tokenResp = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: CLIENT_ID,
        grant_type: 'authorization_code',
        code,
        redirect_uri: getRedirectUri(req),
        code_verifier: verifier,
      }),
    });

    const tokenData = await tokenResp.json();

    if (!tokenResp.ok) {
      console.error('🔴 Token exchange error:', tokenData);
      return res.status(500).send('Token exchange failed');
    }

    // Store tokens in HttpOnly cookies
    const accessOpts = {
      ...COOKIE_OPTS,
      maxAge: tokenData.expires_in * 1000, // seconds → ms
    };
    res.cookie('access_token', tokenData.access_token, accessOpts);

    if (tokenData.refresh_token) {
      const refreshOpts = {
        ...COOKIE_OPTS,
        // Refresh tokens are long‑lived – 30 days is a reasonable default.
        maxAge: 30 * 24 * 60 * 60 * 1000,
      };
      res.cookie('refresh_token', tokenData.refresh_token, refreshOpts);
    }

    // Clean up PKCE verifier
    res.clearCookie('pkce_verifier');

    // Return to SPA root (or you could redirect to a custom page)
    res.redirect('/');
  })
);

// ---------------------------------------------------------------
// 8️⃣ Auth – Refresh access token (optional)
// ---------------------------------------------------------------
app.get(
  '/auth/refresh',
  asyncHandler(async (req, res) => {
    const refreshToken = req.cookies.refresh_token;
    if (!refreshToken) return res.status(401).send('No refresh token');

    const tokenResp = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: CLIENT_ID,
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
      }),
    });

    const data = await tokenResp.json();

    if (!tokenResp.ok) {
      console.error('🔴 Refresh error:', data);
      return res.status(500).json(data);
    }

    // Replace access token cookie
    res.cookie('access_token', data.access_token, {
      ...COOKIE_OPTS,
      maxAge: data.expires_in * 1000,
    });

    res.json({ ok: true });
  })
);

// ---------------------------------------------------------------
// 9️⃣ Drive resumable upload endpoint
// ---------------------------------------------------------------
app.post(
  '/upload-drive',
  express.raw({ type: 'application/octet-stream', limit: '500mb' }),
  asyncHandler(async (req, res) => {
    const accessToken = req.cookies.access_token;
    if (!accessToken) return res.status(401).send('Not authenticated');

    // 1️⃣ Initiate resumable upload session
    const initResp = await fetch(
      'https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable',
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json; charset=UTF-8',
          'X-Upload-Content-Type': 'video/webm',
        },
        body: JSON.stringify({
          name: `meeting-${Date.now()}.webm`,
          mimeType: 'video/webm',
        }),
      }
    );

    if (!initResp.ok) {
      const err = await initResp.text();
      console.error('🔴 Init resumable upload failed:', err);
      return res
        .status(500)
        .send(`Failed to start resumable upload: ${err}`);
    }

    const uploadUrl = initResp.headers.get('Location');
    if (!uploadUrl) {
      return res.status(500).send('Upload URL not returned by Drive API');
    }

    // 2️⃣ Upload the whole blob (single PUT). For true resumable you could chunk here.
    const uploadResp = await fetch(uploadUrl, {
      method: 'PUT',
      headers: {
        // Some proxies strip `content-length`; fallback to the raw header if present.
        'Content-Length': req.headers['content-length'] || req.body.length,
        'Content-Type': 'video/webm',
      },
      body: req.body,
    });

    if (!uploadResp.ok) {
      const err = await uploadResp.text();
      console.error('🔴 Upload failed:', err);
      return res.status(500).send(`Upload failed: ${err}`);
    }

    const fileInfo = await uploadResp.json();
    res.json({
      fileId: fileInfo.id,
      // You can construct a view link if you want; Drive also returns `webViewLink` when requested.
      webViewLink: fileInfo.webViewLink,
    });
  })
);

// ---------------------------------------------------------------
// 10️⃣ Logout – clear all auth cookies
// ---------------------------------------------------------------
app.post('/auth/logout', (req, res) => {
  res.clearCookie('access_token');
  res.clearCookie('refresh_token');
  res.clearCookie('pkce_verifier');
  res.sendStatus(200);
});

// ---------------------------------------------------------------
// 11️⃣ Global error handler (must be after all routes)
// ---------------------------------------------------------------
app.use((err, req, res, _next) => {
  console.error('⚠️ Unhandled error:', err);
  if (!res.headersSent) {
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// ---------------------------------------------------------------
// 12️⃣ Start server – bind to 0.0.0.0 for container platforms
// ---------------------------------------------------------------
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server listening on ${PORT} (${NODE_ENV})`);
});
