// server.js
import express from 'express';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import fetch from 'node-fetch';
import crypto from 'crypto';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
app.set('trust proxy', true);               // <-- important on Railway
app.use(cookieParser());
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'fallback-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
    },
  })
);

const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const SCOPE = encodeURIComponent('openid email profile https://www.googleapis.com/auth/drive.file');

function generatePKCE() {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto
    .createHash('sha256')
    .update(verifier)
    .digest('base64url');
  return { verifier, challenge };
}

// Helper to build base URL (fallback to env var)
function getBaseUrl(req) {
  if (process.env.BASE_URL) return process.env.BASE_URL;
  const proto = req.headers['x-forwarded-proto'] || req.protocol;
  const host = req.headers['x-forwarded-host'] || req.get('host');
  return `${proto}://${host}`;
}

// ---------- Routes ----------
app.get('/auth/google', (req, res) => {
  const { verifier, challenge } = generatePKCE();
  req.session.pkceVerifier = verifier; // store for later verification

  const redirectUri = `${getBaseUrl(req)}/auth/callback`;

  const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?` +
    `client_id=${CLIENT_ID}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&response_type=code` +
    `&scope=${SCOPE}` +
    `&code_challenge=${challenge}` +
    `&code_challenge_method=S256`;

  res.redirect(authUrl);
});

app.get('/auth/callback', async (req, res) => {
  const { code } = req.query;
  const verifier = req.session.pkceVerifier;

  if (!code || !verifier) {
    return res.status(400).send('Missing code or PKCE verifier');
  }

  const redirectUri = `${getBaseUrl(req)}/auth/callback`;

  const tokenResp = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      code,
      grant_type: 'authorization_code',
      redirect_uri: redirectUri,
      code_verifier: verifier,
    }),
  });

  const tokenData = await tokenResp.json();

  if (tokenData.error) {
    console.error('Token error:', tokenData);
    return res.status(400).send('Token exchange failed');
  }

  // Save tokens where you need them (session, DB, etc.)
  req.session.tokens = tokenData;
  res.send('✅ Login successful – you can now use the app.');
});

// Simple health‑check (useful for Railway)
app.get('/health', (_, res) => res.send('OK'));

const PORT = process.env.PORT || 8080;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server listening on ${PORT}`);
});
