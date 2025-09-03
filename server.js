import express from 'express';
import fetch from 'node-fetch';
import cookieParser from 'cookie-parser';
import { randomBytes, createHash } from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import dotenv from 'dotenv';
dotenv.config();

const app = express();
const PORT = process.env.PORT || 8080;
const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const BASE_URL = process.env.BASE_URL; // e.g. https://my-app.onrender.com
const REDIRECT_URI = `${BASE_URL}/auth/callback`;

app.use(express.static('public'));
app.use(cookieParser());

// ---------- PKCE helpers ----------
function base64urlEncode(buffer) {
  return buffer.toString('base64')
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

// ---------- 1️⃣ Login endpoint ----------
app.get('/auth/login', (req, res) => {
  const { verifier, challenge } = generatePKCEPair();

  // store verifier in a temporary signed cookie (expires in 10 min)
  res.cookie('pkce_verifier', verifier, {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    maxAge: 10 * 60 * 1000,
  });

  const authUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
  authUrl.searchParams.set('client_id', CLIENT_ID);
  authUrl.searchParams.set('redirect_uri', REDIRECT_URI);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('scope', 'https://www.googleapis.com/auth/drive.file');
  authUrl.searchParams.set('code_challenge', challenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');
  authUrl.searchParams.set('access_type', 'offline'); // to get refresh token
  authUrl.searchParams.set('prompt', 'consent'); // ensures refresh token on first login

  res.redirect(authUrl.toString());
});

// ---------- 2️⃣ OAuth callback ----------
app.get('/auth/callback', async (req, res) => {
  const code = req.query.code;
  const verifier = req.cookies.pkce_verifier;
  if (!code || !verifier) {
    return res.status(400).send('Missing code or PKCE verifier');
  }

  // Exchange code for tokens
  const tokenResp = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: CLIENT_ID,
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: verifier,
    }),
  });

  const tokenData = await tokenResp.json();
  if (!tokenResp.ok) {
    console.error(tokenData);
    return res.status(500).send('Token exchange failed');
  }

  // Store tokens in HttpOnly cookies (access token short‑lived, refresh token longer)
  const cookieOpts = {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    // Access token lives 1 hour – we let the client refresh when needed.
    maxAge: tokenData.expires_in * 1000,
  };
  res.cookie('access_token', tokenData.access_token, cookieOpts);
  if (tokenData.refresh_token) {
    res.cookie('refresh_token', tokenData.refresh_token, {
      ...cookieOpts,
      // refresh token is “forever” (or until revoked)
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days – arbitrary
    });
  }

  // Clean up the PKCE cookie
  res.clearCookie('pkce_verifier');

  // Redirect back to the SPA (root)
  res.redirect('/');
});

// ---------- 3️⃣ Refresh token endpoint (optional) ----------
app.get('/auth/refresh', async (req, res) => {
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
  if (!tokenResp.ok) return res.status(500).json(data);

  // replace access token cookie
  res.cookie('access_token', data.access_token, {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    maxAge: data.expires_in * 1000,
  });
  res.json({ ok: true });
});

// ---------- 4️⃣ Drive resumable upload ----------
app.post('/upload-drive', express.raw({ type: 'application/octet-stream', limit: '500mb' }), async (req, res) => {
  const accessToken = req.cookies.access_token;
  if (!accessToken) return res.status(401).send('Not authenticated');

  // 1️⃣ Initiate resumable session
  const initResp = await fetch('https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable', {
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
  });

  if (!initResp.ok) {
    const err = await initResp.text();
    return res.status(500).send(`Failed to start resumable upload: ${err}`);
  }
  const uploadUrl = initResp.headers.get('Location');

  // 2️⃣ Upload the whole blob in one request (you could chunk it if you want)
  const uploadResp = await fetch(uploadUrl, {
    method: 'PUT',
    headers: {
      'Content-Length': req.headers['content-length'],
      'Content-Type': 'video/webm',
    },
    body: req.body,
  });

  if (!uploadResp.ok) {
    const err = await uploadResp.text();
    return res.status(500).send(`Upload failed: ${err}`);
  }

  const fileInfo = await uploadResp.json();
  res.json({ fileId: fileInfo.id, webViewLink: fileInfo.webViewLink });
});

// ---------- 5️⃣ Logout route ----------
app.post('/auth/logout', (req, res) => {
  res.clearCookie('access_token');
  res.clearCookie('refresh_token');
  res.clearCookie('pkce_verifier');
  res.sendStatus(200);
});

app.listen(PORT, () => console.log(`🚀 Server listening on ${PORT}`));
