require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(cookieParser());

// --- In-memory stores (for demo purposes) ---
const users = []; // [{ id, username, passwordHash }]
const refreshTokensStore = new Map(); // refreshToken -> { userId, expiresAt }

// --- Config ---
const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET || 'test_access_secret';
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET || 'test_refresh_secret';
const ACCESS_TOKEN_EXPIRY = process.env.ACCESS_TOKEN_EXPIRY || '15m';
const REFRESH_TOKEN_EXPIRY = process.env.REFRESH_TOKEN_EXPIRY || '7d';
const COOKIE_SECURE = process.env.COOKIE_SECURE === 'true';

// Helper: convert expiry string to ms
function parseExpiryToMs(exp) {
  if (typeof exp !== 'string') return 0;
  const num = parseInt(exp.slice(0, -1), 10);
  const unit = exp.slice(-1);
  if (unit === 'd') return num * 24 * 60 * 60 * 1000;
  if (unit === 'h') return num * 60 * 60 * 1000;
  if (unit === 'm') return num * 60 * 1000;
  if (unit === 's') return num * 1000;
  return 0;
}

function generateAccessToken(user) {
  return jwt.sign({ userId: user.id, username: user.username }, ACCESS_TOKEN_SECRET, {
    expiresIn: ACCESS_TOKEN_EXPIRY
  });
}

function generateRefreshToken(user) {
  const token = uuidv4();
  const expiresAt = Date.now() + parseExpiryToMs(REFRESH_TOKEN_EXPIRY);
  refreshTokensStore.set(token, { userId: user.id, expiresAt });
  return token;
}

function setRefreshCookie(res, token) {
  res.cookie('refreshToken', token, {
    httpOnly: true,
    secure: COOKIE_SECURE,
    sameSite: 'lax',
    path: '/refresh',
    maxAge: parseExpiryToMs(REFRESH_TOKEN_EXPIRY)
  });
}

// Middleware: authentication for protected route
function authenticateAccessToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Missing Authorization header' });
  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Malformed Authorization header' });
  jwt.verify(token, ACCESS_TOKEN_SECRET, (err, payload) => {
    if (err) return res.status(401).json({ error: 'Invalid or expired access token' });
    req.user = { id: payload.userId, username: payload.username };
    next();
  });
}

// --- Routes ---

// Registration route
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'username & password required' });
  if (users.find(u => u.username === username)) return res.status(400).json({ error: 'username taken' });
  const passwordHash = await bcrypt.hash(password, 10);
  const user = { id: uuidv4(), username, passwordHash };
  users.push(user);
  res.status(201).json({ message: 'User created', username: user.username });
});

// Login route
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
  const accessToken = generateAccessToken(user);
  const refreshToken = generateRefreshToken(user);
  setRefreshCookie(res, refreshToken);
  res.json({ accessToken, expiresIn: ACCESS_TOKEN_EXPIRY });
});

// Refresh route
app.post('/refresh', (req, res) => {
  const token = req.cookies.refreshToken;
  if (!token) return res.status(401).json({ error: 'No refresh token provided' });
  const stored = refreshTokensStore.get(token);
  if (!stored) return res.status(401).json({ error: 'Invalid refresh token' });
  if (Date.now() > stored.expiresAt) {
    refreshTokensStore.delete(token);
    return res.status(401).json({ error: 'Refresh token expired' });
  }
  const user = users.find(u => u.id === stored.userId);
  if (!user) {
    refreshTokensStore.delete(token);
    return res.status(401).json({ error: 'User not found for token' });
  }
  // Rotate refresh token
  refreshTokensStore.delete(token);
  const newRefreshToken = generateRefreshToken(user);
  setRefreshCookie(res, newRefreshToken);
  const accessToken = generateAccessToken(user);
  res.json({ accessToken, expiresIn: ACCESS_TOKEN_EXPIRY });
});

// Logout route
app.post('/logout', (req, res) => {
  const token = req.cookies.refreshToken;
  if (token) {
    refreshTokensStore.delete(token);
  }
  res.clearCookie('refreshToken', { path: '/refresh' });
  res.json({ message: 'Logged out' });
});

// Example protected route
app.get('/protected', authenticateAccessToken, (req, res) => {
  res.json({ message: `Hello ${req.user.username}, this is protected data.` });
});

// Home route
app.get('/', (req, res) => res.send('JWT refresh demo running'));

// Start the server
app.listen(PORT, () => {
  console.log(`Server listening on ${PORT}`);
});
app.post('/login', async (req, res) => {
  console.log('Login attempt:', req.body);
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);
  console.log('User found:', user);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  const ok = await bcrypt.compare(password, user.passwordHash);
  console.log('Password match:', ok);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

  // continue generating JWT if successful ...
});
