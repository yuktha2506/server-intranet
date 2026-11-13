/**
 * MT CNC-Group backend entry point. Uses in-memory JavaScript data only.
 * No database connection or database packages are used.
 */
const express = require('express');
const http = require('http');
const path = require('path');
const cors = require('cors');
const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');
const createApiRouter = require('./api');

const required = ['JWT_SECRET'];
const missing = required.filter((key) => !process.env[key]);
if (missing.length) throw new Error('Missing required environment settings: ' + missing.join(', '));
if (process.env.JWT_SECRET.length < 32) throw new Error('JWT_SECRET must be at least 32 characters.');
const app = express();
app.disable('x-powered-by');
const server = http.createServer(app);
const frontendOrigin = process.env.FRONTEND_ORIGIN;
if (frontendOrigin) app.use(cors({ origin: frontendOrigin, credentials: true }));
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Content-Security-Policy', "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data:; connect-src 'self' ws: wss:");
  if (process.env.NODE_ENV === 'production') res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});
app.use('/api', (req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  next();
});
app.use(express.json({ limit: '1mb', strict: true }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));

const io = new Server(server, { cors: frontendOrigin ? { origin: frontendOrigin, credentials: true } : undefined });
app.set('io', io);

io.use(async (socket, next) => {
  try {
    const cookieHeader = socket.handshake.headers.cookie || '';
    const cookie = cookieHeader.split(';').map((part) => part.trim()).find((part) => part.startsWith('mt_session='));
    const cookieToken = cookie ? cookie.slice('mt_session='.length) : '';
    const decoded = jwt.verify(cookieToken, process.env.JWT_SECRET);
    const role = decoded.id === 'static-admin' ? 'admin' : decoded.id === 'static-employee' ? 'employee' : null;
    if (decoded.auth_source !== 'static' || !role || decoded.role !== role) return next(new Error('Authentication required'));
    socket.data.user = { id: decoded.id, role };
    next();
  } catch (_) {
    next(new Error('Authentication required'));
  }
});
io.on('connection', (socket) => {
  socket.join(`user:${socket.data.user.id}`);
  if (socket.data.user.role === 'admin') socket.join('admins');
});

app.use('/api', createApiRouter({ jwtSecret: process.env.JWT_SECRET }));
app.get('/api/health', (req, res) => res.json({
  status: 'online',
  app: 'MT CNC-Group - Microtech CNC Pvt. Ltd.',
  storage: 'in-memory',
  loginIdPolicy: 'configured-account-match'
}));
const serveFrontend = (req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.sendFile(path.join(__dirname, 'frontend.html'), (err) => err && next(err));
};
app.get(['/','/frontend.html'], serveFrontend);
app.use((req, res, next) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ success: false, message: 'API endpoint not found.' });
  return serveFrontend(req, res, next);
});
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  if (err && err.type === 'entity.too.large') return res.status(413).json({ success: false, message: 'Request is too large.' });
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) return res.status(400).json({ success: false, message: 'Invalid JSON request body.' });
  console.error('Unhandled request error.');
  return res.status(500).json({ success: false, message: 'Internal server error.' });
});

const port = Number(process.env.PORT || 3000);
async function start() {
  server.listen(port, () => console.log('MT CNC-Group server listening on configured port.'));
}
start().catch((err) => {
  console.error('Unable to start MT CNC-Group backend.');
  process.exitCode = 1;
});

process.on('SIGTERM', () => server.close());
process.on('SIGINT', () => server.close());
