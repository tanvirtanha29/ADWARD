// MHT Earning Website - server for Render (no npm packages needed)
// User site  : https://YOUR-NAME.onrender.com/
// Admin site : https://YOUR-NAME.onrender.com/admin   (password protected)

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = String(process.env.ADMIN_PASSWORD || '211706451');
const SECRET = process.env.SESSION_SECRET || ('mht-' + ADMIN_PASSWORD);
const ROOT = __dirname;

// ---------- page maps ----------
// user pages: every *.html that does not start with "admin-"
const userPages = new Set(
  fs.readdirSync(ROOT).filter(f => f.endsWith('.html') && !f.startsWith('admin-'))
);
// admin pages: /admin/<name>  ->  admin-<name>.html
const adminPages = {
  '': 'admin-index.html',
  'index': 'admin-index.html',
  'user': 'admin-user.html',
  'users': 'admin-user.html',
  'tasks': 'admin-tasks.html',
  'watch': 'admin-watch.html',
  'withdrawal': 'admin-withdrawal.html',
  'withdraw': 'admin-withdrawal.html'
};

// ---------- helpers ----------
const MIME = { '.html': 'text/html; charset=utf-8', '.png': 'image/png' };

function send(res, code, body, headers) {
  res.writeHead(code, Object.assign({
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'same-origin'
  }, headers || {}));
  res.end(body);
}

function sendFile(res, file, extra) {
  fs.readFile(path.join(ROOT, file), (err, data) => {
    if (err) return send(res, 404, 'Not found', { 'Content-Type': 'text/plain; charset=utf-8' });
    send(res, 200, data, Object.assign({ 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' }, extra || {}));
  });
}

function redirect(res, to, headers) {
  send(res, 302, '', Object.assign({ Location: to }, headers || {}));
}

function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

function sign(text) {
  return crypto.createHmac('sha256', SECRET).update(text).digest('hex');
}

function makeToken() {
  const exp = String(Date.now() + 7 * 24 * 3600 * 1000); // 7 days
  return exp + '.' + sign('admin|' + exp);
}

function validToken(token) {
  if (!token) return false;
  const i = token.indexOf('.');
  if (i < 1) return false;
  const exp = token.slice(0, i);
  const sig = token.slice(i + 1);
  if (!/^\d+$/.test(exp) || Number(exp) < Date.now()) return false;
  return safeEqual(sig, sign('admin|' + exp));
}

function getCookie(req, name) {
  const raw = req.headers.cookie || '';
  for (const part of raw.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return decodeURIComponent(v.join('='));
  }
  return '';
}

function isAuthed(req) {
  return validToken(getCookie(req, 'mht_admin'));
}

function sessionCookie(req, token, maxAge) {
  const secure = (req.headers['x-forwarded-proto'] || '').split(',')[0] === 'https' ? '; Secure' : '';
  return 'mht_admin=' + encodeURIComponent(token) + '; Path=/; HttpOnly; SameSite=Strict; Max-Age=' + maxAge + secure;
}

// ---------- brute-force protection ----------
const fails = new Map(); // ip -> { count, until }
function clientIp(req) {
  return ((req.headers['x-forwarded-for'] || '').split(',')[0] || req.socket.remoteAddress || '').trim();
}
function isLocked(ip) {
  const f = fails.get(ip);
  return !!(f && f.until && f.until > Date.now());
}
function recordFail(ip) {
  const f = fails.get(ip) || { count: 0, until: 0 };
  f.count += 1;
  if (f.count >= 5) { f.until = Date.now() + 15 * 60 * 1000; f.count = 0; }
  fails.set(ip, f);
}
function clearFails(ip) { fails.delete(ip); }

// ---------- login page ----------
function loginPage(message) {
  return `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Admin Login</title>
<link rel="icon" href="/favicon.png">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{min-height:100vh;display:grid;place-items:center;background:#F6F7F9;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:#1A1D23;padding:20px}
.card{width:100%;max-width:360px;background:#fff;border:1px solid #E4E7EC;border-radius:16px;padding:28px 24px;box-shadow:0 8px 24px rgba(20,24,32,.10)}
h1{font-size:20px;margin-bottom:4px}
p{font-size:13px;color:#5A6270;margin-bottom:18px}
label{display:block;font-size:12px;font-weight:700;color:#5A6270;margin-bottom:6px}
input{width:100%;height:44px;border:1.5px solid #E4E7EC;border-radius:10px;padding:0 12px;font-size:15px}
input:focus{outline:none;border-color:#0D63F2;box-shadow:0 0 0 3px #EBF2FE}
button{width:100%;height:44px;margin-top:14px;border:0;border-radius:10px;background:#0D63F2;color:#fff;font-weight:700;font-size:14px;cursor:pointer}
button:active{transform:scale(.98)}
.err{background:#FCEBEB;color:#D92D20;border-radius:8px;padding:9px 12px;font-size:13px;margin-bottom:14px}
</style></head><body>
<form class="card" method="POST" action="/admin/login" autocomplete="off">
<h1>Admin Login</h1>
<p>Enter the admin password to continue.</p>
${message ? '<div class="err">' + message + '</div>' : ''}
<label for="pw">Password</label>
<input id="pw" name="password" type="password" autofocus required>
<button type="submit">Login</button>
</form></body></html>`;
}

function readBody(req, limit) {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', c => { data += c; if (data.length > limit) { req.destroy(); resolve(''); } });
    req.on('end', () => resolve(data));
    req.on('error', () => resolve(''));
  });
}

const NOCACHE = { 'Cache-Control': 'no-store', 'X-Robots-Tag': 'noindex, nofollow' };

// ---------- server ----------
http.createServer(async (req, res) => {
  let pathname;
  try { pathname = decodeURIComponent(new URL(req.url, 'http://x').pathname); }
  catch (e) { return send(res, 400, 'Bad request'); }

  const ip = clientIp(req);

  // health check for Render
  if (pathname === '/healthz') return send(res, 200, 'ok', { 'Content-Type': 'text/plain' });

  // ===== ADMIN =====
  if (pathname === '/admin' || pathname.startsWith('/admin/')) {
    const sub = pathname.replace(/^\/admin\/?/, '').replace(/\.html$/, '').replace(/\/+$/, '');

    // logout
    if (sub === 'logout') {
      return redirect(res, '/admin', Object.assign({ 'Set-Cookie': sessionCookie(req, '', 0) }, NOCACHE));
    }

    // login form submit
    if (sub === 'login' && req.method === 'POST') {
      if (isLocked(ip)) {
        return send(res, 429, loginPage('Too many attempts. Try again after 15 minutes.'),
          Object.assign({ 'Content-Type': 'text/html; charset=utf-8' }, NOCACHE));
      }
      const body = await readBody(req, 2048);
      const pw = new URLSearchParams(body).get('password') || '';
      if (safeEqual(pw, ADMIN_PASSWORD)) {
        clearFails(ip);
        return redirect(res, '/admin', Object.assign({ 'Set-Cookie': sessionCookie(req, makeToken(), 7 * 24 * 3600) }, NOCACHE));
      }
      recordFail(ip);
      return send(res, 401, loginPage('Wrong password.'),
        Object.assign({ 'Content-Type': 'text/html; charset=utf-8' }, NOCACHE));
    }

    // already logged in -> serve the admin page
    if (isAuthed(req)) {
      if (Object.prototype.hasOwnProperty.call(adminPages, sub)) {
        return sendFile(res, adminPages[sub], NOCACHE);
      }
      return redirect(res, '/admin');
    }

    // direct link style:  /admin/<password>
    if (sub && !Object.prototype.hasOwnProperty.call(adminPages, sub)) {
      if (isLocked(ip)) {
        return send(res, 429, 'Too many attempts. Try later.', { 'Content-Type': 'text/plain; charset=utf-8' });
      }
      if (safeEqual(sub, ADMIN_PASSWORD)) {
        clearFails(ip);
        return redirect(res, '/admin', Object.assign({ 'Set-Cookie': sessionCookie(req, makeToken(), 7 * 24 * 3600) }, NOCACHE));
      }
      recordFail(ip);
      return send(res, 404, 'Not found', { 'Content-Type': 'text/plain; charset=utf-8' });
    }

    // not logged in -> login page
    return send(res, 200, loginPage(''), Object.assign({ 'Content-Type': 'text/html; charset=utf-8' }, NOCACHE));
  }

  // ===== USER SITE =====
  if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, 'Method not allowed');

  if (pathname === '/' || pathname === '/index' ) return sendFile(res, 'index.html');
  if (pathname === '/favicon.png' || pathname === '/favicon.ico') return sendFile(res, 'favicon.png', { 'Cache-Control': 'public, max-age=86400' });
  if (pathname === '/welcome.html' || pathname === '/welcome') return redirect(res, '/login.html');

  // /login  or  /login.html
  let name = pathname.replace(/^\//, '');
  if (!name.endsWith('.html')) name += '.html';
  if (userPages.has(name)) return sendFile(res, name);

  return send(res, 404, 'Page not found', { 'Content-Type': 'text/plain; charset=utf-8' });
}).listen(PORT, () => console.log('Server running on port ' + PORT));
