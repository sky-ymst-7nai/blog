'use strict';
/**
 * 学習用 Webプロキシ（依存パッケージなし / Node.js 組み込みモジュールのみ）
 *
 * URL形式:  /~/<https|http>/<ホスト>/<パス>?<クエリ>
 *   例) http://localhost:3000/~/https/note.com/login
 *
 * ログインを通すための要点（読むならここから）
 *  1. Cookie はブラウザではなくサーバー側の「Cookie Jar」に保存する
 *     → サイトごとのドメイン/パス/Secure/有効期限を正しく扱える。サイト間で混ざらない
 *  2. リダイレクト(Location)を自分で追わず、プロキシURLに書き換えてブラウザに返す
 *  3. HTML/CSS内のURLをプロキシURLに書き換える（<base>, srcset, meta refresh も対応）
 *  4. Origin / Referer を本来のサイトのものに戻して上流へ送る（CSRFチェック対策）
 *  5. CSP / X-Frame-Options など書き換えを邪魔するヘッダーを除去
 *  6. ページ内JS用の補正スクリプト(public/client.js)を注入
 *     （fetch / XHR / フォーム / document.cookie などをプロキシ経由にする）
 */
const http = require('http');
const https = require('https');
const zlib = require('zlib');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const net = require('net');
const tls = require('tls');

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '127.0.0.1'; // 既定はローカル専用
const AUTH = process.env.BASIC_AUTH || ''; // 公開する場合は "user:pass" を必ず設定
const SESSION_COOKIE = 'px_sid';
const LOG = process.env.LOG !== '0'; // LOG=0 でアクセスログを止める

// 上流への接続を使い回す（TCP/TLSの確立コストを省く＝体感速度の改善）
const agentOpts = { keepAlive: true, maxSockets: 64, maxFreeSockets: 16, timeout: 60000 };
const httpAgent = new http.Agent(agentOpts);
const httpsAgent = new https.Agent(agentOpts);

// 通過を許可するドメイン（末尾一致）。踏み台悪用を防ぐため許可リスト方式。
// 足りないホストは起動ログの "BLOCKED" に出るので ALLOW_HOSTS=a.com,b.net で追加する。
const DEFAULT_ALLOW = [
  'note.com', 'st-note.com',
  'ameba.jp', 'ameblo.jp',
  'fc2.com',
  'hatena.ne.jp', 'hatena.com', 'hatenablog.com', 'hatenablog.jp',
  'hatenadiary.com', 'hatenadiary.jp', 'st-hatena.com',
];
const ALLOW = DEFAULT_ALLOW.concat(
  (process.env.ALLOW_HOSTS || '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean)
);
const allowed = (h) => ALLOW.some((s) => h === s || h.endsWith('.' + s));
const warned = new Set();

// ───────────────────────── Cookie Jar ─────────────────────────
const jars = new Map(); // セッションID -> Cookie配列
const MAX_SESSIONS = 100;

function getJar(sid) {
  if (!jars.has(sid)) {
    if (jars.size >= MAX_SESSIONS) jars.delete(jars.keys().next().value);
    jars.set(sid, []);
  }
  return jars.get(sid);
}
const domainMatch = (host, domain) => host === domain || host.endsWith('.' + domain);
const pathMatch = (reqPath, cp) =>
  reqPath === cp || (reqPath.startsWith(cp) && (cp.endsWith('/') || reqPath[cp.length] === '/'));
function defaultPath(p) {
  if (!p || p[0] !== '/') return '/';
  const i = p.lastIndexOf('/');
  return i <= 0 ? '/' : p.slice(0, i);
}

/** Set-Cookie ヘッダー1本を解釈して Jar に保存（url: そのCookieを返してきたURL） */
function storeCookie(jar, setCookie, url) {
  const parts = setCookie.split(';');
  const pair = parts.shift();
  const eq = pair.indexOf('=');
  if (eq <= 0) return;
  const c = {
    name: pair.slice(0, eq).trim(),
    value: pair.slice(eq + 1).trim(),
    domain: url.hostname,
    hostOnly: true,
    path: defaultPath(url.pathname),
    secure: false,
    httpOnly: false,
    expires: Infinity,
  };
  for (const a of parts) {
    const i = a.indexOf('=');
    const k = (i < 0 ? a : a.slice(0, i)).trim().toLowerCase();
    const v = i < 0 ? '' : a.slice(i + 1).trim();
    if (k === 'domain' && v) {
      const d = v.replace(/^\./, '').toLowerCase();
      if (!domainMatch(url.hostname, d)) return; // 無関係なドメインへのCookieは拒否
      c.domain = d;
      c.hostOnly = false;
    } else if (k === 'path' && v[0] === '/') c.path = v;
    else if (k === 'secure') c.secure = true;
    else if (k === 'httponly') c.httpOnly = true;
    else if (k === 'max-age') c.expires = Date.now() + Number(v) * 1000;
    else if (k === 'expires' && c.expires === Infinity) {
      const t = Date.parse(v);
      if (!Number.isNaN(t)) c.expires = t;
    }
  }
  const idx = jar.findIndex((x) => x.name === c.name && x.domain === c.domain && x.path === c.path);
  if (idx >= 0) jar.splice(idx, 1);
  if (c.expires > Date.now()) jar.push(c); // 期限切れ指定＝削除
}

function matchingCookies(jar, url) {
  const now = Date.now();
  return jar
    .filter(
      (c) =>
        c.expires > now &&
        (c.hostOnly ? url.hostname === c.domain : domainMatch(url.hostname, c.domain)) &&
        pathMatch(url.pathname, c.path) &&
        (!c.secure || url.protocol === 'https:')
    )
    .sort((a, b) => b.path.length - a.path.length);
}
const cookieHeader = (jar, url) => matchingCookies(jar, url).map((c) => `${c.name}=${c.value}`).join('; ');
// ページ内JS(document.cookie)に見せてよいもの＝HttpOnlyでないもの
const jsVisibleCookies = (jar, url) =>
  matchingCookies(jar, url).filter((c) => !c.httpOnly).map((c) => `${c.name}=${c.value}`).join('; ');

// ───────────────────────── URL / HTML / CSS 書き換え ─────────────────────────
const proxify = (u) => '/~/' + u.protocol.slice(0, -1) + '/' + u.host + u.pathname + u.search + u.hash;

function rewriteUrl(raw, base) {
  const s = raw.trim();
  if (!s || s[0] === '#' || /^(javascript|data|blob|about|mailto|tel|sms|file):/i.test(s)) return raw;
  try {
    const a = new URL(s, base);
    return a.protocol === 'http:' || a.protocol === 'https:' ? proxify(a) : raw;
  } catch {
    return raw;
  }
}
const unesc = (s) => s.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, '&');
const esc = (s) => s.replace(/&/g, '&amp;').replace(/"/g, '&quot;');

function rewriteCss(css, base) {
  return css
    .replace(/url\(\s*(["']?)([^"')]*)\1\s*\)/gi, (m, q, u) => 'url(' + q + rewriteUrl(u, base) + q + ')')
    .replace(/@import\s+(["'])([^"']+)\1/gi, (m, q, u) => '@import ' + q + rewriteUrl(u, base) + q);
}

const URL_ATTRS = new Set(['href', 'src', 'action', 'formaction', 'poster', 'background', 'data-src', 'data-original', 'data-href']);
const ATTR_RE = /(\s+)([^\s"'<>\/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'<>`=]+)))?/g;

function fixAttrs(tag, attrs, base) {
  const isRefresh = tag === 'meta' && /http-equiv\s*=\s*["']?refresh/i.test(attrs);
  return attrs.replace(ATTR_RE, (m, sp, name, v1, v2, v3) => {
    const val = v1 !== undefined ? v1 : v2 !== undefined ? v2 : v3;
    if (val === undefined) return m;
    const n = name.toLowerCase();
    const v = unesc(val);
    if (n === 'integrity') return ''; // 書き換え後は SRI ハッシュが合わなくなる
    if (n === 'referrerpolicy') return '';
    if (n === 'rel') return sp + name + '="' + esc(v.replace(/\bnoreferrer\b/gi, '').trim()) + '"';
    if (URL_ATTRS.has(n) || (n === 'data' && tag === 'object')) return sp + name + '="' + esc(rewriteUrl(v, base)) + '"';
    if (n === 'srcset' || n === 'data-srcset' || n === 'imagesrcset') {
      const out = v
        .split(',')
        .map((part) => {
          const t = part.trim();
          const i = t.search(/\s/);
          return i < 0 ? rewriteUrl(t, base) : rewriteUrl(t.slice(0, i), base) + t.slice(i);
        })
        .join(', ');
      return sp + name + '="' + esc(out) + '"';
    }
    if (n === 'style') return sp + name + '="' + esc(rewriteCss(v, base)) + '"';
    if (isRefresh && n === 'content') {
      const out = v.replace(/(url\s*=\s*)(['"]?)([^'"]+)\2/i, (mm, p, q, u) => p + q + rewriteUrl(u, base) + q);
      return sp + name + '="' + esc(out) + '"';
    }
    return m;
  });
}

// <script>/<style> は中身ごと、それ以外はタグ単位で処理する
const TAG_RE =
  /<(script|style)\b([^>]*)>([\s\S]*?)<\/\1\s*>|<([a-zA-Z][\w:-]*)((?:\s+[^\s"'<>\/=]+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s"'<>`=]+))?)*)\s*(\/?)>/gi;

function rewriteHtml(html, target, jar, inject) {
  html = html.replace(/<meta[^>]+http-equiv\s*=\s*["']?content-security-policy[^>]*>/gi, '');
  html = html.replace(/<meta[^>]+name\s*=\s*["']?referrer["']?[^>]*>/gi, '');
  let base = target;
  html = html.replace(/<base\b[^>]*>/gi, (m) => {
    const h = /href\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(m);
    if (h) {
      try { base = new URL(unesc(h[1] ?? h[2] ?? h[3]), target); } catch { /* 無視 */ }
    }
    return '';
  });
  html = html.replace(TAG_RE, (m, sname, sattrs, sbody, tname, tattrs, selfClose) => {
    if (sname) {
      const n = sname.toLowerCase();
      return '<' + sname + fixAttrs(n, sattrs, base) + '>' + (n === 'style' ? rewriteCss(sbody, base) : sbody) + '</' + sname + '>';
    }
    return '<' + tname + fixAttrs(tname.toLowerCase(), tattrs, base) + selfClose + '>';
  });
  if (inject) {
    const cfg = JSON.stringify({ url: target.href, base: base.href, cookie: jsVisibleCookies(jar, target) }).replace(/</g, '\\u003c');
    const tag = `<script>window.__PX_CFG=${cfg};</script><script src="/__px/client.js"></script>`;
    const r = [/<head(\s[^>]*)?>/i, /<html(\s[^>]*)?>/i];
    let done = false;
    for (const re of r) {
      if (re.test(html)) { html = html.replace(re, (x) => x + tag); done = true; break; }
    }
    if (!done) html = tag + html;
  }
  return html;
}

// ───────────────────────── 補助関数 ─────────────────────────
function decodeBody(buf, ct) {
  let cs = (/charset=["']?([\w-]+)/i.exec(ct || '') || [])[1];
  if (!cs) cs = (/<meta[^>]+charset=["']?([\w-]+)/i.exec(buf.subarray(0, 2048).toString('latin1')) || [])[1];
  try { return new TextDecoder((cs || 'utf-8').toLowerCase()).decode(buf); } catch { return buf.toString('utf8'); }
}
function inflateBody(buf, enc) {
  enc = (enc || '').toLowerCase();
  if (enc === 'gzip' || enc === 'x-gzip') return zlib.gunzipSync(buf);
  if (enc === 'br') return zlib.brotliDecompressSync(buf);
  if (enc === 'deflate') { try { return zlib.inflateSync(buf); } catch { return zlib.inflateRawSync(buf); } }
  return buf;
}
const HOP = new Set(['connection', 'keep-alive', 'transfer-encoding', 'upgrade', 'te', 'trailer', 'proxy-authenticate', 'proxy-authorization']);
const DROP_REQ = new Set(['host', 'cookie', 'referer', 'origin', 'accept-encoding', 'via', 'forwarded', 'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto']);
const DROP_RES = new Set(['set-cookie', 'content-security-policy', 'content-security-policy-report-only', 'x-frame-options', 'strict-transport-security',
  'cross-origin-opener-policy', 'cross-origin-embedder-policy', 'cross-origin-resource-policy', 'report-to', 'nel', 'clear-site-data', 'alt-svc', 'content-location']);

function sessionOf(req, res) {
  const m = new RegExp('(?:^|;\\s*)' + SESSION_COOKIE + '=([a-f0-9]{32})').exec(req.headers.cookie || '');
  if (m) return m[1];
  const sid = crypto.randomBytes(16).toString('hex');
  const secure = req.headers['x-forwarded-proto'] === 'https' ? '; Secure' : ''; // Render等のHTTPS終端の裏
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=${sid}; Path=/; HttpOnly; SameSite=Lax${secure}`);
  return sid;
}
function parseProxyPath(url) {
  const m = /^\/~\/(https?)\/([^/?#]+)([^?#]*)(\?[^#]*)?/.exec(url);
  if (!m) return null;
  try { return new URL(`${m[1]}://${m[2]}${m[3] || '/'}${m[4] || ''}`); } catch { return null; }
}
function text(res, code, msg) {
  res.writeHead(code, { 'content-type': 'text/plain; charset=utf-8' });
  res.end(msg);
}
const fails = new Map(); // IP -> { n: 失敗回数, until: ロック解除時刻 }
function clientIp(req) {
  const x = String(req.headers['x-forwarded-for'] || '').split(',').map((t) => t.trim()).filter(Boolean);
  return x.length ? x[x.length - 1] : req.socket.remoteAddress; // 右端＝Renderが付与した実接続元
}
/** 'ok' | 'none'(資格情報なし＝ブラウザの初回要求) | 'bad' | 'locked' */
function authState(req) {
  if (!AUTH) return 'ok';
  const ip = clientIp(req);
  const rec = fails.get(ip);
  if (rec && rec.until > Date.now()) return 'locked';
  const h = req.headers.authorization || '';
  if (!h.startsWith('Basic ')) return 'none';
  const a = Buffer.from(h.slice(6), 'base64');
  const b = Buffer.from(AUTH);
  if (a.length === b.length && crypto.timingSafeEqual(a, b)) { fails.delete(ip); return 'ok'; }
  if (fails.size > 1000) fails.clear();
  const r = rec || { n: 0, until: 0 };
  if (++r.n >= 10) { r.n = 0; r.until = Date.now() + 10 * 60 * 1000; } // 10回失敗で10分ロック
  fails.set(ip, r);
  return 'bad';
}

const sameSiteApprox = (a, b) => {
  const f = (h) => { const p = h.split('.'); return p.slice(-(p.length > 2 && p[p.length - 1].length === 2 && ['co', 'or', 'ne', 'ac', 'go', 'ed', 'gr', 'ad'].includes(p[p.length - 2]) ? 3 : 2)).join('.'); };
  return f(a) === f(b);
};

/** 変換後の本文を、クライアントが対応していれば圧縮して返す（転送量の削減） */
function sendCompressed(req, res, code, out, buf) {
  const ae = String(req.headers['accept-encoding'] || '');
  const done = (b, enc) => {
    if (enc) out['content-encoding'] = enc;
    out.vary = 'Accept-Encoding';
    out['content-length'] = b.length;
    res.writeHead(code, out);
    res.end(b);
  };
  if (buf.length < 1024) return done(buf);
  if (/\bbr\b/.test(ae)) {
    return zlib.brotliCompress(buf, { params: { [zlib.constants.BROTLI_PARAM_QUALITY]: 4 } }, (e, b) => (e ? done(buf) : done(b, 'br')));
  }
  if (/\bgzip\b/.test(ae)) return zlib.gzip(buf, (e, b) => (e ? done(buf) : done(b, 'gzip')));
  done(buf);
}

// ───────────────────────── プロキシ本体 ─────────────────────────
function proxyRequest(req, res, target, jar) {
  if (!allowed(target.hostname)) {
    if (!warned.has(target.hostname)) { warned.add(target.hostname); console.log('BLOCKED host (ALLOW_HOSTS で許可できます):', target.hostname); }
    return text(res, 403, `許可されていないホストです: ${target.hostname}`);
  }

  // 上流へ送るヘッダーを組み立てる
  const h = {};
  for (const [k, v] of Object.entries(req.headers)) {
    if (HOP.has(k) || DROP_REQ.has(k) || k.startsWith('sec-fetch-')) continue;
    if (k === 'authorization' && AUTH) continue;
    h[k] = v;
  }
  h.host = target.host;
  h['accept-encoding'] = 'gzip, deflate, br';
  // Referer: プロキシURL → 本来のURLに戻す。Origin: 本来のページの origin にする
  let realReferer = null;
  try {
    const r = new URL(req.headers.referer || '');
    const p = r.host === req.headers.host && parseProxyPath(r.pathname + r.search);
    if (p) realReferer = p;
  } catch { /* リファラなし */ }
  if (realReferer) h.referer = realReferer.href;
  if (req.headers.origin) h.origin = (realReferer || target).origin;
  const ck = cookieHeader(jar, target);
  if (ck) h.cookie = ck;
  // Sec-Fetch-*: ブラウザの値は「プロキシとの関係」なので、本来のサイトとの関係に作り直す
  const dest = req.headers['sec-fetch-dest'];
  if (dest) {
    const mode = req.headers['sec-fetch-mode'] || 'cors';
    h['sec-fetch-dest'] = dest;
    h['sec-fetch-mode'] = mode;
    h['sec-fetch-site'] = realReferer
      ? realReferer.origin === target.origin ? 'same-origin' : sameSiteApprox(realReferer.hostname, target.hostname) ? 'same-site' : 'cross-site'
      : mode === 'navigate' ? 'none' : 'same-origin';
    if (req.headers['sec-fetch-user']) h['sec-fetch-user'] = req.headers['sec-fetch-user'];
  }

  const lib = target.protocol === 'https:' ? https : http;
  const up = lib.request(
    { hostname: target.hostname.replace(/^\[|\]$/g, ''), port: target.port || undefined, path: target.pathname + target.search, method: req.method, headers: h, agent: target.protocol === 'https:' ? httpsAgent : httpAgent },
    (ur) => {
      for (const sc of ur.headers['set-cookie'] || []) storeCookie(jar, sc, target);

      const out = {};
      for (const [k, v] of Object.entries(ur.headers)) if (!HOP.has(k) && !DROP_RES.has(k)) out[k] = v;
      if (out.location) out.location = rewriteUrl(String(out.location), target);
      out['referrer-policy'] = 'same-origin'; // 全ページで Referer を残す（復元とフォールバックに必要）

      const ct = String(ur.headers['content-type'] || '');
      const isHtml = /text\/html|application\/xhtml/i.test(ct);
      const isCss = /text\/css/i.test(ct);
      if (LOG) console.log(`${req.method} ${target.href} -> ${ur.statusCode}`);

      if (!(isHtml || isCss) || req.method === 'HEAD' || ur.statusCode === 204 || ur.statusCode === 304) {
        res.writeHead(ur.statusCode, out); // そのまま中継（画像・JS・JSONなど）
        return ur.pipe(res);
      }
      const chunks = [];
      ur.on('data', (c) => chunks.push(c));
      ur.on('error', () => res.destroy());
      ur.on('end', () => {
        try {
          let body = decodeBody(inflateBody(Buffer.concat(chunks), ur.headers['content-encoding']), ct);
          if (isHtml) {
            const dest = req.headers['sec-fetch-dest'];
            const inject = dest ? ['document', 'iframe', 'frame', 'embed', 'object'].includes(dest) : /<(html|head|!doctype)/i.test(body);
            body = rewriteHtml(body, target, jar, inject);
            out['cache-control'] = 'no-store';
          } else body = rewriteCss(body, target);
          delete out['content-encoding'];
          delete out.etag; // 書き換え後の本文とは一致しないので外す
          delete out['last-modified'];
          out['content-type'] = ct.replace(/;\s*charset=[^;]*/i, '') + '; charset=utf-8';
          sendCompressed(req, res, ur.statusCode, out, Buffer.from(body, 'utf8'));
        } catch (e) {
          text(res, 502, '本文の変換に失敗しました: ' + e.message);
        }
      });
    }
  );
  up.setTimeout(30000, () => up.destroy(new Error('タイムアウト')));
  up.on('error', (e) => {
    if (!res.headersSent) text(res, 502, '上流への接続エラー: ' + e.message);
    else res.destroy();
  });
  req.pipe(up);
}

/** WebSocket: 上流へ接続し、ハンドシェイクとその後のバイト列をそのまま中継する */
function handleUpgrade(req, socket, head) {
  const fail = (code, msg) => socket.end(`HTTP/1.1 ${code} ${msg}\r\nConnection: close\r\n\r\n`);
  if (authState(req) !== 'ok') return fail(401, 'Unauthorized');
  const m = new RegExp('(?:^|;\\s*)' + SESSION_COOKIE + '=([a-f0-9]{32})').exec(req.headers.cookie || '');
  const target = parseProxyPath(req.url);
  if (!m || !target || !allowed(target.hostname)) return fail(403, 'Forbidden');
  const h = {};
  for (const [k, v] of Object.entries(req.headers)) {
    if (DROP_REQ.has(k) || k.startsWith('sec-fetch-') || (k === 'authorization' && AUTH)) continue;
    h[k] = v;
  }
  h.host = target.host;
  h.origin = target.origin;
  const ck = cookieHeader(getJar(m[1]), target);
  if (ck) h.cookie = ck;
  const secure = target.protocol === 'https:';
  const host = target.hostname.replace(/^\[|\]$/g, '');
  const port = Number(target.port) || (secure ? 443 : 80);
  const up = secure ? tls.connect({ host, port, servername: host }) : net.connect(port, host);
  up.once(secure ? 'secureConnect' : 'connect', () => {
    let raw = `GET ${target.pathname + target.search} HTTP/1.1\r\n`;
    for (const [k, v] of Object.entries(h)) raw += `${k}: ${v}\r\n`;
    up.write(raw + '\r\n');
    if (head && head.length) up.write(head);
    up.pipe(socket);
    socket.pipe(up);
  });
  const close = () => { up.destroy(); socket.destroy(); };
  up.on('error', close);
  socket.on('error', close);
  up.on('close', close);
  socket.on('close', close);
  if (LOG) console.log(`WS ${target.href}`);
}

function createServer() {
  const server = http.createServer((req, res) => {
    if (req.url === '/healthz') return text(res, 200, 'ok'); // 死活監視用（認証なし・情報なし）
    const st = authState(req);
    if (st === 'locked') { res.writeHead(429, { 'retry-after': '600' }); return res.end('too many failed attempts'); }
    if (st !== 'ok') { res.writeHead(401, { 'www-authenticate': 'Basic realm="proxy"' }); return res.end('認証が必要です'); }
    const sid = sessionOf(req, res);
    const jar = getJar(sid);
    const u = new URL(req.url, 'http://local');

    if (u.pathname === '/' || u.pathname === '/index.html') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      return res.end(fs.readFileSync(path.join(__dirname, 'public', 'index.html')));
    }
    if (u.pathname === '/__px/client.js') {
      res.writeHead(200, { 'content-type': 'application/javascript; charset=utf-8', 'cache-control': 'no-store' });
      return res.end(fs.readFileSync(path.join(__dirname, 'public', 'client.js')));
    }
    if (u.pathname === '/go') {
      let v = (u.searchParams.get('url') || '').trim();
      if (!/^https?:\/\//i.test(v)) v = 'https://' + v;
      try { res.writeHead(302, { location: proxify(new URL(v)) }); return res.end(); } catch { return text(res, 400, 'URLが不正です'); }
    }
    if (u.pathname === '/__px/reset') {
      jars.delete(sid);
      res.writeHead(302, { location: '/' });
      return res.end();
    }
    if (u.pathname === '/__px/cookie' && req.method === 'POST') {
      // ページ内JSの document.cookie = "..." をJarに反映する
      let size = 0;
      const chunks = [];
      req.on('data', (c) => { size += c.length; if (size < 16384) chunks.push(c); });
      return req.on('end', () => {
        try {
          const { url, cookie } = JSON.parse(Buffer.concat(chunks).toString());
          const t = new URL(url);
          if (allowed(t.hostname)) storeCookie(jar, String(cookie), t);
        } catch { /* 無視 */ }
        res.writeHead(204);
        res.end();
      });
    }

    const target = parseProxyPath(req.url);
    if (target) return proxyRequest(req, res, target, jar);

    // フォールバック: "/login" のようなプロキシ外パスは、Referer から元サイトを推定して振り替える
    try {
      const r = new URL(req.headers.referer || '');
      const m = r.host === req.headers.host && /^\/~\/(https?)\/([^/?#]+)/.exec(r.pathname);
      if (m) {
        const t = new URL(req.url, `${m[1]}://${m[2]}`);
        res.writeHead(307, { location: proxify(t) }); // 307: メソッドとボディを保つ
        return res.end();
      }
    } catch { /* 無視 */ }
    text(res, 404, 'Not found');
  });
  server.on('upgrade', handleUpgrade);
  return server;
}

module.exports = { createServer };

if (require.main === module) {
  const isLocal = HOST === '127.0.0.1' || HOST === 'localhost' || HOST === '::1';
  if (!isLocal && (!AUTH || AUTH.length < 12)) {
    console.error('外部公開(HOST=' + HOST + ')には、12文字以上の BASIC_AUTH ("user:pass") が必須です。起動を中止します。');
    process.exit(1);
  }
  createServer().listen(PORT, HOST, () => {
    console.log(`Proxy: http://${HOST}:${PORT}/`);
    console.log('許可ドメイン:', ALLOW.join(', '));
  });
}
