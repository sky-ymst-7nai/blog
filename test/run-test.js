'use strict';
// 実サイトに繋がず、ローカルの模擬ログインサイトでプロキシの動作を検証する
process.env.ALLOW_HOSTS = '127.0.0.1';
const http = require('http');
const zlib = require('zlib');
const assert = require('assert');
const crypto = require('crypto');
const { spawn } = require('child_process');
const { createServer } = require('../server');

const cookies = (h) => Object.fromEntries((h || '').split('; ').filter(Boolean).map((s) => [s.slice(0, s.indexOf('=')), s.slice(s.indexOf('=') + 1)]));

const mock = http.createServer((req, res) => {
  const ck = cookies(req.headers.cookie);
  const me = `http://127.0.0.1:${mock.address().port}`;
  if (req.url === '/login') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'content-security-policy': "default-src 'none'" });
    return res.end(`<!doctype html><html><head><title>t</title><link rel="stylesheet" href="/a.css"></head><body>
      <form method="post" action="/session"><input name="user"><input name="pass"></form>
      <a href="${me}/mypage">m</a><img srcset="/x.png 1x, /y.png 2x"><!-- ${"x".repeat(2000)} --></body></html>`);
  }
  if (req.url === '/a.css') { res.writeHead(200, { 'content-type': 'text/css' }); return res.end('body{background:url(/bg.png)}'); }
  if (req.url === '/session' && req.method === 'POST') {
    let b = '';
    req.on('data', (c) => (b += c));
    return req.on('end', () => {
      // 本物のサイトのCSRFチェックを想定: Origin/Referer が自分自身であること
      if (req.headers.origin !== me || !String(req.headers.referer).startsWith(me + '/')) { res.writeHead(403); return res.end('csrf'); }
      if (b !== 'user=taro&pass=pw') { res.writeHead(401); return res.end('ng'); }
      res.writeHead(302, { location: '/mypage', 'set-cookie': ['sid=abc123; Path=/; HttpOnly', 'lang=ja; Path=/; Max-Age=3600'] });
      res.end();
    });
  }
  if (req.url === '/mypage') {
    if (ck.sid !== 'abc123') { res.writeHead(302, { location: '/login' }); return res.end(); }
    return (res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }), res.end(`ようこそ taro (lang=${ck.lang})`));
  }
  if (req.url === '/rp') {
    res.writeHead(200, { 'content-type': 'text/html', 'referrer-policy': 'no-referrer' });
    return res.end('<html><head><meta name="referrer" content="no-referrer"></head><body><a rel="noreferrer noopener" referrerpolicy="no-referrer" href="/x">x</a></body></html>');
  }
  if (req.url === '/sf') {
    res.writeHead(200, { 'content-type': 'application/json' });
    return res.end(JSON.stringify({ site: req.headers['sec-fetch-site'], mode: req.headers['sec-fetch-mode'], dest: req.headers['sec-fetch-dest'] }));
  }
  if (req.url === '/gz') {
    res.writeHead(200, { 'content-type': 'text/html', 'content-encoding': 'gzip' });
    return res.end(zlib.gzipSync('<html><head></head><body><a href="/gz2">gz</a></body></html>'));
  }
  res.writeHead(404); res.end();
});

let seenWs = null;
mock.on('upgrade', (req, socket) => {
  const acc = crypto.createHash('sha1').update(req.headers['sec-websocket-key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
  seenWs = { cookie: req.headers.cookie, host: req.headers.host, origin: req.headers.origin };
  socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + acc + '\r\n\r\n');
  socket.write(Buffer.from([0x81, 5, 104, 101, 108, 108, 111])); // テキストフレーム "hello"
});

const request = (method, url, headers = {}, body) =>
  new Promise((resolve, reject) => {
    const r = http.request(url, { method, headers }, (res) => {
      const ch = [];
      res.on('data', (c) => ch.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(ch).toString(), raw: Buffer.concat(ch) }));
    });
    r.on('error', reject);
    r.end(body);
  });

(async () => {
  await new Promise((r) => mock.listen(0, '127.0.0.1', r));
  const proxy = createServer();
  await new Promise((r) => proxy.listen(0, '127.0.0.1', r));
  const P = `http://127.0.0.1:${proxy.address().port}`;
  const M = `127.0.0.1:${mock.address().port}`;
  const T = `/~/http/${M}`;
  let n = 0;
  const ok = (name) => console.log(`ok ${++n} - ${name}`);

  // 1. ログインページ取得: URL書き換え・スクリプト注入・CSP除去・セッションCookie発行
  let r = await request('GET', `${P}${T}/login`);
  assert.strictEqual(r.status, 200);
  assert(r.body.includes(`action="${T}/session"`), 'form action');
  assert(r.body.includes(`href="${T}/mypage"`), '絶対URLの書き換え');
  assert(r.body.includes(`${T}/x.png 1x, ${T}/y.png 2x`), 'srcset');
  assert(r.body.includes('/__px/client.js'), 'スクリプト注入');
  assert(!r.headers['content-security-policy'], 'CSP除去');
  const sid = /px_sid=([a-f0-9]{32})/.exec(r.headers['set-cookie'][0])[1];
  ok('HTML書き換え / 注入 / CSP除去 / セッション発行');

  // 2. CSS内url()の書き換え
  r = await request('GET', `${P}${T}/a.css`, { cookie: `px_sid=${sid}` });
  assert(r.body.includes(`url(${T}/bg.png)`));
  ok('CSS url() 書き換え');

  // 3. ログインPOST（Origin/Referer の復元が必要）→ リダイレクト書き換え、Cookieはブラウザに渡さない
  const h = { cookie: `px_sid=${sid}`, 'content-type': 'application/x-www-form-urlencoded', origin: P, referer: `${P}${T}/login` };
  r = await request('POST', `${P}${T}/session`, h, 'user=taro&pass=pw');
  assert.strictEqual(r.status, 302);
  assert.strictEqual(r.headers.location, `${T}/mypage`);
  assert(!(r.headers['set-cookie'] || []).some((c) => c.startsWith('sid=')), 'sidがクライアントに漏れていない');
  ok('ログインPOST / Origin・Referer復元 / Location書き換え');

  // 4. ログイン状態の維持（Jar経由でCookie送信）
  r = await request('GET', `${P}${T}/mypage`, { cookie: `px_sid=${sid}` });
  assert(r.body.includes('ようこそ taro (lang=ja)'));
  ok('ログイン後ページの表示（HttpOnly含むCookie維持）');

  // 5. 別セッションにはログイン状態が見えない
  r = await request('GET', `${P}${T}/mypage`);
  assert.strictEqual(r.status, 302);
  assert.strictEqual(r.headers.location, `${T}/login`);
  ok('セッション分離');

  // 6. Referer 起点のフォールバック（/login のようなプロキシ外パス）
  r = await request('GET', `${P}/login`, { cookie: `px_sid=${sid}`, referer: `${P}${T}/mypage` });
  assert.strictEqual(r.status, 307);
  assert.strictEqual(r.headers.location, `${T}/login`);
  ok('ルート相対パスのフォールバック');

  // 7. gzip 本文の展開→書き換え
  r = await request('GET', `${P}${T}/gz`, { cookie: `px_sid=${sid}` });
  assert(r.body.includes(`href="${T}/gz2"`) && !r.headers['content-encoding']);
  ok('gzip展開 / 書き換え');

  // 8. 許可リスト外のブロック
  r = await request('GET', `${P}/~/https/example.org/`, { cookie: `px_sid=${sid}` });
  assert.strictEqual(r.status, 403);
  ok('許可リスト外は403');

  // 9. Referer を潰す指定の無効化
  r = await request('GET', `${P}${T}/rp`, { cookie: `px_sid=${sid}` });
  assert.strictEqual(r.headers['referrer-policy'], 'same-origin');
  assert(!/noreferrer|referrerpolicy|name="referrer"/i.test(r.body) && r.body.includes('noopener'));
  ok('Referrer-Policy 上書き / noreferrer 除去');

  // 10. 圧縮して返す（gzip）
  r = await request('GET', `${P}${T}/login`, { cookie: `px_sid=${sid}`, 'accept-encoding': 'gzip' });
  assert.strictEqual(r.headers['content-encoding'], 'gzip');
  assert(zlib.gunzipSync(r.raw).toString().includes(`action="${T}/session"`));
  ok('変換後HTMLのgzip圧縮');

  // 11. Sec-Fetch-* を本来のサイトとの関係に作り直す
  r = await request('GET', `${P}${T}/sf`, { cookie: `px_sid=${sid}`, 'sec-fetch-dest': 'empty', 'sec-fetch-mode': 'cors', referer: `${P}${T}/login` });
  assert.deepStrictEqual(JSON.parse(r.body), { site: 'same-origin', mode: 'cors', dest: 'empty' });
  r = await request('GET', `${P}${T}/sf`, { cookie: `px_sid=${sid}`, 'sec-fetch-dest': 'document', 'sec-fetch-mode': 'navigate' });
  assert.strictEqual(JSON.parse(r.body).site, 'none');
  ok('Sec-Fetch-Site の再計算');

  // 12. WebSocket 中継（ハンドシェイク / Cookie付与 / Origin復元 / 双方向バイト列）
  const key = crypto.randomBytes(16).toString('base64');
  const frame = await new Promise((resolve, reject) => {
    const wr = http.request(`${P}${T}/ws`, { headers: { Connection: 'Upgrade', Upgrade: 'websocket', 'Sec-WebSocket-Version': '13', 'Sec-WebSocket-Key': key, cookie: `px_sid=${sid}` } });
    wr.on('upgrade', (res, socket, head) => {
      const expect = crypto.createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
      assert.strictEqual(res.statusCode, 101);
      assert.strictEqual(res.headers['sec-websocket-accept'], expect);
      let buf = head;
      const check = () => { if (buf.length >= 7) { socket.destroy(); resolve(buf); } };
      socket.on('data', (d) => { buf = Buffer.concat([buf, d]); check(); });
      check();
    });
    wr.on('error', reject);
    wr.end();
  });
  assert.strictEqual(frame.subarray(2, 7).toString(), 'hello');
  assert(seenWs.cookie.includes('sid=abc123') && seenWs.host === M && seenWs.origin === `http://${M}`);
  ok('WebSocket中継');
  r = await request('GET', `${P}${T}/ws`, { Connection: 'Upgrade', Upgrade: 'websocket' }); // セッションCookieなしのWS接続は拒否
  assert.strictEqual(r.status, 403);

  // 13. Basic認証 + 失敗回数ロック（別プロセスで起動）
  const port = 39500 + Math.floor(Math.random() * 400);
  const child = spawn(process.execPath, [require('path').join(__dirname, '..', 'server.js')], { env: { ...process.env, PORT: String(port), BASIC_AUTH: 'me:longpassword123', LOG: '0' } });
  await new Promise((res) => child.stdout.on('data', function f(d) { if (String(d).includes('Proxy:')) { child.stdout.off('data', f); res(); } }));
  const A = `http://127.0.0.1:${port}/`;
  const good = { authorization: 'Basic ' + Buffer.from('me:longpassword123').toString('base64') };
  const bad = { authorization: 'Basic ' + Buffer.from('me:wrong').toString('base64') };
  assert.strictEqual((await request('GET', A)).status, 401);
  assert.strictEqual((await request('GET', A, good)).status, 200);
  assert.strictEqual((await request('GET', `${A}healthz`)).status, 200);
  for (let i = 0; i < 10; i++) assert.strictEqual((await request('GET', A, bad)).status, 401);
  assert.strictEqual((await request('GET', A, good)).status, 429);
  child.kill();
  ok('Basic認証 / 10回失敗でロック / healthz は認証不要');

  proxy.close(); mock.close();
  console.log(`\n全${n}件 成功`);
  process.exit(0); // keep-alive接続が残ってもテストを確実に終了させる
})().catch((e) => { console.error('FAIL:', e); process.exit(1); });
