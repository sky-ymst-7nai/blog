/* プロキシ経由のページに注入される補正スクリプト。
 * ページ内JSが行う通信・遷移・Cookie操作を、プロキシ経由になるよう書き換える。 */
(function () {
  'use strict';
  var CFG = window.__PX_CFG;
  if (!CFG || window.__PX_LOADED) return;
  window.__PX_LOADED = true;

  var REAL = CFG.url; // 本来のページURL
  var BASE = CFG.base || REAL; // 相対URLの解決基準（<base>があればそれ）
  var ORIGIN = location.origin; // プロキシ自身のorigin

  function toProxy(u, base) {
    if (u === null || u === undefined) return u;
    if (u instanceof URL) u = u.href;
    u = String(u).trim();
    if (u === '' || u.charAt(0) === '#' || /^(javascript|data|blob|about|mailto|tel|sms):/i.test(u)) return u;
    if (u.indexOf('/~/') === 0 || u.indexOf('/__px/') === 0) return u; // 変換済み
    var a;
    try { a = new URL(u, base || BASE); } catch (e) { return u; }
    if (a.protocol !== 'http:' && a.protocol !== 'https:') return u;
    if (a.origin === ORIGIN) {
      if (a.pathname.indexOf('/~/') === 0 || a.pathname.indexOf('/__px/') === 0) return a.pathname + a.search + a.hash;
      // プロキシのorigin宛て(例: location.origin + '/api')は本来のサイト宛てとみなす
      a = new URL(a.pathname + a.search + a.hash, REAL);
    }
    return '/~/' + a.protocol.slice(0, -1) + '/' + a.host + a.pathname + a.search + a.hash;
  }
  window.__px_toProxy = toProxy;

  // fetch
  var _fetch = window.fetch;
  if (_fetch) {
    window.fetch = function (input, init) {
      try {
        if (typeof input === 'string' || input instanceof URL) input = toProxy(input);
        else if (input && input.url) {
          var p = toProxy(input.url);
          if (new URL(p, ORIGIN).href !== input.url) input = new Request(p, input);
        }
      } catch (e) { /* そのまま */ }
      return _fetch.call(this, input, init);
    };
  }

  // XMLHttpRequest
  var _open = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (m, u) {
    var args = Array.prototype.slice.call(arguments);
    args[1] = toProxy(u);
    return _open.apply(this, args);
  };

  // sendBeacon / window.open / history
  if (navigator.sendBeacon) {
    var _beacon = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = function (u, d) { return _beacon(toProxy(u), d); };
  }
  var _wopen = window.open;
  window.open = function (u) {
    var args = Array.prototype.slice.call(arguments);
    if (u) args[0] = toProxy(u);
    return _wopen.apply(window, args);
  };
  ['pushState', 'replaceState'].forEach(function (n) {
    var o = history[n];
    history[n] = function (s, t, u) { return o.call(this, s, t, u === undefined || u === null ? u : toProxy(u)); };
  });

  // 要素のプロパティ(src/href/action)代入をプロキシURLにする
  [
    ['HTMLAnchorElement', 'href'], ['HTMLAreaElement', 'href'], ['HTMLLinkElement', 'href'],
    ['HTMLScriptElement', 'src'], ['HTMLImageElement', 'src'], ['HTMLIFrameElement', 'src'],
    ['HTMLSourceElement', 'src'], ['HTMLMediaElement', 'src'], ['HTMLEmbedElement', 'src'],
    ['HTMLInputElement', 'src'], ['HTMLTrackElement', 'src'], ['HTMLFormElement', 'action'],
    ['HTMLObjectElement', 'data']
  ].forEach(function (p) {
    var C = window[p[0]];
    if (!C) return;
    var d = Object.getOwnPropertyDescriptor(C.prototype, p[1]);
    if (!d || !d.set || !d.configurable) return;
    Object.defineProperty(C.prototype, p[1], {
      get: d.get,
      set: function (v) { d.set.call(this, toProxy(v)); },
      enumerable: d.enumerable,
      configurable: true
    });
  });
  var _setAttr = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function (n, v) {
    var l = String(n).toLowerCase();
    if (l === 'href' || l === 'src' || l === 'action' || l === 'formaction' || l === 'poster') v = toProxy(v);
    return _setAttr.call(this, n, v);
  };

  // 動的に作られたリンク/フォームも、クリック・送信の直前に補正する
  document.addEventListener('click', function (e) {
    var a = e.target && e.target.closest && e.target.closest('a[href],area[href]');
    if (!a) return;
    var raw = a.getAttribute('href');
    var p = toProxy(raw);
    if (p !== raw) _setAttr.call(a, 'href', p);
  }, true);
  document.addEventListener('submit', function (e) {
    var f = e.target;
    if (!f || !f.getAttribute) return;
    var raw = f.getAttribute('action');
    if (raw === null) return;
    var p = toProxy(raw);
    if (p !== raw) _setAttr.call(f, 'action', p);
  }, true);

  // document.cookie: 実体はサーバー側のJar。HttpOnly以外を手元に写し、書き込みはサーバーへ送る
  try {
    var store = {};
    (CFG.cookie || '').split('; ').forEach(function (kv) {
      var i = kv.indexOf('=');
      if (i > 0) store[kv.slice(0, i)] = kv.slice(i + 1);
    });
    Object.defineProperty(Document.prototype, 'cookie', {
      configurable: true,
      get: function () { return Object.keys(store).map(function (k) { return k + '=' + store[k]; }).join('; '); },
      set: function (s) {
        s = String(s);
        var first = s.split(';')[0];
        var i = first.indexOf('=');
        if (i > 0) {
          var name = first.slice(0, i).trim();
          var ma = /;\s*max-age\s*=\s*(-?\d+)/i.exec(s);
          var ex = /;\s*expires\s*=\s*([^;]+)/i.exec(s);
          if ((ma && Number(ma[1]) <= 0) || (ex && Date.parse(ex[1]) < Date.now())) delete store[name];
          else store[name] = first.slice(i + 1).trim();
        }
        _fetch('/__px/cookie', {
          method: 'POST', headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ url: REAL, cookie: s }), keepalive: true, credentials: 'same-origin'
        });
      }
    });
  } catch (e) { /* 無視 */ }

  // WebSocket: wss://サイト/path → wss://プロキシ/~/https/サイト/path
  var _WS = window.WebSocket;
  if (_WS) {
    var wsUrl = function (url) {
      var a = new URL(String(url), BASE), path;
      if (a.host === location.host) {
        path = a.pathname + a.search;
        if (path.indexOf('/~/') !== 0) path = toProxy(path);
      } else {
        path = toProxy(a.href.replace(/^wss:/, 'https:').replace(/^ws:/, 'http:'));
      }
      return (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + path;
    };
    window.WebSocket = function (url, protocols) {
      var u; try { u = wsUrl(url); } catch (e) { u = url; }
      return protocols === undefined ? new _WS(u) : new _WS(u, protocols);
    };
    window.WebSocket.prototype = _WS.prototype;
    ['CONNECTING', 'OPEN', 'CLOSING', 'CLOSED'].forEach(function (k) { window.WebSocket[k] = _WS[k]; });
  }

  // Service Worker は登録させない（スコープがプロキシ全体に及ぶため）
  try {
    if (navigator.serviceWorker) navigator.serviceWorker.register = function () { return Promise.reject(new Error('blocked by proxy')); };
  } catch (e) { /* 無視 */ }

  // location.href = "https://外部サイト/" のような遷移の検出（Chromium系の Navigation API。ベストエフォート）
  if (window.navigation && window.navigation.addEventListener) {
    window.navigation.addEventListener('navigate', function (e) {
      try {
        if (!e.cancelable || e.hashChange || e.downloadRequest || e.formData || e.destination.sameDocument) return;
        var d = new URL(e.destination.url);
        if (d.origin === ORIGIN) return;
        e.preventDefault();
        location.assign(toProxy(d.href));
      } catch (x) { /* 無視 */ }
    });
  }
})();
