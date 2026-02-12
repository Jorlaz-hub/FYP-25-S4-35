/**
 * Client-Side Script Security Inspector - Background Controller
 * Scoring logic and detection features
 * Updates: 
 * 1. Insecure Forms (GET method / external actions)
 * 2. Unsafe Links (Reverse Tabnabbing)
 * 3. [NEW] Cookie Security Analysis
 */

importScripts('sharedAlgo.js');

var CHECKS_KEY = 'checksConfig';
var WHITELIST_KEY = 'whitelistPatterns';

// cache recent response headers per tab
var latestHeadersByTab = {};

// set scan data history limit
var HISTORY_LIMIT = 20;

function normalizePatterns(value) {
  if (!value) return [];
  if (Array.isArray(value)) {
    return value.map(function (v) { return String(v || '').trim(); }).filter(Boolean);
  }
  return String(value)
    .split('\n')
    .map(function (v) { return v.trim(); })
    .filter(Boolean);
}

function hostMatchesPattern(host, pattern) {
  var p = String(pattern || '').toLowerCase();
  var h = String(host || '').toLowerCase();
  if (!p || !h) return false;
  if (p.indexOf('*.') === 0) {
    var base = p.slice(2);
    if (!base) return false;
    return h.endsWith('.' + base);
  }
  return h === p || h.endsWith('.' + p);
}

function isUrlWhitelisted(url, whitelist) {
  var host = '';
  try {
    host = new URL(url).hostname;
  } catch (e) {
    return false;
  }

  var wl = normalizePatterns(whitelist);
  if (!wl.length) return false;
  return wl.some(function (p) { return hostMatchesPattern(host, p); });
}

chrome.runtime.onMessage.addListener(function (message, sender) {
  if (message && message.kind === 'pageScanResult') {
    var key = 'scan:' + message.url;
    var tabId = sender && sender.tab ? sender.tab.id : null;
    var headerCache = tabId != null ? latestHeadersByTab[tabId] : null;
    message.responseHeaders = headerCache ? headerCache.headers : {};

    function saveScanWithCookies(cookieStats) {
      chrome.storage.local.get(['scanEnabled', key, CHECKS_KEY, WHITELIST_KEY], function (data) {
        if (data.scanEnabled === false) return;
        if (isUrlWhitelisted(message.url, data[WHITELIST_KEY])) return;
        var checks = data[CHECKS_KEY] || {};
        var cookieEnabled = typeof checks.cookie === 'boolean' ? checks.cookie : true;
        var safeStats = cookieEnabled ? cookieStats : { missingHttpOnly: 0, missingSecure: 0, missingSameSite: 0 };
        message.cookieIssues = safeStats || { missingHttpOnly: 0, missingSecure: 0, missingSameSite: 0 };
        var list = data[key] || [];
        var entry = { ts: Date.now(), result: message, areas: SharedAlgo.computeAreaScores(message, checks) };
        list.unshift(entry);
        if (list.length > HISTORY_LIMIT) list = list.slice(0, HISTORY_LIMIT);
        var obj = {}; obj[key] = list;
        chrome.storage.local.set(obj);
      });
    }

    // [NEW] Cookie Async Fetch & Analysis
    // Inspect old / stored cookies for URL if the API is available
    if (!chrome.cookies || !chrome.cookies.getAll) {
      saveScanWithCookies({ missingHttpOnly: 0, missingSecure: 0, missingSameSite: 0 });
    } else {
      chrome.cookies.getAll({ url: message.url }, function(cookies) {
        var cookieStats = {
          total: 0,
          missingHttpOnly: 0,
          missingSecure: 0,
          missingSameSite: 0
        };

        if (cookies && cookies.length > 0) {
          cookieStats.total = cookies.length;
          cookies.forEach(function(c) {
            if (!c.httpOnly) cookieStats.missingHttpOnly++;
            if (!c.secure) cookieStats.missingSecure++;
            if (!c.sameSite || c.sameSite === 'no_restriction') cookieStats.missingSameSite++;
          });
        }

        saveScanWithCookies(cookieStats);
      });
    }

    // Return true to indicate we will respond asynchronously (though we aren't sending a response back to content script here)
    return true; 
  }
});

chrome.webRequest.onHeadersReceived.addListener(
  function (details) {
    var wanted = [
      'content-security-policy',
      'strict-transport-security',
      'x-content-type-options',
      'referrer-policy',
      'permissions-policy'
    ];
    var out = {};
    (details.responseHeaders || []).forEach(function (h) {
      var name = (h.name || '').toLowerCase();
      if (wanted.indexOf(name) !== -1) out[name] = h.value || '';
    });
    latestHeadersByTab[details.tabId] = { url: details.url, headers: out, ts: Date.now() };
  },
  { urls: ['<all_urls>'], types: ['main_frame'] },
  ['responseHeaders']
);

chrome.tabs.onRemoved.addListener(function (tabId) {
  if (tabId in latestHeadersByTab) delete latestHeadersByTab[tabId];
});