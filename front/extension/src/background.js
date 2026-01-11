/**
 * Client-Side Script Security Inspector - Background Controller
 * Scoring logic and detection features
 * Updates: 
 * 1. Insecure Forms (GET method / external actions)
 * 2. Unsafe Links (Reverse Tabnabbing)
 * 3. [NEW] Cookie Security Analysis
 */

function clamp(n, min, max) { return Math.max(min, Math.min(max, n)); }
function severity(val) { return val < 40 ? 'unsafe' : val <= 75 ? 'poor' : 'passed'; }

// cache recent response headers per tab
var latestHeadersByTab = {};

function computeAreaScores(info) {
  if (!info || !info.scripts) {
    return {
      structure: { score: 0, severity: 'ready' },
      security: { score: 0, severity: 'ready' },
      exposure: { score: 0, severity: 'ready' },
      overall: { score: 0, severity: 'ready' }
    };
  }

  // --- DATA EXTRACTION ---
  var inlineCount = info.inlineScripts != null ? info.inlineScripts : info.scripts.filter(function (s) { return !s.src; }).length;
  var thirdParty = info.thirdPartyScripts != null ? info.thirdPartyScripts : 0;
  
  if (thirdParty === 0) {
    try {
      var pageOrigin = new URL(info.url).origin;
      info.scripts.forEach(function (s) {
        if (s.src) {
          try {
            var scriptOrigin = new URL(s.src, info.url).origin;
            if (scriptOrigin !== pageOrigin) thirdParty += 1;
          } catch (e) {}
        }
      });
    } catch (e) {}
  }

  var noIntegrity = info.scripts.filter(function (s) { return !!s.src && !s.integrity; }).length;
  var headers = info.responseHeaders || {};
  var hdrs = {};
  Object.keys(headers).forEach(function (k) { hdrs[k.toLowerCase()] = headers[k]; });

  // [NEW] Extract cookies from async lookup
  // If no cookies were found, default to 0 issues
  var cookieIssues = info.cookieIssues || { missingHttpOnly: 0, missingSecure: 0, missingSameSite: 0 };

  var hasCspHeader = !!hdrs['content-security-policy'];
  var noCsp = !hasCspHeader && (info.cspMeta || []).length === 0;
  var inlineEvents = info.inlineEventHandlers || 0;
  var templateMarkers = info.templateMarkers || 0;
  var tokenHits = info.tokenHits || 0;
  var formsWithoutCsrf = info.formsWithoutCsrf || 0;

  // --- SCORING LOGIC MODEL ---

  // structure score
  var structure = 100;
  structure -= clamp(inlineCount * 3, 0, 25);
  structure -= clamp(inlineEvents * 2, 0, 20);
  structure -= clamp(templateMarkers * 3, 0, 15);
  structure -= clamp((info.unsafeLinks || 0) * 2, 0, 10);

  // security score
  var security = 100;

  // 1. CSP Checks
  if (noCsp) {
    security -= 15;
  } else {
    var cspVal = (hdrs['content-security-policy'] || '').toLowerCase();
    if (cspVal.indexOf("'unsafe-inline'") !== -1) security -= 10;
    if (cspVal.indexOf("'unsafe-eval'") !== -1) security -= 5;
    if (cspVal.indexOf("data:") !== -1) security -= 3;
  }

  // 2. Standard Header Checks
  if (!hdrs['strict-transport-security']) security -= 8;
  if (!hdrs['x-content-type-options']) security -= 6;
  if (!hdrs['referrer-policy']) security -= 4;
  if (!hdrs['permissions-policy']) security -= 4;
  
  // 3. Script Integrity & Origin
  security -= clamp(noIntegrity * 2, 0, 16);
  security -= clamp(thirdParty * 2, 0, 16);
  security -= clamp(inlineCount * 1.5, 0, 15);
  
  // 4. HTTPS Check
  try {
    if (new URL(info.url).protocol !== 'https:') security -= 10;
  } catch (e) {}

  // 5. Obfuscation
  var obfuscatedCount = info.scripts.filter(function (s) { return s.isObfuscated; }).length;
  if (obfuscatedCount > 0) {
    security -= (obfuscatedCount * 10);
  }

  // [NEW] Cookie Risk Penalties
  // Deduct points for cookies missing key security attributes
  security -= clamp(cookieIssues.missingHttpOnly * 5, 0, 15); 
  security -= clamp(cookieIssues.missingSecure * 4, 0, 12);
  security -= clamp(cookieIssues.missingSameSite * 2, 0, 8);

  // exposure score
  var exposure = 100;
  exposure -= clamp(formsWithoutCsrf * 5, 0, 25);
  exposure -= clamp(tokenHits * 4, 0, 20);
  exposure -= clamp(thirdParty * 2, 0, 20);
  exposure -= clamp(inlineCount * 1, 0, 10);
  exposure -= clamp((info.insecureForms || 0) * 10, 0, 20);

  // --- CALC FINAL TOTAL ---
  structure = clamp(structure, 0, 100);
  security = clamp(security, 0, 100);
  exposure = clamp(exposure, 0, 100);

  var overallScore = Math.round(((structure + security + exposure) / 3) * 100) / 100;

  return {
    structure: { score: Math.round(structure * 100) / 100, severity: severity(structure) },
    security: { score: Math.round(security * 100) / 100, severity: severity(security) },
    exposure: { score: Math.round(exposure * 100) / 100, severity: severity(exposure) },
    overall: { score: overallScore, severity: severity(overallScore) }
  };
}

// set scan data history limit
var HISTORY_LIMIT = 20;

chrome.runtime.onMessage.addListener(function (message, sender) {
  if (message && message.kind === 'pageScanResult') {
    var key = 'scan:' + message.url;
    var tabId = sender && sender.tab ? sender.tab.id : null;
    var headerCache = tabId != null ? latestHeadersByTab[tabId] : null;
    message.responseHeaders = headerCache ? headerCache.headers : {};

    // [NEW] Cookie Async Fetch & Analysis
    // Inspect old / stored cookies for URL
    chrome.cookies.getAll({ url: message.url }, function(cookies) {
      
      // Default stats
      var cookieStats = {
        total: 0,
        missingHttpOnly: 0,
        missingSecure: 0,
        missingSameSite: 0
      };

      if (cookies && cookies.length > 0) {
        cookieStats.total = cookies.length;
        cookies.forEach(function(c) {
          // Check httpOnly (false means JS can access it -> XSS risk)
          if (!c.httpOnly) cookieStats.missingHttpOnly++;
          
          // Check secure (false means sent over HTTP -> MITM risk)
          if (!c.secure) cookieStats.missingSecure++;
          
          // Check sameSite (undefined or 'no_restriction' -> CSRF risk)
          // Note: 'unspecified' often defaults to Lax in modern browsers, but we flag for explicit safety.
          if (!c.sameSite || c.sameSite === 'no_restriction') cookieStats.missingSameSite++;
        });
      }

      // Attach stats to the message object so computeAreaScores can see them
      message.cookieIssues = cookieStats;

      // PROCEED WITH SAVING
      chrome.storage.local.get(['scanEnabled', key], function (data) {
        if (data.scanEnabled === false) return;
        var list = data[key] || [];
        // Now compute scores (which will now include cookie penalties)
        var entry = { ts: Date.now(), result: message, areas: computeAreaScores(message) };
        list.unshift(entry);
        if (list.length > HISTORY_LIMIT) list = list.slice(0, HISTORY_LIMIT);
        var obj = {}; obj[key] = list;
        chrome.storage.local.set(obj);
      });
    });

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
