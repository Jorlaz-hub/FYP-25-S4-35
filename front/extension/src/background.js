/**
 * Client-Side Script Security Inspector - Background Controller
 * Scoring logic and detection features
 * Updates: 
 * 1. Insecure Forms (GET method / external actions)
 * 2. Unsafe Links (Reverse Tabnabbing)
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
  
  // simple 3rd party calculation logics
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
  
  // detect and penalize reverse tabnabbing
  structure -= clamp((info.unsafeLinks || 0) * 2, 0, 10);

  // security score
  var security = 100;

  // 1. Check for CSP presence
  if (noCsp) {
    security -= 15;
  } 
  else {
  // 2. Check for CSP Quality (New Improvement)
  var cspVal = (hdrs['content-security-policy'] || '').toLowerCase();

  // Penalize unsafe-inline (very risky)
  if (cspVal.indexOf("'unsafe-inline'") !== -1) security -= 10;

  // Penalize unsafe-eval (risky)
  if (cspVal.indexOf("'unsafe-eval'") !== -1) security -= 5;

  // Penalize data: URI usage (evades restrictions)
  if (cspVal.indexOf("data:") !== -1) security -= 3;
  }

  if (!hdrs['strict-transport-security']) security -= 8;
  if (!hdrs['x-content-type-options']) security -= 6;
  if (!hdrs['referrer-policy']) security -= 4;
  if (!hdrs['permissions-policy']) security -= 4;
  security -= clamp(noIntegrity * 2, 0, 16);
  security -= clamp(thirdParty * 2, 0, 16);
  security -= clamp(inlineCount * 1.5, 0, 15);
  try {
    if (new URL(info.url).protocol !== 'https:') security -= 10;
  } catch (e) {}



  // for obfuscatedCount
  var obfuscatedCount = info.scripts.filter(function (s) { 
    return s.isObfuscated; 
  }).length;

  if (obfuscatedCount > 0) {
    security -= (obfuscatedCount * 10);
  }


  // exposure score
  var exposure = 100;
  exposure -= clamp(formsWithoutCsrf * 5, 0, 25);
  exposure -= clamp(tokenHits * 4, 0, 20);
  exposure -= clamp(thirdParty * 2, 0, 20);
  exposure -= clamp(inlineCount * 1, 0, 10);
  
  // detect and penalize insecure forms
  // forms using GET (for passwords) or external links present risks of data leakage
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

// set scan data history limit (potentially lower for more lightweight)
var HISTORY_LIMIT = 20;

chrome.runtime.onMessage.addListener(function (message, sender) {
  if (message && message.kind === 'pageScanResult') {
    var key = 'scan:' + message.url;
    var tabId = sender && sender.tab ? sender.tab.id : null;
    var headerCache = tabId != null ? latestHeadersByTab[tabId] : null;
    message.responseHeaders = headerCache ? headerCache.headers : {};

    chrome.storage.local.get(['scanEnabled', key], function (data) {
      if (data.scanEnabled === false) return;
      var list = data[key] || [];
      var entry = { ts: Date.now(), result: message, areas: computeAreaScores(message) };
      list.unshift(entry);
      if (list.length > HISTORY_LIMIT) list = list.slice(0, HISTORY_LIMIT);
      var obj = {}; obj[key] = list;
      chrome.storage.local.set(obj);
    });
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