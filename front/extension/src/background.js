var ICON_DATA_URL = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR4nGNgYAAAAAMAASsJTYQAAAAASUVORK5CYII=';

function clamp(n, min, max) { return Math.max(min, Math.min(max, n)); }
function severity(val) { return val < 40 ? 'unsafe' : val <= 75 ? 'poor' : 'passed'; }

function computeAreaScores(info) {
  if (!info || !info.scripts) {
    return {
      structure: { score: 0, severity: 'ready' },
      security: { score: 0, severity: 'ready' },
      exposure: { score: 0, severity: 'ready' },
      overall: { score: 0, severity: 'ready' }
    };
  }

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
  var noCsp = (info.cspMeta || []).length === 0;
  var inlineEvents = info.inlineEventHandlers || 0;
  var templateMarkers = info.templateMarkers || 0;
  var tokenHits = info.tokenHits || 0;
  var formsWithoutCsrf = info.formsWithoutCsrf || 0;

  var structure = 100;
  structure -= clamp(inlineCount * 3, 0, 25);
  structure -= clamp(inlineEvents * 2, 0, 20);
  structure -= clamp(templateMarkers * 3, 0, 15);

  var security = 100;
  if (noCsp) security -= 15;
  security -= clamp(noIntegrity * 2, 0, 16);
  security -= clamp(thirdParty * 2, 0, 16);
  security -= clamp(inlineCount * 1.5, 0, 15);
  try {
    if (new URL(info.url).protocol !== 'https:') security -= 10;
  } catch (e) {}

  var exposure = 100;
  exposure -= clamp(formsWithoutCsrf * 5, 0, 25);
  exposure -= clamp(tokenHits * 4, 0, 20);
  exposure -= clamp(thirdParty * 2, 0, 20);
  exposure -= clamp(inlineCount * 1, 0, 10);

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

function estimateIssues(info) {
  var issues = 0;
  if (!info) return 0;
  if ((info.cspMeta || []).length === 0) issues++;
  if ((info.inlineScripts || 0) > 0) issues++;
  if ((info.thirdPartyScripts || 0) > 3) issues++;
  var noIntegrity = info.scripts ? info.scripts.filter(function (s) { return !!s.src && !s.integrity; }).length : 0;
  if (noIntegrity > 5) issues++;
  if ((info.inlineEventHandlers || 0) > 0) issues++;
  if ((info.templateMarkers || 0) > 0) issues++;
  if ((info.tokenHits || 0) > 0) issues++;
  if ((info.formsWithoutCsrf || 0) > 0) issues++;
  return issues;
}

function notifyScan(url, overallScore, overallSeverity, info) {
  var issues = estimateIssues(info);
  var title = 'Script Inspector: ' + overallSeverity.toUpperCase() + ' (' + overallScore + '%)';
  var message = (issues > 0 ? (issues + ' issue(s) detected.') : 'No major issues detected.') + ' Open the popup for details.';
  chrome.notifications.create({
    type: 'basic',
    iconUrl: ICON_DATA_URL,
    title: title,
    message: message,
    contextMessage: url
  });
}

chrome.runtime.onMessage.addListener(function (message, sender) {
  if (message && message.kind === 'pageScanResult') {
    var key = 'scan:' + message.url;
    chrome.storage.local.get(['scanEnabled', key], function (data) {
      if (data.scanEnabled === false) return;
      var list = data[key] || [];
      var entry = { ts: Date.now(), result: message };
      list.unshift(entry);
      var obj = {}; obj[key] = list;
      chrome.storage.local.set(obj);

      var areas = computeAreaScores(message);
      notifyScan(message.url, areas.overall.score, areas.overall.severity, message);
    });
  }
});

chrome.action.onClicked.addListener(function (tab) {
  if (!tab.id) return;
  chrome.scripting.executeScript({
    target: { tabId: tab.id },
    files: ['src/contentScript.js']
  });
});
