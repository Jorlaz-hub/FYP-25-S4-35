var ENABLED_KEY = 'scanEnabled';
var HEALTH_COLORS = {
  unsafe: '#ef4444',
  poor: '#f59e0b',
  passed: '#22c55e',
  ready: '#eab308',
  offline: '#94a3b8'
};
var STATE_COLORS = {
  done: '#22c55e',
  ready: '#f59e0b',
  offline: '#94a3b8'
};

var stateSnapshot = { enabled: true, hasResults: false };
var latestEntry = null;
var latestHealth = null;
var latestAreas = null;

function formatRow(label, value) {
  var row = document.createElement('div');
  row.className = 'row';
  var l = document.createElement('strong');
  l.textContent = label;
  var v = document.createElement('span');
  v.textContent = value;
  row.appendChild(l);
  row.appendChild(v);
  return row;
}

function setStatus(message) {
  var el = document.getElementById('status');
  if (el) el.textContent = message || '';
}

function setHealthDisplay(scoreText, severity, caption, angleDeg) {
  var scoreEl = document.getElementById('healthScore');
  var labelEl = document.getElementById('healthLabel');
  var captionEl = document.getElementById('healthCaption');
  var ringEl = document.getElementById('healthRing');
  var color = HEALTH_COLORS[severity] || '#94a3b8';

  if (scoreEl) scoreEl.textContent = scoreText;
  if (captionEl) captionEl.textContent = caption;
  if (labelEl) {
    var labelText = severity === 'passed' ? 'PASSED' : severity === 'poor' ? 'POOR' : severity.toUpperCase();
    labelEl.textContent = labelText;
    labelEl.style.background = color + '1a';
    labelEl.style.color = color;
    labelEl.style.borderColor = color + '33';
  }
  if (ringEl) {
    ringEl.style.setProperty('--health-angle', (angleDeg || 0) + 'deg');
    ringEl.style.setProperty('--health-color', color);
  }
}

function computeHealth(info) {
  var scores = computeAreaScores(info);
  return scores.overall;
}

function updateHealthNoData(state) {
  if (state === 'offline') {
    setHealthDisplay('--', 'offline', 'Scanning disabled', 0);
  } else {
    setHealthDisplay('--', 'ready', 'Refresh or scan to get health', 0);
  }
}

function clamp(n, min, max) {
  return Math.max(min, Math.min(max, n));
}

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

  function sev(val) { return val < 40 ? 'unsafe' : val <= 75 ? 'poor' : 'passed'; }

  var overallScore = Math.round(((structure + security + exposure) / 3) * 100) / 100;
  return {
    structure: { score: Math.round(structure * 100) / 100, severity: sev(structure) },
    security: { score: Math.round(security * 100) / 100, severity: sev(security) },
    exposure: { score: Math.round(exposure * 100) / 100, severity: sev(exposure) },
    overall: { score: overallScore, severity: sev(overallScore) }
  };
}

function updateStateUI() {
  var state = 'ready';
  if (stateSnapshot.enabled === false) state = 'offline';
  else if (stateSnapshot.hasResults) state = 'done';

  if (state === 'done') setStatus('Scan completed for this page.');
  else if (state === 'ready') setStatus('Ready: refresh or navigate to run a scan.');
  else if (state === 'offline') setStatus('Offline: scanning is disabled.');

  var pluginState = document.getElementById('pluginState');
  if (pluginState) {
    pluginState.textContent = state.toUpperCase();
    pluginState.style.color = STATE_COLORS[state] || '#0f172a';
  }

  if (!stateSnapshot.hasResults || state === 'offline') {
    updateHealthNoData(state === 'offline' ? 'offline' : 'ready');
  }
}

function updateToggleUI(enabled) {
  var toggle = document.getElementById('scanToggle');
  var status = document.getElementById('toggleStatus');
  if (toggle) toggle.checked = enabled;
  if (status) status.textContent = enabled ? 'Enabled' : 'Disabled';
  var scanBtn = document.getElementById('scanBtn');
  if (scanBtn) scanBtn.disabled = !enabled;
}

function loadToggle(callback) {
  chrome.storage.local.get([ENABLED_KEY], function (data) {
    var enabled = data[ENABLED_KEY];
    if (enabled === undefined) enabled = true;
    stateSnapshot.enabled = enabled;
    updateToggleUI(enabled);
    updateStateUI();
    if (callback) callback(enabled);
  });
}

function withActiveTab(fn) {
  chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    var tab = tabs && tabs[0];
    if (!tab || !tab.id || !tab.url) {
      setStatus('No active tab to scan.');
      return;
    }
    fn(tab);
  });
}

function render(results) {
  var container = document.getElementById('results');
  if (!container) return;
  container.innerHTML = '';

  stateSnapshot.hasResults = !!(results && results.length);
  updateStateUI();

  if (!results || !results.length) {
    var empty = document.createElement('div');
    empty.className = 'empty';
    empty.textContent = 'No scans yet for this page. Click "Scan now" or reload the page.';
    container.appendChild(empty);
    latestEntry = null;
    latestHealth = null;
    return;
  }

  // Use latest scan (list is unshifted in background)
  latestEntry = results[0];
  var latest = latestEntry.result;
  latestAreas = latestEntry.areas || computeAreaScores(latest);
  latestHealth = latestAreas.overall;
  var angle = (latestHealth.score / 100) * 360;
  var caption = latestHealth.severity === 'passed' ? 'Secure posture' : latestHealth.severity === 'poor' ? 'Issues detected' : 'Unsafe';
  setHealthDisplay(latestHealth.score + '%', latestHealth.severity, caption, angle);

  results.slice(0, 10).forEach(function (r) {
    var w = document.createElement('div');
    w.className = 'card';
    var info = r.result;

    var ts = r.ts ? new Date(r.ts) : null;
    var inlineCount = 0;
    var externalCount = 0;
    var thirdParty = 0;
    try {
      var pageOrigin = new URL(info.url).origin;
      info.scripts.forEach(function (s) {
        if (s.src) {
          externalCount += 1;
          var scriptOrigin = new URL(s.src, info.url).origin;
          if (scriptOrigin !== pageOrigin) thirdParty += 1;
        } else {
          inlineCount += 1;
        }
      });
    } catch (e) { /* ignore url errors */ }

    w.appendChild(formatRow('URL', info.url));
    w.appendChild(formatRow('Scanned', ts ? ts.toLocaleString() : 'Unknown'));
    w.appendChild(formatRow('Scripts', info.scripts.length + ' total'));
    w.appendChild(formatRow('Inline scripts', String(inlineCount)));
    w.appendChild(formatRow('External scripts', externalCount + ' (' + thirdParty + ' third-party)'));
    w.appendChild(formatRow('CSP Meta Tags', String(info.cspMeta.length)));
    container.appendChild(w);
  });
}

function loadResults() {
  withActiveTab(function (tab) {
    var key = 'scan:' + tab.url;
    chrome.storage.local.get([key], function (data) {
      render((data || {})[key] || []);
    });
  });
}

function runScan() {
  chrome.storage.local.get([ENABLED_KEY], function (data) {
    var enabled = data[ENABLED_KEY];
    if (enabled === undefined) enabled = true;
    if (!enabled) {
      setStatus('Enable scanning first.');
      return;
    }
    withActiveTab(function (tab) {
      setStatus('Running scan...');
      chrome.scripting.executeScript(
        { target: { tabId: tab.id }, files: ['src/contentScript.js'] },
        function () {
          if (chrome.runtime.lastError) {
            setStatus('Cannot run on this page: ' + chrome.runtime.lastError.message);
          } else {
            setStatus('Scan triggered. Refresh the popup to see results.');
          }
        }
      );
    });
  });
}

function handleFullReview() {
  if (!latestEntry || !latestEntry.result) {
    setStatus('Run a scan first to view the full review.');
    return;
  }
  var key = 'scan:' + latestEntry.result.url;
  chrome.storage.local.set({ reviewTargetKey: key }, function () {
    chrome.tabs.create({ url: chrome.runtime.getURL('src/review.html') });
  });
}

function handleDownload() {
  if (!latestEntry || !latestEntry.result) {
    setStatus('Run a scan first to download a report.');
    return;
  }
  var payload = {
    url: latestEntry.result.url,
    scannedAt: latestEntry.ts ? new Date(latestEntry.ts).toISOString() : null,
    health: latestHealth,
    areas: latestAreas || (latestEntry.result ? computeAreaScores(latestEntry.result) : null),
    scripts: latestEntry.result.scripts,
    cspMeta: latestEntry.result.cspMeta
  };
  var blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  var blobUrl = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = blobUrl;
  a.download = 'script-inspector-report.json';
  document.body.appendChild(a);
  a.click();
  setTimeout(function () {
    document.body.removeChild(a);
    URL.revokeObjectURL(blobUrl);
  }, 50);
  setStatus('Report downloaded.');
}

document.addEventListener('DOMContentLoaded', function () {
  var toggle = document.getElementById('scanToggle');
  if (toggle) {
    toggle.addEventListener('change', function (e) {
      var enabled = !!e.target.checked;
      var obj = {}; obj[ENABLED_KEY] = enabled;
      chrome.storage.local.set(obj);
      updateToggleUI(enabled);
      stateSnapshot.enabled = enabled;
      updateStateUI();
      setStatus(enabled ? 'Scanning enabled' : 'Scanning disabled');
    });
  }

  var scanBtn = document.getElementById('scanBtn');
  if (scanBtn) {
    scanBtn.addEventListener('click', runScan);
  }

  var fullReviewBtn = document.getElementById('fullReviewBtn');
  if (fullReviewBtn) {
    fullReviewBtn.addEventListener('click', handleFullReview);
  }

  var downloadBtn = document.getElementById('downloadBtn');
  if (downloadBtn) {
    downloadBtn.addEventListener('click', handleDownload);
  }

  loadToggle();
  loadResults();
});
