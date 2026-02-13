var ENABLED_KEY = 'scanEnabled';
var CHECKS_KEY = 'checksConfig';
var WHITELIST_KEY = 'whitelistPatterns';
var ALERTS_ENABLED_KEY = 'alertsEnabled';
var DEFAULT_CHECKS = SharedAlgo.DEFAULT_CHECKS;
var normalizeChecks = SharedAlgo.normalizeChecks;
var computeAreaScores = SharedAlgo.computeAreaScores;
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
var historyVisible = false;
var historyDataCache = null;
var lastCriticalAlertKey = '';
var alertsEnabled = true;
var pendingConfirmAction = null;

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

function showPopupAlert(message) {
  var box = document.getElementById('popupAlert');
  var text = document.getElementById('popupAlertText');
  if (!box || !text) return;
  text.textContent = message || '';
  box.style.display = '';
}

function hidePopupAlert() {
  var box = document.getElementById('popupAlert');
  if (!box) return;
  box.style.display = 'none';
}

function showPopupConfirm(message, onConfirm) {
  var box = document.getElementById('popupConfirm');
  var text = document.getElementById('popupConfirmText');
  if (!box || !text) return;
  text.textContent = message || '';
  pendingConfirmAction = typeof onConfirm === 'function' ? onConfirm : null;
  box.style.display = '';
}

function hidePopupConfirm() {
  var box = document.getElementById('popupConfirm');
  if (!box) return;
  box.style.display = 'none';
  pendingConfirmAction = null;
}

function updateAlertsToggleUI(enabled) {
  var toggle = document.getElementById('alertsToggle');
  if (toggle) toggle.checked = !!enabled;
}

function getCriticalAlertInfo(info, health, checks) {
  if (!info) return null;
  var cfg = checks || normalizeChecks(null);

  if (cfg.https) {
    try {
      if (new URL(info.url).protocol !== 'https:') {
        return {
          code: 'https',
          message: 'Critical: This page is not using HTTPS. Data can be intercepted. Avoid entering sensitive information.'
        };
      }
    } catch (e) {}
  }

  if (cfg.insecureForms && (info.insecureForms || 0) > 0) {
    return {
      code: 'insecureForms',
      message: 'Critical: Insecure form detected (password via GET or external form action). Submitted data may be exposed.'
    };
  }

  if (cfg.csrf && (info.formsWithoutCsrfUnsafe || 0) > 0) {
    return {
      code: 'csrf',
      message: 'Critical: POST form without CSRF protection detected. Requests may be forged by another site.'
    };
  }

  if (cfg.tokenHits && (info.tokenHitsUnsafe || 0) > 0) {
    return {
      code: 'tokenHits',
      message: 'Critical: Possible hardcoded API key/token found in inline script. Secrets may be exposed to attackers.'
    };
  }

  if (health && typeof health.score === 'number' && health.score <= 40) {
    return {
      code: 'health40',
      message: 'Critical: Page security health is 40% or below. Immediate review is recommended.'
    };
  }

  return null;
}

function maybeShowCriticalAlert(entry, health, checks) {
  if (!alertsEnabled) return;
  if (!entry || !entry.result) return;
  var alertInfo = getCriticalAlertInfo(entry.result, health, checks);
  if (!alertInfo) return;

  var key = String(entry.result.url || '') + '|' + String(entry.ts || '') + '|' + alertInfo.code;
  if (key === lastCriticalAlertKey) return;
  lastCriticalAlertKey = key;
  showPopupAlert(alertInfo.message);
}

var checksConfig = normalizeChecks(null);

function saveChecks(next, callback) {
  var obj = {}; obj[CHECKS_KEY] = next;
  chrome.storage.local.set(obj, function () {
    if (callback) callback();
  });
}

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

function getHostFromUrl(url) {
  try {
    var parsed = new URL(url);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return '';
    return parsed.hostname || '';
  } catch (e) {
    return '';
  }
}

function evaluateAccess(url, whitelist) {
  var host = '';
  try {
    host = new URL(url).hostname;
  } catch (e) {
    return { blocked: true, reason: 'Invalid URL.' };
  }

  var wl = normalizePatterns(whitelist);
  var whitelisted = wl.some(function (p) { return hostMatchesPattern(host, p); });
  return { blocked: false, whitelisted: whitelisted };
}

function setPluginState(label, color) {
  var pluginState = document.getElementById('pluginState');
  if (!pluginState) return;
  pluginState.textContent = label;
  if (color) pluginState.style.color = color;
}

function renderWhitelisted(url) {
  var container = document.getElementById('results');
  if (container) {
    container.innerHTML = '';
    var card = document.createElement('div');
    card.className = 'card';
    var row = document.createElement('div');
    row.className = 'row';
    var label = document.createElement('strong');
    label.textContent = 'Whitelist';
    var value = document.createElement('span');
    value.textContent = url;
    row.appendChild(label);
    row.appendChild(value);
    card.appendChild(row);
    container.appendChild(card);
  }
  setHealthDisplay('100%', 'passed', 'Whitelisted', 360);
  setPreviousHealthRing(null);
  setPluginState('WHITELISTED', '#16a34a');
  setStatus('Whitelisted: scan skipped.');
  var scanBtn = document.getElementById('scanBtn');
  if (scanBtn) scanBtn.disabled = true;
}

function renderUnavailable(message) {
  var container = document.getElementById('results');
  if (container) {
    container.innerHTML = '';
    var empty = document.createElement('div');
    empty.className = 'empty';
    empty.textContent = message || 'Unable to access this page.';
    container.appendChild(empty);
  }
  setStatus(message || 'Unable to access this page.');
}

function renderList(container, items) {
  if (!container) return;
  container.innerHTML = '';
  if (!items.length) {
    var empty = document.createElement('div');
    empty.className = 'whitelist-row';
    empty.textContent = 'No entries yet.';
    container.appendChild(empty);
    return;
  }

  items.forEach(function (item) {
    var row = document.createElement('div');
    row.className = 'whitelist-row';
    var label = document.createElement('span');
    label.textContent = item;
    var remove = document.createElement('button');
    remove.type = 'button';
    remove.className = 'whitelist-action';
    remove.textContent = 'Delete';
    remove.addEventListener('click', function () {
      removePattern(item);
    });
    row.appendChild(label);
    row.appendChild(remove);
    container.appendChild(row);
  });
}

function loadAllowlists() {
  var whitelistList = document.getElementById('whitelistList');
  chrome.storage.local.get([WHITELIST_KEY], function (data) {
    var wl = normalizePatterns(data[WHITELIST_KEY]);
    renderList(whitelistList, wl);
  });
}

function addPattern(inputEl) {
  if (!inputEl) return;
  var value = String(inputEl.value || '').trim();
  if (!value) {
    withActiveTab(function (tab) {
      var host = getHostFromUrl(tab.url);
      if (!host) {
        setStatus('Unable to whitelist this page.');
        return;
      }
      addPatternValue(host, inputEl);
    });
    return;
  }
  addPatternValue(value, inputEl);
}

function addPatternValue(value, inputEl) {
  var trimmed = String(value || '').trim();
  if (!trimmed) return;
  chrome.storage.local.get([WHITELIST_KEY], function (data) {
    var items = normalizePatterns(data[WHITELIST_KEY]);
    if (items.indexOf(trimmed) === -1) items.push(trimmed);
    var obj = {}; obj[WHITELIST_KEY] = items;
    chrome.storage.local.set(obj, function () {
      if (inputEl) inputEl.value = '';
      loadAllowlists();
      setStatus('Whitelist updated.');
    });
  });
}

function removePattern(value) {
  chrome.storage.local.get([WHITELIST_KEY], function (data) {
    var items = normalizePatterns(data[WHITELIST_KEY]).filter(function (item) {
      return item !== value;
    });
    var obj = {}; obj[WHITELIST_KEY] = items;
    chrome.storage.local.set(obj, function () {
      loadAllowlists();
      setStatus('List updated.');
    });
  });
}

function updateMasterToggle(checks) {
  var master = document.getElementById('checksAll');
  if (!master) return;
  var values = Object.keys(DEFAULT_CHECKS).map(function (key) { return checks[key]; });
  var allOn = values.every(function (v) { return v; });
  var allOff = values.every(function (v) { return !v; });
  master.checked = allOn;
  master.indeterminate = !allOn && !allOff;
}

function applyChecksToUI(checks) {
  var inputs = document.querySelectorAll('[data-check]');
  inputs.forEach(function (input) {
    var key = input.getAttribute('data-check');
    if (!key) return;
    input.checked = !!checks[key];
  });
  updateMasterToggle(checks);
}

function bindCheckToggles() {
  var master = document.getElementById('checksAll');
  if (master) {
    master.addEventListener('change', function (e) {
      var enabled = !!e.target.checked;
      var next = {};
      Object.keys(DEFAULT_CHECKS).forEach(function (key) {
        next[key] = enabled;
      });
      checksConfig = next;
      applyChecksToUI(checksConfig);
      saveChecks(checksConfig, function () {
        setStatus(enabled ? 'All checks enabled.' : 'All checks disabled.');
        loadResults();
      });
    });
  }

  var inputs = document.querySelectorAll('[data-check]');
  inputs.forEach(function (input) {
    input.addEventListener('change', function () {
      var key = input.getAttribute('data-check');
      var next = normalizeChecks(checksConfig);
      next[key] = !!input.checked;
      checksConfig = next;
      updateMasterToggle(checksConfig);
      saveChecks(checksConfig, function () {
        setStatus('Checks updated.');
        loadResults();
      });
    });
  });
}

function showView(viewName) {
  var views = {
    main: document.getElementById('mainView'),
    settings: document.getElementById('settingsView')
  };
  var headerActions = document.getElementById('headerActions');
  Object.keys(views).forEach(function (key) {
    if (!views[key]) return;
    views[key].classList.toggle('is-active', key === viewName);
  });
  if (headerActions) {
    headerActions.style.display = viewName === 'settings' ? 'none' : '';
  }
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

function setPreviousHealthRing(score, severity, caption, angleDeg) {
  const card = document.getElementById('previousHealthCard');
  const ring = document.getElementById('healthRingBefore');
  const scoreEl = document.getElementById('healthScoreBefore');
  const captionEl = document.getElementById('healthCaptionBefore');
  const labelEl = document.getElementById('healthLabelBefore');
  const color = HEALTH_COLORS[severity] || '#94a3b8';

  if (!card || !ring || !scoreEl || !captionEl || !labelEl) return;

  if (score === null) {
    card.style.display = 'none';
    return;
  }

  card.style.display = 'block';

  scoreEl.textContent = score + '%';
  captionEl.textContent = caption;
  labelEl.textContent = severity === 'passed' ? 'PASSED' : severity === 'poor' ? 'POOR' : severity.toUpperCase();
  labelEl.style.background = color + '1a';
  labelEl.style.color = color;
  labelEl.style.borderColor = color + '33';

  ring.style.setProperty('--health-angle', (angleDeg || 0) + 'deg');
  ring.style.setProperty('--health-color', color);
}

function computeHealth(info) {
  var scores = computeAreaScores(info, checksConfig);
  return scores.overall;
}

function updateHealthNoData(state) {
  if (state === 'offline') {
    setHealthDisplay('--', 'offline', 'Scanning disabled', 0);
  } else {
    setHealthDisplay('--', 'ready', 'Refresh or scan to get health', 0);
  }
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
  var settingsToggle = document.getElementById('settingsScanToggle');
  if (toggle) toggle.checked = enabled;
  if (settingsToggle) settingsToggle.checked = enabled;
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

function loadChecks(callback) {
  chrome.storage.local.get([CHECKS_KEY], function (data) {
    checksConfig = normalizeChecks(data[CHECKS_KEY]);
    applyChecksToUI(checksConfig);
    if (!data[CHECKS_KEY]) {
      saveChecks(checksConfig);
    }
    if (callback) callback(checksConfig);
  });
}

function loadAlertsSetting(callback) {
  chrome.storage.local.get([ALERTS_ENABLED_KEY], function (data) {
    var enabled = data[ALERTS_ENABLED_KEY];
    if (enabled === undefined) enabled = true;
    alertsEnabled = !!enabled;
    updateAlertsToggleUI(alertsEnabled);
    if (data[ALERTS_ENABLED_KEY] === undefined) {
      var obj = {}; obj[ALERTS_ENABLED_KEY] = alertsEnabled;
      chrome.storage.local.set(obj);
    }
    if (callback) callback(alertsEnabled);
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
  latestAreas = computeAreaScores(latest, checksConfig);
  latestHealth = latestAreas.overall;
  var angle = (latestHealth.score / 100) * 360;
  var caption = latestHealth.severity === 'passed' ? 'Secure posture' : latestHealth.severity === 'poor' ? 'Issues detected' : 'Unsafe';
  setHealthDisplay(latestHealth.score + '%', latestHealth.severity, caption, angle);
  maybeShowCriticalAlert(latestEntry, latestHealth, checksConfig);

  if (results.length >= 2) {
    previousEntry = results[1];
    previousAreas = computeAreaScores(previousEntry.result, checksConfig);
    previousHealth = previousAreas.overall;

    // Only show previous if score is different
    setPreviousHealthRing(
      previousHealth.score !== latestHealth.score ? previousHealth.score : null,
      previousHealth.severity,
      previousHealth.severity === 'passed' ? 'Secure posture' 
        : previousHealth.severity === 'poor' ? 'Issues detected' : 'Unsafe',
      (previousHealth.score / 100) * 360
    );
  } else {
    setPreviousHealthRing(null);
  }

  const meter = document.querySelector('.health-meter');
  const visibleRings = [...meter.querySelectorAll('.ring')].filter(r => r.offsetParent !== null);
  meter.style.justifyContent = visibleRings.length > 1 ? 'space-between' : 'center';

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
    chrome.storage.local.get([key, WHITELIST_KEY], function (data) {
      var access = evaluateAccess(tab.url, data[WHITELIST_KEY]);
      if (access.blocked) {
        renderUnavailable(access.reason);
        return;
      }
      if (access.whitelisted) {
        renderWhitelisted(tab.url);
        return;
      }
      updateToggleUI(stateSnapshot.enabled);
      render((data || {})[key] || []);
    });
  });
}

function runScan() {
  chrome.storage.local.get([ENABLED_KEY, WHITELIST_KEY], function (data) {
    var enabled = data[ENABLED_KEY];
    if (enabled === undefined) enabled = true;
    if (!enabled) {
      setStatus('Enable scanning first.');
      return;
    }
    withActiveTab(function (tab) {
      var access = evaluateAccess(tab.url, data[WHITELIST_KEY]);
      if (access.blocked) {
        renderUnavailable(access.reason);
        return;
      }
      if (access.whitelisted) {
        renderWhitelisted(tab.url);
        return;
      }
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

function handleRefresh() {
  setStatus('Refreshing...');
  loadResults();
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
    areas: latestAreas || (latestEntry.result ? computeAreaScores(latestEntry.result, checksConfig) : null),
    scripts: latestEntry.result.scripts,
    cspMeta: latestEntry.result.cspMeta,
    responseHeaders: latestEntry.result.responseHeaders || {}
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


function setHistoryVisibility(container, visible) {
  if (!container) return;
  container.dataset.visible = visible ? 'true' : 'false';
  container.classList.toggle('is-hidden', !visible);
}

function updateSelectedDownloadVisibility() {
  var row = document.getElementById('downloadSelectedRow');
  var container = document.getElementById('historyContainer');
  if (!row || !container) return;
  var checked = container.querySelectorAll('input[type="checkbox"]:checked');
  row.style.display = checked.length ? '' : 'none';
}

function renderHistoryList(data) {
  var container = document.getElementById('historyContainer');
  if (!container) return;

  container.innerHTML = '';
  var scanKeys = Object.keys(data || {}).filter(function (k) { return k.indexOf('scan:') === 0; });
  var searchInput = document.getElementById('historySearchInput');
  var query = searchInput ? String(searchInput.value || '').trim().toLowerCase() : '';

  if (query) {
    scanKeys = scanKeys.filter(function (key) {
      return key.replace('scan:', '').toLowerCase().indexOf(query) !== -1;
    });
  }

  if (scanKeys.length === 0) {
    container.textContent = query ? 'No domains matched your search.' : 'No scan history available.';
    updateSelectedDownloadVisibility();
    return;
  }

  scanKeys.forEach(function (key, siteIndex) {
    var historyList = data[key] || [];
    var url = key.replace('scan:', '');

    var siteCard = document.createElement('div');
    siteCard.className = 'history-site';

    var urlBar = document.createElement('div');
    urlBar.className = 'history-url-bar';

    var urlIndex = document.createElement('span');
    urlIndex.className = 'history-url-index';
    urlIndex.textContent = String(siteIndex + 1);

    var urlText = document.createElement('span');
    urlText.className = 'history-url-text';
    urlText.textContent = url;

    var copyBtn = document.createElement('button');
    copyBtn.type = 'button';
    copyBtn.className = 'history-copy-btn';
    copyBtn.title = 'Copy URL';
    copyBtn.setAttribute('aria-label', 'Copy URL');
    copyBtn.textContent = 'Copy';
    copyBtn.addEventListener('click', function () {
      copyToClipboard(url);
    });

    urlBar.appendChild(urlIndex);
    urlBar.appendChild(urlText);
    urlBar.appendChild(copyBtn);
    siteCard.appendChild(urlBar);

    var scanList = document.createElement('ul');
    scanList.className = 'history-scan-list';

    historyList.forEach(function (entry, index) {
      var row = document.createElement('label');
      row.className = 'scan-entry';

      var checkbox = document.createElement('input');
      checkbox.type = 'checkbox';
      checkbox.dataset.site = url;
      checkbox.dataset.index = index;

      var date = entry.ts ? new Date(entry.ts).toLocaleString() : 'Unknown';
      var score = entry.areas && entry.areas.overall ? entry.areas.overall.score : '--';
      var severity = entry.areas && entry.areas.overall ? entry.areas.overall.severity : '--';

      var meta = document.createElement('div');
      meta.className = 'scan-meta';

      var dateText = document.createElement('span');
      dateText.className = 'scan-date';
      dateText.textContent = date;

      var scoreText = document.createElement('span');
      scoreText.className = 'scan-score';
      scoreText.textContent = 'Score: ' + score;

      if (severity !== '--') {
        var badge = document.createElement('span');
        badge.className = 'severity-badge ' + String(severity).toLowerCase();
        badge.textContent = severity;
        scoreText.appendChild(badge);
      }

      row.appendChild(checkbox);
      meta.appendChild(dateText);
      meta.appendChild(scoreText);
      row.appendChild(meta);
      scanList.appendChild(row);
    });

    siteCard.appendChild(scanList);
    container.appendChild(siteCard);
  });

  updateSelectedDownloadVisibility();
}

function handleHistory() {
  var historySection = document.getElementById('historySection');
  var container = document.getElementById('historyContainer');
  var historyBtn = document.getElementById('historyBtn');
  var historySearchInput = document.getElementById('historySearchInput');
  if (!historySection || !container) return;

  if (historyVisible) {
    historyVisible = false;
    historySection.style.display = 'none';
    container.innerHTML = '';
    if (historySearchInput) historySearchInput.value = '';
    historyDataCache = null;
    if (historyBtn) historyBtn.textContent = 'View history';
    updateSelectedDownloadVisibility();
    return;
  }

  historyVisible = true;
  historySection.style.display = 'block';
  if (historyBtn) historyBtn.textContent = 'Hide history';
  if (historySearchInput) historySearchInput.value = '';
  container.textContent = 'Loading history...';

  chrome.storage.local.get(null, function (data) {
    historyDataCache = data || {};
    renderHistoryList(historyDataCache);
  });
}

function getSelectedScan(container) {
  if (!container) return null;
  var checked = container.querySelectorAll('input[type="checkbox"]:checked');
  if (!checked.length) return { error: 'Please select a scan from view history first' };
  if (checked.length > 1) return { error: 'Only one scan should be selected' };

  var cb = checked[0];
  return { site: cb.dataset.site, index: cb.dataset.index };
}

function getSelectedScans(container) {
  if (!container) return [];
  var checked = container.querySelectorAll('input[type="checkbox"]:checked');
  var selected = [];
  checked.forEach(function (cb) {
    selected.push({ site: cb.dataset.site, index: Number(cb.dataset.index) });
  });
  return selected;
}

function copyToClipboard(text) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).catch(function () {
      fallbackCopy(text);
    });
    return;
  }
  fallbackCopy(text);
}

function fallbackCopy(text) {
  var textarea = document.createElement('textarea');
  textarea.value = text;
  textarea.setAttribute('readonly', '');
  textarea.style.position = 'fixed';
  textarea.style.opacity = '0';
  document.body.appendChild(textarea);
  textarea.select();
  try {
    document.execCommand('copy');
  } catch (err) {
    // No-op if copy fails in restricted contexts.
  }
  document.body.removeChild(textarea);
}

function handleClearStorage() {
  showPopupConfirm('Clear all stored scan results?', function () {
    chrome.storage.local.clear(function () {
      setStatus('All stored results cleared.');
      loadToggle();
      loadChecks(function () {
        loadResults();
      });
      var historySection = document.getElementById('historySection');
      var container = document.getElementById('historyContainer');
      var historySearchInput = document.getElementById('historySearchInput');
      if (historySection) historySection.style.display = 'none';
      if (container) container.textContent = 'No history loaded yet.';
      if (historySearchInput) historySearchInput.value = '';
      historyVisible = false;
      historyDataCache = null;
      var historyBtn = document.getElementById('historyBtn');
      if (historyBtn) historyBtn.textContent = 'View history';
    });
  });
}

document.addEventListener('DOMContentLoaded', function () {
  var popupAlertClose = document.getElementById('popupAlertClose');
  if (popupAlertClose) {
    popupAlertClose.addEventListener('click', hidePopupAlert);
  }
  var popupConfirmCancel = document.getElementById('popupConfirmCancel');
  if (popupConfirmCancel) {
    popupConfirmCancel.addEventListener('click', function () {
      hidePopupConfirm();
      setStatus('Clear cancelled.');
    });
  }
  var popupConfirmOk = document.getElementById('popupConfirmOk');
  if (popupConfirmOk) {
    popupConfirmOk.addEventListener('click', function () {
      var action = pendingConfirmAction;
      hidePopupConfirm();
      if (action) action();
    });
  }

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

  var settingsToggle = document.getElementById('settingsScanToggle');
  if (settingsToggle) {
    settingsToggle.addEventListener('change', function (e) {
      var enabled = !!e.target.checked;
      var obj = {}; obj[ENABLED_KEY] = enabled;
      chrome.storage.local.set(obj);
      updateToggleUI(enabled);
      stateSnapshot.enabled = enabled;
      updateStateUI();
      setStatus(enabled ? 'Scanning enabled' : 'Scanning disabled');
    });
  }

  var alertsToggle = document.getElementById('alertsToggle');
  if (alertsToggle) {
    alertsToggle.addEventListener('change', function (e) {
      alertsEnabled = !!e.target.checked;
      var obj = {}; obj[ALERTS_ENABLED_KEY] = alertsEnabled;
      chrome.storage.local.set(obj);
      setStatus(alertsEnabled ? 'Critical alerts enabled.' : 'Critical alerts disabled.');
    });
  }

  var scanBtn = document.getElementById('scanBtn');
  if (scanBtn) {
    scanBtn.addEventListener('click', runScan);
  }

  var refreshBtn = document.getElementById('refreshBtn');
  if (refreshBtn) {
    refreshBtn.addEventListener('click', handleRefresh);
  }

  var settingsBtn = document.getElementById('settingsBtn');
  if (settingsBtn) {
    settingsBtn.addEventListener('click', function () {
      showView('settings');
    });

  //Added for FAQ page
  var faqBtn = document.getElementById('faqBtn');
  if (faqBtn) {
    faqBtn.addEventListener('click', function () {
      var faqURL = chrome.runtime.getURL('src/faq.html');
      window.open(faqURL, '_blank');
    });
  }
  }

  function setDropdownState(toggle, body, isOpen) {
    if (!toggle || !body) return;
    toggle.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
    body.setAttribute('aria-hidden', isOpen ? 'false' : 'true');
    var action = toggle.querySelector('.dropdown-action');
    if (action) action.textContent = isOpen ? 'Hide' : 'Show';
  }

  var settingsToggle = document.getElementById('settingsToggle');
  var settingsBody = document.getElementById('settingsBody');
  if (settingsToggle && settingsBody) {
    settingsToggle.addEventListener('click', function () {
      var isOpen = settingsBody.classList.toggle('is-open');
      setDropdownState(settingsToggle, settingsBody, isOpen);
    });
  }

  var checksToggle = document.getElementById('checksToggle');
  var checksBody = document.getElementById('checksBody');
  if (checksToggle && checksBody) {
    checksToggle.addEventListener('click', function () {
      var isOpen = checksBody.classList.toggle('is-open');
      setDropdownState(checksToggle, checksBody, isOpen);
      if (isOpen) loadChecks();
    });
  }

  var moreToggle = document.getElementById('moreToggle');
  var moreBody = document.getElementById('moreBody');
  if (moreToggle && moreBody) {
    moreToggle.addEventListener('click', function () {
      var isOpen = moreBody.classList.toggle('is-open');
      setDropdownState(moreToggle, moreBody, isOpen);
    });
  }

  var whitelistToggle = document.getElementById('whitelistToggle');
  var whitelistBody = document.getElementById('whitelistBody');
  if (whitelistToggle && whitelistBody) {
    whitelistToggle.addEventListener('click', function () {
      var isOpen = whitelistBody.classList.toggle('is-open');
      setDropdownState(whitelistToggle, whitelistBody, isOpen);
    });
  }

  var settingsClearBtn = document.getElementById('settingsClearBtn');
  if (settingsClearBtn) {
    settingsClearBtn.addEventListener('click', handleClearStorage);
  }

  var whitelistInput = document.getElementById('whitelistInput');
  var whitelistAddBtn = document.getElementById('whitelistAddBtn');

  if (whitelistAddBtn && whitelistInput) {
    whitelistAddBtn.addEventListener('click', function () {
      addPattern(whitelistInput);
    });
    whitelistInput.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') {
        e.preventDefault();
        addPattern(whitelistInput);
      }
    });
  }

  var repoBtn = document.getElementById('repoBtn');
  if (repoBtn) {
    repoBtn.addEventListener('click', function () {
      var repoURL = 'https://github.com/Jorlaz-hub/FYP-25-S4-35.git';
      window.open(repoURL, '_blank');
    });
  }

  var historyBtn = document.getElementById('historyBtn');
  if (historyBtn) {
    historyBtn.addEventListener('click', function () {
      handleHistory();
    });
  }

  var historyContainer = document.getElementById('historyContainer');
  if (historyContainer) {
    historyContainer.addEventListener('change', function (e) {
      if (e && e.target && e.target.type === 'checkbox') {
        updateSelectedDownloadVisibility();
      }
    });
  }

  var historySearchInput = document.getElementById('historySearchInput');
  if (historySearchInput) {
    historySearchInput.addEventListener('input', function () {
      if (!historyVisible || !historyDataCache) return;
      renderHistoryList(historyDataCache);
    });
  }

  var downloadAllBtn = document.getElementById('downloadAllBtn');
  if (downloadAllBtn) {
    downloadAllBtn.addEventListener('click', function () {
      chrome.storage.local.get(null, function (data) {
        var scanHistory = {};

        Object.keys(data).forEach(function (key) {
          if (key.indexOf('scan:') === 0) {
            scanHistory[key.replace('scan:', '')] = data[key];
          }
        });

        if (Object.keys(scanHistory).length === 0) {
          setStatus('No scan history available to download.');
          return;
        }

        var json = JSON.stringify(scanHistory, null, 2);
        var blob = new Blob([json], { type: 'application/json' });
        var url = URL.createObjectURL(blob);

        var a = document.createElement('a');
        a.href = url;
        a.download = 'scan-history-' + new Date().toISOString().slice(0, 10) + '.json';
        a.click();

        URL.revokeObjectURL(url);
        setStatus('History downloaded.');
      });
    });
  }

  var downloadSelectedBtn = document.getElementById('downloadSelectedBtn');
  if (downloadSelectedBtn) {
    downloadSelectedBtn.addEventListener('click', function () {
      var container = document.getElementById('historyContainer');
      var selected = getSelectedScans(container);
      if (!selected.length) {
        setStatus('Select at least one scan from history first.');
        return;
      }

      chrome.storage.local.get(null, function (data) {
        var payload = {};

        selected.forEach(function (item) {
          var key = 'scan:' + item.site;
          var list = data[key] || [];
          var entry = list[item.index];
          if (!entry) return;
          if (!payload[item.site]) payload[item.site] = [];
          payload[item.site].push(entry);
        });

        if (!Object.keys(payload).length) {
          setStatus('Selected scans could not be found.');
          return;
        }

        var json = JSON.stringify(payload, null, 2);
        var blob = new Blob([json], { type: 'application/json' });
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url;
        a.download = 'selected-scan-history-' + new Date().toISOString().slice(0, 10) + '.json';
        a.click();
        URL.revokeObjectURL(url);
        setStatus('Selected scans downloaded.');
      });
    });
  }

  var generateReportBtn = document.getElementById('generateReportBtn');
  if (generateReportBtn) {
    generateReportBtn.addEventListener('click', function () {
      var historyContainer = document.getElementById('historyContainer');
      var selected = getSelectedScan(historyContainer);
      if (!selected || selected.error) {
        var message = selected && selected.error ? selected.error : 'Please select a scan from view history first';
        showPopupAlert(message);
        setStatus(message);
        return;
      }

      var key = 'scan:' + selected.site;
      chrome.storage.local.get(key, function (data) {
        var entry = data[key] && data[key][selected.index];
        if (!entry) {
          setStatus('Selected scan could not be found.');
          return;
        }

        var reportId = 'report-' + Date.now();
        var storageKey = 'report:' + reportId;

        chrome.storage.local.set(
          (function () {
            var obj = {};
            obj[storageKey] = { site: selected.site, entry: entry };
            return obj;
          })(),
          function () {
            var reportUrl = chrome.runtime.getURL(
              'src/report.html?id=' + encodeURIComponent(reportId)
            );
            window.open(reportUrl, '_blank');
          }
        );
      });
    });
  }

  var fullReviewBtn = document.getElementById('fullReviewBtn');
  if (fullReviewBtn) {
    fullReviewBtn.addEventListener('click', function () {
      var historyContainer = document.getElementById('historyContainer');
      var selected = getSelectedScan(historyContainer);
      if (!selected || selected.error) {
        var message = selected && selected.error ? selected.error : 'Please select a scan from view history first';
        showPopupAlert(message);
        setStatus(message);
        return;
      }

      var key = 'scan:' + selected.site;
      chrome.storage.local.get(key, function (data) {
        var entry = data[key] && data[key][selected.index];
        if (!entry) {
          setStatus('Selected scan could not be found.');
          return;
        }

        chrome.storage.local.set({ reviewTargetKey: key }, function () {
          var reviewUrl = chrome.runtime.getURL('src/review.html');
          window.open(reviewUrl, '_blank');
        });
      });
    });
  }

  var settingsBack = document.getElementById('settingsBack');
  if (settingsBack) {
    settingsBack.addEventListener('click', function () {
      showView('main');
    });
  }

  bindCheckToggles();
  loadToggle();
  loadAllowlists();
  loadAlertsSetting(function () {
    loadChecks(function () {
      loadResults();
    });
  });
});