var ENABLED_KEY = 'scanEnabled';
var CHECKS_KEY = 'checksConfig';
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

var checksConfig = normalizeChecks(null);

function saveChecks(next, callback) {
  var obj = {}; obj[CHECKS_KEY] = next;
  chrome.storage.local.set(obj, function () {
    if (callback) callback();
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
    settings: document.getElementById('settingsView'),
    more: document.getElementById('moreView')
  };
  Object.keys(views).forEach(function (key) {
    if (!views[key]) return;
    views[key].classList.toggle('is-active', key === viewName);
  });
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

function handleMore() {
  showView('more');
}

function setHistoryVisibility(container, visible) {
  if (!container) return;
  container.dataset.visible = visible ? 'true' : 'false';
  container.classList.toggle('is-hidden', !visible);
}

function handleHistory() {
  var container = document.getElementById('historyContainer');
  var historyBtn = document.getElementById('historyBtn');
  if (!container || !historyBtn) return;

  var isVisible = container.dataset.visible === 'true';
  if (isVisible) {
    setHistoryVisibility(container, false);
    historyBtn.textContent = 'View';
    return;
  }

  setHistoryVisibility(container, true);
  historyBtn.textContent = 'Hide';
  container.textContent = 'Loading history...';

  chrome.storage.local.get(null, function (data) {
    container.innerHTML = '';
    var scanKeys = Object.keys(data).filter(function (k) { return k.indexOf('scan:') === 0; });
    if (scanKeys.length === 0) {
      container.textContent = 'No scan history available.';
      return;
    }

    scanKeys.forEach(function (key) {
      var historyList = data[key];
      var url = key.replace('scan:', '');

      var title = document.createElement('h3');
      title.textContent = url;
      container.appendChild(title);

      var ul = document.createElement('ul');
      historyList.forEach(function (entry) {
        var li = document.createElement('li');
        var date = entry.ts ? new Date(entry.ts).toLocaleString() : 'Unknown';
        var score = entry.areas && entry.areas.overall ? entry.areas.overall.score : '--';
        var severity = entry.areas && entry.areas.overall ? entry.areas.overall.severity : '--';
        li.textContent = date + ' - Score: ' + score + ' (' + severity + ')';
        ul.appendChild(li);
      });

      container.appendChild(ul);
    });
  });
}

function handleClearStorage() {
  chrome.storage.local.clear(function () {
    setStatus('All stored results cleared.');
    loadToggle();
    loadChecks(function () {
      loadResults();
    });
    var container = document.getElementById('historyContainer');
    if (container) {
      setHistoryVisibility(container, false);
      container.textContent = 'No history loaded yet.';
    }
    var historyBtn = document.getElementById('historyBtn');
    if (historyBtn) historyBtn.textContent = 'View';
  });
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

  var refreshBtn = document.getElementById('refreshBtn');
  if (refreshBtn) {
    refreshBtn.addEventListener('click', handleRefresh);
  }

  var openMorePageBtn = document.getElementById('openMorePageBtn');
  if (openMorePageBtn) {
    openMorePageBtn.addEventListener('click', function () {
      chrome.tabs.create({ url: chrome.runtime.getURL('src/more.html') });
    });
  }

  var openSettingsPageBtn = document.getElementById('openSettingsPageBtn');
  if (openSettingsPageBtn) {
    openSettingsPageBtn.addEventListener('click', function () {
      chrome.tabs.create({ url: chrome.runtime.getURL('src/settings.html') });
    });
  }

  var settingsBtn = document.getElementById('settingsBtn');
  if (settingsBtn) {
    settingsBtn.addEventListener('click', function () {
      showView('settings');
      loadChecks();
    });
  }

  var settingsBack = document.getElementById('settingsBack');
  if (settingsBack) {
    settingsBack.addEventListener('click', function () {
      showView('main');
    });
  }

  var moreBtn = document.getElementById('morePanelBtn');
  if (moreBtn) {
    moreBtn.addEventListener('click', handleMore);
  }

  var moreBack = document.getElementById('moreBack');
  if (moreBack) {
    moreBack.addEventListener('click', function () {
      showView('main');
    });
  }

  bindCheckToggles();
  loadToggle();
  loadChecks(function () {
    loadResults();
  });
});
