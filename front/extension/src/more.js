var ENABLED_KEY = 'scanEnabled';
var CHECKS_KEY = 'checksConfig';
var DEFAULT_CHECKS = {
  https: true,
  csp: true,
  cspQuality: true,
  hsts: true,
  xcto: true,
  referrer: true,
  permissions: true,
  thirdParty: true,
  sri: true,
  inlineScripts: true,
  inlineEvents: true,
  templateMarkers: true,
  obfuscated: true,
  unsafeLinks: true,
  csrf: true,
  insecureForms: true,
  tokenHits: true
};

var checksConfig = normalizeChecks(null);

function normalizeChecks(raw) {
  var out = {};
  Object.keys(DEFAULT_CHECKS).forEach(function (key) {
    out[key] = raw && typeof raw[key] === 'boolean' ? raw[key] : DEFAULT_CHECKS[key];
  });
  return out;
}

function setStatus(msg) {
  var el = document.getElementById('status');
  if (el) el.textContent = msg || '';
}

function loadToggle() {
  chrome.storage.local.get([ENABLED_KEY], function (data) {
    var enabled = data[ENABLED_KEY];
    if (enabled === undefined) enabled = true;
    var toggle = document.getElementById('scanToggle');
    if (toggle) toggle.checked = enabled;
  });
}

function bindSettings() {
  var toggle = document.getElementById('scanToggle');
  if (toggle) {
    toggle.addEventListener('change', function (e) {
      var enabled = !!e.target.checked;
      var obj = {}; obj[ENABLED_KEY] = enabled;
      chrome.storage.local.set(obj, function () {
        setStatus(enabled ? 'Scanning enabled' : 'Scanning disabled');
      });
    });
  }

  var clearBtn = document.getElementById('clear');
  if (clearBtn) {
    clearBtn.addEventListener('click', function () {
      chrome.storage.local.clear(function () {
        setStatus('All stored results cleared.');
        loadToggle();
        loadChecks();
      });
    });
  }
}

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

function loadChecks() {
  chrome.storage.local.get([CHECKS_KEY], function (data) {
    checksConfig = normalizeChecks(data[CHECKS_KEY]);
    applyChecksToUI(checksConfig);
    if (!data[CHECKS_KEY]) {
      saveChecks(checksConfig);
    }
  });
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
      });
    });
  });
}

document.addEventListener('DOMContentLoaded', function () {
  loadToggle();
  bindSettings();
  loadChecks();
  bindCheckToggles();

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
      var container = document.getElementById('historyContainer');
      if (!container) return;
      container.innerHTML = 'Loading history...';

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
    });
  }

  var downloadBtn = document.getElementById('downloadBtn');
  if (downloadBtn) {
    downloadBtn.addEventListener('click', function () {
      chrome.storage.local.get(null, function (data) {
        var scanHistory = {};

        Object.keys(data).forEach(function (key) {
          if (key.indexOf('scan:') === 0) {
            scanHistory[key.replace('scan:', '')] = data[key];
          }
        });

        if (Object.keys(scanHistory).length === 0) {
          alert('No scan history available to download.');
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
      });
    });
  }
});
