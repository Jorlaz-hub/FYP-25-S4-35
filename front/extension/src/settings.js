var ENABLED_KEY = 'scanEnabled';
var CHECKS_KEY = 'checksConfig';
var DEFAULT_CHECKS = SharedAlgo.DEFAULT_CHECKS;
var normalizeChecks = SharedAlgo.normalizeChecks;

var checksConfig = normalizeChecks(null);

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
  var confirmOverlay = document.getElementById('confirmOverlay');
  var confirmCancel = document.getElementById('confirmCancel');
  var confirmClear = document.getElementById('confirmClear');

  function openConfirm() {
    if (!confirmOverlay) return;
    confirmOverlay.classList.add('is-open');
    confirmOverlay.setAttribute('aria-hidden', 'false');
  }

  function closeConfirm() {
    if (!confirmOverlay) return;
    confirmOverlay.classList.remove('is-open');
    confirmOverlay.setAttribute('aria-hidden', 'true');
  }

  if (clearBtn) {
    clearBtn.addEventListener('click', function () {
      openConfirm();
    });
  }

  if (confirmCancel) {
    confirmCancel.addEventListener('click', closeConfirm);
  }

  if (confirmOverlay) {
    confirmOverlay.addEventListener('click', function (e) {
      if (e.target === confirmOverlay) {
        closeConfirm();
      }
    });
  }

  if (confirmClear) {
    confirmClear.addEventListener('click', function () {
      chrome.storage.local.clear(function () {
        setStatus('All stored results cleared.');
        loadToggle();
        loadChecks();
        closeConfirm();
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
});
