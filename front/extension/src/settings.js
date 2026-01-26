var ENABLED_KEY = 'scanEnabled';

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
        closeConfirm();
      });
    });
  }
}

document.addEventListener('DOMContentLoaded', function () {
  loadToggle();
  bindSettings();
});
