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

function bindEvents() {
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
      });
    });
  }
}

document.addEventListener('DOMContentLoaded', function () {
  loadToggle();
  bindEvents();
});
