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
  bindSettings();

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
