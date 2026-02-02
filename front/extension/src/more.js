document.addEventListener('DOMContentLoaded', function () {
  var repoBtn = document.getElementById('repoBtn');
  var historyBtn = document.getElementById('historyBtn');
  var historySection = document.getElementById('historySection');
  var historyContainer = document.getElementById('historyContainer');
  var downloadHistoryBtn = document.getElementById('downloadHistoryBtn');
  var downloadSelectedRow = document.getElementById('downloadSelectedRow');
  var downloadSelectedBtn = document.getElementById('downloadSelectedBtn');
  var generateReportBtn = document.getElementById('generateReportBtn');
  var fullReviewBtn = document.getElementById('fullReviewBtn');

  var historyVisible = false;

  if (repoBtn) {
    repoBtn.addEventListener('click', function () {
      var repoURL = 'https://github.com/Jorlaz-hub/FYP-25-S4-35.git';
      window.open(repoURL, '_blank');
    });
  }

  if (historyBtn) {
    historyBtn.addEventListener('click', function () {
      if (!historySection || !historyContainer) return;

      if (historyVisible) {
        historyVisible = false;
        historySection.style.display = 'none';
        historyContainer.innerHTML = '';
        if (downloadSelectedRow) downloadSelectedRow.style.display = 'none';
        return;
      }

      historyVisible = true;
      historySection.style.display = 'block';
      historyContainer.textContent = 'Loading history...';

      chrome.storage.local.get(null, function (data) {
        historyContainer.innerHTML = '';

        var scanKeys = Object.keys(data).filter(function (k) { return k.indexOf('scan:') === 0; });
        if (scanKeys.length === 0) {
          historyContainer.textContent = 'No scan history available.';
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
            checkbox.addEventListener('change', updateDownloadSelectedVisibility);

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
          historyContainer.appendChild(siteCard);
        });

        updateDownloadSelectedVisibility();
      });
    });
  }

  if (downloadHistoryBtn) {
    downloadHistoryBtn.addEventListener('click', function () {
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

  if (generateReportBtn) {
    generateReportBtn.addEventListener('click', function () {
      if (!historyContainer) return;
      var checkedBoxes = historyContainer.querySelectorAll('input[type="checkbox"]:checked');

      if (checkedBoxes.length === 0) {
        alert('Please select a scan from view history first');
        return;
      }

      if (checkedBoxes.length > 1) {
        alert('Only one scan should be selected');
        return;
      }

      var cb = checkedBoxes[0];
      var site = cb.dataset.site;
      var index = cb.dataset.index;
      var key = 'scan:' + site;

      chrome.storage.local.get(key, function (data) {
        var entry = data[key] && data[key][index];
        if (!entry) {
          alert('Selected scan could not be found.');
          return;
        }

        var reportId = 'report-' + Date.now();
        var storageKey = 'report:' + reportId;

        chrome.storage.local.set(
          (function () {
            var obj = {};
            obj[storageKey] = { site: site, entry: entry };
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

  if (fullReviewBtn) {
    fullReviewBtn.addEventListener('click', function () {
      if (!historyContainer) return;
      var checkedBoxes = historyContainer.querySelectorAll('input[type="checkbox"]:checked');

      if (checkedBoxes.length === 0) {
        alert('Please select a scan from view history first');
        return;
      }

      if (checkedBoxes.length > 1) {
        alert('Only one scan should be selected');
        return;
      }

      var cb = checkedBoxes[0];
      var site = cb.dataset.site;
      var index = cb.dataset.index;
      var key = 'scan:' + site;

      chrome.storage.local.get(key, function (data) {
        var entry = data[key] && data[key][index];
        if (!entry) {
          alert('Selected scan could not be found.');
          return;
        }

        chrome.storage.local.set({ reviewTargetKey: key }, function () {
          var reviewUrl = chrome.runtime.getURL('src/review.html');
          window.open(reviewUrl, '_blank');
        });
      });
    });
  }

  if (downloadSelectedBtn) {
    downloadSelectedBtn.addEventListener('click', function () {
      if (!historyContainer) return;
      chrome.storage.local.get(null, function (data) {
        var selectedScans = {};
        var checkedBoxes = historyContainer.querySelectorAll('input[type="checkbox"]:checked');

        checkedBoxes.forEach(function (cb) {
          var site = cb.dataset.site;
          var index = cb.dataset.index;
          var key = 'scan:' + site;
          var entry = data[key] && data[key][index];
          if (!entry) return;

          if (!selectedScans[site]) {
            selectedScans[site] = [];
          }
          selectedScans[site].push(entry);
        });

        if (Object.keys(selectedScans).length === 0) {
          alert('No past scans selected to download.');
          return;
        }

        var json = JSON.stringify(selectedScans, null, 2);
        var blob = new Blob([json], { type: 'application/json' });
        var url = URL.createObjectURL(blob);

        var a = document.createElement('a');
        a.href = url;
        a.download = 'selected-scans-' + new Date().toISOString().slice(0, 10) + '.json';
        a.click();

        URL.revokeObjectURL(url);
      });
    });
  }

  function updateDownloadSelectedVisibility() {
    if (!historyContainer || !downloadSelectedRow) return;
    var checkedCount = historyContainer.querySelectorAll('input[type="checkbox"]:checked').length;
    downloadSelectedRow.style.display = checkedCount > 0 ? 'flex' : 'none';
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
});

