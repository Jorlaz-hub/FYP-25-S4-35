document.addEventListener('DOMContentLoaded', () => {
  const repoBtn = document.getElementById('repoBtn');
  const historyBtn = document.getElementById('historyBtn');
  const historyContainer = document.getElementById('historyContainer');
  const downloadSelectedBtn = document.getElementById('downloadSelectedBtn');
  const downloadAllBtn = document.getElementById('downloadAllBtn');

  // --------------------------------
  // Open GitHub Repository
  // --------------------------------
  repoBtn.addEventListener('click', () => {
    const repoURL = 'https://github.com/Jorlaz-hub/FYP-25-S4-35.git';
    window.open(repoURL, '_blank');
  });

  // --------------------------------
  // View Scan History
  // --------------------------------
  historyBtn.addEventListener('click', () => {
    historyContainer.innerHTML = 'Loading history...';
    downloadSelectedBtn.style.display = 'none';

    chrome.storage.local.get(null, (data) => {
      historyContainer.innerHTML = '';

      const scanKeys = Object.keys(data).filter(k => k.startsWith('scan:'));
      if (scanKeys.length === 0) {
        historyContainer.textContent = 'No scan history available.';
        return;
      }

      scanKeys.forEach((key) => {
        const site = key.replace('scan:', '');
        const historyList = data[key];

        // Site title
        const title = document.createElement('h3');
        title.className = 'site-title';
        title.textContent = site;
        historyContainer.appendChild(title);

        // Scan entries
        historyList.forEach((entry, index) => {
          const row = document.createElement('label');
          row.className = 'scan-entry';

          const checkbox = document.createElement('input');
          checkbox.type = 'checkbox';
          checkbox.dataset.site = site;
          checkbox.dataset.index = index;
          checkbox.addEventListener('change', updateDownloadButtonVisibility);

          const date = entry.ts
            ? new Date(entry.ts).toLocaleString()
            : 'Unknown';

          const score = entry.areas?.overall?.score ?? '--';
          const severity = entry.areas?.overall?.severity ?? '--';

          const text = document.createElement('span');
          text.textContent = `${date} - Score: ${score} (${severity})`;

          row.appendChild(checkbox);
          row.appendChild(text);
          historyContainer.appendChild(row);
        });
      });
    });
  });

  // --------------------------------
  // Download SELECTED scans
  // --------------------------------
  downloadSelectedBtn.addEventListener('click', () => {
    chrome.storage.local.get(null, (data) => {
      const selectedScans = {};
      const checkedBoxes = historyContainer.querySelectorAll(
        'input[type="checkbox"]:checked'
      );

      checkedBoxes.forEach((cb) => {
        const site = cb.dataset.site;
        const index = cb.dataset.index;
        const key = `scan:${site}`;

        const entry = data[key]?.[index];
        if (!entry) return;

        if (!selectedScans[site]) {
          selectedScans[site] = [];
        }
        selectedScans[site].push(entry);
      });

      if (Object.keys(selectedScans).length === 0) return;

      downloadJSON(
        selectedScans,
        `selected-scans-${new Date().toISOString().slice(0, 10)}.json`
      );
    });
  });

  // --------------------------------
  // Download ALL scans
  // --------------------------------
  downloadAllBtn.addEventListener('click', () => {
    chrome.storage.local.get(null, (data) => {
      const allScans = {};

      Object.keys(data).forEach((key) => {
        if (key.startsWith('scan:')) {
          allScans[key.replace('scan:', '')] = data[key];
        }
      });

      if (Object.keys(allScans).length === 0) {
        alert('No scan history available.');
        return;
      }

      downloadJSON(
        allScans,
        `all-scans-${new Date().toISOString().slice(0, 10)}.json`
      );
    });
  });

  // --------------------------------
  // Helpers
  // --------------------------------
  function updateDownloadButtonVisibility() {
    const anyChecked =
      historyContainer.querySelectorAll('input[type="checkbox"]:checked')
        .length > 0;

    downloadSelectedBtn.style.display = anyChecked ? 'block' : 'none';
  }

  function downloadJSON(data, filename) {
    const blob = new Blob(
      [JSON.stringify(data, null, 2)],
      { type: 'application/json' }
    );

    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');

    a.href = url;
    a.download = filename;
    a.click();

    URL.revokeObjectURL(url);
  }
});