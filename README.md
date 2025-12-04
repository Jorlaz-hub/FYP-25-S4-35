# Client-Side Script Security Inspector

Chrome Extension (Manifest V3) that inspects client-side scripts and CSP meta tags on web pages. Built entirely with HTML/CSS/JS/JSON — no build step required.

## Structure

- `front/extension/manifest.json`: Extension manifest
- `front/extension/src/`: Popup, options, background, and content script files
- `back/`: Optional backend (empty initially)

## Quick Start

1. Open Chrome and navigate to `chrome://extensions`
2. Enable Developer Mode
3. Click "Load unpacked" and select the `front/extension` folder

## How it works

- The content script scans the page for scripts and CSP meta tags and sends a message
- The background service worker stores results per-URL in `chrome.storage.local`
- The popup displays recent scan results for the active tab
- The options page provides a button to clear stored results

## Notes

- This is a minimal baseline to start iterating on security checks
- You can expand to analyze headers using appropriate extension permissions/APIs
