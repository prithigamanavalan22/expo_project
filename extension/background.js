/**
 * PhishGuard Background Service Worker (Manifest V3)
 *
 * RESPONSIBILITIES:
 *  1. Listens for tab URL changes via chrome.tabs.onUpdated
 *  2. Extracts the current tab URL
 *  3. Calls the local PhishGuard API (POST /api/v1/scan)
 *  4. Stores the result in chrome.storage for the popup to display
 *  5. Sends a message to content.js to show an overlay if phishing detected
 *
 * SECURITY NOTES:
 *  - Only communicates with localhost:8000 (declared in host_permissions).
 *  - JWT token is stored in chrome.storage.local after login.
 *  - No eval() or innerHTML usage — all data flows as structured JSON.
 *  - API responses are validated before being acted upon.
 */

const API_BASE = "http://localhost:8000/api/v1";

// Track URLs we've already scanned to avoid duplicate requests
const recentlyScanned = new Set();
const SCAN_COOLDOWN_MS = 5000; // 5 second cooldown per URL

/**
 * Get the JWT token from chrome.storage.
 * Returns null if the user hasn't logged in yet.
 */
async function getAuthToken() {
  return new Promise((resolve) => {
    chrome.storage.local.get(["authToken"], (result) => {
      resolve(result.authToken || null);
    });
  });
}

/**
 * Call the PhishGuard API to scan a URL.
 *
 * SECURITY: The request is sent only to the whitelisted localhost origin.
 * The JWT token is attached via Authorization header — never in the URL body.
 *
 * @param {string} url - The URL to scan
 * @returns {Promise<Object>} - The scan result from the API
 */
async function scanURL(url) {
  const token = await getAuthToken();

  const headers = {
    "Content-Type": "application/json",
  };

  // Attach JWT if available
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  try {
    const response = await fetch(`${API_BASE}/scan`, {
      method: "POST",
      headers: headers,
      body: JSON.stringify({ url: url }),
    });

    if (!response.ok) {
      // If 401, token expired or missing — user needs to log in via popup
      if (response.status === 401) {
        console.warn("[PhishGuard] Authentication required. Please log in.");
        return { prediction: "unknown", confidence: 0, error: "auth_required" };
      }
      console.error(`[PhishGuard] API error: ${response.status}`);
      return { prediction: "unknown", confidence: 0, error: "api_error" };
    }

    const result = await response.json();
    return result;
  } catch (error) {
    console.error("[PhishGuard] Network error:", error.message);
    return { prediction: "unknown", confidence: 0, error: "network_error" };
  }
}

/**
 * Process a scan result and update storage + content script.
 *
 * SECURITY: Result data is validated before acting on it.
 * Only the prediction field is trusted — it's an enum from the server.
 *
 * @param {string} url - The scanned URL
 * @param {Object} result - The API response
 * @param {number} tabId - The Chrome tab ID
 */
async function processScanResult(url, result, tabId) {
  // Validate prediction value — only allow expected values
  const validPredictions = ["safe", "phishing", "unknown"];
  const prediction = validPredictions.includes(result.prediction)
    ? result.prediction
    : "unknown";

  const scanData = {
    url: url,
    prediction: prediction,
    confidence: result.confidence || 0,
    timestamp: Date.now(),
    scanId: result.id || null,
  };

  // Store the latest scan result for the popup to display
  await chrome.storage.local.set({
    lastScan: scanData,
  });

  // Update the badge icon color
  updateBadge(prediction, tabId);

  // If phishing detected, notify the content script to show the alert overlay
  if (prediction === "phishing") {
    try {
      chrome.tabs.sendMessage(tabId, {
        action: "showPhishingAlert",
        url: url,
        confidence: result.confidence,
      });
    } catch (err) {
      // Content script may not be loaded on chrome:// pages
      console.log("[PhishGuard] Could not inject alert (page not accessible):", err.message);
    }
  } else if (prediction === "safe") {
    // Clear any existing alert on safe pages
    try {
      chrome.tabs.sendMessage(tabId, {
        action: "clearAlert",
      });
    } catch (err) {
      // Content script may not be loaded
    }
  }
}

/**
 * Update the browser action badge to show scan status.
 * Green = safe, Red = phishing, Gray = unknown.
 *
 * @param {string} prediction - "safe", "phishing", or "unknown"
 * @param {number} tabId - The Chrome tab ID
 */
function updateBadge(prediction, tabId) {
  const badgeConfig = {
    safe: { color: "#22c55e", text: "✓" },
    phishing: { color: "#ef4444", text: "!" },
    unknown: { color: "#6b7280", text: "?" },
  };

  const config = badgeConfig[prediction] || badgeConfig.unknown;

  chrome.action.setBadgeBackgroundColor({ color: config.color, tabId: tabId });
  chrome.action.setBadgeText({ text: config.text, tabId: tabId });
}

// ===========================================================================
//  EVENT LISTENERS
// ===========================================================================

/**
 * Listen for tab updates (URL changes).
 *
 * SECURITY: Only processes HTTP/HTTPS URLs — skips chrome://, file://, etc.
 */
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  // Only process when the page finishes loading
  if (changeInfo.status !== "complete") return;

  const url = tab.url;
  if (!url) return;

  // SECURITY: Only scan HTTP/HTTPS URLs
  if (!url.startsWith("http://") && !url.startsWith("https://")) return;

  // Skip localhost / API server URLs
  if (url.includes("localhost:8000") || url.includes("127.0.0.1:8000")) return;

  // Cooldown: don't re-scan the same URL within SCAN_COOLDOWN_MS
  if (recentlyScanned.has(url)) return;
  recentlyScanned.add(url);
  setTimeout(() => recentlyScanned.delete(url), SCAN_COOLDOWN_MS);

  // Perform the scan
  const result = await scanURL(url);
  await processScanResult(url, result, tabId);
});

/**
 * Listen for messages from the popup or content scripts.
 * Enables manual "scan now" from the popup.
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "scanCurrentTab") {
    // Get the active tab and scan it
    chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
      try {
        if (tabs[0] && tabs[0].url) {
          const url = tabs[0].url;
          if (url.startsWith("http://") || url.startsWith("https://")) {
            const result = await scanURL(url);
            await processScanResult(url, result, tabs[0].id);
            sendResponse({ success: true, result: result });
          } else {
            sendResponse({ success: false, error: "Not a valid HTTP/HTTPS URL" });
          }
        } else {
          sendResponse({ success: false, error: "No active tab" });
        }
      } catch (err) {
        console.error("[PhishGuard] Scan error:", err);
        sendResponse({ success: false, error: err.message });
      }
    });
    return true; // Keep the message channel open for async sendResponse
  }

  if (message.action === "getLastScan") {
    chrome.storage.local.get(["lastScan"], (result) => {
      sendResponse({ lastScan: result.lastScan || null });
    });
    return true;
  }
});
