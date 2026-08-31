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
 * Stored credentials for silent re-authentication when a JWT expires.
 * Credentials live in chrome.storage.local (encrypted at-rest by the browser)
 * and are ONLY used to transparently refresh the token on a 401 — never sent
 * anywhere except the localhost login endpoint.
 */
async function getStoredCredentials() {
  return new Promise((resolve) => {
    chrome.storage.local.get(["username", "authPassword"], (result) => {
      if (result.username && result.authPassword) {
        resolve({ username: result.username, password: result.authPassword });
      } else {
        resolve(null);
      }
    });
  });
}

async function setStoredPassword(password) {
  await chrome.storage.local.set({ authPassword: password });
}

let reauthInFlight = null;

/**
 * Silently re-login with stored credentials and cache the fresh token.
 * Multiple concurrent 401-triggered refreshes share one login call.
 * Returns the new token, or null if no stored credentials / login fails.
 */
async function reAuthenticate() {
  if (reauthInFlight) return reauthInFlight;
  reauthInFlight = (async () => {
    const creds = await getStoredCredentials();
    if (!creds) return null;
    try {
      const resp = await fetch(`${API_BASE}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: creds.username, password: creds.password }),
      });
      if (!resp.ok) return null;
      const data = await resp.json();
      if (data.access_token) {
        await chrome.storage.local.set({ authToken: data.access_token });
        return data.access_token;
      }
      return null;
    } catch (err) {
      console.warn("[PhishGuard] Re-auth failed:", err.message);
      return null;
    } finally {
      reauthInFlight = null;
    }
  })();
  return reauthInFlight;
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
async function scanURL(url, includeAnalysis = false) {
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
      body: JSON.stringify({ url: url, analysis: includeAnalysis }),
    });

    if (!response.ok) {
      // 401 -> token expired/missing. Silently re-login with stored creds
      // and retry ONCE so a stale token never silently breaks scans.
      if (response.status === 401) {
        const newToken = await reAuthenticate();
        if (newToken) {
          const retryHeaders = {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${newToken}`,
          };
          const retry = await fetch(`${API_BASE}/scan`, {
            method: "POST",
            headers: retryHeaders,
            body: JSON.stringify({ url: url, analysis: includeAnalysis }),
          });
          if (retry.ok) return await retry.json();
        }
        console.warn("[PhishGuard] Authentication required (re-login failed).");
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
 * Scan a decoded QR-code payload (or URL) through the shared risk engine.
 * Used by the popup's QR scanner tab.

 * @param {string} url - The URL decoded from the QR code
 * @returns {Promise<Object>} - The scan result
 */
async function scanQRURL(url) {
  return scanURL(url, false);
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
  const validPredictions = ["safe", "suspicious", "phishing", "unknown"];
  const prediction = validPredictions.includes(result.prediction)
    ? result.prediction
    : "unknown";

  const scanData = {
    url: url,
    prediction: prediction,
    confidence: result.confidence || 0,
    risk_score: result.risk_score || 0,
    explanation: Array.isArray(result.explanation) ? result.explanation : [],
    sandbox: result.sandbox || null,
    redirect_chain: Array.isArray(result.redirect_chain) ? result.redirect_chain : [],
    risk_factors: Array.isArray(result.risk_factors) ? result.risk_factors : [],
    brand: result.brand || null,
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
        risk_score: result.risk_score,
        brand: result.brand,
        topFactors: Array.isArray(result.risk_factors)
          ? result.risk_factors.slice(0, 4).map((f) => f.name)
          : [],
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

  // Perform the scan — deep analysis so the sandbox (content analysis) is
  // populated for the popup + overlay. This fetches & inspects page content.
  const result = await scanURL(url, true);
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
            const result = await scanURL(url, true);
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

  if (message.action === "scanUrlText") {
    // Scan an arbitrary URL typed/pasted in the popup's Env Sandbox view.
    const url = typeof message.url === "string" ? message.url.trim() : "";
    if (!url || (!url.startsWith("http://") && !url.startsWith("https://"))) {
      sendResponse({ success: false, error: "Not a valid HTTP/HTTPS URL" });
      return;
    }
    (async () => {
      try {
        const result = await scanURL(url, true);
        if (result && result.prediction) {
          await processScanResult(url, result, null);
          sendResponse({ success: true, result: result });
        } else {
          sendResponse({ success: false, error: (result && result.error) || "Scan failed" });
        }
      } catch (err) {
        console.error("[PhishGuard] scanUrlText error:", err);
        sendResponse({ success: false, error: err.message });
      }
    })();
    return true; // async sendResponse
  }
});
