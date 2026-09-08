/**
 * PhishGuard Background Service Worker (Manifest V3)
 *
 * RESPONSIBILITIES:
 *  1. Listens for tab URL changes via chrome.tabs.onUpdated
 *  2. Extracts the current tab URL
 *  3. Calls the local PhishGuard API (POST /api/v1/scan)
 *  4. Stores the result in chrome.storage for the popup to display
 *  5. Sends a message to content.js to show an overlay (Phishing or Safe)
 *
 * SECURITY NOTES:
 *  - Only communicates with localhost:8000 (declared in host_permissions).
 *  - JWT token is stored in chrome.storage.local after login.
 *  - No eval() or innerHTML usage — all data flows as structured JSON.
 *  - API responses are validated before being acted upon.
 */

const API_BASE = "http://localhost:8000/api/v1";
const HEALTH_URL = "http://localhost:8000/health";

// ---------------------------------------------------------------------------
// BACKEND REACHABILITY / AUTO-RECONNECT
// The backend auto-starts with Windows. Right after a reboot it may still be
// coming up, so the extension keeps probing /health and waiting for it instead
// of immediately failing with "backend not reachable".
// ---------------------------------------------------------------------------
let healthPoller = null;

async function probeBackend() {
  try {
    const resp = await fetch(HEALTH_URL, { method: "GET", cache: "no-store" });
    const ready = resp.ok;
    await chrome.storage.local.set({
      backendHealth: { ready, at: Date.now() },
    });
    return ready;
  } catch (err) {
    await chrome.storage.local.set({
      backendHealth: { ready: false, at: Date.now(), error: err.message },
    });
    return false;
  }
}

/**
 * Wait until the backend answers /health. Resolves true when available.
 */
function waitForBackend(maxWaitMs = 30000) {
  return new Promise((resolve) => {
    const start = Date.now();
    const tick = async () => {
      if (await probeBackend()) return resolve(true);
      if (Date.now() - start >= maxWaitMs) return resolve(false);
      setTimeout(tick, 1500 + Math.random() * 500);
    };
    tick();
  });
}

/**
 * Slow background poller. Once the backend becomes healthy it stores state the
 * popup reads and stops polling; the poller restarts on the next SW wake if the
 * backend has gone away again.
 */
let backendWasReady = null;

async function rescanPendingTabs() {
  try {
    const tabs = await chrome.tabs.query({ status: "complete" });
    for (const tab of tabs) {
      const url = tab.url || "";
      if (!/^https?:\/\//i.test(url)) continue;
      if (url.includes("localhost:8000") || url.includes("127.0.0.1:8000")) continue;
      if (recentlyScanned.has(url) || tabScanInFlight.has(tab.id)) continue;
      tabLastScannedUrl.set(tab.id, url);
      recentlyScanned.add(url);
      setTimeout(() => recentlyScanned.delete(url), SCAN_COOLDOWN_MS);
      const p = (async () => {
        const result = await scanURL(url, true);
        await processScanResult(url, result, tab.id);
      })().catch(() => {}).finally(() => {
        tabScanInFlight.delete(tab.id);
      });
      tabScanInFlight.set(tab.id, p);
    }
  } catch (err) {
    console.log("[PhishGuard] rescan after backend recovery error:", err.message);
  }
}

function startHealthPoller() {
  if (healthPoller) return;
  healthPoller = setInterval(async () => {
    const ready = await probeBackend();
    if (ready) {
      clearInterval(healthPoller);
      healthPoller = null;
      // Backend just recovered — re-check the tabs we could not reach earlier.
      if (backendWasReady === false) await rescanPendingTabs();
      backendWasReady = true;
    } else {
      backendWasReady = false;
    }
  }, 4000);
}

chrome.runtime.onStartup?.addListener(() => startHealthPoller());
startHealthPoller();

// Track URLs we've already scanned to avoid duplicate requests
const recentlyScanned = new Set();
const SCAN_COOLDOWN_MS = 5000; // 5 second cooldown per URL

// Per-tab tracking of the URL we last scanned
const tabLastScannedUrl = new Map(); // tabId -> url string
const tabScanInFlight = new Map();   // tabId -> Promise (dedupe concurrent scans)

/**
 * Get the JWT token from chrome.storage.
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
 */
async function scanURL(url, includeAnalysis = false) {
  const token = await getAuthToken();

  const headers = {
    "Content-Type": "application/json",
  };

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
      // DNS / URL-format validation gate failure (backend 422) -> surface a
      // clean "Is not valid URL" result so the UI can explain it.
      if (response.status === 422) {
        let detail = null;
        try {
          const parsed = await response.json();
          detail = parsed && parsed.detail ? parsed.detail : null;
        } catch (e) { /* non-JSON body — fall back to generic api_error */ }
        if (detail && detail.url_valid === false) {
          return { prediction: "unknown", confidence: 0, error: "invalid_url", detail: detail };
        }
      }
      console.error(`[PhishGuard] API error: ${response.status}`);
      return { prediction: "unknown", confidence: 0, error: "api_error" };
    }

    const result = await response.json();
    return result;
  } catch (error) {
    console.error("[PhishGuard] Network error:", error.message);
    // Backend may still be starting (e.g. right after a reboot) — wait for it
    // and retry once before giving up.
    if (await waitForBackend(15000)) {
      try {
        const retry = await fetch(`${API_BASE}/scan`, {
          method: "POST",
          headers: headers,
          body: JSON.stringify({ url: url, analysis: includeAnalysis }),
        });
        if (retry.ok) return await retry.json();
        if (retry.status === 401) {
          const newToken = await reAuthenticate();
          if (newToken) {
            const retryAuth = await fetch(`${API_BASE}/scan`, {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${newToken}`,
              },
              body: JSON.stringify({ url: url, analysis: includeAnalysis }),
            });
            if (retryAuth.ok) return await retryAuth.json();
          }
        }
      } catch (e2) {
        console.error("[PhishGuard] Retry after backend wait also failed:", e2.message);
      }
    }
    return { prediction: "unknown", confidence: 0, error: "network_error" };
  }
}

/**
 * Scan a decoded QR-code payload (or URL).
 */
async function scanQRURL(url) {
  return scanURL(url, false);
}

/**
 * Process a scan result and update storage + content script overlay.
 * UPDATED: Sends 'showSafeAlert' for safe sites and 'showPhishingAlert' for phishing sites.
 */
async function processScanResult(url, result, tabId) {
  // Normalize string casing to lower case ("Phishing" / "PHISHING" -> "phishing")
  const rawPrediction = (result.prediction || "unknown").toString().toLowerCase();

  const validPredictions = ["safe", "suspicious", "phishing", "unknown"];
  const prediction = validPredictions.includes(rawPrediction)
    ? rawPrediction
    : "unknown";

  const scanData = {
    url: url,
    prediction: prediction,
    confidence: result.confidence || 0,
    risk_score: result.risk_score || 0,
    risk_level: result.risk_level || "unknown",
    recommendation: result.recommendation || "",
    final_url: result.final_url || url,
    explanation: Array.isArray(result.explanation) ? result.explanation : [],
    sandbox: result.sandbox || null,
    redirect_chain: Array.isArray(result.redirect_chain) ? result.redirect_chain : [],
    risk_factors: Array.isArray(result.risk_factors) ? result.risk_factors : [],
    brand: result.brand || null,
    visual_brand: result.visual_brand || null,
    analysis_depth: result.analysis_depth || null,
    auto_escalated: Boolean(result.auto_escalated),
    timestamp: Date.now(),
    scanId: result.id || null,
  };

  // Store the latest scan result for the popup to display
  await chrome.storage.local.set({
    lastScan: scanData,
  });

  // Update badge icon
  if (tabId) {
    updateBadge(prediction, tabId);
  }

  // Handle message delivery with dynamic script injection fallback
  if (prediction === "phishing") {
    const alertPayload = {
      action: "showPhishingAlert",
      url: url,
      confidence: result.confidence,
      risk_score: result.risk_score,
      brand: result.brand,
      topFactors: Array.isArray(result.risk_factors)
        ? result.risk_factors.slice(0, 4).map((f) => f.name)
        : [],
    };

    if (tabId) {
      chrome.tabs.sendMessage(tabId, alertPayload).catch(() => {
        // If content script is not yet listening, dynamically inject content.js and re-send
        chrome.scripting.executeScript({
          target: { tabId: tabId },
          files: ["content.js"]
        }).then(() => {
          setTimeout(() => {
            chrome.tabs.sendMessage(tabId, alertPayload).catch((err) => {
              console.log("[PhishGuard] Script injection overlay error:", err.message);
            });
          }, 100);
        }).catch(err => {
          console.log("[PhishGuard] Script injection blocked on this tab:", err.message);
        });
      });
    }
  } else if (prediction === "safe" && tabId) {
    const safePayload = {
      action: "showSafeAlert",
      url: url
    };

    chrome.tabs.sendMessage(tabId, safePayload).catch(() => {
      // If content script is not yet listening, dynamically inject content.js and re-send
      chrome.scripting.executeScript({
        target: { tabId: tabId },
        files: ["content.js"]
      }).then(() => {
        setTimeout(() => {
          chrome.tabs.sendMessage(tabId, safePayload).catch((err) => {
            console.log("[PhishGuard] Script injection safe banner error:", err.message);
          });
        }, 100);
      }).catch(err => {
        console.log("[PhishGuard] Script injection blocked on this tab:", err.message);
      });
    });
  } else if (tabId) {
    chrome.tabs.sendMessage(tabId, { action: "clearAlert" }).catch(() => {});
  }
}

/**
 * Update the browser action badge to show scan status.
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

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  const url = tab.url;
  if (!url || (!url.startsWith("http://") && !url.startsWith("https://"))) return;

  // Skip localhost / API server URLs
  if (url.includes("localhost:8000") || url.includes("127.0.0.1:8000")) return;

  const urlChanged = changeInfo.url && changeInfo.url !== (tabLastScannedUrl.get(tabId) || null);
  const finishedLoading = changeInfo.status === "complete";

  if (!urlChanged && !finishedLoading) return;
  if (finishedLoading && !urlChanged && tabLastScannedUrl.get(tabId) === url) return;

  if (recentlyScanned.has(url)) return;
  if (tabScanInFlight.has(tabId)) return;

  tabLastScannedUrl.set(tabId, url);
  recentlyScanned.add(url);
  setTimeout(() => recentlyScanned.delete(url), SCAN_COOLDOWN_MS);

  const scanPromise = (async () => {
    const result = await scanURL(url, true);
    await processScanResult(url, result, tabId);
  })()
    .catch((err) => console.error("[PhishGuard] auto-scan error:", err))
    .finally(() => {
      tabScanInFlight.delete(tabId);
    });

  tabScanInFlight.set(tabId, scanPromise);
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "backendStatus") {
    const timeoutMs =
      message.maxWaitMs != null ? Number(message.maxWaitMs) : 30000;
    waitForBackend(timeoutMs).then((ready) => {
      sendResponse({ ready });
    });
    return true;
  }

  if (message.action === "waitForBackend") {
    waitForBackend(Number(message.maxWaitMs) || 30000).then((ready) => {
      sendResponse({ ready });
    });
    return true;
  }

  if (message.action === "scanCurrentTab") {
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
    return true;
  }

  if (message.action === "getLastScan") {
    chrome.storage.local.get(["lastScan"], (result) => {
      sendResponse({ lastScan: result.lastScan || null });
    });
    return true;
  }

  if (message.action === "scanUrlText") {
    const url = typeof message.url === "string" ? message.url.trim() : "";
    if (!url || (!url.startsWith("http://") && !url.startsWith("https://"))) {
      sendResponse({ success: false, error: "Not a valid HTTP/HTTPS URL" });
      return;
    }
    (async () => {
      try {
        const result = await scanURL(url, true);
        if (result && result.error === "invalid_url") {
          // DNS/format validation failed — report it without touching the
          // badge/overlay state (no real scan happened).
          sendResponse({ success: true, result: result });
          return;
        }
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
    return true;
  }
});