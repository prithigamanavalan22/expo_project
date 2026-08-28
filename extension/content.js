/**
 * PhishGuard Content Script
 *
 * Injects into every web page the user visits.
 * Receives messages from background.js and displays visual alerts.
 *
 * SECURITY NOTES:
 * - Uses DOM APIs (createElement, textContent) — NEVER innerHTML — to prevent XSS.
 * - No user-supplied data is written as HTML; all text is set via textContent.
 * - Alert overlay is scoped to a single DOM element with a unique ID.
 * - Cleanup removes the element completely when no longer needed.
 */

const OVERLAY_ID = "phishguard-alert-overlay";

/**
 * Create and display a high-visibility phishing warning overlay.
 * The overlay blocks the page content and warns the user.
 *
 * SECURITY: Uses textContent (not innerHTML) for all user-facing text.
 * The confidence value is cast to a Number to prevent injection.
 *
 * @param {string} url - The phishing URL detected
 * @param {number} confidence - The model's confidence score (0-1)
 */
function showPhishingOverlay(url, confidence) {
  // Remove any existing overlay first
  removeOverlay();

  // --- Create overlay container ---
  const overlay = document.createElement("div");
  overlay.id = OVERLAY_ID;

  // Apply styles via CSSOM (no inline style attribute = CSP-safe)
  const s = overlay.style;
  s.position = "fixed";
  s.top = "0";
  s.left = "0";
  s.width = "100vw";
  s.height = "100vh";
  s.zIndex = "2147483647"; // Maximum z-index to overlay everything
  s.backgroundColor = "rgba(0, 0, 0, 0.92)";
  s.display = "flex";
  s.alignItems = "center";
  s.justifyContent = "center";
  s.fontFamily = "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif";

  // --- Card container ---
  const card = document.createElement("div");
  const cs = card.style;
  cs.backgroundColor = "#1a1a2e";
  cs.border = "3px solid #ef4444";
  cs.borderRadius = "16px";
  cs.padding = "40px";
  cs.maxWidth = "520px";
  cs.textAlign = "center";
  cs.boxShadow = "0 0 60px rgba(239, 68, 68, 0.4)";

  // --- Warning icon (text, not image — no external resource loading) ---
  const icon = document.createElement("div");
  icon.textContent = "⚠";
  const is = icon.style;
  is.fontSize = "64px";
  is.marginBottom = "12px";
  card.appendChild(icon);

  // --- Title ---
  const title = document.createElement("h1");
  title.textContent = "PHISHING DETECTED";
  const ts = title.style;
  ts.color = "#ef4444";
  ts.fontSize = "28px";
  ts.margin = "8px 0";
  ts.letterSpacing = "2px";
  card.appendChild(title);

  // --- Subtitle ---
  const subtitle = document.createElement("p");
  subtitle.textContent = "This website has been flagged as a potential phishing site.";
  const ss = subtitle.style;
  ss.color = "#e5e7eb";
  ss.fontSize = "16px";
  ss.margin = "8px 0";
  card.appendChild(subtitle);

  // --- URL display (escaped via textContent — XSS safe) ---
  const urlLabel = document.createElement("p");
  urlLabel.textContent = "Flagged URL:";
  const uls = urlLabel.style;
  uls.color = "#9ca3af";
  uls.fontSize = "12px";
  uls.marginBottom = "4px";
  card.appendChild(urlLabel);

  const urlDisplay = document.createElement("div");
  urlDisplay.textContent = url;
  const uds = urlDisplay.style;
  uds.backgroundColor = "#111827";
  uds.color = "#f87171";
  uds.padding = "10px 14px";
  uds.borderRadius = "8px";
  uds.fontSize = "13px";
  uds.wordBreak = "break-all";
  uds.border = "1px solid #374151";
  uds.marginBottom = "16px";
  card.appendChild(urlDisplay);

  // --- Confidence score (cast to Number — prevents injection) ---
  const confidenceValue = Number(confidence) || 0;
  const confidenceText = document.createElement("p");
  confidenceText.textContent = `Risk Score: ${(confidenceValue * 100).toFixed(1)}%`;
  const ct = confidenceText.style;
  ct.color = "#fbbf24";
  ct.fontSize = "14px";
  ct.margin = "4px 0 20px";
  card.appendChild(confidenceText);

  // --- Warning message ---
  const warning = document.createElement("p");
  warning.textContent = "Do NOT enter personal information, passwords, or payment details on this site.";
  const ws = warning.style;
  ws.color = "#fbbf24";
  ws.fontSize = "14px";
  ws.fontWeight = "bold";
  ws.margin = "0 0 20px";
  card.appendChild(warning);

  // --- "Go Back" button ---
  const goBackBtn = document.createElement("button");
  goBackBtn.textContent = "← Go Back to Safety";
  const gb = goBackBtn.style;
  gb.backgroundColor = "#ef4444";
  gb.color = "#ffffff";
  gb.border = "none";
  gb.padding = "12px 28px";
  gb.borderRadius = "8px";
  gb.fontSize = "16px";
  gb.fontWeight = "bold";
  gb.cursor = "pointer";
  gb.marginRight = "12px";
  goBackBtn.addEventListener("click", () => {
    window.history.back();
  });
  card.appendChild(goBackBtn);

  // --- "Continue Anyway" button ---
  const continueBtn = document.createElement("button");
  continueBtn.textContent = "Continue at Own Risk →";
  const cb = continueBtn.style;
  cb.backgroundColor = "transparent";
  cb.color = "#9ca3af";
  cb.border = "1px solid #4b5563";
  cb.padding = "12px 28px";
  cb.borderRadius = "8px";
  cb.fontSize = "16px";
  cb.cursor = "pointer";
  continueBtn.addEventListener("click", () => {
    removeOverlay();
  });
  card.appendChild(continueBtn);

  overlay.appendChild(card);
  document.body.appendChild(overlay);
}

/**
 * Remove the phishing overlay from the DOM if it exists.
 * Called when the user clicks "Continue anyway" or when a safe page is loaded.
 */
function removeOverlay() {
  const existing = document.getElementById(OVERLAY_ID);
  if (existing) {
    existing.remove();
  }
}

// ===========================================================================
//  MESSAGE LISTENER — receives commands from background.js
// ===========================================================================

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "showPhishingAlert") {
    // SECURITY: confidence is cast to Number to prevent injection
    showPhishingOverlay(message.url || "Unknown URL", Number(message.confidence) || 0);
    sendResponse({ success: true });
  }

  if (message.action === "clearAlert") {
    removeOverlay();
    sendResponse({ success: true });
  }
});
