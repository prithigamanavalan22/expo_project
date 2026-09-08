/**
 * PhishGuard Popup Script
 *
 * Manages the popup UI: login/register forms, scan button, and history display.
 *
 * SECURITY NOTES:
 * - All dynamic text is set via textContent (not innerHTML) — prevents XSS.
 * - User credentials are sent only to localhost:8000 via HTTPS POST.
 * - JWT token is stored in chrome.storage.local (encrypted by Chrome).
 * - No eval() or dynamic code execution anywhere in this file.
 */

const API_BASE = "http://localhost:8000/api/v1";
const HEALTH_URL = "http://localhost:8000/health";

// ===========================================================================
//  BACKEND READINESS / AUTO-RETRY
//  The backend auto-starts with Windows, but right after a reboot it may still
//  be booting. Instead of immediately showing "Backend not reachable", the
//  popup polls /health and retries the request before giving up.
// ===========================================================================

/**
 * Wait until the backend answers /health. Resolves true when available.
 */
async function waitForBackend(maxWaitMs = 12000) {
  const start = Date.now();
  for (;;) {
    try {
      const resp = await fetch(HEALTH_URL, { method: "GET", cache: "no-store" });
      if (resp.ok) return true;
    } catch (err) {
      // not ready yet — keep polling
    }
    if (Date.now() - start >= maxWaitMs) return false;
    await new Promise((resolve) => setTimeout(resolve, 1500));
  }
}

/**
 * fetch() that auto-waits for the backend and retries the request once before
 * letting the caller's error handling take over.
 */
async function fetchWithBackendRetry(url, options, maxWaitMs = 12000) {
  let lastError;
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      return await fetch(url, options);
    } catch (err) {
      lastError = err;
      if (!(await waitForBackend(maxWaitMs))) break;
    }
  }
  throw lastError;
}

// ===========================================================================
//  DOM Element References
// ===========================================================================

const loginSection = document.getElementById("loginSection");
const registerSection = document.getElementById("registerSection");
const dashboardSection = document.getElementById("dashboardSection");

const usernameInput = document.getElementById("usernameInput");
const passwordInput = document.getElementById("passwordInput");
const loginBtn = document.getElementById("loginBtn");
const loginError = document.getElementById("loginError");

const regUsernameInput = document.getElementById("regUsernameInput");
const regEmailInput = document.getElementById("regEmailInput");
const regPasswordInput = document.getElementById("regPasswordInput");
const registerBtn = document.getElementById("registerBtn");
const registerError = document.getElementById("registerError");

const showRegisterLink = document.getElementById("showRegisterLink");
const showLoginLink = document.getElementById("showLoginLink");

const displayUsername = document.getElementById("displayUsername");
const scanNowBtn = document.getElementById("scanNowBtn");
const scanLoading = document.getElementById("scanLoading");
const scanResultContainer = document.getElementById("scanResultContainer");
const statusCard = document.getElementById("statusCard");
const statusIcon = document.getElementById("statusIcon");
const statusText = document.getElementById("statusText");
const confidenceFill = document.getElementById("confidenceFill");
const scannedUrl = document.getElementById("scannedUrl");
const historyList = document.getElementById("historyList");
const logoutBtn = document.getElementById("logoutBtn");

// New feature elements
const riskMeter = document.getElementById("riskMeter");
const riskValue = document.getElementById("riskValue");
const riskMarker = document.getElementById("riskMarker");
const whySection = document.getElementById("whySection");
const whyList = document.getElementById("whyList");
const sandboxSection = document.getElementById("sandboxSection");
const sandboxGrid = document.getElementById("sandboxGrid");

// New feature display elements
const brandSection = document.getElementById("brandSection");
const brandText = document.getElementById("brandText");
const redirectSection = document.getElementById("redirectSection");
const redirectList = document.getElementById("redirectList");

// Visual brand similarity elements
const visualBrandSection = document.getElementById("visualBrandSection");
const visualBrandText = document.getElementById("visualBrandText");
const visualBrandBar = document.getElementById("visualBrandBar");
const visualBrandMeta = document.getElementById("visualBrandMeta");

// Tab + QR elements
const urlScanTabBtn = document.getElementById("urlScanTabBtn");
const qrScanTabBtn = document.getElementById("qrScanTabBtn");
const urlScanPanel = document.getElementById("urlScanPanel");
const qrScanPanel = document.getElementById("qrScanPanel");
const qrDropzone = document.getElementById("qrDropzone");
const qrFileInput = document.getElementById("qrFileInput");
const qrPreviewWrap = document.getElementById("qrPreviewWrap");
const qrPreview = document.getElementById("qrPreview");
const qrLoading = document.getElementById("qrLoading");
const qrError = document.getElementById("qrError");
const qrResults = document.getElementById("qrResults");

// Environment Sandbox elements
const envScanTabBtn = document.getElementById("envScanTabBtn");
const envScanPanel = document.getElementById("envScanPanel");
const envUrlInput = document.getElementById("envUrlInput");
const envUrlScanBtn = document.getElementById("envUrlScanBtn");
const envUrlLoading = document.getElementById("envUrlLoading");
const envResults = document.getElementById("envResults");
const envResUrl = document.getElementById("envResUrl");
const envVerdict = document.getElementById("envVerdict");
const envChecks = document.getElementById("envChecks");
const envSignals = document.getElementById("envSignals");
const envConfidence = document.getElementById("envConfidence");
const envQrDropzone = document.getElementById("envQrDropzone");
const envQrFileInput = document.getElementById("envQrFileInput");
const envQrLoading = document.getElementById("envQrLoading");
const envQrError = document.getElementById("envQrError");

// Redirect chain awareness elements
const envRedirectSection = document.getElementById("envRedirectSection");
const envRedirectWarn = document.getElementById("envRedirectWarn");
const envRedirectToggle = document.getElementById("envRedirectToggle");
const envRedirectList = document.getElementById("envRedirectList");

// Risk Analysis section elements
const envRiskAnalysis = document.getElementById("envRiskAnalysis");
const raGaugeArc = document.getElementById("raGaugeArc");
const raGaugeValue = document.getElementById("raGaugeValue");
const raVerdict = document.getElementById("raVerdict");
const raRiskLevel = document.getElementById("raRiskLevel");
const raReasons = document.getElementById("raReasons");
const raReasonsList = document.getElementById("raReasonsList");
const raRecommendation = document.getElementById("raRecommendation");
const raStatusPill = document.getElementById("raStatusPill");
const raInsight = document.getElementById("raInsight");
const userBadge = document.getElementById("userBadge");
const raFactorTitle = document.getElementById("raFactorTitle");
const raFactorCount = document.getElementById("raFactorCount");
const raFactorList = document.getElementById("raFactorList");
const raFactorsBlock = document.getElementById("raFactorsBlock");
const raNoFactors = document.getElementById("raNoFactors");
const envValidation = document.getElementById("envValidation");
const raTouchFlow = document.getElementById("raTouchFlow");
const raNoRedirect = document.getElementById("raNoRedirect");
const raRedirectFlow = document.getElementById("raRedirectFlow");

// ===========================================================================
//  VIEW LAYOUT — Env Sandbox is the default/only visible view.
//  The old URL / QR top-nav tabs were removed; their scan controls now live
//  inside the Env Sandbox panel. Guarded so a missing tab row never breaks the
//  script.
// ===========================================================================

function initEnvActive() {
  if (urlScanPanel) urlScanPanel.classList.add("hidden");
  if (qrScanPanel) qrScanPanel.classList.add("hidden");
  if (envScanPanel) envScanPanel.classList.remove("hidden");
}

(function bindEnvView() {
  // If the tab buttons exist (kept in some builds), bind them; otherwise safe.
  if (typeof urlScanTabBtn !== "undefined" && urlScanTabBtn && urlScanTabBtn.addEventListener) {
    urlScanTabBtn.addEventListener("click", () => showScanTab("url"));
  }
  if (typeof qrScanTabBtn !== "undefined" && qrScanTabBtn && qrScanTabBtn.addEventListener) {
    qrScanTabBtn.addEventListener("click", () => showScanTab("qr"));
  }
  if (typeof envScanTabBtn !== "undefined" && envScanTabBtn && envScanTabBtn.addEventListener) {
    envScanTabBtn.addEventListener("click", () => showScanTab("env"));
  }
})();

function showScanTab(tab) {
  const isUrl = tab === "url";
  const isEnv = tab === "env";
  if (typeof urlScanTabBtn !== "undefined" && urlScanTabBtn) urlScanTabBtn.classList.toggle("active", isUrl);
  if (typeof qrScanTabBtn !== "undefined" && qrScanTabBtn) qrScanTabBtn.classList.toggle("active", tab === "qr");
  if (typeof envScanTabBtn !== "undefined" && envScanTabBtn) envScanTabBtn.classList.toggle("active", isEnv);
  if (urlScanPanel) urlScanPanel.classList.toggle("hidden", !isUrl);
  if (qrScanPanel) qrScanPanel.classList.toggle("hidden", tab !== "qr");
  if (envScanPanel) envScanPanel.classList.toggle("hidden", !isEnv);
  if (isEnv) loadEnvironmentFromLastScan();
}

initEnvActive();

// ===========================================================================
//  VIEW MANAGEMENT
// ===========================================================================

function showView(view) {
  // SECURITY: Use classList to toggle visibility — no innerHTML manipulation
  loginSection.classList.toggle("hidden", view !== "login");
  registerSection.classList.toggle("hidden", view !== "register");
  dashboardSection.classList.toggle("hidden", view !== "dashboard");
  if (userBadge) userBadge.classList.toggle("hidden", view !== "dashboard");
}

// ===========================================================================
//  AUTH: LOGIN
// ===========================================================================

loginBtn.addEventListener("click", async () => {
  loginError.style.display = "none";
  const username = usernameInput.value.trim();
  const password = passwordInput.value;

  if (!username || !password) {
    loginError.textContent = "Please fill in all fields.";
    loginError.style.display = "block";
    return;
  }

  loginBtn.disabled = true;
  loginBtn.textContent = "Signing in...";

  try {
    const response = await fetchWithBackendRetry(`${API_BASE}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });

    if (!response.ok) {
      const err = await response.json();
      loginError.textContent = err.detail || "Invalid credentials.";
      loginError.style.display = "block";
      return;
    }

    const data = await response.json();

    // SECURITY: Store token in chrome.storage — encrypted by the browser
    // Credentials are kept so the background can silently re-auth on expiry.
    await chrome.storage.local.set({
      authToken: data.access_token,
      username: username,
      authPassword: password,
    });

    showDashboard(username);
  } catch (err) {
    loginError.textContent = "Cannot reach server. Is the backend running?";
    loginError.style.display = "block";
  } finally {
    loginBtn.disabled = false;
    loginBtn.textContent = "Sign In";
  }
});

// ===========================================================================
//  AUTH: REGISTER
// ===========================================================================

showRegisterLink.addEventListener("click", () => showView("register"));
showLoginLink.addEventListener("click", () => showView("login"));

registerBtn.addEventListener("click", async () => {
  registerError.style.display = "none";
  const username = regUsernameInput.value.trim();
  const email = regEmailInput.value.trim();
  const password = regPasswordInput.value;

  if (!username || !email || !password) {
    registerError.textContent = "Please fill in all fields.";
    registerError.style.display = "block";
    return;
  }

  if (password.length < 8) {
    registerError.textContent = "Password must be at least 8 characters.";
    registerError.style.display = "block";
    return;
  }

  registerBtn.disabled = true;
  registerBtn.textContent = "Creating account...";

  try {
    const response = await fetchWithBackendRetry(`${API_BASE}/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, email, password }),
    });

    if (!response.ok) {
      const err = await response.json();
      registerError.textContent = err.detail || "Registration failed.";
      registerError.style.display = "block";
      return;
    }

    // Auto-login after successful registration
    const loginResponse = await fetchWithBackendRetry(`${API_BASE}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });

    if (loginResponse.ok) {
      const loginData = await loginResponse.json();
      await chrome.storage.local.set({
        authToken: loginData.access_token,
        username: username,
        authPassword: password,
      });
      showDashboard(username);
    } else {
      showView("login");
    }
  } catch (err) {
    registerError.textContent = "Cannot reach server. Is the backend running?";
    registerError.style.display = "block";
  } finally {
    registerBtn.disabled = false;
    registerBtn.textContent = "Create Account";
  }
});

// ===========================================================================
//  DASHBOARD
// ===========================================================================

async function showDashboard(username) {
  // SECURITY: textContent prevents XSS — username is not inserted as HTML
  displayUsername.textContent = username;
  showView("dashboard");

  // Load existing scan result if any
  loadLastScan();

  // Load scan history
  loadHistory();

  // Auto-detect current tab URL and pre-fill + auto-scan
  autoDetectCurrentTab();
}

function autoDetectCurrentTab() {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (chrome.runtime.lastError || !tabs || !tabs.length) return;
    const tab = tabs[0];
    const url = tab.url;
    if (!url || (!url.startsWith("http://") && !url.startsWith("https://"))) return;
    if (url.includes("localhost:8000") || url.includes("127.0.0.1:8000")) return;

    // Pre-fill the URL input
    if (envUrlInput) envUrlInput.value = url;

    // Auto-scan the current tab URL
    envScanUrl(url);
  });
}

// ===========================================================================
//  SCAN BUTTON
// ===========================================================================

scanNowBtn.addEventListener("click", () => {
  scanLoading.classList.remove("hidden");
  scanResultContainer.classList.add("hidden");
  scanNowBtn.disabled = true;

  // Send message to background.js to trigger a scan
  chrome.runtime.sendMessage({ action: "scanCurrentTab" }, (response) => {
    scanLoading.classList.add("hidden");
    scanNowBtn.disabled = false;

    if (response && response.success && response.result) {
      displayScanResult(response.result);
    }
  });
});

function displayScanResult(result) {
  scanResultContainer.classList.remove("hidden");

  const prediction = result.prediction || "unknown";
  const confidence = Number(result.confidence) || 0;
  const confidencePercent = (confidence * 100).toFixed(1);

  // Update card class
  statusCard.className = `status-card ${prediction}`;

  // SECURITY: textContent — never innerHTML for user data
  switch (prediction) {
    case "safe":
      statusIcon.textContent = "✅";
      statusText.textContent = "Safe to Browse";
      break;
    case "phishing":
      statusIcon.textContent = "🚨";
      statusText.textContent = "Phishing Detected!";
      break;
    case "suspicious":
      statusIcon.textContent = "⚠️";
      statusText.textContent = "Suspicious — Proceed with Caution";
      break;
    default:
      statusIcon.textContent = "❓";
      statusText.textContent = "Unable to Determine";
  }

  confidenceFill.style.width = `${confidencePercent}%`;

  // Set bar color based on prediction
  if (prediction === "safe") {
    confidenceFill.style.backgroundColor = "#22c55e";
  } else if (prediction === "phishing") {
    confidenceFill.style.backgroundColor = "#ef4444";
  } else {
    confidenceFill.style.backgroundColor = "#64748b";
  }

  // SECURITY: textContent prevents URL-based XSS
  scannedUrl.textContent = result.url || "N/A";

  // --- Risk Score Meter (0-100) ---
  const riskScore = Number(result.risk_score) || 0;
  renderRiskMeter(riskScore, prediction);

  // --- Explanation list ---
  renderExplanation(result.explanation || []);

  // --- Sandbox / content analysis details ---
  renderSandbox(result.sandbox || null);

  // --- Brand similarity check ---
  renderBrand(result.brand || null);

  // --- Visual brand similarity check (NEW) ---
  renderVisualBrand(result.visual_brand || null);

  // --- Redirect chain ---
  renderRedirectChain(result.redirect_chain || []);

  // --- Structured risk factors (compact tags) ---
  renderRiskFactorTags(result.risk_factors || []);

  // --- Environment Sandbox dashboard (source-node + stats view) ---
  envRenderResult(result);
}

function renderBrand(brand) {
  brandSection.classList.add("hidden");
  if (!brand) return;
  const show =
    (brand.verdict === "lookalike" && brand.brand) ||
    (brand.verdict === "phishing" && brand.threat_matches);
  if (!show) return;
  brandSection.classList.remove("hidden");
  if (brand.verdict === "lookalike") {
    brandText.textContent =
      `⚠ Impersonates "${brand.brand}" (${brand.brand_url}) — not the real site.`;
  } else if (brand.verdict === "phishing") {
    brandText.textContent = `🚨 Flagged by external reputation service: ${(brand.threat_matches || []).join(", ")}`;
  }
}

function renderVisualBrand(visual) {
  if (!visual || !visual.checked) {
    if (visualBrandSection) visualBrandSection.classList.add("hidden");
    return;
  }
  const sim = Number(visual.similarity) || 0;
  const verdict = visual.verdict;
  const brand = visual.best_brand;

  // Only surface meaningful matches; a clean/neutral result hides the block.
  if (verdict === "clean" || verdict === "neutral" || sim < 50) {
    if (visualBrandSection) visualBrandSection.classList.add("hidden");
    return;
  }

  if (visualBrandSection) visualBrandSection.classList.remove("hidden");

  if (verdict === "impersonation") {
    visualBrandText.textContent = `🚨 Visual clone: page renders like "${brand}" (${sim}% similar) but is hosted elsewhere.`;
    visualBrandText.style.color = "#f87171";
    if (visualBrandBar) visualBrandBar.style.backgroundColor = "#ef4444";
  } else {
    visualBrandText.textContent = `⚠ Visual lookalike: appearance is ${sim}% similar to "${brand}".`;
    visualBrandText.style.color = "#fbbf24";
    if (visualBrandBar) visualBrandBar.style.backgroundColor = "#fbbf24";
  }

  if (visualBrandBar) visualBrandBar.style.width = `${Math.max(0, Math.min(100, sim))}%`;

  const comps = visual.component_scores || {};
  const meta = [];
  if (comps.color != null) meta.push(`Color ${comps.color}%`);
  if (comps.perceptual_hash != null) meta.push(`Layout ${comps.perceptual_hash}%`);
  if (comps.layout_edge != null) meta.push(`Edge ${comps.layout_edge}%`);
  const bestUrl = visual.best_brand_url || "";
  if (bestUrl) meta.unshift(bestUrl);
  if (visualBrandMeta) visualBrandMeta.textContent = meta.join(" · ");
}

function renderRedirectChain(chain) {
  while (redirectList.firstChild) {
    redirectList.removeChild(redirectList.firstChild);
  }
  const hops = Array.isArray(chain) ? chain : [];
  if (hops.length === 0) {
    redirectSection.classList.add("hidden");
    return;
  }
  // Only show if there are actual redirects (more than the final entry)
  if (hops.length <= 1 && (hops[0] || {}).final) {
    redirectSection.classList.add("hidden");
    return;
  }
  redirectSection.classList.remove("hidden");
  hops.forEach((hop, i) => {
    const li = document.createElement("li");
    const arrow = i < hops.length - 1 ? " → " : "";
    li.textContent = `${i === 0 ? "Start" : hop.final ? "Final" : `Hop ${i}`}: ${hop.url}  [HTTP ${hop.status}]${arrow}`;
    redirectList.appendChild(li);
  });
}

function renderRiskFactorTags(factors) {
  // remove previous tags container if any
  const oldTags = document.getElementById("factorTags");
  if (oldTags) oldTags.remove();
  const arr = Array.isArray(factors) ? factors : [];
  if (arr.length === 0) return;
  if (arr.length === 1 && arr[0].code === "no_signals") return;

  const container = document.createElement("div");
  container.id = "factorTags";
  container.style.cssText = "margin-top:12px;";
  const title = document.createElement("div");
  title.textContent = "Risk Factors";
  title.style.cssText =
    "font-size:12px;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px;";
  container.appendChild(title);

  const row = document.createElement("div");
  row.style.cssText = "display:flex;flex-wrap:wrap;gap:6px;";
  const colorMap = {
    critical: "#ef4444",
    high: "#f97316",
    medium: "#eab308",
    low: "#64748b",
  };
  arr.forEach((f) => {
    const chip = document.createElement("span");
    chip.textContent = f.name;
    chip.style.cssText =
      `background:${colorMap[f.severity] || "#64748b"}20;color:${colorMap[f.severity] || "#94a3b8"};` +
      "padding:4px 8px;border-radius:999px;font-size:11px;font-weight:600;border:1px solid " +
      `${colorMap[f.severity] || "#64748b"}55;`;
    row.appendChild(chip);
  });
  container.appendChild(row);
  statusCard.appendChild(container);
}

function renderRiskMeter(score, prediction) {
  if (score > 0) {
    riskMeter.classList.remove("hidden");
    riskValue.textContent = `${score} / 100`;
    riskMarker.style.left = `${Math.max(0, Math.min(100, score))}%`;
  } else {
    riskMeter.classList.add("hidden");
  }
}

function renderExplanation(reasons) {
  // SECURITY: Build list items with textContent, never innerHTML
  while (whyList.firstChild) {
    whyList.removeChild(whyList.firstChild);
  }
  if (reasons.length === 0) {
    whySection.style.display = "none";
    return;
  }
  whySection.style.display = "block";
  reasons.forEach((reason) => {
    const li = document.createElement("li");
    li.textContent = reason;
    whyList.appendChild(li);
  });
}

function renderSandbox(sandbox) {
  while (sandboxGrid.firstChild) {
    sandboxGrid.removeChild(sandboxGrid.firstChild);
  }
  if (!sandbox) {
    sandboxSection.style.display = "none";
    return;
  }
  sandboxSection.style.display = "block";

  const addItem = (label, value, good) => {
    const item = document.createElement("div");
    item.className = "sandbox-item";
    const lbl = document.createElement("span");
    lbl.className = "sb-label";
    lbl.textContent = label;
    const val = document.createElement("span");
    val.className = good ? "sb-good" : "sb-bad";
    val.textContent = value;
    item.appendChild(lbl);
    item.appendChild(val);
    sandboxGrid.appendChild(item);
  };

  if (sandbox.unreachable) {
    addItem("Page reachable", "No (could not fetch)", true);
    return;
  }
  const forms = Number(sandbox.credential_forms) || 0;
  addItem("Login/credential forms", String(forms), forms === 0);
  addItem("Insecure form submits", String(sandbox.insecure_forms || 0), !sandbox.insecure_forms);
  addItem("External links", String(sandbox.external_links || 0), !sandbox.external_links);
  addItem("Domain mismatch", sandbox.domain_mismatch ? "Yes" : "No", !sandbox.domain_mismatch);
  addItem("Redirects", sandbox.redirected ? "Yes" : "No", !sandbox.redirected);
  addItem("Hidden iframes", sandbox.has_iframe ? "Yes" : "No", !sandbox.has_iframe);

  // --- Deep static-analysis signals (added with the deepened sandbox) ---
  addItem("Suspicious login page", sandbox.suspicious_login_page ? "Yes" : "No", !sandbox.suspicious_login_page);
  const anchors = Array.isArray(sandbox.suspicious_anchors) ? sandbox.suspicious_anchors : [];
  addItem("Social-eng link text", anchors.length ? String(anchors.length) : "0", anchors.length === 0);
  const hidden = Number(sandbox.hidden_fields) || 0;
  addItem("Hidden form fields", String(hidden), hidden === 0);
  const ratio = Number(sandbox.external_link_ratio) || 0;
  addItem("External link ratio", Math.round(ratio * 100) + "%", ratio < 0.9);

  // Technology fingerprint (informational)
  const tech = Array.isArray(sandbox.detected_technologies)
    ? sandbox.detected_technologies
    : [];
  if (tech.length) {
    const techItem = document.createElement("div");
    techItem.className = "sandbox-item";
    const techLbl = document.createElement("span");
    techLbl.className = "sb-label";
    techLbl.textContent = "Detected tech";
    const techVal = document.createElement("span");
    techVal.className = "sb-good";
    techVal.textContent = tech.join(", ");
    techItem.appendChild(techLbl);
    techItem.appendChild(techVal);
    sandboxGrid.appendChild(techItem);
  }
}

// ===========================================================================
//  QR CODE SCANNER (quishing detection)
// ===========================================================================

qrDropzone.addEventListener("click", () => qrFileInput.click());
qrFileInput.addEventListener("change", (e) => {
  const file = e.target.files && e.target.files[0];
  if (!file) return;
  readAndScanQRFiles(file);
});

function readAndScanQRFiles(file) {
  const reader = new FileReader();
  reader.onload = (ev) => {
    const dataUrl = ev.target.result; // "data:image/png;base64,...."
    // Extract pure base64 payload (drop the data URL prefix)
    const commaIdx = dataUrl.indexOf(",");
    const base64 = commaIdx >= 0 ? dataUrl.slice(commaIdx + 1) : dataUrl;

    // Show preview thumbnail
    qrPreview.src = dataUrl;
    qrPreviewWrap.classList.remove("hidden");

    qrError.style.display = "none";
    qrResults.innerHTML = "";
    qrLoading.classList.remove("hidden");

    // SECURITY: Send the image DIRECTLY from the popup to the whitelisted
    // backend (popup shares the extension's host_permissions). Decoding happens
    // server-side in-memory — nothing is executed from the image.
    // NOTE: We do NOT use chrome.runtime.sendMessage here because MV3 message
    // passing has a payload size limit that real camera photos easily exceed.
    scanQRFetch(base64)
      .then((res) => {
        qrLoading.classList.add("hidden");
        if (res && res.success) {
          renderQRResult(res.result);
        } else {
          qrError.textContent =
            (res && res.error) || "QR scan failed. Please check the image.";
          qrError.style.display = "block";
        }
      })
      .catch((err) => {
        qrLoading.classList.add("hidden");
        qrError.textContent = err.message || "QR scan failed. Please check the image.";
        qrError.style.display = "block";
      });
  };
  reader.readAsDataURL(file);
}

/**
 * POST the QR image bytes (base64) to the backend QR scan endpoint directly.
 * Avoids MV3 message-size limits for large photos.
 */
async function scanQRFetch(imageBase64) {
  const token = await getStoredToken();
  const headers = { "Content-Type": "application/json" };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  try {
    const response = await fetchWithBackendRetry(`${API_BASE}/scan/qr`, {
      method: "POST",
      headers: headers,
      body: JSON.stringify({ image_base64: imageBase64, scan_url: true }),
    });

    if (!response.ok) {
      let detail = `API error ${response.status}`;
      try {
        const errBody = await response.json();
        if (errBody.detail) detail = errBody.detail;
      } catch (_) {}
      if (response.status === 401) detail = "Authentication required. Please log in.";
      return { success: false, error: detail };
    }

    const data = await response.json();
    return { success: true, result: data };
  } catch (error) {
    if (error && (error.message || "").toLowerCase().includes("failed to fetch")) {
      return {
        success: false,
        error: "Cannot reach the backend. Is `python run_server.py` running?",
      };
    }
    return { success: false, error: error.message || "Network error." };
  }
}

function renderQRResult(res) {
  // SECURITY: build DOM via textContent only
  while (qrResults.firstChild) {
    qrResults.removeChild(qrResults.firstChild);
  }

  // Overall summary banner
  const results = res.results || [];
  const anyPhish = results.some((r) => r.prediction === "phishing");
  const anySusp = results.some((r) => r.prediction === "suspicious");

  const banner = document.createElement("div");
  banner.className = `qr-result-card ${anyPhish ? "phishing" : anySusp ? "suspicious" : "safe"}`;
  if (res.no_urls) {
    banner.textContent = res.summary || "QR decoded but contained no URL.";
    qrResults.appendChild(banner);
    return;
  }
  banner.textContent = res.summary || "QR scan complete.";
  qrResults.appendChild(banner);

  if (anyPhish) {
    const danger = document.createElement("div");
    danger.className = "danger-banner";
    danger.textContent =
      "⚠️ WARNING: This QR code contains a phishing URL. Do not scan or open it.";
    qrResults.appendChild(danger);
  }

  // Decoded payloads
  const decodedLabel = document.createElement("div");
  decodedLabel.textContent = `Decoded from QR (${res.decoded.length}):`;
  decodedLabel.style.fontSize = "12px";
  decodedLabel.style.color = "#94a3b8";
  decodedLabel.style.margin = "10px 0 4px";
  qrResults.appendChild(decodedLabel);

  res.decoded.forEach((d) => {
    const chip = document.createElement("div");
    chip.className = "qr-url";
    chip.textContent = d;
    qrResults.appendChild(chip);
  });

  // Per-URL detailed results
  results.forEach((r) => {
    const card = document.createElement("div");
    card.className = `qr-result-card ${r.prediction}`;
    card.style.marginTop = "10px";

    const head = document.createElement("div");
    head.textContent =
      r.prediction === "safe"
        ? "✅ Safe"
        : r.prediction === "phishing"
        ? "🚨 Phishing"
        : "⚠️ Suspicious";
    card.appendChild(head);

    const score = document.createElement("div");
    score.textContent = `Risk score: ${r.risk_score}/100`;
    score.style.fontSize = "12px";
    score.style.color = "#94a3b8";
    score.style.marginTop = "4px";
    card.appendChild(score);

    const urlEl = document.createElement("div");
    urlEl.className = "qr-url";
    urlEl.textContent = r.url;
    card.appendChild(urlEl);

    // Brand lookalike warning
    if (r.brand && r.brand.verdict === "lookalike" && r.brand.brand) {
      const b = document.createElement("div");
      b.textContent = `Impersonates "${r.brand.brand}" (${r.brand.brand_url})`;
      b.style.cssText = "color:#fbbf24;font-size:12px;font-weight:600;margin-top:6px;";
      card.appendChild(b);
    }

    // Risk factor tags
    if (r.risk_factors && r.risk_factors.length) {
      const colors = { critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#64748b" };
      const tagRow = document.createElement("div");
      tagRow.style.cssText = "display:flex;flex-wrap:wrap;gap:4px;margin-top:6px;";
      r.risk_factors
        .filter((f) => f.code !== "no_signals")
        .slice(0, 5)
        .forEach((f) => {
          const c = colors[f.severity] || "#64748b";
          const chip = document.createElement("span");
          chip.textContent = f.name;
          chip.style.cssText =
            `background:${c}20;color:${c};padding:2px 6px;border-radius:999px;` +
            `font-size:10px;font-weight:600;border:1px solid ${c}55;`;
          tagRow.appendChild(chip);
        });
      card.appendChild(tagRow);
    }

    // Explanations
    if (r.explanation && r.explanation.length) {
      const whyHead = document.createElement("div");
      whyHead.textContent = "Why:";
      whyHead.style.fontSize = "11px";
      whyHead.style.color = "#64748b";
      whyHead.style.marginTop = "6px";
      card.appendChild(whyHead);
      const ul = document.createElement("ul");
      ul.style.margin = "4px 0 0 16px";
      r.explanation.forEach((reason) => {
        const li = document.createElement("li");
        li.textContent = reason;
        li.style.fontSize = "11px";
        li.style.color = "#cbd5e1";
        li.style.marginBottom = "2px";
        ul.appendChild(li);
      });
      card.appendChild(ul);
    }

    qrResults.appendChild(card);
  });
}

// ===========================================================================
//  LOAD LAST SCAN (from chrome.storage)
// ===========================================================================

function loadLastScan() {
  chrome.storage.local.get(["lastScan"], (result) => {
    if (result.lastScan) {
      displayScanResult(result.lastScan);
      envRenderResult(result.lastScan);
    }
  });
}

// ===========================================================================
//  RISK ANALYSIS RENDERING
//  Populates the Risk Analysis section of the URL scan result page:
//   - Circular 0-100 gauge + verdict + risk level
//   - Main reasons (explanation)
//   - Recommended action
//   - Structured risk factors (status/name/description/importance)
//   - "What happens if I touch this URL?" educational flow (NEVER navigates)
//   - Redirect visualization
//  SECURITY: All DOM built with createElement/textContent — never innerHTML.
// ===========================================================================

function clearNode(node) {
  if (!node) return;
  while (node.firstChild) node.removeChild(node.firstChild);
}

function fallbackRiskLevel(pred) {
  if (pred === "safe") return "low";
  if (pred === "suspicious") return "suspicious";
  if (pred === "phishing") return "high";
  return "unknown";
}

function fallbackRecommendation(pred) {
  switch (pred) {
    case "phishing":
      return "Do not enter passwords, OTPs, banking information, or other sensitive information on this website.";
    case "suspicious":
      return "Proceed with caution. Verify the exact domain in the address bar and look for HTTPS before entering personal or financial information.";
    case "safe":
      return "No significant threats detected. This URL appears safe to browse.";
    default:
      return "Unable to determine risk. Avoid sharing sensitive information until the site is verified.";
  }
}

function factorStatus(f) {
  if (f.status) return f.status;
  const sev = f.severity;
  if (sev === "critical" || sev === "high") return "danger";
  return "warning";
}

const FACTOR_STATUS_LABEL = { safe: "SAFE", warning: "WARNING", danger: "DANGEROUS" };
const FACTOR_ICON = { safe: "✓", warning: "⚠", danger: "🚨" };
const SEVERITY_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };

function envRenderRiskAnalysis(result, redirected) {
  if (!envRiskAnalysis) return;
  envRiskAnalysis.classList.remove("hidden");

  const pred = (result.prediction || "unknown").toString().toLowerCase();
  const score = Math.max(0, Math.min(100, Number(result.risk_score) || 0));

  // ---- 1. Circular gauge (SVG ring, r=52) ----
  const C = 2 * Math.PI * 52;
  if (raGaugeArc) {
    raGaugeArc.style.strokeDasharray = String(C);
    // Double rAF lets the CSS stroke-dashoffset transition animate smoothly.
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        raGaugeArc.style.strokeDashoffset = String(C * (1 - score / 100));
      });
    });
  }
  const gaugeColor =
    pred === "safe" ? "#10B981" :
    pred === "phishing" ? "#EF4444" :
    pred === "suspicious" ? "#FBBF24" : "#8F9CAE";
  if (raGaugeArc) raGaugeArc.style.stroke = gaugeColor;
  if (raGaugeValue) raGaugeValue.textContent = String(score);

  // ---- 2. Verdict + risk level ----
  const verdictLabel =
    pred === "safe" ? "🟢 SAFE" :
    pred === "phishing" ? "🔴 PHISHING" :
    pred === "suspicious" ? "🟡 SUSPICIOUS" : "❓ Unable to Determine";
  if (raVerdict) {
    raVerdict.textContent = verdictLabel;
    raVerdict.className = `ra-verdict ${pred}`;
  }
  const riskLevel = result.risk_level || fallbackRiskLevel(pred);
  const levelLabel =
    riskLevel === "low" ? "Low Risk" :
    riskLevel === "high" ? "High Risk" :
    riskLevel === "suspicious" ? "Suspicious" : "Unknown risk";
  if (raRiskLevel) raRiskLevel.textContent = `Risk Score ${score}/100 · ${levelLabel}`;

  // ---- 3. Main reasons ----
  const reasons = Array.isArray(result.explanation) ? result.explanation : [];
  clearNode(raReasonsList);
  if (raReasons) raReasons.style.display = reasons.length ? "" : "none";
  reasons.forEach((reason) => {
    const li = document.createElement("li");
    li.textContent = reason;
    if (raReasonsList) raReasonsList.appendChild(li);
  });

  // ---- 4. Recommended action ----
  const rec = result.recommendation || fallbackRecommendation(pred);
  if (raRecommendation) {
    raRecommendation.textContent = rec;
    raRecommendation.className = `ra-recommend ${pred}`;
  }

  // ---- 4b. Status pill badge (SAFE / SUSPICIOUS / DANGEROUS / UNKNOWN) ----
  const pillText =
    pred === "safe" ? "SAFE" :
    pred === "phishing" ? "DANGEROUS" :
    pred === "suspicious" ? "SUSPICIOUS" : "UNKNOWN";
  if (raStatusPill) {
    raStatusPill.textContent = pillText;
    raStatusPill.className = `ra-status-pill ${pred}`;
  }

  // ---- 4c. Insight callout — headline reason behind the verdict ----
  const insight = reasons[0] || rec;
  if (raInsight) {
    raInsight.textContent = insight;
    raInsight.className = `ra-callout ${pred}`;
  }

  // ---- 5. Risk factors (safe results: none shown) ----
  const showFactors = pred !== "safe";
  const factors = showFactors && Array.isArray(result.risk_factors) ? result.risk_factors : [];
  clearNode(raFactorList);
  if (raFactorsBlock) raFactorsBlock.classList.toggle("hidden", !showFactors);
  if (raNoFactors) raNoFactors.classList.toggle("hidden", showFactors);
  if (raFactorTitle) raFactorTitle.textContent = "Risk Factors";
  if (raFactorCount) raFactorCount.textContent = factors.length ? `${factors.length} found` : "";

  factors.forEach((f) => {
    const st = factorStatus(f);
    const li = document.createElement("li");
    li.className = `ra-factor ${st}`;

    const icon = document.createElement("span");
    icon.className = "ra-factor-icon";
    icon.textContent = FACTOR_ICON[st] || "•";
    li.appendChild(icon);

    const body = document.createElement("div");
    body.className = "ra-factor-body";

    const name = document.createElement("div");
    name.className = "ra-factor-name";
    name.textContent = f.name || "Unknown factor";
    const badge = document.createElement("span");
    badge.className = `ra-factor-status ${st}`;
    badge.textContent = FACTOR_STATUS_LABEL[st] || "WARNING";
    name.appendChild(badge);
    body.appendChild(name);

    if (f.description) {
      const desc = document.createElement("div");
      desc.className = "ra-factor-desc";
      desc.textContent = f.description;
      body.appendChild(desc);
    }

    const imp = document.createElement("div");
    imp.className = "ra-factor-imp";
    imp.textContent = `Importance: ${SEVERITY_LABEL[f.severity] || f.severity || "Unknown"}`;
    body.appendChild(imp);

    li.appendChild(body);
    if (raFactorList) raFactorList.appendChild(li);
  });

  // ---- 6. "What happens if I touch this URL?" (educational, never navigates) ----
  clearNode(raTouchFlow);
  const risky = pred === "phishing" || pred === "suspicious";
  const steps = risky
    ? [
        { text: "You tap the URL", cls: "warn" },
        { text: "Browser opens the destination", cls: "warn" },
        { text: redirected ? "The URL redirects to another website" : "URL may redirect to another website", cls: "danger" },
        { text: "Website may attempt to collect sensitive information", cls: "danger" },
        { text: "Possible phishing/fraud risk", cls: "danger" },
      ]
    : [
        { text: "You tap the URL", cls: "safe" },
        { text: "Browser opens the expected website", cls: "safe" },
        { text: "No suspicious behavior detected", cls: "safe" },
      ];
  steps.forEach((step, i) => {
    const li = document.createElement("li");
    li.className = step.cls;
    const dot = document.createElement("span");
    dot.className = "ra-flow-dot";
    li.appendChild(dot);
    const txt = document.createElement("span");
    txt.textContent = step.text;
    li.appendChild(txt);
    if (raTouchFlow) raTouchFlow.appendChild(li);
    if (i < steps.length - 1) {
      const arrow = document.createElement("div");
      arrow.className = "ra-flow-arrow";
      arrow.textContent = "↓";
      if (raTouchFlow) raTouchFlow.appendChild(arrow);
    }
  });

  // ---- 7. Redirect visualization ----
  const chain = Array.isArray(result.redirect_chain) ? result.redirect_chain : [];
  clearNode(raRedirectFlow);
  if (!redirected) {
    if (raNoRedirect) raNoRedirect.textContent = "No redirect detected.";
    if (raRedirectFlow) raRedirectFlow.classList.add("hidden");
    return;
  }
  if (raNoRedirect) raNoRedirect.textContent = "";
  if (raRedirectFlow) raRedirectFlow.classList.remove("hidden");
  chain.forEach((hop, i) => {
    const li = document.createElement("li");
    li.className = hop.final ? "ra-final" : "";
    const label = i === 0 ? "Original" : hop.final ? "Final" : `Redirect ${i}`;
    li.textContent = `${label}: ${hop.url}  [HTTP ${hop.status}]`;
    if (raRedirectFlow) raRedirectFlow.appendChild(li);
    if (i < chain.length - 1) {
      const arrow = document.createElement("div");
      arrow.className = "ra-redirect-arrow";
      arrow.textContent = "↓";
      if (raRedirectFlow) raRedirectFlow.appendChild(arrow);
    }
  });
}

// ===========================================================================
//  ENVIRONMENT SANDBOX
//  Minimal view: inline Scan URL + Scan QR inputs. After a scan, shows the
//  Source Node verdict badge and the Checks / Signals / Confidence stats.
// ===========================================================================

// DNS / URL-format validation banner shown BEFORE the phishing result.
function envRenderValidation(result) {
  if (!envValidation) return;
  clearNode(envValidation);

  if (result && result.error === "invalid_url" && result.detail) {
    const d = result.detail;
    envValidation.className = "env-validation err";
    const main = document.createElement("div");
    main.textContent = d.message || "Is not valid URL";
    envValidation.appendChild(main);
    if (d.explanation) {
      const sub = document.createElement("div");
      sub.className = "env-validation-sub";
      sub.textContent = d.explanation;
      envValidation.appendChild(sub);
    }
    return;
  }

  if (result && result.dns_valid) {
    envValidation.className = "env-validation ok";
    const main = document.createElement("div");
    main.textContent = "URL is reachable through DNS";
    envValidation.appendChild(main);
    const sub = document.createElement("div");
    sub.className = "env-validation-sub";
    sub.textContent = "Continue to PhishGuard analysis..." +
      (result.dns_hostname ? ` (${result.dns_hostname})` : "");
    envValidation.appendChild(sub);
    return;
  }

  if (result && result.dns_valid === false) {
    envValidation.className = "env-validation warn";
    const main = document.createElement("div");
    main.textContent = "DNS check: domain could not be resolved";
    envValidation.appendChild(main);
    const sub = document.createElement("div");
    sub.className = "env-validation-sub";
    sub.textContent = "The URL did not resolve via DNS, so the verdict below is " +
      "based on URL characteristics only. PhishGuard still never opened the URL.";
    envValidation.appendChild(sub);
    return;
  }

  envValidation.classList.add("hidden");
}

function envRenderResult(result) {
  if (!result) {
    if (envResults) envResults.classList.add("hidden");
    if (envRiskAnalysis) envRiskAnalysis.classList.add("hidden");
    envRenderValidation(null);
    return;
  }
  if (envResults) envResults.classList.remove("hidden");
  envRenderValidation(result);

  const pred = result.prediction || "no_data";
  const url = result.url || "N/A";

  if (envResUrl) {
    envResUrl.textContent = url;
    envResUrl.style.color = pred === "phishing" ? "#EF4444" : "#8F9CAE";
  }

  const verdictText =
    pred === "phishing" ? "Status Verdict: PHISHING" :
    pred === "suspicious" ? "Status Verdict: Suspicious" :
    pred === "safe" ? "Status Verdict: Standard Consumer" :
    "Status Verdict: No Data";
  if (envVerdict) {
    envVerdict.textContent = verdictText;
    envVerdict.style.color = pred === "phishing" ? "#EF4444" : pred === "suspicious" ? "#FBBF24" : "#00FF66";
  }

  // Stats: Checks = 4 probes, Signals = flagged signals, Confidence.
  const sb = result.sandbox || null;
  const brand = result.brand || null;
  let signaled = 0;
  if (pred === "phishing") signaled = 4;
  else if (pred === "suspicious") signaled = 2;
  else if (brand && brand.verdict === "lookalike") signaled = 1;
  else if (sb && (sb.domain_mismatch || sb.suspicious_login_page)) signaled = 1;

  // If the URL forwards through redirects, show the "Redirection" box and
  // count it as an additional flagged signal.
  const chain = Array.isArray(result.redirect_chain) ? result.redirect_chain : [];
  const redirected = chain.length > 1 && !(chain.length === 1 && chain[0] && chain[0].final);
  if (redirected) signaled += 1;
  renderEnvRedirects(chain, redirected);
  envRenderRiskAnalysis(result, redirected);

  if (envChecks) envChecks.textContent = "4 Probes";
  if (envSignals) {
    envSignals.textContent = signaled + " Flagged";
    envSignals.style.color = signaled > 0 ? "#EF4444" : "#10B981";
  }
  const conf = (Number(result.confidence) || 0) * 100;
  if (envConfidence) envConfidence.textContent = conf.toFixed(1) + "%";
}

// ===========================================================================
//  REDIRECCTION AWARENESS
//  When the scanner unwraps a multi-hop redirect chain, surface it in the env
//  dashboard: a warning plus a button that reveals each hop in the chain.
// ===========================================================================

let envRedirectListOpen = false;

function renderEnvRedirects(chain, redirected) {
  if (!envRedirectSection) return;
  if (!redirected) {
    envRedirectSection.classList.add("hidden");
    envRedirectListOpen = false;
    return;
  }

  const hops = Array.isArray(chain) ? chain : [];
  envRedirectSection.classList.remove("hidden");
  envRedirectWarn.textContent =
    `Multiple redirects detected — this URL forwards through ${hops.length - 1} hop(s) ` +
    `before reaching its base landing page.`;

  // (Re)build the chain list
  while (envRedirectList.firstChild) {
    envRedirectList.removeChild(envRedirectList.firstChild);
  }
  hops.forEach((hop, i) => {
    const li = document.createElement("li");
    li.className = "env-redirect-hop";
    const arrow = i < hops.length - 1 ? " → " : " ✔";
    li.textContent = `${i === 0 ? "Start" : hop.final ? "Final" : `Hop ${i}`}: ${hop.url}  [HTTP ${hop.status}]${arrow}`;
    envRedirectList.appendChild(li);
  });

  if (envRedirectToggle) {
    envRedirectToggle.textContent = envRedirectListOpen ? "Hide Redirect Chain" : "View Redirect Chain";
  }
  if (envRedirectList) envRedirectList.classList.toggle("hidden", !envRedirectListOpen);
}

if (envRedirectToggle) {
  envRedirectToggle.addEventListener("click", () => {
    envRedirectListOpen = !envRedirectListOpen;
    envRedirectToggle.textContent = envRedirectListOpen ? "Hide Redirect Chain" : "View Redirect Chain";
    if (envRedirectList) envRedirectList.classList.toggle("hidden", !envRedirectListOpen);
  });
}

// Guards against out-of-order scan responses. The popup auto-scans the current
// (possibly safe) tab on open; if that slow auto-scan completes AFTER a faster
// manual scan (a phishing site is usually unreachable and fails fast), it would
// otherwise overwrite the phishing verdict with the safe tab's result.
let envScanToken = 0;

async function envScanUrl(urlValue) {
  if (envUrlLoading) envUrlLoading.classList.remove("hidden");
  if (envQrError) envQrError.style.display = "none";

  if (!urlValue) {
    if (envUrlLoading) envUrlLoading.classList.add("hidden");
    if (envQrError) { envQrError.textContent = "Please enter a URL to scan."; envQrError.style.display = "block"; }
    return;
  }
  if (!/^https?:\/\//i.test(urlValue)) {
    urlValue = "https://" + urlValue;
  }

  // Capture this scan's identity; any LATER scan bumps the token and makes
  // stale responses from this one (e.g. the auto-detect scan) get ignored.
  const myToken = ++envScanToken;

  let result = null;
  try {
    // Scan via the background service worker so it stores the result and
    // keeps the badge/follow-on behavior consistent with the main flow.
    result = await new Promise((resolve) => {
      chrome.runtime.sendMessage(
        { action: "scanUrlText", url: urlValue },
        (resp) => {
          if (chrome.runtime.lastError) return resolve({ error: chrome.runtime.lastError.message });
          resolve(resp && resp.result ? resp.result : null);
        }
      );
    });
  } catch (e) {
    result = null;
  } finally {
    if (envUrlLoading) envUrlLoading.classList.add("hidden");
  }

  // Only render the freshest request's result — a newer scan supersedes this one.
  if (myToken !== envScanToken) return;

  if (result && result.error === "invalid_url") {
    envRenderValidation(result);
    if (envResults) envResults.classList.add("hidden");
    return;
  }

  if (result && result.prediction) {
    envRenderResult(result);
  } else {
    // Backend may still be starting — wait for it, then retry the scan once
    // before showing an error to the user.
    const wasReady = await waitForBackend(10000);
    if (wasReady) {
      try {
        result = await new Promise((resolve) => {
          chrome.runtime.sendMessage(
            { action: "scanUrlText", url: urlValue },
            (resp) => {
              if (chrome.runtime.lastError) return resolve(null);
              resolve(resp && resp.result ? resp.result : null);
            }
          );
        });
      } catch (e) {
        result = null;
      }
    }
    if (myToken !== envScanToken) return;
    if (result && result.error === "invalid_url") {
      envRenderValidation(result);
      if (envResults) envResults.classList.add("hidden");
      return;
    }
    if (result && result.prediction) {
      envRenderResult(result);
    } else if (envQrError) {
      envQrError.textContent = "Scan failed. Is the backend running?";
      envQrError.style.display = "block";
    }
  }
}

if (envUrlScanBtn) {
  envUrlScanBtn.addEventListener("click", () => {
    envScanUrl(envUrlInput ? envUrlInput.value.trim() : "");
  });
}
if (envUrlInput) {
  envUrlInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") envScanUrl(envUrlInput.value.trim());
  });
}

// QR handling inside the env sandbox
if (envQrDropzone) {
  envQrDropzone.addEventListener("click", () => {
    if (envQrFileInput) envQrFileInput.click();
  });
}
if (envQrFileInput) {
  envQrFileInput.addEventListener("change", (e) => {
    const file = e.target.files && e.target.files[0];
    if (!file) return;
    envScanQrFile(file);
  });
}

function envScanQrFile(file) {
  const reader = new FileReader();
  reader.onload = (ev) => {
    const dataUrl = ev.target.result;
    const commaIdx = dataUrl.indexOf(",");
    const base64 = commaIdx >= 0 ? dataUrl.slice(commaIdx + 1) : dataUrl;

    if (envQrError) envQrError.style.display = "none";
    if (envQrLoading) envQrLoading.classList.remove("hidden");

    scanQRFetch(base64)
      .then((res) => {
        if (envQrLoading) envQrLoading.classList.add("hidden");
        if (res && res.success) {
          if (res.result && res.result.results && res.result.results.length) {
            // Show the first (or most-severe) URL result in the env dashboard
            envRenderResult(res.result.results[0]);
          } else if (res.result && res.result.summary) {
            if (envQrError) { envQrError.textContent = res.result.summary; envQrError.style.display = "block"; }
          }
        } else {
          if (envQrError) { envQrError.textContent = (res && res.error) || "QR scan failed."; envQrError.style.display = "block"; }
        }
      });
  };
  reader.readAsDataURL(file);
}

function loadEnvironmentFromLastScan() {
  chrome.storage.local.get(["lastScan"], (result) => {
    envRenderResult(result.lastScan || null);
  });
}

// ===========================================================================
//  LOAD HISTORY from the backend API
// ===========================================================================

async function loadHistory() {
  let token = await getStoredToken();
  if (!token) return;

  const attempt = (tok) =>
    fetchWithBackendRetry(`${API_BASE}/dashboard/history`, {
      method: "GET",
      headers: {
        "Authorization": `Bearer ${tok}`,
        "Content-Type": "application/json",
      },
    });

  let response;
  try {
    response = await attempt(token);

    // 401 -> token expired. Silently re-login with stored creds and retry once
    // so a stale token never silently empties the history panel.
    if (response.status === 401) {
      const newToken = await silentReauth();
      if (newToken) {
        token = newToken;
        response = await attempt(newToken);
      }
    }

    if (!response.ok) return;

    const data = await response.json();
    renderHistory(data.history || []);
  } catch (err) {
    // Backend unreachable — silent fail, retry happens on next open
  }
}

/**
 * Silently re-login using stored credentials (mirrors the background helper).
 * Used when a JWT expires so history keeps loading without manual re-login.
 */
async function silentReauth() {
  const creds = await new Promise((resolve) => {
    chrome.storage.local.get(["username", "authPassword"], (result) => {
      if (result.username && result.authPassword) {
        resolve({ username: result.username, password: result.authPassword });
      } else {
        resolve(null);
      }
    });
  });
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
    return null;
  }
}

function renderHistory(historyItems) {
  // SECURITY: Clear existing content using textContent on child removal
  while (historyList.firstChild) {
    historyList.removeChild(historyList.firstChild);
  }

  // Show only the 5 most recent
  const items = historyItems.slice(0, 5);

  if (items.length === 0) {
    const emptyMsg = document.createElement("p");
    emptyMsg.textContent = "No scans yet. Click 'Scan Current Page' to start.";
    emptyMsg.style.color = "#64748b";
    emptyMsg.style.fontSize = "12px";
    emptyMsg.style.textAlign = "center";
    emptyMsg.style.padding = "12px";
    historyList.appendChild(emptyMsg);
    return;
  }

  items.forEach((item) => {
    const historyItem = document.createElement("div");
    historyItem.className = "history-item";

    const dot = document.createElement("span");
    dot.className = `history-dot ${item.prediction}`;

    const urlText = document.createElement("span");
    urlText.className = "history-url";
    // SECURITY: textContent — URL is displayed as text, never as HTML
    urlText.textContent = item.url;

    historyItem.appendChild(dot);
    historyItem.appendChild(urlText);
    historyList.appendChild(historyItem);
  });
}

// ===========================================================================
//  LOGOUT
// ===========================================================================

logoutBtn.addEventListener("click", async () => {
  await chrome.storage.local.remove(["authToken", "username", "authPassword", "lastScan"]);
  showView("login");

  // Clear inputs
  usernameInput.value = "";
  passwordInput.value = "";
});

// ===========================================================================
//  HELPER: Get stored auth token
// ===========================================================================

async function getStoredToken() {
  return new Promise((resolve) => {
    chrome.storage.local.get(["authToken"], (result) => {
      resolve(result.authToken || null);
    });
  });
}

// ===========================================================================
//  INITIALIZATION
// ===========================================================================

(async function init() {
  const token = await getStoredToken();
  if (token) {
    // SECURITY: Retrieve stored username via textContent-safe path
    chrome.storage.local.get(["username"], (result) => {
      showDashboard(result.username || "User");
    });
  } else {
    showView("login");
  }
})();
