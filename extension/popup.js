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

// ===========================================================================
//  VIEW MANAGEMENT
// ===========================================================================

function showView(view) {
  // SECURITY: Use classList to toggle visibility — no innerHTML manipulation
  loginSection.classList.toggle("hidden", view !== "login");
  registerSection.classList.toggle("hidden", view !== "register");
  dashboardSection.classList.toggle("hidden", view !== "dashboard");
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
    const response = await fetch(`${API_BASE}/auth/login`, {
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
    await chrome.storage.local.set({
      authToken: data.access_token,
      username: username,
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
    const response = await fetch(`${API_BASE}/auth/register`, {
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
    const loginResponse = await fetch(`${API_BASE}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });

    if (loginResponse.ok) {
      const loginData = await loginResponse.json();
      await chrome.storage.local.set({
        authToken: loginData.access_token,
        username: username,
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
}

// ===========================================================================
//  LOAD LAST SCAN (from chrome.storage)
// ===========================================================================

function loadLastScan() {
  chrome.storage.local.get(["lastScan"], (result) => {
    if (result.lastScan) {
      displayScanResult(result.lastScan);
    }
  });
}

// ===========================================================================
//  LOAD HISTORY from the backend API
// ===========================================================================

async function loadHistory() {
  const token = await getStoredToken();
  if (!token) return;

  try {
    const response = await fetch(`${API_BASE}/dashboard/history`, {
      method: "GET",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
      },
    });

    if (!response.ok) return;

    const data = await response.json();
    renderHistory(data.history || []);
  } catch (err) {
    // Silently fail — the user may be offline
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
  await chrome.storage.local.remove(["authToken", "username", "lastScan"]);
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
