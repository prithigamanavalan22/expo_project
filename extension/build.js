#!/usr/bin/env node
/**
 * PhishGuard Cross-Browser Build Script
 * ======================================
 *
 * Generates distributable ZIP packages from the single MV3 source in
 * `D:\asm_expo\extension` for all target browsers:
 *
 *   dist/phishguard-chromium.zip   -> Google Chrome, Microsoft Edge, Brave, Zen
 *                                      (all Chromium — zero source changes)
 *   dist/phishguard-firefox.zip    -> Firefox (WebExtensions, browser.* shim)
 *
 * Usage:
 *   node build.js
 *
 * The Chromium build is the source as-is.
 * The Firefox build swaps background.service_worker -> background.scripts,
 * adds browser_specific_settings.gecko.id (required to load in Firefox), and
 * injects a tiny chrome->browser polyfill so the single codebase runs on both.
 */

const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

const SRC = __dirname;                       // extension/ source dir
const DIST = path.join(SRC, "dist");
const BUILD = path.join(DIST, "_build");     // temp build staging

const FIREFOX_GECKO_ID = "phishguard@local.example";

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------
function copyDir(src, dest) {
  if (!fs.existsSync(src)) return;
  fs.mkdirSync(dest, { recursive: true });
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    const s = path.join(src, entry.name);
    const d = path.join(dest, entry.name);
    // skip build outputs & dist so we don't recurse into ourselves
    if (entry.name === "dist" || entry.name === "node_modules") continue;
    if (entry.isDirectory()) copyDir(s, d);
    else fs.copyFileSync(s, d);
  }
}

function zipDir(dir, zipPath) {
  fs.rmSync(zipPath, { force: true });
  execSync(
    `powershell -NoProfile -Command "Compress-Archive -Path '${dir}\\*' -DestinationPath '${zipPath}' -Force"`,
    { encoding: "utf8" }
  );
  return zipPath;
}

function cleanDir(dir) {
  fs.rmSync(dir, { recursive: true, force: true });
}

// ---------------------------------------------------------------------------
// Chromium build (Chrome / Edge / Brave / Zen) — source as-is
// ---------------------------------------------------------------------------
function buildChromium() {
  console.log("[1/3] Building Chromium package (Chrome/Edge/Brave/Zen)...");
  const out = path.join(BUILD, "chromium");
  cleanDir(out);
  copyDir(SRC, out);
  const zipPath = path.join(DIST, "phishguard-chromium.zip");
  zipDir(out, zipPath);
  console.log("      -> " + zipPath);
}

// ---------------------------------------------------------------------------
// Firefox build — WebExtensions conversion
// ---------------------------------------------------------------------------
function buildFirefox() {
  console.log("[2/3] Building Firefox package (WebExtensions)...");
  const out = path.join(BUILD, "firefox");
  cleanDir(out);
  copyDir(SRC, out);

  // --- 1. Patch manifest.json for Firefox ---
  const manifestPath = path.join(out, "manifest.json");
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));

  // Firefox MV3 uses background.scripts (event page), not service_worker.
  manifest.background = {
    scripts: ["background.js"],
    type: "module",
  };

  // Required for Firefox to load the extension.
  manifest.browser_specific_settings = {
    gecko: {
      id: FIREFOX_GECKO_ID,
      strict_min_version: "109.0",
    },
  };

  // Firefox disallows some content_scripts matches; relax to http/https.
  if (Array.isArray(manifest.content_scripts)) {
    manifest.content_scripts.forEach((cs) => {
      cs.matches = ["http://*/*", "https://*/*"];
    });
  }

  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));

  // --- 2. Inject a chrome -> browser polyfill for the Firefox build ---
  // Firefox supports the legacy `chrome.*` namespace for most APIs, but a
  // polyfill normalises promise/return-value differences. We inject it into
  // each JS file that references chrome.*
  const polyfill = `// PhishGuard Firefox WebExtensions polyfill
// Uses the browser.* namespace (returns promises) when available.
if (typeof browser !== "undefined" && !globalThis.__pgPolyfill) {
  globalThis.__pgPolyfill = true;
  for (const key of Object.keys(browser)) {
    if (typeof chrome === "undefined") {
      globalThis.chrome = browser;
      break;
    }
  }
  const wrap = (ns, method) => {
    if (typeof chrome === "undefined" || !chrome[ns]) return;
    const orig = chrome[ns][method];
    if (typeof orig !== "function" || !browser[ns] || !browser[ns][method]) return;
    if (!orig.__pgPromised) {
      chrome[ns][method] = (...args) => browser[ns][method](...args);
      chrome[ns][method].__pgPromised = true;
    }
  };
  // storage and runtime are the most-used; wrap common ones.
  wrap("storage", "local");
  wrap("runtime", "sendMessage");
  wrap("runtime", "onMessage");
  wrap("tabs", "query");
  wrap("tabs", "onUpdated");
  wrap("action", "setBadgeText");
  wrap("action", "setBadgeBackgroundColor");
}
`;

  const jsFiles = ["background.js", "popup.js", "content.js"];
  for (const f of jsFiles) {
    const p = path.join(out, f);
    if (fs.existsSync(p)) {
      const content = fs.readFileSync(p, "utf8");
      fs.writeFileSync(p, polyfill + "\n" + content);
    }
  }

  const zipPath = path.join(DIST, "phishguard-firefox.zip");
  zipDir(out, zipPath);
  console.log("      -> " + zipPath);
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
async function main() {
  fs.mkdirSync(DIST, { recursive: true });
  buildChromium();
  buildFirefox();
  cleanDir(BUILD);
  console.log("[3/3] Done. Packages written to " + DIST);
}

main().catch((e) => {
  console.error("Build failed:", e.message);
  process.exit(1);
});
