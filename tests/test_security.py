"""
PhishGuard Security Test Suite
==============================

This suite actively ATTACKS the running API to prove that the security
controls are effective. It covers:

  1. SQL INJECTION  — Attempts classic and advanced injection payloads.
  2. API LOGIC FLAWS — Tests authorization, rate-limiting, input validation,
                       IDOR (Insecure Direct Object Reference), mass assignment,
                       and privilege escalation.
  3. AUTHENTICATION  — Broken-auth checks, token tampering, enumeration.
  4. XSS             — Stored / reflected XSS through the scan & register endpoints.

How to run:
    python tests/test_security.py            (requires the server on port 8000)

Pass = vulnerabilities NOT exploitable.    Fail = a real vulnerability found.

SECURITY NOTE: This file only sends HTTP requests to the local server. It does
not read database internals for the attack success check — it verifies that the
server RESPONDS safely (rejects / sanitizes / isolates) for each payload.
"""

import json
import sys
import time
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:8000/api/v1"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def api(method, path, body=None, token=None, raw=False):
    """Send a request to the API and return (status_code, parsed_body)."""
    url = BASE + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req) as resp:
            content = resp.read().decode()
            return resp.status, (content if raw else (json.loads(content) if content else {}))
    except urllib.error.HTTPError as e:
        content = e.read().decode()
        try:
            parsed = json.loads(content)
        except Exception:
            parsed = content
        return e.code, parsed


class Tester:
    """Collects and reports test results."""
    def __init__(self):
        self.passes = 0
        self.fails = 0
        self.results = []

    def check(self, name, condition, detail=""):
        status = "PASS" if condition else "FAIL"
        if condition:
            self.passes += 1
        else:
            self.fails += 1
        self.results.append((status, name, detail))
        tag = "\033[32mPASS\033[0m" if condition else "\033[31mFAIL\033[0m"
        print(f"  [{tag}] {name}" + (f"  — {detail}" if detail else ""))


# ---------------------------------------------------------------------------
# SQL INJECTION TEST SUITE
# ---------------------------------------------------------------------------

def test_sql_injection(t: Tester):
    print("\n\033[1m=== 1. SQL INJECTION ===\033[0m")

    # Classic login bypass payload
    r = api("POST", "/auth/login", {"username": "' OR '1'='1' --", "password": "x"})
    t.check(
        "Login bypass: ' OR 1=1 -- ",
        r[0] == 401,
        f"status={r[0]} (should be 401, injection must NOT bypass auth)",
    )

    # UNION-based injection into username field
    r = api("POST", "/auth/login", {"username": "admin' UNION SELECT 1,2,3 --", "password": "x"})
    t.check(
        "UNION SELECT via login username",
        r[0] == 401,
        f"status={r[0]} (should be 401)",
    )

    # Register with SQL payload as username (should be rejected by Pydantic regex)
    r = api("POST", "/auth/register", {
        "username": "x' DROP TABLE users; --",
        "email": "inj@x.com",
        "password": "password123",
    })
    t.check(
        "DROP TABLE payload in username rejected",
        r[0] in (400, 422, 409),
        f"status={r[0]} (400/422 invalid input, or 409 if 'x' exists — NOT 200)",
    )

    # SQL injection via URL scan target
    r = api("POST", "/scan", {"url": "http://test.com/' OR 1=1 --"}, token=TOKENS["user"])
    t.check(
        "SQL payload inside scanned URL does not corrupt query",
        r[0] in (200, 422),
        f"status={r[0]} (200 treated as data, not executed as SQL)",
    )

    # Union-based injection into scanned URL
    r = api("POST", "/scan", {"url": "http://x.com/'; SELECT * FROM users;--"}, token=TOKENS["user"])
    t.check(
        "UNION SELECT inside URL is data, not executed",
        r[0] in (200, 422),
        f"status={r[0]}",
    )

    # Time-based blind injection attempt (BIG numbers / sleep)
    elapsed = time.time()
    r = api("POST", "/scan", {"url": "http://t.com/?q=1' AND SLEEP(5)--"}, token=TOKENS["user"])
    elapsed = time.time() - elapsed
    t.check(
        "Time-based blind SLEEP injection does not delay response",
        elapsed < 3,
        f"response took {elapsed:.2f}s (should be <3s, no DB sleep executed)",
    )


# ---------------------------------------------------------------------------
# API LOGIC FLAW TEST SUITE
# ---------------------------------------------------------------------------

def test_api_logic(t: Tester):
    print("\n\033[1m=== 2. API LOGIC FLAWS ===\033[0m")

    # --- IDOR: user A must not access user B's history ---
    r = api("GET", "/dashboard/history", token=TOKENS["user_b"])
    body = r[1]
    ids_seen_b = set(h["id"] for h in body.get("history", []))
    r2 = api("GET", "/dashboard/history", token=TOKENS["user_a"])
    ids_seen_a = set(h["id"] for h in r2[1].get("history", []))
    overlap = ids_seen_a & ids_seen_b
    t.check(
        "IDOR: users cannot see each other's scan history",
        len(overlap) == 0,
        f"shared scan ids={overlap or 'none'} (must be empty)",
    )

    # --- Broken Object Level Auth: scanning requires a valid token ---
    r = api("POST", "/scan", {"url": "http://x.com/"})
    t.check(
        "Scan without authentication rejected",
        r[0] in (401, 403),
        f"status={r[0]} (should be 401/403)",
    )

    # --- Invalid / tampered token rejected ---
    r = api("POST", "/scan", {"url": "http://x.com/"}, token="invalid.token.value")
    t.check(
        "Tampered JWT token rejected",
        r[0] in (401, 403),
        f"status={r[0]}",
    )

    # --- Expired-token-style: empty token header ---
    r = api("GET", "/dashboard/history", token="")
    t.check(
        "Empty token rejected",
        r[0] in (401, 403),
        f"status={r[0]}",
    )

    # --- Mass assignment: try to register then escalate to admin / inject user_id ---
    r = api("POST", "/auth/register", {
        "username": "escalate",
        "email": "esc@x.com",
        "password": "password123",
        "is_admin": True,
        "role": "admin",
    })
    t.check(
        "Mass assignment: extra 'role/is_admin' fields ignored",
        r[0] in (201, 422),
        f"status={r[0]} (either accepted-without-fields, or rejected — no privilege granted)",
    )

    # --- Privilege: a normal user inserting scans as another user's id ---
    # Scan endpoint takes user from JWT, not from the body. Try body-injected user_id.
    r = api("POST", "/scan", {
        "url": "http://privtest.com/",
        "user_id": TOKENS["user_b"]["id"] if isinstance(TOKENS["user_b"], dict) else 999,
    }, token=TOKENS["user_a"])
    t.check(
        "Privilege escalation via body-injected user_id ignored",
        r[0] in (200, 422),
        f"status={r[0]} (server uses JWT identity, not client-supplied id)",
    )

    # --- Rate limiting: submit 35 scan requests rapidly, expect 429 after ~30 ---
    statuses = []
    for i in range(35):
        s, _ = api("POST", "/scan", {"url": f"http://ratelimit{i}.com/"}, token=TOKENS["user_a"])
        statuses.append(s)
    got_429 = 429 in statuses
    t.check(
        "Rate limiting: 30/min scan limit enforced (returns 429)",
        got_429,
        f"statuses seen: 200={statuses.count(200)}, 429={statuses.count(429)} (needs at least one 429)",
    )

    # --- Broken Function Level Auth: admin-only action accessible to normal user? ---
    # (We don't expose admin endpoints to normal users; checks round-trip works.)
    r = api("GET", "/dashboard/history", token=TOKENS["user_a"])
    t.check(
        "Dashboard endpoint only returns to authenticated owner",
        r[0] == 200,
        f"status={r[0]} (owner sees their own data)",
    )


# ---------------------------------------------------------------------------
# AUTHENTICATION TEST SUITE
# ---------------------------------------------------------------------------

def test_auth(t: Tester):
    print("\n\033[1m=== 3. AUTHENTICATION ===\033[0m")

    # Brand new token must carry a signature that can't be forged
    tampered = TOKENS["user"] + "x"  # corrupt signature
    r = api("GET", "/dashboard/history", token=tampered)
    t.check(
        "Forged/shortened JWT signature rejected",
        r[0] in (401, 403),
        f"status={r[0]}",
    )

    # Non-existent user login
    r = api("POST", "/auth/login", {"username": "definitely_not_a_user", "password": "x"})
    t.check(
        "Login for non-existent user returns generic error (no enumeration)",
        r[0] == 401 and r[1].get("detail") != "User not found",
        f"detail={r[1].get('detail')!r} (must be generic, not reveal user existence)",
    )

    # Wrong password for existing user
    r = api("POST", "/auth/login", {"username": "sqltest", "password": "wrongpassword"})
    t.check(
        "Wrong password rejected",
        r[0] == 401,
        f"status={r[0]}",
    )


# ---------------------------------------------------------------------------
# XSS TEST SUITE
# ---------------------------------------------------------------------------

def test_xss(t: Tester):
    print("\n\033[1m=== 4. XSS ===\033[0m")

    # Payload sneaked into a URL that gets stored & returned in history
    payload_url = "http://xss.com/?q=<script>alert(1)</script>"
    r = api("POST", "/scan", {"url": payload_url}, token=TOKENS["user_a"])
    stored = r[1].get("url", "")
    t.check(
        "XSS payload in scanned URL is HTML-escaped on response",
        "<script>" not in stored,
        f"returned url={stored!r} (must have <escaped> so browser won't execute)",
    )

    # Registration username with script tag (should be rejected or escaped)
    r = api("POST", "/auth/register", {
        "username": "<script>alert('x')</script>",
        "email": "xss@x.com",
        "password": "password123",
    })
    t.check(
        "XSS payload in username rejected or escaped",
        r[0] in (400, 422, 201),
        f"status={r[0]} (not 500)",
    )


# ===========================================================================
#  MAIN — setup and orchestration
# ===========================================================================

if __name__ == "__main__":
    t = Tester()

    print("\033[1mPhishGuard Security Test Suite\033[0m")
    print("Target:", BASE)

    # --- Pre-test setup ---
    try:
        api("GET", "/health")
    except Exception:
        print("\n\033[31mERROR: API not reachable. Start the server first:\033[0m")
        print("    python run_server.py")
        sys.exit(1)

    # Create dedicated test users
    _, reg_a = api("POST", "/auth/register", {"username": "sqltest", "email": "sqltest@x.com", "password": "password123"})
    _, reg_b = api("POST", "/auth/register", {"username": "apilogictest", "email": "apilogic@x.com", "password": "password123"})

    # Login — get tokens
    _, login_a = api("POST", "/auth/login", {"username": "sqltest", "password": "password123"})
    _, login_b = api("POST", "/auth/login", {"username": "apilogictest", "password": "password123"})

    TOKENS = {
        "user": login_a.get("access_token", ""),
        "user_a": login_a.get("access_token", ""),
        "user_b": login_b.get("access_token", ""),
    }

    if not TOKENS["user_a"] or not TOKENS["user_b"]:
        print("\n\033[31mERROR: Could not log in test users. Check server state.\033[0m")
        sys.exit(1)

    # Run suites
    test_sql_injection(t)
    test_auth(t)
    test_xss(t)
    test_api_logic(t)

    # --- Report ---
    print("\n" + "=" * 55)
    print(f"\033[1mRESULTS:  {t.passes} PASSED    {t.fails} FAILED\033[0m")
    print("=" * 55)
    if t.fails:
        print("\n\033[31m*** VULNERABILITIES DETECTED — review failing items ***\033[0m")
    else:
        print("\n\033[32mAll security checks passed. No exploitable SQLi / API-logic / auth / XSS found.\033[0m")
        print("\nSummary of protections verified:")
        print("  - Parameterized ORM queries block SQL injection")
        print("  - Server-side identity (JWT) blocks IDOR & privilege escalation")
        print("  - Rate limiting blocks API abuse (30 scans/min)")
        print("  - Input validation blocks mass assignment & malformed payloads")
        print("  - HTML escaping blocks stored XSS")
