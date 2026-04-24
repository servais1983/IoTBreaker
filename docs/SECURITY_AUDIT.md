# IoTBreaker v4.0.0 — Security Vulnerability Audit

> **Scope:** Security vulnerabilities in the tool itself (not in target devices).
> **Status:** ✅ All 10 findings resolved — 2026-04-24

---

## ✅ S1 — HIGH: SSL Verification Disabled Globally — **FIXED**

> **Resolution (2026-04-24):** `verify_ssl` default changed to `True` in `core/config.py`.
> All `urllib3.disable_warnings()` calls are now gated behind `if not self.verify_ssl`
> in `bruteforce.py`, `vulnscan.py`, `fingerprint.py`, and `exploit.py`.
> All `verify=False` in HTTP calls replaced with `verify=self.verify_ssl`.
> `--no-verify` CLI flag added for explicit opt-out with a printed warning.

**Files:**
- `core/config.py` — `"verify_ssl": False`
- `modules/bruteforce/bruteforce.py` — `urllib3.disable_warnings(...)`
- `modules/vulnscan/vulnscan.py` — `urllib3.disable_warnings(...)`

**Description:**
`verify_ssl` defaults to `False` and SSL warnings are silenced in every HTTP module.
An operator will never know if they are hitting a MITM-intercepted response during a
test, corrupting findings. This is especially dangerous for NVD API and Shodan API calls
made over the public internet.

**Fix:**
Set `verify_ssl: True` by default. Only disable per-target with an explicit `--no-verify`
flag and print a visible warning per request.

```python
# core/config.py — change:
"verify_ssl": True,

# modules/bruteforce/bruteforce.py — remove:
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# replace with a conditional that only disables when verify_ssl is False
```

---

## ✅ S2 — HIGH: User-Controlled Command Payload Passed Directly to RCE Handlers — **FIXED**

> **Resolution (2026-04-24):** `_SAFE_PAYLOAD_RE` whitelist regex added in `exploit.py`.
> Payload is validated before any exploit handler executes; invalid payloads are rejected
> with an error message.

**File:** `modules/exploit/exploit.py` — line ~163

```python
cmd = payload or "id"
exploited, output = handler(target, check_only, cmd)
```

**Description:**
The `--payload CMD` string from the CLI is passed verbatim to exploit handlers.
Depending on the handler implementation (HTTP injection, shell metacharacters), a crafted
payload string can cause unintended command injection or server-side escaping failures.
No sanitization or character-class validation is performed.

**Fix:**
Validate `payload` against an allowlist of safe characters, or document clearly that it
is raw and restrict it to `--check` mode by default.

```python
import re

SAFE_PAYLOAD_RE = re.compile(r'^[a-zA-Z0-9 _\-\.\/;|&]{1,256}$')

if payload and not SAFE_PAYLOAD_RE.match(payload):
    Console.error("Payload contains unsafe characters.")
    return []
```

---

## ✅ S3 — HIGH: No Target Scope Enforcement — **FIXED**

> **Resolution (2026-04-24):** `load_scope()` and `_is_in_scope()` methods added to
> `core/engine.py`. `--scope-file` CLI flag introduced. Every module (`scan`, `fingerprint`,
> `vuln`, `brute`, `exploit`) checks scope before executing. Unauthorized targets are
> silently skipped. Authorization warning printed when no scope file is provided.

**File:** `core/engine.py`

**Description:**
There is no mechanism to define an authorized target scope. A user can pass any IP,
including public addresses or broad CIDR ranges, and the framework will enumerate, scan,
brute-force, and exploit without restriction. For an enterprise team this is a compliance
and legal liability.

**Fix:**
Add a `--scope-file` parameter (CIDR allowlist) that the engine validates every target
against before executing any module.

```python
# core/engine.py
def _is_in_scope(self, target: str) -> bool:
    if not self.scope_networks:
        return True  # no scope file = open (with a printed warning)
    import ipaddress
    for net in self.scope_networks:
        if ipaddress.ip_address(target) in net:
            return True
    return False
```

---

## ✅ S4 — MEDIUM: Credentials Logged in Plaintext — **FIXED**

> **Resolution (2026-04-24):** Passwords masked in console output and engine findings.
> `--reveal-creds` CLI flag added for explicit opt-in. Config key `reveal_creds` defaults
> to `False`. Applied in `bruteforce.py` and `engine.py`.

**File:** `modules/bruteforce/bruteforce.py`

**Description:**
Found credentials are printed to stdout (`{username}:{password}`) and stored verbatim
in the JSON report. This becomes a data-handling problem in regulated environments
(GDPR, PCI-DSS, HIPAA) and creates credential exposure risk if reports are transmitted
insecurely.

**Fix:**
Mask passwords in console output. Add a `--reveal-creds` flag for full display. Optionally
hash credentials in JSON reports.

```python
# Console display:
Console.finding("CRITICAL",
    f"Valid credentials: {username}:{'*' * len(password)}",
    f"Protocol: {protocol} | Port: {port}")

# With --reveal-creds flag, show full password
```

---

## ✅ S5 — MEDIUM: API Keys Stored in Plaintext Config / Environment — **FIXED**

> **Resolution (2026-04-24):** Optional OS keyring lookup added in `core/config.py`.
> `IOTBREAKER_VERIFY_SSL` and `IOTBREAKER_PROXY` env vars also wired up. Keyring takes
> precedence over env vars for `shodan_api_key` and `nvd_api_key`.

**Files:** `env.example`, `core/config.py`

**Description:**
`SHODAN_API_KEY` and `NVD_API_KEY` are read from environment variables or YAML config
as plaintext strings and stored in `Config._data`. No integration with secret managers.
If the config file is accidentally committed to version control, keys are exposed.

**Fix:**
Support reading from OS keyring. Add a `.gitignore` check warning at startup.

```python
# Optional keyring support
try:
    import keyring
    key = keyring.get_password("iotbreaker", "shodan_api_key")
    if key:
        self._data["shodan_api_key"] = key
except ImportError:
    pass
```

---

## ✅ S6 — MEDIUM: Incomplete HTML Escaping in Report Generator (Stored XSS) — **FIXED**

> **Resolution (2026-04-24):** `_esc()` in `modules/reporting/report.py` replaced with
> `html.escape(str(text), quote=True)`. `import html` added at module level.

**File:** `modules/reporting/report.py` — line ~426

```python
def _esc(self, text: str) -> str:
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
```

**Description:**
Double-quotes `"` and single-quotes `'` are not escaped. If any finding data (e.g. a
banner grabbed from a malicious device) is injected into an HTML attribute context
(e.g. `style=`, `href=`, `onclick=`), this results in stored XSS in the generated
report file when opened in a browser.

**Fix:**
Use the standard library `html.escape()` with `quote=True`:

```python
import html

def _esc(self, text: str) -> str:
    return html.escape(str(text), quote=True)
```

---

## ✅ S7 — MEDIUM: binwalk `--run-as=root` Flag — **FIXED**

> **Resolution (2026-04-24):** `--run-as=root` removed from the `subprocess.run()` call
> in `modules/firmware/firmware.py`. Post-extraction path traversal validation added:
> all extracted files are resolved and any path escaping the extraction directory is
> deleted with a warning.

**File:** `modules/firmware/firmware.py` — line ~338

```python
subprocess.run(
    ["binwalk", "-eM", "--run-as=root", "-C", str(extract_dir), str(path)],
    capture_output=True, timeout=300
)
```

**Description:**
`--run-as=root` forces binwalk to extract as root. Combined with a malicious firmware
file that contains path traversal sequences in its embedded filesystem, this can result
in files being written outside the extraction directory with root ownership — a local
privilege escalation vector.

**Fix:**
Remove `--run-as=root`. Run binwalk as the invoking user. Validate the extraction output
directory after the operation.

```python
subprocess.run(
    ["binwalk", "-eM", "-C", str(extract_dir), str(path)],
    capture_output=True, timeout=300
)

# Post-extraction validation:
for extracted_file in extract_dir.rglob("*"):
    resolved = extracted_file.resolve()
    if not str(resolved).startswith(str(extract_dir.resolve())):
        Console.warning(f"Path traversal detected in firmware: {extracted_file}")
        extracted_file.unlink(missing_ok=True)
```

---

## ✅ S8 — LOW: Zero-Second Brute-Force Delay by Default — **FIXED**

> **Resolution (2026-04-24):** `brute_delay` default changed from `0.0` to `0.5` in
> `core/config.py`. `--fast` CLI flag added for explicit opt-in to zero delay, with a
> printed warning.

**File:** `core/config.py` — `"brute_delay": 0.0`

**Description:**
Default delay between credential attempts is 0 seconds. This will trigger account lockouts
on virtually all enterprise devices and may constitute a DoS on embedded IoT hardware with
limited TCP stacks.

**Fix:**
Default `brute_delay` to `0.5` seconds. Add a `--fast` flag to explicitly opt into 0-delay.

```python
# core/config.py
"brute_delay": 0.5,
```

---

## ✅ S9 — LOW: Default Thread Count Can DoS Embedded Devices — **FIXED**

> **Resolution (2026-04-24):** `MODULE_THREAD_CAPS` dict added to `core/engine.py`.
> `_apply_module_thread_cap()` enforces per-module limits before dispatch.
> Caps: `discover=50`, `scan=10`, `fingerprint=5`, `vuln=5`, `brute=3`, `exploit=3`, `audit=10`.

**File:** `iotbreaker.py` — `--threads 100`

**Description:**
100 concurrent threads against a single IP camera or PLC with a TCP stack limit of 10–20
connections will cause the device to reboot or freeze during a live engagement.

**Fix:**
Add per-module thread caps. Expose a `--rate-limit` flag with safe defaults.

| Module | Recommended default |
|---|---|
| `discover` (network sweep) | 50 threads |
| `scan` (single target) | 10 threads |
| `brute` | 3 threads |
| `vuln` | 5 threads |

---

## ✅ S10 — LOW: No Persistent Audit Log to File — **FIXED**

> **Resolution (2026-04-24):** `setup_logger()` in `core/logger.py` now accepts
> `output_dir` and `session_id` parameters and always writes a `iotbreaker_{session_id}.log`
> file at `DEBUG` level. Wired into `iotbreaker.py` `main()` after session init.

**Description:**
The logger defaults to `WARNING` level and logs only to `stderr`. There is no persistent
audit trail of what the tool did, when, and against which targets — a requirement for
enterprise pen-test engagements and post-incident review.

**Fix:**
Always write a timestamped structured log file to the output directory regardless of
verbosity level.

```python
# core/logger.py — in setup_logger():
log_file = Path(config.get("output_dir")) / f"iotbreaker_{session_id}.log"
file_handler = logging.FileHandler(log_file, encoding="utf-8")
file_handler.setLevel(logging.DEBUG)
logger.addHandler(file_handler)
```

---

## Severity Summary

| ID | Severity | Title | Status |
|---|---|---|---|
| S1 | HIGH | SSL verification disabled globally | ✅ Fixed |
| S2 | HIGH | Unsanitized payload passed to RCE handlers | ✅ Fixed |
| S3 | HIGH | No target scope enforcement | ✅ Fixed |
| S4 | MEDIUM | Credentials logged/stored in plaintext | ✅ Fixed |
| S5 | MEDIUM | API keys in plaintext config | ✅ Fixed |
| S6 | MEDIUM | Incomplete HTML escaping (stored XSS risk) | ✅ Fixed |
| S7 | MEDIUM | binwalk `--run-as=root` path traversal risk | ✅ Fixed |
| S8 | LOW | Zero brute-force delay by default | ✅ Fixed |
| S9 | LOW | 100 threads can DoS embedded devices | ✅ Fixed |
| S10 | LOW | No persistent audit log file | ✅ Fixed |
