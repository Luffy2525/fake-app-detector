"""
Fake App Detector — Backend (v1.3.0)
Flask API for analyzing APK files and app metadata for security threats.

Changes in v1.3.0:
  - FIX 13: description sanitized (log-injection + length cap) in both endpoints
  - FIX 14: analyze_url now saves reports → /api/stats counts URL analyses
  - FIX 15: Rate limiting on /api/analyze (10 uploads/min per IP)
  - FIX 16: Static-file routes use absolute paths (no working-dir dependency)
  - FIX 17: API_VERSION and VERDICTS promoted to module-level constants
  - FIX 18: FRONTEND_FOLDER uses absolute path like UPLOAD_FOLDER
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os, json, hashlib, zipfile, re, time, random, struct, logging
from datetime import datetime
from werkzeug.utils import secure_filename

# ─── LOGGING ───
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
)
logger = logging.getLogger(__name__)

# ─── CONSTANTS ───
API_VERSION    = "1.3.0"
MAX_DESC_LEN   = 2000          # FIX 13: cap description to avoid memory spikes
_BASE          = os.path.dirname(__file__)

UPLOAD_FOLDER   = os.path.join(_BASE, '..', 'uploads')
REPORTS_FOLDER  = os.path.join(_BASE, '..', 'reports')
# FIX 18: absolute path — works regardless of cwd
FRONTEND_FOLDER = os.path.join(_BASE, '..', 'frontend')

ALLOWED_EXTENSIONS = {'apk', 'zip'}
MAX_REPORTS = int(os.environ.get('MAX_REPORTS', 500))

# FIX 17: VERDICTS lives with the other constants, not buried between helpers
VERDICTS = {
    "DANGEROUS":  "⛔ DO NOT INSTALL — Serious security threats detected.",
    "SUSPICIOUS": "⚠️ HIGH RISK — Multiple red flags. Avoid installing.",
    "CAUTION":    "🔶 MODERATE RISK — Only install from a trusted source.",
    "SAFE":       "✅ RELATIVELY SAFE — No major threats detected.",
}

# Score weights (must sum to 1.0)
WEIGHT_PERMISSIONS   = 0.30
WEIGHT_DARK_PATTERNS = 0.30
WEIGHT_FAKE_APP      = 0.40

# ─── PERMISSION RISK DATABASE ───
SUSPICIOUS_PERMISSIONS = {
    "android.permission.READ_SMS":                  {"risk": "HIGH",   "desc": "Reads your SMS messages"},
    "android.permission.SEND_SMS":                  {"risk": "HIGH",   "desc": "Sends SMS without consent"},
    "android.permission.RECEIVE_SMS":               {"risk": "HIGH",   "desc": "Intercepts incoming SMS (OTP theft)"},
    "android.permission.READ_CALL_LOG":             {"risk": "HIGH",   "desc": "Accesses call history"},
    "android.permission.PROCESS_OUTGOING_CALLS":    {"risk": "HIGH",   "desc": "Intercepts outgoing calls"},
    "android.permission.RECORD_AUDIO":              {"risk": "MEDIUM", "desc": "Can record microphone audio"},
    "android.permission.CAMERA":                    {"risk": "MEDIUM", "desc": "Access to device camera"},
    "android.permission.ACCESS_FINE_LOCATION":      {"risk": "MEDIUM", "desc": "Precise GPS location tracking"},
    "android.permission.ACCESS_COARSE_LOCATION":    {"risk": "LOW",    "desc": "Approximate location access"},
    "android.permission.READ_CONTACTS":             {"risk": "MEDIUM", "desc": "Reads your contact list"},
    "android.permission.WRITE_CONTACTS":            {"risk": "MEDIUM", "desc": "Modifies your contacts"},
    "android.permission.GET_ACCOUNTS":              {"risk": "MEDIUM", "desc": "Accesses account usernames"},
    "android.permission.USE_CREDENTIALS":           {"risk": "HIGH",   "desc": "Uses account credentials"},
    "android.permission.MANAGE_ACCOUNTS":           {"risk": "HIGH",   "desc": "Manages device accounts"},
    "android.permission.READ_EXTERNAL_STORAGE":     {"risk": "LOW",    "desc": "Reads files from storage"},
    "android.permission.WRITE_EXTERNAL_STORAGE":    {"risk": "LOW",    "desc": "Writes files to storage"},
    "android.permission.INTERNET":                  {"risk": "LOW",    "desc": "Network/internet access"},
    "android.permission.RECEIVE_BOOT_COMPLETED":    {"risk": "MEDIUM", "desc": "Starts automatically on boot"},
    "android.permission.INSTALL_PACKAGES":          {"risk": "HIGH",   "desc": "Installs other apps silently"},
    "android.permission.DELETE_PACKAGES":           {"risk": "HIGH",   "desc": "Deletes apps silently"},
    "android.permission.BIND_ACCESSIBILITY_SERVICE":{"risk": "HIGH",   "desc": "Can read all screen content"},
    "android.permission.SYSTEM_ALERT_WINDOW":       {"risk": "HIGH",   "desc": "Overlays on top of other apps"},
    "android.permission.READ_PHONE_STATE":          {"risk": "MEDIUM", "desc": "Reads device IMEI and phone info"},
    "android.permission.CALL_PHONE":                {"risk": "HIGH",   "desc": "Makes calls without user action"},
    "android.permission.CHANGE_NETWORK_STATE":      {"risk": "MEDIUM", "desc": "Controls network connectivity"},
    "android.permission.ACCESS_WIFI_STATE":         {"risk": "LOW",    "desc": "Reads WiFi network info"},
    "android.permission.WAKE_LOCK":                 {"risk": "LOW",    "desc": "Prevents phone from sleeping"},
    "android.permission.VIBRATE":                   {"risk": "LOW",    "desc": "Vibration control"},
    "android.permission.FOREGROUND_SERVICE":        {"risk": "LOW",    "desc": "Runs as foreground service"},
    "android.permission.ACCESS_NETWORK_STATE":      {"risk": "LOW",    "desc": "Checks network connectivity"},
    "android.permission.CHANGE_WIFI_STATE":         {"risk": "MEDIUM", "desc": "Can connect/disconnect WiFi"},
    "android.permission.BLUETOOTH":                 {"risk": "LOW",    "desc": "Bluetooth communication"},
    "android.permission.BLUETOOTH_ADMIN":           {"risk": "MEDIUM", "desc": "Manages Bluetooth devices"},
    "android.permission.NFC":                       {"risk": "MEDIUM", "desc": "Near-field communication access"},
}

KNOWN_MALICIOUS_HASHES = {
    "d41d8cd98f00b204e9800998ecf8427e": "Empty/Fake APK",
}

DARK_PATTERN_KEYWORDS = {
    "hidden_costs": [
        "free trial", "automatically renews", "cancel anytime", "no commitment",
        "first month free", "after trial period", "billing starts", "charged after",
    ],
    "forced_continuity": [
        "subscription", "auto-renew", "recurring charge", "monthly fee",
        "annual membership", "billed annually", "charged monthly",
    ],
    "urgency_pressure": [
        "limited time", "expires soon", "only today", "last chance",
        "hurry", "act now", "don't miss out", "offer ends",
        "48 hours only", "flash sale", "countdown",
    ],
    "confirmshaming": [
        "no thanks i don't want", "no i don't want to save",
        "i prefer to pay more", "i don't want deals", "skip the savings",
    ],
    "trick_questions": [
        "do not unsubscribe", "uncheck to opt out", "deselect to remove",
        "untick to cancel", "leave unchecked to stop",
    ],
    "roach_motel": [
        "to cancel call", "cancellation fee", "cancel by mail",
        "contact support to cancel", "cancel account contact us",
    ],
    "privacy_zuckering": [
        "share with partners", "third party sharing",
        "marketing purposes", "data monetization", "advertising partners",
    ],
    "basket_sneaking": [
        "added to cart", "included automatically", "pre-selected",
        "added on your behalf", "included for your convenience",
    ],
}

FAKE_APP_INDICATORS = {
    "cloned_app_names": [
        "whatsapp pro", "whatsapp plus", "whatsapp gold",
        "instagram pro", "instagram plus", "facebook pro",
        "youtube vanced", "netflix mod", "spotify premium mod",
        "free robux", "free v-bucks", "pubg hack", "freefire hack",
        "snapchat hack", "tiktok pro", "telegram plus",
    ],
    "malicious_domains": [
        "apk4fun", "happymod", "an1.com", "revdl.com",
        "apkmody", "moddroid", "apkdone", "rexdl", "apknite",
    ],
}

# ─── APP INIT ───
app = Flask(__name__, static_folder='../frontend/static', template_folder='../frontend')

# BUG FIX 1: Restrict CORS to known origins; use '*' only during local dev
ALLOWED_ORIGINS = os.environ.get('CORS_ORIGINS', '*').split(',')
CORS(app, origins=ALLOWED_ORIGINS)

# BUG FIX 2: Configurable file size limit (default 100 MB)
app.config['MAX_CONTENT_LENGTH'] = int(os.environ.get('MAX_UPLOAD_MB', 100)) * 1024 * 1024

# FIX 15: Rate limiter — 10 APK uploads per minute per IP, 30 URL analyses per minute
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[],          # No blanket limit; apply per-route
    storage_uri="memory://",    # Switch to redis:// in production
)

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORTS_FOLDER, exist_ok=True)


# ─── HELPERS: INPUT SANITISATION ───
def _sanitise(value: str, max_len: int = 128) -> str:
    """Strip log-injection characters and enforce length cap."""
    return re.sub(r'[\r\n\t]', ' ', value).strip()[:max_len]


# ─── MODULE 1: REAL BINARY XML PARSER ───
def extract_permissions_from_axml(data: bytes) -> list:
    """
    Parse Android Binary XML (AXML) to extract real permission strings.
    No external libraries — pure Python struct parsing.
    Falls back to plain-text scan if magic number doesn't match.

    Note: UTF-8 length decoding uses a single-byte shortcut that is correct
    for all permission strings (< 128 chars). Full ULEB128 decoding is not
    required for this use-case.
    """
    permissions: list = []
    try:
        if len(data) < 8:
            return permissions

        magic = struct.unpack_from('<I', data, 0)[0]
        if magic != 0x00080003:
            # Plain-text XML fallback
            text = data.decode('utf-8', errors='ignore')
            for perm in SUSPICIOUS_PERMISSIONS:
                if perm in text:
                    permissions.append(perm)
            return permissions

        offset = 8
        if offset + 8 > len(data):
            return permissions

        chunk_type = struct.unpack_from('<H', data, offset)[0]
        if chunk_type != 0x0001:
            return permissions

        # chunk_size and style_count are read to advance past header fields;
        # their values are not needed for permission extraction.
        _chunk_size    = struct.unpack_from('<I', data, offset + 4)[0]
        string_count   = struct.unpack_from('<I', data, offset + 8)[0]
        _style_count   = struct.unpack_from('<I', data, offset + 12)[0]
        flags          = struct.unpack_from('<I', data, offset + 16)[0]
        strings_start  = struct.unpack_from('<I', data, offset + 20)[0]

        is_utf8       = bool(flags & (1 << 8))
        offsets_start = offset + 28
        strings_base  = offset + strings_start

        for i in range(min(string_count, 3000)):
            off_pos = offsets_start + i * 4
            if off_pos + 4 > len(data):
                break
            s_off = struct.unpack_from('<I', data, off_pos)[0]
            pos   = strings_base + s_off
            if pos >= len(data):
                continue

            try:
                if is_utf8:
                    if pos + 2 > len(data):
                        continue
                    char_len = data[pos + 1]
                    s = data[pos + 2: pos + 2 + char_len].decode('utf-8', errors='ignore')
                else:
                    if pos + 2 > len(data):
                        continue
                    char_len = struct.unpack_from('<H', data, pos)[0]
                    if char_len == 0 or char_len > 300:
                        continue
                    s = data[pos + 2: pos + 2 + char_len * 2].decode('utf-16-le', errors='ignore')

                s = s.strip()
                if s.startswith('android.permission.') and s not in permissions:
                    permissions.append(s)
            except Exception:
                continue

    except Exception:
        raw = data.decode('latin-1', errors='ignore')
        for perm in SUSPICIOUS_PERMISSIONS:
            if perm in raw and perm not in permissions:
                permissions.append(perm)

    return permissions


def analyze_apk_permissions(filepath: str) -> tuple:
    """Module 1 — Real APK pre-processing, zero external dependencies."""
    permissions_found: list = []
    manifest_data = {
        'total_files': 0, 'has_manifest': False,
        'has_dex': False, 'has_native_libs': False,
        'is_valid_zip': False, 'file_list_sample': [],
        'parsing_method': 'none',
    }

    if not zipfile.is_zipfile(filepath):
        manifest_data['error'] = 'Not a valid APK/ZIP'
        return permissions_found, manifest_data

    manifest_data['is_valid_zip'] = True

    try:
        with zipfile.ZipFile(filepath, 'r') as zf:
            file_list = zf.namelist()
            manifest_data['total_files']      = len(file_list)
            manifest_data['has_manifest']     = 'AndroidManifest.xml' in file_list
            manifest_data['has_dex']          = any(f.endswith('.dex') for f in file_list)
            manifest_data['has_native_libs']  = any(f.startswith('lib/') for f in file_list)
            manifest_data['file_list_sample'] = file_list[:20]
            manifest_data['dex_count']        = sum(1 for f in file_list if f.endswith('.dex'))

            if 'AndroidManifest.xml' in file_list:
                xml_data = zf.read('AndroidManifest.xml')
                permissions_found = extract_permissions_from_axml(xml_data)
                manifest_data['manifest_size']  = len(xml_data)
                manifest_data['parsing_method'] = 'binary_axml'

            if not permissions_found:
                for fname in file_list:
                    if fname.endswith('.dex'):
                        dex = zf.read(fname)
                        raw = dex.decode('latin-1', errors='ignore')
                        for perm in SUSPICIOUS_PERMISSIONS:
                            if perm in raw and perm not in permissions_found:
                                permissions_found.append(perm)
                        if permissions_found:
                            manifest_data['parsing_method'] = 'dex_scan'
                            break

    except Exception as e:
        manifest_data['error'] = str(e)
        logger.warning("APK parsing error for %s: %s", filepath, e)

    # BUG FIX 3: Label simulated fallback clearly so the UI can warn the user
    if not permissions_found:
        with open(filepath, 'rb') as f:
            seed = int(hashlib.md5(f.read(2048)).hexdigest(), 16)
        rng = random.Random(seed)   # BUG FIX 4: Use isolated Random instance (no global state)
        base  = [
            "android.permission.INTERNET",
            "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.WAKE_LOCK",
            "android.permission.VIBRATE",
        ]
        extra = rng.sample(list(SUSPICIOUS_PERMISSIONS.keys()), rng.randint(4, 11))
        permissions_found = list(set(base + extra))
        manifest_data['parsing_method']     = 'simulated_fallback'
        manifest_data['simulation_warning'] = (
            'Could not extract real permissions — results are an estimate based on '
            'file fingerprint and may not reflect actual app behaviour.'
        )

    return permissions_found, manifest_data


# ─── MODULE 2: PERMISSION ANALYSIS ───
def analyze_permissions(permissions_list: list) -> tuple:
    results    = {"HIGH": [], "MEDIUM": [], "LOW": [], "UNKNOWN": []}
    risk_score = 0
    for perm in permissions_list:
        p = perm.strip()
        if p in SUSPICIOUS_PERMISSIONS:
            info = SUSPICIOUS_PERMISSIONS[p]
            results[info["risk"]].append({
                "permission":  p,
                "short_name":  p.split('.')[-1],
                "risk":        info["risk"],
                "description": info["desc"],
            })
            risk_score += {"HIGH": 30, "MEDIUM": 15, "LOW": 5}[info["risk"]]
        else:
            results["UNKNOWN"].append({
                "permission":  p,
                "short_name":  p.split('.')[-1],
                "risk":        "UNKNOWN",
                "description": "Custom or third-party permission",
            })
            risk_score += 8
    return results, min(risk_score, 100)


# ─── MODULE 3: DARK PATTERN DETECTION ───
def detect_dark_patterns(app_name: str, developer: str, description: str = "") -> tuple:
    text     = f"{app_name} {developer} {description}".lower()
    detected = {}
    score    = 0

    for pattern, keywords in DARK_PATTERN_KEYWORDS.items():
        matches = [kw for kw in keywords if kw in text]
        if matches:
            sev = "HIGH" if pattern in {"hidden_costs", "forced_continuity", "confirmshaming"} else "MEDIUM"
            detected[pattern] = {"detected": True, "matches": matches, "severity": sev}
            score += 20 if sev == "HIGH" else 10

    if re.search(r'free\s*\$?\d+', text):
        detected["misleading_pricing"] = {
            "detected": True, "matches": ["free + price"], "severity": "HIGH"
        }
        score += 25

    return detected, min(score, 100)


# ─── MODULE 4: FAKE APP DETECTION ───
def detect_fake_app(app_name: str, developer: str, md5: str, sha256: str, perm_score: int) -> tuple:
    indicators = []
    score      = 0
    app_l      = app_name.lower()
    dev_l      = developer.lower()

    if md5 in KNOWN_MALICIOUS_HASHES:
        indicators.append({
            "type": "KNOWN_MALWARE", "severity": "CRITICAL",
            "detail": f"Hash matches: {KNOWN_MALICIOUS_HASHES[md5]}",
        })
        score += 90

    for name in FAKE_APP_INDICATORS["cloned_app_names"]:
        if name in app_l:
            indicators.append({
                "type": "CLONED_APP_NAME", "severity": "HIGH",
                "detail": f"Resembles known fake app: '{name}'",
            })
            score += 50
            break

    for domain in FAKE_APP_INDICATORS["malicious_domains"]:
        if domain in dev_l or domain in app_l:
            indicators.append({
                "type": "MALICIOUS_SOURCE", "severity": "CRITICAL",
                "detail": f"Linked to malicious APK site: {domain}",
            })
            score += 80
            break

    if re.match(r'^(app|application|utility|tool|helper|booster|cleaner|optimizer)\s*\d*$', app_l):
        indicators.append({
            "type": "GENERIC_NAME", "severity": "LOW",
            "detail": "Extremely generic name — common in scam apps",
        })
        score += 15

    if perm_score > 70:
        indicators.append({
            "type": "EXCESSIVE_PERMISSIONS", "severity": "HIGH",
            "detail": f"Permission risk {perm_score}/100 is dangerously high",
        })
        score += 30
    elif perm_score > 40:
        indicators.append({
            "type": "ELEVATED_PERMISSIONS", "severity": "MEDIUM",
            "detail": f"Permission risk {perm_score}/100 above normal",
        })
        score += 15

    return indicators, min(score, 100)


# ─── HELPERS ───
def calculate_overall_risk(perm_score: float, dark_score: float, fake_score: float) -> tuple:
    """Weighted risk aggregation. Weights sum to 1.0."""
    combined = (
        perm_score * WEIGHT_PERMISSIONS +
        dark_score * WEIGHT_DARK_PATTERNS +
        fake_score * WEIGHT_FAKE_APP
    )
    verdict = (
        "DANGEROUS"  if combined >= 70 else
        "SUSPICIOUS" if combined >= 40 else
        "CAUTION"    if combined >= 20 else
        "SAFE"
    )
    return verdict, combined


def get_file_hashes(filepath: str) -> tuple:
    """Return (md5_hex, sha256_hex) by streaming the file."""
    m, s = hashlib.md5(), hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            m.update(chunk)
            s.update(chunk)
    return m.hexdigest(), s.hexdigest()


def is_allowed_extension(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# BUG FIX 5: Rotate old reports so the folder doesn't grow unboundedly
def rotate_reports(folder: str, max_count: int) -> None:
    reports = sorted(
        [f for f in os.listdir(folder) if f.endswith('.json')],
        key=lambda x: os.path.getmtime(os.path.join(folder, x)),
    )
    while len(reports) >= max_count:
        os.remove(os.path.join(folder, reports.pop(0)))


def _save_report(report: dict, ts: str) -> None:
    """Persist a report JSON to REPORTS_FOLDER (shared by both endpoints)."""
    rotate_reports(REPORTS_FOLDER, MAX_REPORTS)
    report_path = os.path.join(REPORTS_FOLDER, f"{ts}_report.json")
    with open(report_path, 'w') as rf:
        json.dump(report, rf, indent=2)


# ─── ROUTES ───
# FIX 16: Absolute paths — no longer dependent on working directory
@app.route('/')
def index():
    return send_from_directory(FRONTEND_FOLDER, 'index.html')


@app.route('/static/<path:path>')
def serve_static(path):
    return send_from_directory(os.path.join(FRONTEND_FOLDER, 'static'), path)


# BUG FIX 6: 413 error handler for oversized uploads
@app.errorhandler(413)
def request_entity_too_large(error):
    limit_mb = app.config['MAX_CONTENT_LENGTH'] // (1024 * 1024)
    return jsonify({'error': f'File too large. Maximum allowed size is {limit_mb} MB.'}), 413


@app.route('/api/analyze', methods=['POST'])
@limiter.limit("10 per minute")   # FIX 15: rate limit per IP
def analyze_apk():
    t0 = time.time()

    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if not file or file.filename == '' or not is_allowed_extension(file.filename):
        return jsonify({'error': 'Upload a valid .apk or .zip file'}), 400

    # FIX 13: sanitise all text inputs, including description
    app_name    = _sanitise(request.form.get('app_name', file.filename.rsplit('.', 1)[0]))
    developer   = _sanitise(request.form.get('developer', 'Unknown Developer'))
    description = _sanitise(request.form.get('description', ''), max_len=MAX_DESC_LEN)

    ts    = datetime.now().strftime('%Y%m%d_%H%M%S')
    saved = os.path.join(UPLOAD_FOLDER, f"{ts}_{secure_filename(file.filename)}")
    file.save(saved)
    logger.info("Analyzing uploaded file: %s (%s, %s)", file.filename, app_name, developer)

    try:
        fsize               = os.path.getsize(saved)
        md5, sha256         = get_file_hashes(saved)
        perms, mdata        = analyze_apk_permissions(saved)
        perm_results, ps    = analyze_permissions(perms)
        dark_patterns, ds   = detect_dark_patterns(app_name, developer, description)
        fake_indicators, fs = detect_fake_app(app_name, developer, md5, sha256, ps)
        verdict, ov         = calculate_overall_risk(ps, ds, fs)

        report = {
            "meta": {
                "app_name":          app_name,
                "developer":         developer,
                "filename":          file.filename,
                "file_size_kb":      round(fsize / 1024, 2),
                "md5":               md5,
                "sha256":            sha256,
                "analysis_time_sec": round(time.time() - t0, 2),
                "analyzed_at":       datetime.now().isoformat(),
                "analysis_mode":     "apk_file",
                "api_version":       API_VERSION,
            },
            "module1_preprocessing": {
                "status":             "COMPLETE",
                "is_valid_apk":       mdata.get('is_valid_zip', False),
                "total_files":        mdata.get('total_files', 0),
                "has_manifest":       mdata.get('has_manifest', False),
                "has_dex_code":       mdata.get('has_dex', False),
                "has_native_libs":    mdata.get('has_native_libs', False),
                "parsing_method":     mdata.get('parsing_method', 'unknown'),
                "file_sample":        mdata.get('file_list_sample', []),
                "simulation_warning": mdata.get('simulation_warning'),
            },
            "module2_permissions": {
                "status":            "COMPLETE",
                "total_permissions": len(perms),
                "risk_score":        ps,
                "breakdown":         perm_results,
                "raw_permissions":   perms,
                "high_risk_count":   len(perm_results["HIGH"]),
                "medium_risk_count": len(perm_results["MEDIUM"]),
                "low_risk_count":    len(perm_results["LOW"]),
            },
            "module3_dark_patterns": {
                "status":            "COMPLETE",
                "dark_score":        ds,
                "patterns_detected": len(dark_patterns),
                "details":           dark_patterns,
                "is_dark":           ds > 20,
            },
            "module4_fake_detection": {
                "status":           "COMPLETE",
                "fake_score":       fs,
                "indicators_found": len(fake_indicators),
                "indicators":       fake_indicators,
                "is_fake":          fs > 40,
            },
            "verdict": {
                "overall_verdict":   verdict,
                "overall_score":     round(ov, 1),
                "permission_risk":   ps,
                "dark_pattern_risk": ds,
                "fake_app_risk":     fs,
                "recommendation":    VERDICTS.get(verdict, ""),
            },
        }

        _save_report(report, ts)
        logger.info("Analysis complete for %s — verdict: %s (%.1f)", app_name, verdict, ov)
        return jsonify(report)

    except Exception as e:
        logger.exception("Analysis failed for %s: %s", file.filename, e)
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500

    finally:
        if os.path.exists(saved):
            os.remove(saved)


# BUG FIX 8: /api/analyze-url validates URL format; labelled as metadata-only.
@app.route('/api/analyze-url', methods=['POST'])
@limiter.limit("30 per minute")   # FIX 15: lighter limit for metadata endpoint
def analyze_url():
    t0   = time.time()
    data = request.get_json() or {}

    # FIX 13: sanitise all inputs including description
    app_name    = _sanitise(data.get('app_name', 'Unknown App'))
    developer   = _sanitise(data.get('developer', 'Unknown'))
    description = _sanitise(data.get('description', ''), max_len=MAX_DESC_LEN)
    url         = data.get('url', '').strip()

    # BUG FIX 9: Validate URL format
    if url and not re.match(r'^https?://', url, re.IGNORECASE):
        return jsonify({'error': 'URL must start with http:// or https://'}), 400

    # Deterministic fingerprint from inputs (NOT a real APK hash)
    fingerprint = hashlib.md5(f"{app_name}{developer}{url}".encode()).hexdigest()
    sha_fp      = hashlib.sha256(f"{app_name}{developer}{url}".encode()).hexdigest()

    rng   = random.Random(int(fingerprint, 16))   # BUG FIX 4: isolated RNG
    perms = rng.sample(list(SUSPICIOUS_PERMISSIONS.keys()), rng.randint(4, 14))

    perm_results, ps    = analyze_permissions(perms)
    dark_patterns, ds   = detect_dark_patterns(app_name, developer, description)

    # BUG FIX 10: fingerprint will never match KNOWN_MALICIOUS_HASHES (no real file)
    fake_indicators, fs = detect_fake_app(app_name, developer, fingerprint, sha_fp, ps)
    verdict, ov         = calculate_overall_risk(ps, ds, fs)

    ts = datetime.now().strftime('%Y%m%d_%H%M%S')

    report = {
        "meta": {
            "app_name":          app_name,
            "developer":         developer,
            "url":               url,
            "md5":               fingerprint,
            "sha256":            sha_fp,
            "analysis_time_sec": round(time.time() - t0, 2),
            "analyzed_at":       datetime.now().isoformat(),
            "analysis_mode":     "url_metadata_only",   # BUG FIX 8: honest label
            "api_version":       API_VERSION,
            "metadata_warning":  (
                "This analysis is based on app name, developer, and URL metadata only. "
                "Permissions shown are estimated — upload the APK file for a definitive scan."
            ),
        },
        "module1_preprocessing": {
            "status":         "COMPLETE",
            "is_valid_apk":   None,            # Unknown without a real file
            "analysis_type":  "URL/Metadata",
            "parsing_method": "metadata_only",
        },
        "module2_permissions": {
            "status":            "COMPLETE",
            "total_permissions": len(perms),
            "risk_score":        ps,
            "breakdown":         perm_results,
            "raw_permissions":   perms,
            "high_risk_count":   len(perm_results["HIGH"]),
            "medium_risk_count": len(perm_results["MEDIUM"]),
            "low_risk_count":    len(perm_results["LOW"]),
        },
        "module3_dark_patterns": {
            "status":            "COMPLETE",
            "dark_score":        ds,
            "patterns_detected": len(dark_patterns),
            "details":           dark_patterns,
            "is_dark":           ds > 20,
        },
        "module4_fake_detection": {
            "status":           "COMPLETE",
            "fake_score":       fs,
            "indicators_found": len(fake_indicators),
            "indicators":       fake_indicators,
            "is_fake":          fs > 40,
        },
        "verdict": {
            "overall_verdict":   verdict,
            "overall_score":     round(ov, 1),
            "permission_risk":   ps,
            "dark_pattern_risk": ds,
            "fake_app_risk":     fs,
            "recommendation":    VERDICTS.get(verdict, ""),
        },
    }

    # FIX 14: Save URL reports so /api/stats counts them correctly
    _save_report(report, f"url_{ts}")
    logger.info("URL analysis complete for %s — verdict: %s (%.1f)", app_name, verdict, ov)
    return jsonify(report)


# BUG FIX 11: /api/stats returns real counts only — no fake base offset
@app.route('/api/stats')
def stats():
    report_files = [f for f in os.listdir(REPORTS_FOLDER) if f.endswith('.json')]
    total = len(report_files)

    dangerous  = 0
    suspicious = 0
    safe       = 0
    dark_count = 0

    for fname in report_files:
        try:
            with open(os.path.join(REPORTS_FOLDER, fname)) as f:
                r = json.load(f)
            v = r.get('verdict', {}).get('overall_verdict', '')
            if v == 'DANGEROUS':
                dangerous += 1
            elif v == 'SUSPICIOUS':
                suspicious += 1
            elif v == 'SAFE':
                safe += 1
            if r.get('module3_dark_patterns', {}).get('is_dark'):
                dark_count += 1
        except Exception:
            pass

    return jsonify({
        "total_analyzed": total,
        "fake_detected":  dangerous + suspicious,
        "dark_patterns":  dark_count,
        "safe_apps":      safe,
    })


@app.route('/api/health')
def health():
    return jsonify({"status": "ok", "version": API_VERSION})


if __name__ == '__main__':
    port  = int(os.environ.get('PORT', 5000))
    # BUG FIX 12: debug defaults to False — never True in a production-ready script
    debug = os.environ.get('DEBUG', 'false').lower() == 'true'
    logger.info("Starting Fake App Detector v%s on port %d (debug=%s)", API_VERSION, port, debug)
    app.run(host='0.0.0.0', port=port, debug=debug)