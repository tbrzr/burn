#!/usr/bin/env python3
"""burn: zero-knowledge "burn after reading" notes.

The server only ever stores ciphertext. Encryption happens in the browser and, in
random-key mode, the key lives in the URL #fragment, which browsers never send.
Free tier: text, 1 view, up to 24h. Pro (credit-gated, optional): bigger payload,
up to 5 views, up to 7 days. Credit packs are sold through Stripe Checkout and
confirmed by retrieving the session (no webhook needed). Payments are off unless
STRIPE_SECRET is set.

Configuration is by environment variables, or a KEY=VALUE file named by BURN_CONFIG_FILE.
See README.md.
"""
import json, os, re, threading, time, hashlib, secrets as pysecrets, urllib.parse, urllib.request
from flask import Flask, jsonify, request, send_from_directory
from werkzeug.exceptions import HTTPException

HERE = os.path.dirname(os.path.abspath(__file__))
WEB = os.path.join(HERE, "web")
app = Flask(__name__, static_folder=WEB, static_url_path="")
LOCK = threading.RLock()   # serializes note/credit read-modify-write so a one-view note can only be read once

@app.errorhandler(HTTPException)
def _json_error(e):
    return jsonify({"error": e.description}), e.code
DATA = os.environ.get("BURN_DATA_DIR", os.path.join(HERE, "data"))
NOTES = DATA + "/notes"
CREDITS_FILE = DATA + "/credits.json"
BLOCK_FILE = DATA + "/blocklist.json"
REPORTS_FILE = DATA + "/reports.json"
FREE_USAGE_FILE = DATA + "/free_usage.json"
SALT_FILE = DATA + "/.salt"
SECRETS_FILE = os.environ.get("BURN_CONFIG_FILE", "")   # optional KEY=VALUE file
os.makedirs(NOTES, exist_ok=True)
os.chmod(DATA, 0o700)
os.chmod(NOTES, 0o700)

# Text-only by design. The server can never read ciphertext, so the only way to keep
# file-borne abuse (malware/CSAM) off the platform is to not allow file-sized payloads.
# These caps fit text/passwords/keys but reject anything file-sized.
FREE_MAX_CT = 32 * 1024
PRO_MAX_CT = 96 * 1024
FREE_MAX_HOURS = 24
PRO_MAX_HOURS = 168
PRO_MAX_VIEWS = 5
REPORTS_TO_BLOCK = 3             # reports against one creator hash before auto-block
FREE_DAILY_CAP = 3               # free burns per IP per UTC day before Pro is required

def salt():
    try:
        with open(SALT_FILE) as f:
            return f.read().strip()
    except Exception:
        s = pysecrets.token_hex(16)
        try:
            with open(SALT_FILE, "w") as f: f.write(s)
            os.chmod(SALT_FILE, 0o600)
        except Exception:
            pass
        return s

def ip_hash(ip):
    return hashlib.sha256((salt() + "|" + (ip or "")).encode()).hexdigest()[:16]

def is_blocked(h):
    return h in load(BLOCK_FILE, [])

def verify_turnstile(token, ip):
    """Cloudflare Turnstile. If no secret is configured, pass through (so the tool
    still works pre-config). If configured, a missing/invalid token is rejected;
    a network error to Cloudflare fails OPEN so a CF outage can't lock everyone out."""
    secret = env().get("TURNSTILE_SECRET_KEY")
    if not secret:
        return True
    if not token:
        return False
    try:
        body = urllib.parse.urlencode({"secret": secret, "response": token, "remoteip": ip}).encode()
        req = urllib.request.Request("https://challenges.cloudflare.com/turnstile/v0/siteverify", data=body)
        with urllib.request.urlopen(req, timeout=10) as r:
            return bool(json.load(r).get("success"))
    except Exception:
        return True

def env():
    """Config from the optional BURN_CONFIG_FILE, overridden by real environment variables."""
    out = {}
    if SECRETS_FILE:
        try:
            with open(SECRETS_FILE) as f:
                for line in f:
                    line = line.strip()
                    if "=" in line and not line.startswith("#"):
                        k, v = line.split("=", 1); out[k.strip()] = v.strip()
        except Exception:
            pass
    for k in ("STRIPE_SECRET", "PACK_PRICE_CENTS", "PACK_CREDITS", "TURNSTILE_SITE_KEY", "TURNSTILE_SECRET_KEY"):
        if os.environ.get(k):
            out[k] = os.environ[k]
    return out

def load(path, d):
    try:
        with open(path) as f: return json.load(f)
    except Exception: return d

def save(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f: json.dump(obj, f)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)

def sweep():
    now = time.time()
    try:
        for fn in os.listdir(NOTES):
            p = os.path.join(NOTES, fn)
            try:
                if json.load(open(p)).get("exp", 0) < now: os.remove(p)
            except Exception:
                try: os.remove(p)
                except Exception: pass
    except Exception:
        pass

def credits_for(token):
    return load(CREDITS_FILE, {}).get(token, {}).get("credits", 0)

def take_credit(token):
    with LOCK:
        allc = load(CREDITS_FILE, {})
        if allc.get(token, {}).get("credits", 0) <= 0:
            return False
        allc[token]["credits"] -= 1; save(CREDITS_FILE, allc)
        return True

def give_credit(token):
    with LOCK:
        allc = load(CREDITS_FILE, {})
        if token in allc:
            allc[token]["credits"] = allc[token].get("credits", 0) + 1; save(CREDITS_FILE, allc)

def today_str():
    return time.strftime("%Y-%m-%d", time.gmtime())

def free_uses_today(h):
    rec = load(FREE_USAGE_FILE, {}).get(h, {})
    return rec.get("count", 0) if rec.get("date") == today_str() else 0

def record_free_use(h):
    all_usage = load(FREE_USAGE_FILE, {})
    rec = all_usage.get(h, {})
    if rec.get("date") != today_str():
        rec = {"date": today_str(), "count": 0}
    rec["count"] = rec.get("count", 0) + 1
    all_usage[h] = rec
    save(FREE_USAGE_FILE, all_usage)

MAX_NOTES = 8000           # disk-abuse ceiling for stored (unburned) notes
RATE = {}                  # in-memory per-IP sliding windows (single worker)
TRUST_PROXY = os.environ.get("BURN_TRUST_PROXY", "") == "1"   # set only behind a proxy that sets X-Real-IP
def get_ip():
    if TRUST_PROXY:
        return request.headers.get("X-Real-IP") or request.remote_addr or "?"
    return request.remote_addr or "?"
def rate_ok(bucket, ip, limit, window):
    now = time.time(); key = bucket + "|" + ip
    arr = [t for t in RATE.get(key, []) if now - t < window]
    if len(arr) >= limit:
        RATE[key] = arr; return False
    arr.append(now); RATE[key] = arr
    if len(RATE) > 5000:
        for k in list(RATE.keys()):
            RATE[k] = [t for t in RATE[k] if now - t < 3600]
            if not RATE[k]: del RATE[k]
    return True
def note_count():
    try: return sum(1 for f in os.listdir(NOTES) if f.endswith(".json"))
    except Exception: return 0


@app.route("/")
def index():
    return send_from_directory(WEB, "index.html")

@app.route("/api/health")
def health():
    return jsonify({"ok": True, "payments": bool(env().get("STRIPE_SECRET"))})

@app.route("/api/config")
def config():
    e = env()
    return jsonify({"payments": bool(e.get("STRIPE_SECRET")),
                    "pack_credits": int(e.get("PACK_CREDITS", 20)),
                    "pack_price": int(e.get("PACK_PRICE_CENTS", 300)),
                    "free_daily_cap": FREE_DAILY_CAP,
                    "turnstile_sitekey": e.get("TURNSTILE_SITE_KEY", "")})

@app.route("/api/credits/<token>")
def credits(token):
    if not rate_ok("credits", get_ip(), 30, 600):
        return jsonify({"error": "rate"}), 429
    return jsonify({"credits": credits_for(token)})

@app.route("/api/create", methods=["POST"])
def create():
    ipx = get_ip(); h = ip_hash(ipx)
    if not rate_ok("create", ipx, 20, 600):
        return jsonify({"error": "rate"}), 429
    if is_blocked(h):
        return jsonify({"error": "blocked"}), 403
    d = request.get_json(silent=True) or {}
    if not d.get("tos"):
        return jsonify({"error": "tos"}), 400
    if not verify_turnstile(d.get("cf_token", ""), ipx):
        return jsonify({"error": "turnstile"}), 403
    ct = d.get("ct", "")
    if not isinstance(ct, str) or not ct:
        return jsonify({"error": "empty"}), 400
    pro = bool(d.get("pro"))
    token = d.get("token", "")
    try:
        hours = int(d.get("hours", 24)); views = int(d.get("views", 1))
    except Exception:
        return jsonify({"error": "bad params"}), 400
    if pro:
        if len(ct) > PRO_MAX_CT: return jsonify({"error": "too_big"}), 413
        hours = max(1, min(PRO_MAX_HOURS, hours)); views = max(1, min(PRO_MAX_VIEWS, views))
        if not take_credit(token):   # atomic check + decrement, so concurrent creates cannot double-spend
            return jsonify({"error": "no_credits"}), 402
    else:
        if free_uses_today(h) >= FREE_DAILY_CAP:
            return jsonify({"error": "daily_limit", "limit": FREE_DAILY_CAP}), 402
        if len(ct) > FREE_MAX_CT: return jsonify({"error": "too_big_free"}), 413
        hours = max(1, min(FREE_MAX_HOURS, hours)); views = 1
    sweep()
    if note_count() >= MAX_NOTES:
        if pro: give_credit(token)
        return jsonify({"error": "busy"}), 503
    nid = pysecrets.token_urlsafe(12)
    save(os.path.join(NOTES, nid + ".json"),
         {"ct": ct, "views": views, "exp": time.time() + hours * 3600, "pw": bool(d.get("pw")), "ip": h})
    if not pro:
        with LOCK:
            record_free_use(h)
    return jsonify({"ok": True, "id": nid, "views": views, "hours": hours})

@app.route("/api/note/<nid>")
def peek(nid):
    """Returns whether the note exists + if it is password protected. Does NOT burn."""
    if not rate_ok("peek", get_ip(), 30, 600):
        return jsonify({"error": "rate"}), 429
    nid = re.sub(r"[^A-Za-z0-9_\-]", "", nid)
    p = os.path.join(NOTES, nid + ".json")
    n = load(p, None)
    if not n or n.get("exp", 0) < time.time():
        if n:
            try: os.remove(p)
            except Exception: pass
        return jsonify({"gone": True})
    return jsonify({"exists": True, "pw": n.get("pw", False)})

@app.route("/api/note/<nid>/burn", methods=["POST"])
def burn(nid):
    """Consumes one view, returns ciphertext, deletes when views exhausted."""
    if not rate_ok("burn", get_ip(), 30, 600):
        return jsonify({"error": "rate"}), 429
    nid = re.sub(r"[^A-Za-z0-9_\-]", "", nid)
    p = os.path.join(NOTES, nid + ".json")
    LOCK.acquire()
    try:
        return _burn_locked(p)
    finally:
        LOCK.release()

def _burn_locked(p):
    n = load(p, None)
    if not n or n.get("exp", 0) < time.time():
        if n:
            try: os.remove(p)
            except Exception: pass
        return jsonify({"gone": True}), 404
    ct = n["ct"]; n["views"] -= 1
    if n["views"] <= 0:
        try: os.remove(p)
        except Exception: pass
    else:
        save(p, n)
    return jsonify({"ct": ct, "views_left": max(0, n["views"])})

@app.route("/api/report", methods=["POST"])
def report():
    """A recipient flags a link as abusive. We can't read the content (it's E2E
    encrypted), so the safe action is: destroy the note now and count the report
    against its creator. Enough reports auto-blocks that creator from posting."""
    if not rate_ok("report", get_ip(), 20, 600):
        return jsonify({"error": "rate"}), 429
    d = request.get_json(silent=True) or {}
    nid = re.sub(r"[^A-Za-z0-9_\-]", "", d.get("id", ""))
    p = os.path.join(NOTES, nid + ".json")
    n = load(p, None)
    h = n.get("ip") if n else None
    if n:
        try: os.remove(p)
        except Exception: pass
    if h:
        reps = load(REPORTS_FILE, {})
        reps[h] = reps.get(h, 0) + 1
        save(REPORTS_FILE, reps)
        if reps[h] >= REPORTS_TO_BLOCK:
            bl = load(BLOCK_FILE, [])
            if h not in bl:
                bl.append(h); save(BLOCK_FILE, bl)
    return jsonify({"ok": True})

# ---------------- micro-payments (Stripe Checkout, webhook-free) ----------------
def stripe_post(path, data, key):
    body = urllib.parse.urlencode(data, doseq=True).encode()
    req = urllib.request.Request("https://api.stripe.com/v1/" + path, data=body,
                                 headers={"Authorization": "Bearer " + key,
                                          "Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.load(r)

def stripe_get(path, key):
    req = urllib.request.Request("https://api.stripe.com/v1/" + path,
                                 headers={"Authorization": "Bearer " + key})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.load(r)

@app.route("/api/checkout", methods=["POST"])
def checkout():
    # Card-testing defense (same lesson as the 2026-06-25 $0.99 incident): this mints a
    # payable Stripe session and the subdomain is gray-cloud, so app-level limits are the
    # only guard. Tight short window + a daily ceiling per IP.
    ip = get_ip()
    if not rate_ok("checkout", ip, 6, 60) or not rate_ok("checkout_day", ip, 30, 86400):
        return jsonify({"error": "rate"}), 429
    e = env(); key = e.get("STRIPE_SECRET")
    if not key:
        return jsonify({"error": "payments_off"}), 501
    d = request.get_json(silent=True) or {}
    token = re.sub(r"[^A-Za-z0-9_\-]", "", d.get("token", ""))[:64]
    if not token:
        return jsonify({"error": "no_token"}), 400
    price = int(e.get("PACK_PRICE_CENTS", 300)); packc = int(e.get("PACK_CREDITS", 20))
    base = (os.environ.get("BURN_BASE_URL") or request.host_url).rstrip("/")
    try:
        sess = stripe_post("checkout/sessions", {
            "mode": "payment",
            "success_url": base + "/?paid={CHECKOUT_SESSION_ID}&token=" + token,
            "cancel_url": base + "/?cancel=1",
            "line_items[0][quantity]": 1,
            "line_items[0][price_data][currency]": "usd",
            "line_items[0][price_data][unit_amount]": price,
            "line_items[0][price_data][product_data][name]": "Burn Pro Credits (%d)" % packc,
            "metadata[token]": token,
            "metadata[credits]": packc,
        }, key)
        return jsonify({"url": sess["url"]})
    except Exception as ex:
        return jsonify({"error": "stripe_error"}), 502

@app.route("/api/confirm", methods=["POST"])
def confirm():
    # Block enumeration of Stripe session ids (each confirm calls the Stripe API).
    if not rate_ok("confirm", get_ip(), 20, 600):
        return jsonify({"error": "rate"}), 429
    e = env(); key = e.get("STRIPE_SECRET")
    if not key:
        return jsonify({"error": "payments_off"}), 501
    d = request.get_json(silent=True) or {}
    sid = re.sub(r"[^A-Za-z0-9_\-]", "", d.get("session_id", ""))
    token = re.sub(r"[^A-Za-z0-9_\-]", "", d.get("token", ""))[:64]
    if not sid or not token:
        return jsonify({"error": "bad"}), 400
    try:
        sess = stripe_get("checkout/sessions/" + sid, key)
    except Exception as ex:
        return jsonify({"error": "stripe_error"}), 502
    if sess.get("payment_status") != "paid" or (sess.get("metadata", {}) or {}).get("token") != token:
        return jsonify({"error": "not_paid"}), 402
    with LOCK:
        allc = load(CREDITS_FILE, {})
        rec = allc.get(token, {"credits": 0, "redeemed": []})
        if sid in rec.get("redeemed", []):
            return jsonify({"credits": rec["credits"], "already": True})
        add = int((sess.get("metadata", {}) or {}).get("credits", 0) or 0)
        rec["credits"] = rec.get("credits", 0) + add
        rec.setdefault("redeemed", []).append(sid)
        allc[token] = rec; save(CREDITS_FILE, allc)
    return jsonify({"credits": rec["credits"], "added": add})

if __name__ == "__main__":
    app.run(host=os.environ.get("BURN_HOST", "127.0.0.1"), port=int(os.environ.get("BURN_PORT", "8350")), threaded=True)
