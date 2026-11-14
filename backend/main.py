import os
import re
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import joblib
from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

app = FastAPI(title="ScamShield API")

BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_PATH = BASE_DIR / "ml" / "url_model.joblib"
DASHBOARD = BASE_DIR / "dashboard" / "index.html"
bundle = joblib.load(MODEL_PATH)
vec, clf = bundle["vec"], bundle["clf"]

# Secret key for dashboard/history/stats. Set ADMIN_KEY on Render.
# If it is not set (running locally), those pages stay open.
ADMIN_KEY = os.environ.get("ADMIN_KEY", "")


def require_key(key: str = ""):
    if ADMIN_KEY and not secrets.compare_digest(key, ADMIN_KEY):
        raise HTTPException(status_code=401, detail="Invalid or missing key")


# ---------- Database (SQLite) ----------

DB_PATH = Path(__file__).resolve().parent / "scans.db"


def init_db():
    with sqlite3.connect(DB_PATH) as con:
        con.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT, content TEXT, verdict TEXT,
            score REAL, created_at TEXT)""")


def save_scan(kind, content, verdict, score):
    with sqlite3.connect(DB_PATH) as con:
        con.execute(
            "INSERT INTO scans (kind, content, verdict, score, created_at) "
            "VALUES (?,?,?,?,?)",
            (kind, content[:500], verdict, score,
             datetime.now(timezone.utc).isoformat()))


init_db()

# ---------- Config ----------

TRUSTED = {
    "google.com", "github.com", "amazon.in", "amazon.com", "microsoft.com",
    "wikipedia.org", "sbi.co.in", "onlinesbi.sbi", "hdfcbank.com",
    "icicibank.com", "npci.org.in", "youtube.com", "linkedin.com",
}

SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "cutt.ly"}
SUSPICIOUS_WORDS = ["login", "verify", "update", "secure", "kyc",
                    "account", "refund", "bonus", "free", "confirm"]
RISKY_TLDS = (".top", ".xyz", ".tk", ".click", ".work", ".gq", ".ml", ".cf")


class UrlIn(BaseModel):
    url: str


class TextIn(BaseModel):
    text: str


def clean_url(u: str) -> str:
    return re.sub(r"^https?://", "", u.strip().lower())


def get_host(clean: str) -> str:
    host = re.split(r"[/?#]", clean, maxsplit=1)[0]
    return host.split("@")[-1].split(":")[0]


def is_trusted(host: str) -> bool:
    return any(host == d or host.endswith("." + d) for d in TRUSTED)


@app.get("/")
def home():
    return {"status": "ScamShield API is running"}


# ---------- URL scanner ----------

def scan_core(item: UrlIn):
    clean = clean_url(item.url)
    host = get_host(clean)
    reasons = []

    if is_trusted(host):
        return {"url": item.url, "verdict": "Safe", "score": 0.0,
                "reasons": ["Domain is on the trusted list"]}

    score = float(clf.predict_proba(vec.transform([clean]))[0][1])

    if any(w in clean for w in SUSPICIOUS_WORDS):
        reasons.append("Contains words scammers often use (login, verify, kyc...)")
    if host.endswith(RISKY_TLDS):
        reasons.append("Uses a domain ending often abused by scammers")
    if host in SHORTENERS:
        reasons.append("Shortened link hides the real destination")
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        reasons.append("Uses a raw IP address instead of a domain name")
    if clean.count("-") >= 3:
        reasons.append("Domain has many hyphens")
    if score >= 0.5:
        reasons.append("Text pattern closely matches known phishing URLs")

    if score >= 0.8:
        verdict = "Dangerous"
    elif score >= 0.4:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    return {"url": item.url, "verdict": verdict,
            "score": round(score, 3), "reasons": reasons}


@app.post("/scan")
def scan(item: UrlIn):
    r = scan_core(item)
    save_scan("url", item.url, r["verdict"], r["score"])
    return r


# ---------- Scam message (SMS / email text) scanner ----------

SCAM_PATTERNS = [
    (r"\b(kyc|know your customer)\b", "Asks you to update or verify KYC"),
    (r"(account|card|sim|upi).{0,30}(block|suspend|deactivat|expire|freez)",
     "Threatens to block or suspend your account"),
    (r"\b(urgent|immediately|within \d+ (hours|hrs|minutes)|last chance|expires? today)\b",
     "Creates false urgency"),
    (r"\b(otp|cvv|pin|password)\b", "Mentions OTP, PIN, CVV or password"),
    (r"(lottery|lucky draw|you (have )?won|prize|cashback|reward points)",
     "Promises a prize or reward"),
    (r"(refund|electricity bill|power (will be )?(cut|disconnect))",
     "Refund or utility-bill pressure"),
    (r"(click|tap|open).{0,20}(link|here|below)", "Pushes you to click a link"),
    (r"(anydesk|teamviewer|quicksupport)",
     "Asks you to install remote-access software"),
    (r"(send|transfer|pay).{0,20}(₹|rs\.?|inr|\d+)",
     "Asks for a payment or transfer"),
]

LINK_RE = re.compile(
    r"(https?://\S+|\b[\w-]+(\.[a-z][a-z-]{1,})+(/\S*)?)", re.I)


@app.post("/scan-text")
def scan_text(item: TextIn):
    text = item.text.lower()
    reasons = [msg for pat, msg in SCAM_PATTERNS if re.search(pat, text)]
    score = min(len(reasons) / 4, 1.0)

    links = [m.group(0).rstrip(".,)") for m in LINK_RE.finditer(item.text)]
    link_results = []
    for link in links[:5]:
        r = scan_core(UrlIn(url=link))
        link_results.append(
            {"url": link, "verdict": r["verdict"], "score": r["score"]})
        if r["verdict"] == "Dangerous":
            reasons.append(f"Contains a dangerous link: {link}")
            score = max(score, 0.9)

    if score >= 0.75:
        verdict = "Dangerous"
    elif score >= 0.4:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    save_scan("text", item.text, verdict, round(score, 2))
    return {"verdict": verdict, "score": round(score, 2),
            "reasons": reasons, "links": link_results}


# ---------- Protected: history, stats, dashboard ----------

@app.get("/history", dependencies=[Depends(require_key)])
def history(limit: int = 50):
    with sqlite3.connect(DB_PATH) as con:
        rows = con.execute(
            "SELECT id, kind, content, verdict, score, created_at "
            "FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    cols = ["id", "kind", "content", "verdict", "score", "created_at"]
    return [dict(zip(cols, r)) for r in rows]


@app.get("/stats", dependencies=[Depends(require_key)])
def stats():
    with sqlite3.connect(DB_PATH) as con:
        rows = con.execute(
            "SELECT verdict, COUNT(*) FROM scans GROUP BY verdict").fetchall()
    return {"total":