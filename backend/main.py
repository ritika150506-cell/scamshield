import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import joblib
from fastapi import FastAPI
from fastapi.responses import FileResponse
from pydantic import BaseModel

app = FastAPI(title="ScamShield API")

BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_PATH = BASE_DIR / "ml" / "url_model.joblib"
DASHBOARD = BASE_DIR / "dashboard" / "index.html"
bundle = joblib.load(MODEL_PATH)
vec, clf = bundle["vec"], bundle["clf"]

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

# Domains we trust: checked BEFORE the model
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
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}",