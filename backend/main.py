import re
from pathlib import Path

import joblib
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="ScamShield API")

MODEL_PATH = Path(__file__).resolve().parent.parent / "ml" / "url_model.joblib"
bundle = joblib.load(MODEL_PATH)
vec, clf = bundle["vec"], bundle["clf"]

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


@app.post("/scan")
def scan(item: UrlIn):
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