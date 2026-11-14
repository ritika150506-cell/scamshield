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

# matches http(s) links and bare domains like sbi-kyc-update-now.top or bit.ly/xyz
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
        r = scan(UrlIn(url=link))
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

    return {"verdict": verdict, "score": round(score, 2),
            "reasons": reasons, "links": link_results}