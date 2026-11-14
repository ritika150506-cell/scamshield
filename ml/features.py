import re

SUSPICIOUS_WORDS = ["login", "verify", "update", "secure", "account",
                    "bank", "kyc", "free", "bonus", "confirm", "upi", "refund"]
SHORTENERS = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "cutt.ly"]

def extract_features(url: str) -> dict:
    url = str(url).strip()
    # remove the scheme so the model can't cheat using http/https
    clean = re.sub(r"^https?://", "", url.lower())

    # split by hand instead of urlparse (urlparse crashes on malformed URLs)
    host_end = len(clean)
    for sep in ("/", "?", "#"):
        i = clean.find(sep)
        if i != -1:
            host_end = min(host_end, i)
    host = clean[:host_end]
    rest = clean[host_end:]
    path = re.split(r"[?#]", rest, maxsplit=1)[0]

    digits = sum(c.isdigit() for c in clean)
    return {
        "url_length": len(clean),
        "host_length": len(host),
        "path_length": len(path),
        "num_dots": clean.count("."),
        "num_hyphens": clean.count("-"),
        "num_digits": digits,
        "digit_ratio": digits / max(len(clean), 1),
        "num_at": clean.count("@"),
        "num_question": clean.count("?"),
        "num_equals": clean.count("="),
        "num_percent": clean.count("%"),
        "num_slashes": clean.count("/"),
        "num_subdomains": max(host.count(".") - 1, 0),
        "has_ip": int(bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}(:\d+)?", host))),
        "has_suspicious_word": int(any(w in clean for w in SUSPICIOUS_WORDS)),
        "is_shortener": int(any(s in host for s in SHORTENERS)),
    }