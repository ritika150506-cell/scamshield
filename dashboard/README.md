# ScamShield: AI Phishing and Scam Detector

A Chrome extension and API that warns you about phishing links and scam
messages (fake KYC, UPI refund, courier and bill scams) before you fall for them.

**Live API:** https://scamshield-np7w.onrender.com/docs
(Free tier: the first request after idle can take up to a minute.)

## Features
- Scans every page you open and shows a badge on the icon: OK, !, or X
- Full-page red warning on dangerous sites
- Paste an SMS or email into the popup to check it for scam language
- Every verdict comes with plain-language reasons
- Private dashboard (admin key) with scan history and stats

## How it works
1. Trusted-domain allowlist, checked first to avoid false alarms
2. Character n-gram TF-IDF + Logistic Regression model on the URL text
3. Rule-based explanations: risky TLDs, many hyphens, shorteners, raw IPs
4. Message scanner: scam-phrase patterns, plus a scan of every link inside

## Model results
| Model | Split | Phishing precision | Phishing recall |
|---|---|---|---|
| Random Forest, 16 handcrafted features | random | 0.84 | 0.74 |
| TF-IDF + Logistic Regression | random | 0.93 | 0.92 |
| TF-IDF + Logistic Regression | by domain | 0.88 | 0.91 |

The random split can put URLs from the same scam site in both train and test,
which inflates scores. The by-domain row is the realistic one: it tests on
sites the model has never seen.

Dataset: Kaggle "Phishing Site URLs" (about 507k unique URLs after removing
duplicates; a 100k sample was used for training).

## Limitations
- The dataset is from around 2012, so newer scam styles are under-represented.
- The model sees only the URL text, not page content or domain age.
- Some legitimate sites (for example Google Forms links) look like phishing in
  this dataset, so a trusted-domain allowlist is applied first.
- The message scanner is rule-based, not an LLM.
- On the free hosting tier, scan history resets when the server restarts.

## Tech stack
Python, scikit-learn, FastAPI, SQLite, Chrome Extension (Manifest V3),
Docker, Render.

## Project structure
    backend/     FastAPI app (scan, scan-text, history, stats, dashboard)
    extension/   Chrome extension (popup, auto-scan badge, warning banner)
    dashboard/   Dashboard page
    ml/          Feature code and the trained URL model
    notebooks/   Model experiments

## Run locally
    python -m venv venv
    venv\Scripts\activate
    pip install -r requirements.txt
    uvicorn backend.main:app --reload

Then open http://127.0.0.1:8000/docs. To use the extension, load the
`extension` folder at chrome://extensions (Developer mode, Load unpacked)
and set the API address on the first line of `background.js` and `popup.js`.

## Screenshots
![Popup](screenshots/popup.png)
![Warning banner](screenshots/banner.png)
![Dashboard](screenshots/dashboard.png)