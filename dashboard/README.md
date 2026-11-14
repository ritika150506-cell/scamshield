# ScamShield: AI Phishing and Scam Detector

Chrome extension and API that flags phishing links and scam messages
(fake KYC, UPI refund, bill threats) with plain-language reasons.

Live API: https://scamshield-np7w.onrender.com/docs

## Features
- Auto-scans every page, with a badge (OK, !, X) and a red warning banner
- Paste an SMS or email to check it for scam language
- Admin dashboard with scan history and stats

## Model
Character n-gram TF-IDF + Logistic Regression on about 500k URLs
(Kaggle "Phishing Site URLs").

| Model | Split | Phishing precision | Phishing recall |
|---|---|---|---|
| Random Forest, 16 handcrafted features | random | 0.84 | 0.74 |
| TF-IDF + Logistic Regression | random | 0.93 | 0.92 |
| TF-IDF + Logistic Regression | by domain | 0.88 | 0.91 |

## Tech stack
Python, scikit-learn, FastAPI, SQLite, Chrome Extension (Manifest V3),
Docker, Render.

## Run locally
    pip install -r requirements.txt
    uvicorn backend.main:app --reload
Load the `extension` folder at chrome://extensions (Developer mode).