# PhishGuard — Phishing URL Detection System (CSL-G57)
Student: Somya Saboo | Roll No.: 23ESKCY050 | Batch: CS-IOT-A-G2

## Run on Windows
1. Install Python 3.10+; open this folder in VS Code.
2. Terminal: `python -m venv .venv`
3. Activate PowerShell: `.venv\Scripts\Activate.ps1` (CMD: `.venv\Scripts\activate.bat`).
4. `pip install -r requirements.txt`
5. `python app.py`; visit `http://127.0.0.1:8000`.

## Features
Rule-based lexical feature scoring + Random Forest ML; local SQLite history stores URL SHA-256 digest only; HMAC-SHA256 audit value; RSA-PSS/SHA-256 digital signature of each scan receipt. The submitted URL is never fetched, resolved or opened.

Safe lexical examples: `https://example.com/` and fabricated `http://secure-login-verify-account.com/login?confirm=1`. Never visit the fabricated test string. Synthetic model examples are for demonstration only and do not represent a real-world threat dataset or benchmark.

Database: `data/scans.db`. Demo RSA keys are created in `keys/` on first run. Protect the private key; do not publish it. Development server binds only to localhost over HTTP. A real deployment requires HTTPS/TLS, authentication, rate limiting, secure secret management and key rotation.
