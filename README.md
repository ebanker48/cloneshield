# Simple Clone Scanner — v3 (No Password, PDF Exports, History)

**What it does:** paste domains → scans for registered lookalikes (dnstwist) → flags HTML-similar pages → shows results and saves to history. Now includes **PDF exports** for current results and full history.

## Deploy on Streamlit Community Cloud (recommended)
1. Create a **public GitHub repo** and add:
   - `app.py`
   - `requirements.txt`
2. Go to https://streamlit.io/cloud → **Deploy an app** → connect your repo → entry file = `app.py`.
3. Done. You have a cloud HTTPS URL.

## Run locally (Mac/Windows/Linux)
```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

## Notes
- History saves to `history.csv` in the working directory.
- This MVP uses **HTML text similarity**; raise the threshold for fewer false positives.
- Streamlit Cloud does not run background jobs; to automate nightly scans, use an external scheduler (e.g., GitHub Actions calling a webhook) or run this locally on a schedule. I can wire that up if you want.
