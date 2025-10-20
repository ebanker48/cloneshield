# CloneShield — Streamlit (No dnstwist version)

Detect spoofed or cloned websites by generating lookalike domains in pure Python and comparing HTML similarity.

## Deploy on Streamlit Cloud
1. Create a **public GitHub repo** and add:
   - app.py
   - requirements.txt
   - runtime.txt
2. Go to https://streamlit.io/cloud → Deploy an app → select your repo → entry file = `app.py`.
3. Streamlit Cloud will build and host your app automatically.

## Run locally
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```
