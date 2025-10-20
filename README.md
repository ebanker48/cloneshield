# CloneShield — Simple Clone Website Scanner (v3.1)

Detect spoofed or cloned websites by scanning for registered lookalikes (via dnstwist) and comparing HTML similarity.

## Deploy on Streamlit Cloud
1. Create a **public GitHub repo** and add:
   - app.py
   - requirements.txt
   - runtime.txt
2. Go to https://streamlit.io/cloud → Deploy an app → select your repo → entry file = `app.py`.
3. Done! Streamlit Cloud will build and host your app automatically.

## Run locally (Mac/Windows/Linux)
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```
