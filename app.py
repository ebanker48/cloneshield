import subprocess, json, os, time, io
from typing import List, Dict
import requests
import pandas as pd
import streamlit as st
from difflib import SequenceMatcher
from reportlab.lib.pagesizes import letter, landscape
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

DEFAULT_THRESHOLD = 0.60
DNSTWIST_TIMEOUT = 30
FETCH_TIMEOUT = 10
UA = {"User-Agent": "CloneShield/0.3 (+msp)"}
HISTORY_FILE = "history.csv"

def run_dnstwist(domain: str) -> List[Dict]:
    try:
        out = subprocess.check_output(
            ["python", "-m", "dnstwist", "--registered", "--json", domain],
            stderr=subprocess.DEVNULL,
            timeout=DNSTWIST_TIMEOUT,
        )
        return [d for d in json.loads(out) if d.get("registered")]
    except Exception:
        return []

def fetch_html(url: str, timeout: int = FETCH_TIMEOUT) -> str | None:
    try:
        r = requests.get(url, headers=UA, timeout=timeout, allow_redirects=True)
        if r.status_code == 200 and "html" in r.headers.get("content-type","").lower():
            return " ".join(r.text.split())
    except Exception:
        pass
    return None

def similarity(a: str | None, b: str | None) -> float:
    return SequenceMatcher(None, a or "", b or "").ratio()

def scan_domain(target: str, threshold: float) -> pd.DataFrame:
    canon = fetch_html(f"https://{target}") or fetch_html(f"http://{target}")
    if not canon:
        return pd.DataFrame(columns=["timestamp","target","suspect_domain","similarity","url","ip","ns","mx","notes"])
    rows = []
    for r in run_dnstwist(target):
        sus = r.get("domain")
        html = fetch_html(f"https://{sus}") or fetch_html(f"http://{sus}")
        if not html:
            continue
        sim = similarity(canon, html)
        if sim >= threshold:
            rows.append({
                "timestamp": int(time.time()),
                "target": target,
                "suspect_domain": sus,
                "similarity": round(sim, 3),
                "url": f"https://{sus}",
                "ip": ", ".join(r.get("dns_a", []) or []),
                "ns": ", ".join(r.get("dns_ns", []) or []),
                "mx": ", ".join(r.get("dns_mx", []) or []),
                "notes": "HTML-similar (text ratio)"
            })
    return pd.DataFrame(rows)

def load_history() -> pd.DataFrame:
    if os.path.exists(HISTORY_FILE):
        try:
            return pd.read_csv(HISTORY_FILE)
        except Exception:
            pass
    return pd.DataFrame()

def append_history(df: pd.DataFrame):
    if df is None or df.empty:
        return
    old = load_history()
    new = pd.concat([old, df], ignore_index=True) if not old.empty else df
    new.to_csv(HISTORY_FILE, index=False)

def df_to_pdf_bytes(df: pd.DataFrame, title: str) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(letter))
    elems = []
    styles = getSampleStyleSheet()
    elems.append(Paragraph(title, styles["Title"]))
    elems.append(Spacer(1, 12))
    if "timestamp" in df.columns:
        df["when"] = pd.to_datetime(df["timestamp"], unit="s").dt.strftime("%Y-%m-%d %H:%M")
    cols = [c for c in ["when","target","suspect_domain","similarity","url","ip","ns","mx","notes"] if c in df.columns]
    data = [cols] + df[cols].astype(str).values.tolist()
    table = Table(data, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0),colors.black),
        ("TEXTCOLOR",(0,0),(-1,0),colors.white),
        ("GRID",(0,0),(-1,-1),0.25,colors.grey),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.whitesmoke,colors.lightgrey]),
    ]))
    elems.append(table)
    doc.build(elems)
    buf.seek(0)
    return buf.read()

st.set_page_config(page_title="CloneShield", page_icon="🛡️", layout="centered")
st.title("🛡️ CloneShield — Simple Clone Website Scanner")

with st.expander("How it works"):
    st.markdown("""
- Generates **lookalike domains** using `dnstwist`.
- Fetches HTML and compares with your site.
- Displays matches above threshold and saves to history.
    """)

tabs = st.tabs(["Scan", "History"])

with tabs[0]:
    st.write("Enter client domains (one per line):")
    with st.form("scan_form"):
        domains_input = st.text_area("Domains", placeholder="firstmetro.com\nplantersfirstbank.com", height=140)
        threshold = st.slider("Similarity threshold", 0.4, 0.95, DEFAULT_THRESHOLD, 0.01)
        run_btn = st.form_submit_button("Run Scan", type="primary")
    if run_btn:
        domains = [d.strip() for d in domains_input.splitlines() if d.strip()]
        if not domains:
            st.warning("Please enter at least one domain.")
        else:
            results_all = []
            progress = st.progress(0)
            for i, d in enumerate(domains, start=1):
                st.write(f"Scanning {d}...")
                df = scan_domain(d, threshold)
                if not df.empty:
                    results_all.append(df)
                progress.progress(i/len(domains))
            progress.empty()
            if results_all:
                results = pd.concat(results_all, ignore_index=True)
                st.success(f"Found {len(results)} suspicious lookalikes.")
                st.dataframe(results, use_container_width=True)
                csv = results.to_csv(index=False).encode()
                st.download_button("Download CSV", csv, "findings.csv")
                pdf = df_to_pdf_bytes(results, "CloneShield Report — Current Results")
                st.download_button("Download PDF", pdf, "findings.pdf")
                append_history(results)
            else:
                st.info("No suspicious lookalikes found.")

with tabs[1]:
    st.subheader("Scan History")
    hist = load_history()
    if hist.empty:
        st.info("No history yet.")
    else:
        hist["when"] = pd.to_datetime(hist["timestamp"], unit="s").astype(str)
        st.dataframe(hist, use_container_width=True)
        csv = hist.to_csv(index=False).encode()
        st.download_button("Download Full History CSV", csv, "history.csv")
        pdf = df_to_pdf_bytes(hist, "CloneShield Report — Full History")
        st.download_button("Download Full History PDF", pdf, "history.pdf")
        if st.button("Clear History"):
            os.remove(HISTORY_FILE)
            st.success("History cleared.")
