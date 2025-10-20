import os, time, io, re
import requests
import pandas as pd
import streamlit as st
from difflib import SequenceMatcher
from urllib.parse import urlparse
from reportlab.lib.pagesizes import letter, landscape
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

DEFAULT_THRESHOLD = 0.60
CONNECT_TIMEOUT = 6
READ_TIMEOUT = 12
UA = {"User-Agent": "CloneShield/0.4 (+streamlit)"}
HISTORY_FILE = "history.csv"

COMMON_TLDS = [".com",".net",".org",".co",".io",".info",".biz",".site",".online",".app"]
PREFIXES = ["secure","login","verify","account","support","update","auth","my","portal","service"]
SUFFIXES = ["login","secure","verify","update","auth","support","access","portal"]
SUBS = ["secure","login","verify","auth","account","portal"]

def split_domain(domain):
    d = domain.strip().lower()
    if d.startswith("http://") or d.startswith("https://"):
        d = urlparse(d).netloc
    parts = d.split(".")
    if len(parts) < 2:
        return d, ""
    return ".".join(parts[:-1]), "." + parts[-1]

def gen_candidates(domain, cap=300):
    name, tld = split_domain(domain)
    if not name:
        return []
    domains = set()
    for p in PREFIXES:
        domains.add(f"{p}{name}{tld or '.com'}")
        domains.add(f"{p}-{name}{tld or '.com'}")
    for s in SUFFIXES:
        domains.add(f"{name}{s}{tld or '.com'}")
        domains.add(f"{name}-{s}{tld or '.com'}")
    for sub in SUBS:
        domains.add(f"{sub}.{name}{tld or '.com'}")
    # TLD variations
    for alt in COMMON_TLDS:
        if alt != tld:
            domains.add(f"{name}{alt}")
    # Obvious forms
    domains.add(f"{name}-login{tld or '.com'}")
    domains.add(f"{name}-secure{tld or '.com'}")
    domains.add(f"login-{name}{tld or '.com'}")
    domains.add(f"secure-{name}{tld or '.com'}")
    return list(domains)[:cap]

def fetch_html(url):
    try:
        r = requests.get(url, headers=UA, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT), allow_redirects=True)
        if r.status_code < 400 and "html" in r.headers.get("content-type","").lower():
            return " ".join(r.text.split())
    except Exception:
        pass
    return None

def similarity(a,b):
    return SequenceMatcher(None, a or "", b or "").ratio()

def scan_domain(target, threshold):
    canon = fetch_html(f"https://{target}") or fetch_html(f"http://{target}")
    rows = []
    if not canon:
        return pd.DataFrame(rows, columns=["timestamp","target","suspect_domain","similarity","url","notes"])
    candidates = gen_candidates(target, cap=200)
    for cand in candidates:
        html = fetch_html(f"https://{cand}") or fetch_html(f"http://{cand}")
        if not html:
            continue
        sim = similarity(canon, html)
        if sim >= threshold:
            rows.append({
                "timestamp": int(time.time()),
                "target": target,
                "suspect_domain": cand,
                "similarity": round(sim, 3),
                "url": f"https://{cand}",
                "notes": "HTML-similar"
            })
    return pd.DataFrame(rows)

def load_history():
    if os.path.exists(HISTORY_FILE):
        try:
            return pd.read_csv(HISTORY_FILE)
        except Exception:
            return pd.DataFrame()
    return pd.DataFrame()

def append_history(df):
    if df is None or df.empty:
        return
    old = load_history()
    new = pd.concat([old, df], ignore_index=True) if not old.empty else df
    new.to_csv(HISTORY_FILE, index=False)

def df_to_pdf_bytes(df, title):
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(letter))
    elems, styles = [], getSampleStyleSheet()
    elems.append(Paragraph(title, styles["Title"]))
    elems.append(Spacer(1, 12))
    if "timestamp" in df.columns:
        df["when"] = pd.to_datetime(df["timestamp"], unit="s").dt.strftime("%Y-%m-%d %H:%M")
    cols = [c for c in ["when","target","suspect_domain","similarity","url","notes"] if c in df.columns]
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
st.title("🛡️ CloneShield — No dnstwist version")

with st.expander("How it works"):
    st.markdown("- Generates lookalike candidates in Python\n- Fetches each site\n- Compares HTML with your real site\n- Shows matches above threshold")

tabs = st.tabs(["Scan","History"])

with tabs[0]:
    st.write("Enter domains (one per line):")
    with st.form("scan_form"):
        domains_input = st.text_area("Domains", placeholder="firstmetro.com\nplantersfirstbank.com")
        threshold = st.slider("Similarity threshold",0.4,0.95,DEFAULT_THRESHOLD,0.01)
        run_btn = st.form_submit_button("Run Scan",type="primary")
    if run_btn:
        domains = [d.strip() for d in domains_input.splitlines() if d.strip()]
        if not domains:
            st.warning("Enter at least one domain.")
        else:
            all_results=[]
            progress=st.progress(0)
            for i,d in enumerate(domains,start=1):
                st.write(f"Scanning {d}…")
                df=scan_domain(d,threshold)
                if not df.empty:
                    all_results.append(df)
                progress.progress(i/len(domains))
            progress.empty()
            if all_results:
                results=pd.concat(all_results,ignore_index=True)
                st.success(f"Found {len(results)} suspicious lookalikes.")
                st.dataframe(results,use_container_width=True)
                st.download_button("Download CSV",results.to_csv(index=False).encode(),"findings.csv")
                st.download_button("Download PDF",df_to_pdf_bytes(results,"CloneShield Report — Current Results"),"findings.pdf",mime="application/pdf")
                append_history(results)
            else:
                st.info("No suspicious lookalikes found.")

with tabs[1]:
    st.subheader("History")
    hist=load_history()
    if hist.empty:
        st.info("No history yet.")
    else:
        hist["when"]=pd.to_datetime(hist["timestamp"],unit="s").astype(str)
        st.dataframe(hist,use_container_width=True)
        st.download_button("Download Full CSV",hist.to_csv(index=False).encode(),"history.csv")
        st.download_button("Download Full PDF",df_to_pdf_bytes(hist,"CloneShield Report — Full History"),"history.pdf",mime="application/pdf")
        if st.button("Clear History"):
            os.remove(HISTORY_FILE)
            st.success("History cleared.")
