\
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

# -----------------------
# Config
# -----------------------
DEFAULT_THRESHOLD = 0.60
DNSTWIST_TIMEOUT = 30
FETCH_TIMEOUT    = 10
UA = {"User-Agent": "CloneScanner/0.3 (+msp)"}

HISTORY_FILE = "history.csv"   # simple on-disk history

# -----------------------
# Utilities
# -----------------------
def run_dnstwist(domain: str) -> List[Dict]:
    try:
        out = subprocess.check_output(
            ["dnstwist", "--registered", "--json", domain],
            stderr=subprocess.DEVNULL,
            timeout=DNSTWIST_TIMEOUT,
        )
        data = json.loads(out)
        return [d for d in data if d.get("registered")]
    except Exception:
        return []

def fetch_html(url: str, timeout: int = FETCH_TIMEOUT) -> str | None:
    try:
        r = requests.get(url, headers=UA, timeout=timeout, allow_redirects=True)
        ctype = r.headers.get("content-type","").lower()
        if r.status_code == 200 and ("text/html" in ctype or "text/" in ctype):
            return " ".join(r.text.split())
    except Exception:
        pass
    return None

def similarity(a: str | None, b: str | None) -> float:
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a, b).ratio()

def scan_domain(target: str, threshold: float) -> pd.DataFrame:
    canon = fetch_html(f"https://{target}") or fetch_html(f"http://{target}")
    rows = []
    if not canon:
        return pd.DataFrame(rows, columns=[
            "timestamp","target","suspect_domain","similarity","url","ip","ns","mx","notes"
        ])

    regs = run_dnstwist(target)
    for r in regs:
        sus = r.get("domain")
        url = f"https://{sus}"
        html = fetch_html(url) or fetch_html(url.replace("https://","http://"))
        if not html:
            continue
        sim = similarity(canon, html)
        if sim >= threshold:
            rows.append({
                "timestamp": int(time.time()),
                "target": target,
                "suspect_domain": sus,
                "similarity": round(sim, 3),
                "url": url,
                "ip": ", ".join(r.get("dns_a", []) or []),
                "ns": ", ".join(r.get("dns_ns", []) or []),
                "mx": ", ".join(r.get("dns_mx", []) or []),
                "notes": "HTML-similar (simple text ratio)"
            })
    return pd.DataFrame(rows)

def load_history() -> pd.DataFrame:
    if os.path.exists(HISTORY_FILE):
        try:
            return pd.read_csv(HISTORY_FILE)
        except Exception:
            return pd.DataFrame()
    return pd.DataFrame()

def append_history(df: pd.DataFrame):
    if df is None or df.empty:
        return
    old = load_history()
    new = pd.concat([old, df], ignore_index=True) if not old.empty else df
    new.to_csv(HISTORY_FILE, index=False)

def df_download_button(df: pd.DataFrame, label: str, filename: str):
    csv_bytes = df.to_csv(index=False).encode("utf-8")
    st.download_button(label, data=csv_bytes, file_name=filename, mime="text/csv")

def df_to_pdf_bytes(df: pd.DataFrame, title: str = "Clone Scan Report") -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(letter), leftMargin=24, rightMargin=24, topMargin=24, bottomMargin=24)
    elements = []
    styles = getSampleStyleSheet()
    elements.append(Paragraph(title, styles["Title"]))
    elements.append(Spacer(1, 12))

    cols = ["timestamp", "target", "suspect_domain", "similarity", "url", "ip", "ns", "mx", "notes"]
    df = df.copy()
    if "timestamp" in df.columns:
        df["when"] = pd.to_datetime(df["timestamp"], unit="s").dt.strftime("%Y-%m-%d %H:%M")
        cols = ["when", "target", "suspect_domain", "similarity", "url", "ip", "ns", "mx", "notes"]
    headers = cols
    data = [headers] + df[cols].astype(str).values.tolist()

    table = Table(data, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#222222")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("ALIGN", (0,0), (-1,-1), "LEFT"),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE", (0,0), (-1,0), 11),
        ("FONTSIZE", (0,1), (-1,-1), 9),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.whitesmoke, colors.lightgrey]),
        ("GRID", (0,0), (-1,-1), 0.25, colors.grey),
    ]))
    elements.append(table)
    doc.build(elements)
    buffer.seek(0)
    return buffer.read()

# -----------------------
# UI
# -----------------------
st.set_page_config(page_title="Simple Clone Scanner", page_icon="🕵️", layout="centered")
st.title("🕵️ Simple Clone Website Scanner")

with st.expander("How it works (MVP)", expanded=False):
    st.markdown(\"\"\"\
- Generates **lookalike domains** using `dnstwist` (registered only).
- Fetches HTML for each candidate and compares to the **canonical site** via a simple text similarity ratio.
- Rows above the **threshold** are shown and saved to **history**.
    \"\"\"\
    )

tabs = st.tabs(["Scan", "History"])

with tabs[0]:
    st.write("Enter one or more client domains (no protocol). Example: `firstmetro.com`")
    with st.form("scan_form"):
        domains_input = st.text_area(
            "Client domains (one per line)",
            placeholder="firstmetro.com\\nplantersfirstbank.com",
            height=140
        )
        threshold = st.slider("Similarity threshold", 0.40, 0.95, DEFAULT_THRESHOLD, 0.01, help="Higher = fewer alerts")
        run_btn = st.form_submit_button("Run Scan", type="primary")

    if run_btn:
        domains = [d.strip() for d in (domains_input or "").splitlines() if d.strip() and not d.strip().startswith("#")]
        if not domains:
            st.warning("Please enter at least one domain.")
        else:
            all_results = []
            progress = st.progress(0)
            status = st.empty()
            for i, d in enumerate(domains, start=1):
                status.write(f"Scanning **{d}** ({i}/{len(domains)}) …")
                df = scan_domain(d, threshold)
                if not df.empty:
                    all_results.append(df)
                progress.progress(i/len(domains))
            status.empty(); progress.empty()

            if all_results:
                results = pd.concat(all_results, ignore_index=True)
                st.success(f"Found **{len(results)}** suspicious lookalike(s) across {len(domains)} domain(s).")
                st.dataframe(results, use_container_width=True)

                # Downloads
                df_download_button(results, "Download current results (CSV)", "findings.csv")
                pdf_bytes = df_to_pdf_bytes(results, title="Clone Scan Report (Current Results)")
                st.download_button("Download current results (PDF)", data=pdf_bytes, file_name="findings.pdf", mime="application/pdf")

                # Save to history
                append_history(results)
            else:
                st.info("No suspicious lookalikes found at/above the selected threshold.")

with tabs[1]:
    st.subheader("Scan History")
    hist = load_history()
    if hist is None or hist.empty:
        st.info("No history yet. Run a scan to populate this page.")
    else:
        # Show latest first
        hist_sorted = hist.sort_values("timestamp", ascending=False).reset_index(drop=True)
        hist_sorted["when"] = pd.to_datetime(hist_sorted["timestamp"], unit="s").astype(str)
        st.dataframe(hist_sorted[["when","target","suspect_domain","similarity","url","ip","ns","mx","notes"]], use_container_width=True)

        # Downloads
        df_download_button(hist_sorted, "Download full history (CSV)", "history.csv")
        hist_pdf = df_to_pdf_bytes(hist_sorted, title="Clone Scan Report (Full History)")
        st.download_button("Download full history (PDF)", data=hist_pdf, file_name="history.pdf", mime="application/pdf")

        with st.expander("Manage history"):
            if st.button("Clear history file"):
                try:
                    os.remove(HISTORY_FILE)
                    st.success("History cleared. Refresh the page.")
                except FileNotFoundError:
                    st.info("History already empty.")
