import time, requests, streamlit as st
from difflib import SequenceMatcher
from urllib.parse import urlparse

DEFAULT_THRESHOLD=0.60
CONNECT_TIMEOUT=6
READ_TIMEOUT=12
UA={"User-Agent":"CloneShield/mini"}
HISTORY_FILE="history.csv"

COMMON_TLDS=[".com",".net",".org",".co",".io",".info",".biz",".site",".online",".app"]
PREFIXES=["secure","login","verify","account","support","update","auth","my","portal","service"]
SUFFIXES=["login","secure","verify","update","auth","support","access","portal"]
SUBS=["secure","login","verify","auth","account","portal"]

def split_domain(domain):
    d=domain.strip().lower()
    if d.startswith(("http://","https://")): d=urlparse(d).netloc
    parts=d.split(".")
    if len(parts)<2: return d,""
    return ".".join(parts[:-1]),"."+parts[-1]

def gen_candidates(domain,cap=200):
    name,tld=split_domain(domain)
    if not name: return []
    out=set()
    for p in PREFIXES: out|={f"{p}{name}{tld or '.com'}",f"{p}-{name}{tld or '.com'}"}
    for s in SUFFIXES: out|={f"{name}{s}{tld or '.com'}",f"{name}-{s}{tld or '.com'}"}
    for sub in SUBS: out.add(f"{sub}.{name}{tld or '.com'}")
    for alt in COMMON_TLDS:
        if alt!=tld: out.add(f"{name}{alt}")
    out|={f"{name}-login{tld or '.com'}",f"{name}-secure{tld or '.com'}",f"login-{name}{tld or '.com'}",f"secure-{name}{tld or '.com'}"}
    return list(out)[:cap]

def fetch_html(url):
    try:
        r=requests.get(url,headers=UA,timeout=(CONNECT_TIMEOUT,READ_TIMEOUT),allow_redirects=True)
        if r.status_code<400 and "html" in r.headers.get("content-type","").lower():
            return " ".join(r.text.split())
    except Exception: pass
    return None

def similarity(a,b): return SequenceMatcher(None,a or "",b or "").ratio()

def scan_domain(target,threshold):
    canon=fetch_html(f"https://{target}") or fetch_html(f"http://{target}")
    rows=[]
    if not canon: return rows
    for cand in gen_candidates(target):
        html=fetch_html(f"https://{cand}") or fetch_html(f"http://{cand}")
        if not html: continue
        sim=similarity(canon,html)
        if sim>=threshold:
            rows.append({"timestamp":int(time.time()),"target":target,"suspect_domain":cand,"similarity":round(sim,3),"url":f"https://{cand}"})
    return rows

def load_history():
    try:
        with open(HISTORY_FILE,"r",encoding="utf-8") as f:
            lines=[l.strip() for l in f if l.strip()]
            hdr=lines[0].split(",");data=[]
            for l in lines[1:]:
                vals=l.split(",");data.append(dict(zip(hdr,vals)))
            return data
    except Exception:return[]

def append_history(rows):
    if not rows:return
    existed=load_history();all_rows=existed+rows
    hdr=["timestamp","target","suspect_domain","similarity","url"]
    with open(HISTORY_FILE,"w",encoding="utf-8") as f:
        f.write(",".join(hdr)+"\n")
        for r in all_rows:f.write(",".join(str(r[h]) for h in hdr)+"\n")

def to_csv(rows):
    if not rows:return b""
    hdr=["timestamp","target","suspect_domain","similarity","url"]
    out=",".join(hdr)+"\n"
    for r in rows:out+=",".join(str(r[h]) for h in hdr)+"\n"
    return out.encode()

def show_table(rows):
    if not rows:st.info("No suspicious lookalikes found.");return
    hdr=["When","Target","Suspect","Similarity","URL"]
    st.write("| "+" | ".join(hdr)+" |");st.write("|"+"|".join(["---"]*len(hdr))+"|")
    for r in rows:
        when=time.strftime("%Y-%m-%d %H:%M",time.localtime(int(r["timestamp"])))
        st.write(f"| {when} | {r['target']} | {r['suspect_domain']} | {r['similarity']} | {r['url']} |")

st.set_page_config(page_title="CloneShield (Mini)",page_icon="🛡️",layout="centered")
st.title("🛡️ CloneShield — Mini")

tabs=st.tabs(["Scan","History"])
with tabs[0]:
    with st.form("scan"):
        domains=st.text_area("Domains (one per line)","firstmetro.com\nplantersfirstbank.com",height=120)
        threshold=st.slider("Similarity threshold",0.4,0.95,DEFAULT_THRESHOLD,0.01)
        go=st.form_submit_button("Run Scan",type="primary")
    if go:
        targets=[d.strip() for d in domains.splitlines() if d.strip()]
        if not targets:st.warning("Please enter at least one domain.")
        else:
            results=[];prog=st.progress(0)
            for i,t in enumerate(targets,start=1):
                st.write(f"Scanning {t}…")
                results+=scan_domain(t,threshold)
                prog.progress(i/len(targets))
            prog.empty();show_table(results)
            if results:
                st.download_button("Download CSV",to_csv(results),"findings.csv","text/csv")
                append_history(results)

with tabs[1]:
    st.subheader("History")
    hist=load_history();show_table(hist)
    if hist:
        st.download_button("Download Full History CSV",to_csv(hist),"history.csv","text/csv")
        if st.button("Clear History"):
            import os
            try:os.remove(HISTORY_FILE);st.success("History cleared. Refresh the page.")
            except FileNotFoundError:st.info("History already empty.")
