from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import email, re, requests, hashlib, sqlite3, base64, dkim, whois
from urlextract import URLExtract
from datetime import datetime
import dateparser

app = FastAPI(title="Email Forensics Pro Enterprise", version="4.0")
extractor = URLExtract()

# =====================================================================
# 🛑 PASTE YOUR FREE VIRUSTOTAL API KEY HERE (KEEP THE QUOTATION MARKS)
# =====================================================================
VIRUSTOTAL_API_KEY = "c8f2bed4522a57f8028aa59e7c2b2f03a120e2aa18033b2b1093fce8791d1a96"

# --- Database Setup (Visitor Tracker) ---
DB_FILE = "telemetry.db"
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS stats (id INTEGER PRIMARY KEY, visits INTEGER)''')
    c.execute('''INSERT OR IGNORE INTO stats (id, visits) VALUES (1, 0)''')
    conn.commit()
    conn.close()

init_db()

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

class EmailData(BaseModel):
    raw_email: str

# --- Forensic Functions ---
def get_body(msg):
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == 'text/plain' and 'attachment' not in str(part.get('Content-Disposition')):
                return part.get_payload(decode=True).decode(errors='ignore')
    return msg.get_payload(decode=True).decode(errors='ignore')

def extract_public_ips(headers):
    pattern = re.compile(r'\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]')
    ips = []
    for h in reversed(headers):
        for ip in pattern.findall(h):
            if not ip.startswith(('10.', '192.168.', '127.', '172.')) and ip not in ips:
                ips.append(ip)
    return ips

def get_geo(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=3).json()
        if res.get("status") == "success":
            return {"ip": ip, "country": res.get("country"), "city": res.get("city"), "isp": res.get("isp"), "lat": res.get("lat"), "lon": res.get("lon")}
    except: pass
    return None

def check_virustotal(urls):
    if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY == "YOUR_API_KEY_HERE": return []
    threats = []
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    for url in urls[:2]:
        clean_url = url.strip()
        try:
            url_id = base64.urlsafe_b64encode(clean_url.encode()).decode().strip("=")
            res = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
            if res.status_code == 200:
                data = res.json()
                malicious_count = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
                if malicious_count > 0:
                    threats.append(f"🚨 VIRUSTOTAL: '{clean_url}' flagged as MALWARE.")
        except: continue
    return threats

def nlp_intent(body):
    triggers = ["urgent", "wire transfer", "password", "suspended", "verify account", "invoice", "unauthorized", "login"]
    return [t for t in triggers if t in body.lower()]

def get_domain_reputation(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list): creation_date = creation_date[0]
        if creation_date:
            return (datetime.now() - creation_date).days
    except: pass
    return None

def analyze_header_delays(received_headers):
    delays = []
    times = []
    time_pattern = re.compile(r';\s*(.*)$')
    for h in received_headers:
        match = time_pattern.search(h)
        if match:
            dt = dateparser.parse(match.group(1))
            if dt: times.append(dt)
    if len(times) > 1:
        for i in range(len(times)-1):
            diff = abs((times[i] - times[i+1]).total_seconds())
            delays.append(diff)
    return delays

# --- API Endpoints ---
@app.get("/visit-count")
def get_visits():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE stats SET visits = visits + 1 WHERE id = 1")
    conn.commit()
    c.execute("SELECT visits FROM stats WHERE id = 1")
    count = c.fetchone()[0]
    conn.close()
    return {"total_visits": count}

@app.post("/analyze")
def analyze(data: EmailData):
    msg = email.message_from_string(data.raw_email)
    body = get_body(msg)
    received_headers = msg.get_all("Received") or []
    
    # 1. Parsing & Crypto
    hash256 = hashlib.sha256(body.encode('utf-8', errors='ignore')).hexdigest()
    is_dkim_valid = dkim.verify(data.raw_email.encode('utf-8')) if "DKIM-Signature" in data.raw_email else False
    keywords = nlp_intent(body)
    
    # 2. Header parsing for DMARC
    from_addr = msg.get("From", "")
    return_path = msg.get("Return-Path", "")
    reply_to = msg.get("Reply-To", "")
    
    from_dom = from_addr.split('@')[-1].strip('<>') if '@' in from_addr else ""
    return_dom = return_path.split('@')[-1].strip('<>') if '@' in return_path else ""
    reply_dom = reply_to.split('@')[-1].strip('<>') if '@' in reply_to else ""
    
    dmarc_aligned = (from_dom == return_dom) and is_dkim_valid
    
    # 3. Deep Forensics (Whois & Time Delays)
    domain_age = get_domain_reputation(from_dom)
    transit_delays = analyze_header_delays(received_headers)
    
    # 4. Routing
    ips = extract_public_ips(received_headers)
    route = [get_geo(ip) for ip in ips[:3] if get_geo(ip)]
    origin = route[0] if route else {"country": "Unknown", "city": "Unknown", "isp": "Unknown"}
    reply_geo = get_geo(reply_dom) if reply_dom and reply_dom != from_dom else None
    
    # 5. Threat Intel
    raw_urls = extractor.find_urls(body)
    urls = [re.sub(r'[\n\r].*', '', u).strip() for u in raw_urls if u.startswith('http')]
    vt_threats = check_virustotal(urls)
    
    # 6. Risk Scoring
    score, findings = 0, []
    if from_dom and return_dom and from_dom != return_dom:
        score += 35; findings.append("Domain Mismatch (Spoofing risk).")
    if reply_dom and reply_dom != from_dom:
        score += 35; findings.append(f"Reply-To Trap: Routes to {reply_dom}.")
    if domain_age and domain_age < 30:
        score += 40; findings.append(f"Brand New Domain: Sender domain is only {domain_age} days old (High Phishing Probability).")
    if any(d > 3600 for d in transit_delays):
        score += 15; findings.append("Suspicious Transit Delay: Email was held on an intermediate server for over an hour.")
    if not is_dkim_valid:
        score += 20; findings.append("DKIM Cryptography Invalid/Missing.")
    if keywords:
        score += (len(keywords)*5)
    if vt_threats:
        score += 50; findings.extend(vt_threats)
        
    final_score = min(score, 100)
    
    # This is the "Lunchbox" getting sent to the website!
    return {
        "metadata": {"from": from_addr, "to": msg.get("To",""), "subject": msg.get("Subject",""), "date": msg.get("Date",""), "domain_age": domain_age},
        "crypto": {"sha256": hash256, "dkim_valid": is_dkim_valid, "dmarc_aligned": dmarc_aligned},
        "routing": {"origin_ip": ips[0] if ips else "Unknown", "geo": origin, "map_route": route, "reply_geo": reply_geo},
        "payload": {"urls": urls, "vt_threats": vt_threats, "keywords": keywords},
        "report": {"risk_score": final_score, "risk_level": "HIGH" if final_score >= 65 else "MEDIUM" if final_score >= 30 else "LOW", "findings": findings}
    }