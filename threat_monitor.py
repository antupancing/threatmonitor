import feedparser
import re
import sqlite3
import schedule
import time
from datetime import datetime, timezone, timedelta
from dateutil import parser, tz
import google.generativeai as genai
import http.client
from http.client import IncompleteRead
from io import BytesIO
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# === Configure Gemini API ===
genai.configure(api_key="AIzaSyB6YtF3dWSdTRoDkGs26zdGE4vn1YcVBww")  # Replace with your key

# Patch for IncompleteRead error in feedparser
def patched_http_response_read(self, amt=None):
    try:
        return self._original_read(amt)
    except IncompleteRead as e:
        return e.partial

http.client.HTTPResponse._original_read = http.client.HTTPResponse.read
http.client.HTTPResponse.read = patched_http_response_read

# === RSS Feeds List ===
RSS_FEEDS = [
    "https://www.cisa.gov/news.xml",
    "https://www.us-cert.gov/ncas/alerts.xml",
    "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml",
    "https://blog.talosintelligence.com/rss/",
    "https://isc.sans.edu/rssfeed.xml",
    "https://feeds.feedburner.com/securityweek",
    "https://securelist.com/feed/",
    "https://www.bleepingcomputer.com/feed/",
    "https://threatpost.com/feed/",
    "https://krebsonsecurity.com/feed/",
    "https://thehackernews.com/feeds/posts/default",
    "https://thedfirreport.com/feed/",
    "https://www.malwarebytes.com/blog/feed",
    "https://unit42.paloaltonetworks.com/feed/",
    "https://research.checkpoint.com/feed/",
    "https://www.infosecurity-magazine.com/rss/news/",
    "https://medium.com/feed/mitre-attack",
    "https://garwarner.blogspot.com/feeds/posts/default",
    "https://news.sophos.com/en-us/category/security-operations/feed/",
    "https://feeds.feedburner.com/eset/blog",
    "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss-analyzed.xml",
    "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml",
    "https://googleprojectzero.blogspot.com/feeds/posts/default",
    "https://www.tenable.com/blog/rss",
    "https://www.crowdstrike.com/en-us/blog/feed",
    "https://www.netskope.com/blog/category/threat-research/feed",
    "https://redcanary.com/feed/",
    "https://intezer.com/feed/"
]

DB_FILE = "threat_intel.db"

# === Timezone mapping ===
tzinfos = {
    "EDT": tz.gettz("America/New_York"),
    "EST": tz.gettz("America/New_York"),
    "PDT": tz.gettz("America/Los_Angeles"),
    "PST": tz.gettz("America/Los_Angeles"),
    "GMT": tz.gettz("GMT"),
    "UTC": tz.gettz("UTC"),
}

# === Initialize Database ===
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS threat_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            link TEXT,
            published TEXT,
            summary TEXT,
            iocs TEXT,
            actor TEXT,
            detection TEXT,
            remediation TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    ''')
    conn.commit()
    conn.close()

# === Fetch RSS Entries ===
def fetch_rss_entries(rss_url):
    feed = feedparser.parse(rss_url)
    entries = []

    for entry in feed.entries:
        raw_published = entry.get('published', '') or entry.get('updated', '')
        published_display = raw_published

        try:
            dt = parser.parse(raw_published, tzinfos=tzinfos)
            dt = dt.astimezone(timezone(timedelta(hours=8)))
            published_display = dt.strftime("%d %b %Y, %I:%M %p")
        except Exception as e:
            print(f"[!] Date parsing failed: {raw_published} - {e}")

        entries.append({
    'title': entry.get('title', ''),
    'link': entry.get('link', ''),
    'published': dt.isoformat(),  # Save as ISO string
    'summary': entry.get('summary', '')
})

    return entries

# === IOC Extractors ===
def extract_iocs(text):
    return {
        'ips': re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text),
        'domains': re.findall(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b', text),
        'hashes': re.findall(r'\b[a-fA-F0-9]{32,64}\b', text),
        'cves': re.findall(r'CVE-\d{4}-\d{4,7}', text)
    }

def extract_actor(text):
    keywords = ["APT", "Lazarus", "TA505", "Cobalt", "FIN7", "Fancy Bear", "Anonymous", "Conti", "LockBit"]
    for word in keywords:
        if word.lower() in text.lower():
            return word
    return "Unknown"

def extract_detection(text):
    if any(term in text.lower() for term in ["detected", "mitre", "ioc"]):
        return "Detection technique mentioned"
    return "TBD"

def extract_remediation(text):
    if any(term in text.lower() for term in ["patch", "update", "mitigation"]):
        return "Patch or mitigation advised"
    return "TBD"

# === Store Entry ===
def store_entry(entry, iocs, actor, detection, remediation):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute("SELECT COUNT(*) FROM threat_data WHERE link = ?", (entry['link'],))
    exists = c.fetchone()[0] > 0

    inserted = False
    if not exists:
        c.execute('''
            INSERT INTO threat_data (
                title, link, published, summary, iocs, actor, detection, remediation
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            entry['title'],
            entry['link'],
            entry['published'],
            entry['summary'],
            str(iocs),
            actor,
            detection,
            remediation
        ))
        inserted = True

    conn.commit()
    conn.close()
    return inserted

# === Generate AI Summary for All RSS ===
def summarize_all_rss(entries):
    if not entries:
        return "No entries to summarize."

    # ✅ Combine and truncate input to avoid token limit
    combined = "\n\n".join([f"- {e['title']}\n{e['summary']}" for e in entries])
    combined = combined[:12000]  # Limit input size for Gemini free tier

    try:
        genai.configure(api_key="AIzaSyB6YtF3dWSdTRoDkGs26zdGE4vn1YcVBww")  # Optional if already configured
        model = genai.GenerativeModel("models/gemini-1.5-flash")

        response = model.generate_content(
            f"""You are a cybersecurity analyst. Analyze the following RSS summaries and provide a high-level summary in 5–8 bullet points highlighting threats, vulnerabilities, attack types, or actors:\n\n{combined}"""
        )
        summary = response.text.strip()

        # Store to DB
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", ("summary_all_ai", summary))
        conn.commit()
        conn.close()

        print("\n[Gemini AI Overall Summary]\n" + summary + "\n")
        return summary

    except Exception as e:
        print(f"[!] Gemini failed to summarize all RSS: {e}")
        return "Summary failed."

# === Main Monitoring Function ===
def monitor_feeds():
    print("[+] Starting RSS feed check...")
    all_entries = []
    total_inserted = 0
    total_skipped = 0

    for url in RSS_FEEDS:
        print(f"Fetching: {url}")
        entries = fetch_rss_entries(url)

        for entry in entries:
            iocs = extract_iocs(entry['summary'])
            actor = extract_actor(entry['summary'])
            detection = extract_detection(entry['summary'])
            remediation = extract_remediation(entry['summary'])

            if store_entry(entry, iocs, actor, detection, remediation):
                total_inserted += 1
                all_entries.append(entry)  # Only keep newly inserted entries for summary
            else:
                total_skipped += 1

    print(f"[✓] Total Inserted: {total_inserted} | Skipped (duplicates): {total_skipped}")

    # Store last fetched time (MYT)
    mytz = timezone(timedelta(hours=8))
    now = datetime.now(mytz).strftime("%Y-%m-%d %I:%M:%S %p GMT+8")

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", ("last_fetched", now))
    conn.commit()
    conn.close()

    # Summarize only new entries
    if total_inserted > 0:
        summarize_all_rss(all_entries)
    else:
        print("[=] No new threats")
        

def send_email_notification(entry):
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    import traceback

    sender_email = "azmeel82@yahoo.com.my"
    sender_password = "kucx ipls ibyp akqy"  # App password
    recipient_emails = ["azmil.nazim@gmail.com"]

    subject = f"[Threat Intel Alert] {entry['title']}"
    body = f"""
New Threat Intelligence Entry Detected:

Title: {entry['title']}
Published: {entry['published']}
Link: {entry['link']}
Summary: {entry['summary']}

Indicators of Compromise:
{entry.get('iocs', '')}

Actor: {entry.get('actor', '')}
Detection: {entry.get('detection', '')}
Remediation: {entry.get('remediation', '')}
"""

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = ", ".join(recipient_emails)
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain', 'utf-8'))

    try:
        with smtplib.SMTP_SSL("smtp.mail.yahoo.com", 465) as server:
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, recipient_emails, msg.as_string())
        print(f"[✓] Email sent: {entry['title']}")
    except Exception as e:
        print(f"[!] Failed to send email: {e}")
        traceback.print_exc()
        
        
# === Run Once and Schedule ===
if __name__ == "__main__":
    init_db()
    monitor_feeds()
    schedule.every(5).minutes.do(monitor_feeds)
    print("[+] Threat Monitor Running...")
    while True:
        schedule.run_pending()
        time.sleep(10)
