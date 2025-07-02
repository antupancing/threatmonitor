from flask import Flask, render_template, request
import sqlite3
from datetime import datetime, timedelta, timezone
import ast
from threat_monitor import RSS_FEEDS
from threat_monitor import extract_actor, extract_detection, extract_remediation
from threat_monitor import monitor_feeds  # Import your function
import threading
import time

def background_scheduler():
    while True:
        print("[⏰] Running scheduled threat check...")
        monitor_feeds()
        time.sleep(300)  # Run every 5 mins (adjust as needed)

# Start background thread
threading.Thread(target=background_scheduler, daemon=True).start()


from flask import Flask, render_template
import os

app = Flask(__name__)
DB_FILE = "threat_intel.db"

# === Fetch Data from Database ===
def fetch_entries_from_db():
    """
    Fetches all threat data entries from the SQLite database.
    Parses and reformats dates, extracts IOCs, and calculates total IOCs.
    Also retrieves the last fetch timestamp and AI-generated summary.
    
    Returns:
        entries (list): Parsed threat entries
        ioc_total (int): Total number of extracted IOCs
        latest_date (str): Date of latest entry
        last_fetched (str): Last RSS pull time
        overall_summary (str): AI-generated summary
    """
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    # Fetch threat entries
    c.execute("SELECT title, link, published, summary, iocs FROM threat_data ORDER BY id DESC")
    rows = c.fetchall()

    # Fetch last fetched time
    c.execute("SELECT value FROM meta WHERE key = 'last_fetched'")
    result = c.fetchone()
    last_fetched = result[0] if result else "N/A"

    # Fetch AI summary (if available)
    c.execute("SELECT value FROM meta WHERE key = 'summary_all_ai'")
    summary_result = c.fetchone()
    overall_summary = summary_result[0] if summary_result else "No summary available."

    conn.close()

    entries = []
    ioc_total = 0

    for row in rows:
        title, link, published, summary, iocs_str = row

        # Attempt to parse and convert date
        try:
            dt = datetime.fromisoformat(published.replace('Z', '+00:00'))
            dt = dt.astimezone(timezone(timedelta(hours=8)))  # Convert to UTC+8
            published_display = dt.strftime("%d %b %Y, %I:%M %p")
        except:
            dt = None
            published_display = published

        # Convert stringified IOC dictionary to real dict
        try:
            iocs_dict = ast.literal_eval(iocs_str)
            iocs = (
                iocs_dict.get('ips', []) +
                iocs_dict.get('domains', []) +
                iocs_dict.get('hashes', []) +
                iocs_dict.get('cves', [])
            )
        except:
            iocs = []

        ioc_count = len(iocs)
        ioc_total += ioc_count

        entries.append({
            "title": title,
            "link": link,
            "published": published_display,
            "summary": summary,
            "iocs": iocs,
            "ioc_count": ioc_count,
            "actor": extract_actor(summary),
            "detection": extract_detection(summary),
            "remediation": extract_remediation(summary),
            "dt": dt  # for sorting
        })

    # Remove entries without valid datetime and sort descending
    entries = sorted([e for e in entries if e['dt']], key=lambda x: x['dt'], reverse=True)

    latest_date = entries[0]['published'] if entries else "N/A"

    return entries, ioc_total, latest_date, last_fetched, overall_summary

# === Main Dashboard Route ===
@app.route('/')
def dashboard():
    """
    Renders the main dashboard.
    Supports optional search filtering by query parameter 'q'.
    Displays threat entries, total IOCs, and AI summary.
    """
    query = request.args.get("q", "").lower()
    all_entries, total_iocs, latest_date, last_fetched, overall_summary = fetch_entries_from_db()

    # Search filter
    if query:
        filtered_entries = [
            e for e in all_entries
            if query in (e['summary'] + e['title']).lower()
        ]
    else:
        filtered_entries = all_entries

    return render_template(
        "dashboard.html",
        entries=filtered_entries,
        total_threats=len(filtered_entries),
        ioc_count=sum(e["ioc_count"] for e in filtered_entries),
        latest_date=latest_date,
        last_checked=datetime.now().strftime("%d %b %Y, %I:%M %p"),
        last_fetched=last_fetched,
        query=query,
        rss_feeds=RSS_FEEDS,
        overall_summary=overall_summary
    )

def home():
    return render_template("dashboard.html")  # or your main route

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
    
    
# === Run the Flask App ===
if __name__ == '__main__':
    app.run(debug=True)
