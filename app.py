# app.py
import ssl
import requests
from requests.adapters import HTTPAdapter
from flask import Flask, request, jsonify, send_from_directory, send_file
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import os
from flask_cors import CORS
from datetime import datetime

app = Flask(__name__, static_folder="static", static_url_path="/static")
CORS(app)  # dev convenience - ok for local testing

# --- Custom SSL Adapter (compatible signature) ---
class SSLAdapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False, **kwargs):
        context = ssl.create_default_context()
        # WARNING: using 'ALL' ciphers may be insecure; kept to preserve your original intent
        context.set_ciphers("ALL")
        kwargs["ssl_context"] = context
        return super().init_poolmanager(connections, maxsize, block, **kwargs)

session = requests.Session()
session.mount("https://", SSLAdapter())
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
})

# --- Helpers ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PAYLOAD_FILE = os.path.join(BASE_DIR, "payloads.txt")
REPORT_FILE = os.path.join(BASE_DIR, "sql_injection_report.html")

def load_payloads(filepath=PAYLOAD_FILE):
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            payloads = [line.strip() for line in f if line.strip()]
        return payloads
    except FileNotFoundError:
        return []

def get_forms(url):
    """Return (forms_list, error_string). error_string is None on success."""
    try:
        r = session.get(url, timeout=15, allow_redirects=True)
        r.raise_for_status()
        soup = BeautifulSoup(r.content, "html.parser")
        forms = soup.find_all("form")
        return forms, None
    except Exception as e:
        app.logger.warning(f"get_forms failed for {url}: {e}")
        return [], str(e)

def form_details(form):
    action = form.attrs.get("action") or ""
    method = form.attrs.get("method", "get")
    inputs = []
    for i in form.find_all(["input", "textarea", "select"]):
        input_type = i.attrs.get("type", "text")
        name = i.attrs.get("name")
        value = i.attrs.get("value", "") or ""
        inputs.append({"type": input_type, "name": name, "value": value})
    return {"action": action, "method": method, "inputs": inputs}

def vulnerable(response, payload):
    """Heuristics to detect SQLi evidence. Keep conservative to reduce false positives."""
    try:
        content = response.content.decode(errors="ignore").lower()
    except Exception:
        content = response.text.lower() if response.text else ""

    sql_errors = [
        "quoted string not properly terminated",
        "unclosed quotation mark after the character string",
        "you have an error in your sql syntax",
        "mysql_fetch_array(",
        "warning: mysql",
        "sql syntax",
        "syntax error",
        "sql error",
        "invalid query"
    ]

    for e in sql_errors:
        if e in content:
            return True

    if response.status_code == 500:
        return True

    # look for admin/login bypass markers (conservative)
    if "welcome, admin" in content or "you are logged in as admin" in content:
        return True

    # only treat payload echo as evidence if error messages also present
    if payload.lower() in content and any(e in content for e in sql_errors):
        return True

    return False

def severity_label(result):
    """Return a simple severity label based on result type."""
    if result.get("vulnerability") == "SQL Injection Detected":
        return "High"
    if result.get("vulnerability") == "Error":
        return "Medium"
    return "Low"

def sql_injection_scan(url):
    payloads = load_payloads()
    forms, fetch_error = get_forms(url)
    results = []

    if not payloads:
        results.append({
            "url": url,
            "vulnerability": "No payloads loaded",
            "description": "payloads.txt not found or empty. Place payloads in payloads.txt",
            "severity_score": "N/A"
        })
        return results

    # Show the real error if the page could not be fetched
    if fetch_error:
        results.append({
            "url": url,
            "vulnerability": "Connection Failed",
            "description": f"Could not reach the URL. Error: {fetch_error}",
            "severity_score": "N/A"
        })
        return results

    if not forms:
        results.append({
            "url": url,
            "vulnerability": "No forms found",
            "description": "Page was reached but no HTML forms were detected.",
            "severity_score": "Low"
        })
        return results

    for form in forms:
        details = form_details(form)
        action = urljoin(url, details["action"])
        for payload in payloads:
            # build data dict
            data = {}
            for inp in details["inputs"]:
                name = inp.get("name")
                if not name:
                    continue
                if inp.get("type") == "hidden" or inp.get("value"):
                    data[name] = (inp.get("value") or "") + payload
                elif inp.get("type") in ("submit", "button"):
                    # skip; submit buttons are not data fields
                    continue
                else:
                    data[name] = f"test{payload}"

            try:
                if details["method"].lower() == "post":
                    res = session.post(action, data=data, timeout=15)
                else:
                    res = session.get(action, params=data, timeout=15)
            except Exception as e:
                results.append({
                    "url": action,
                    "payload": payload,
                    "vulnerability": "Error",
                    "description": f"Request failed: {e}",
                    "severity_score": "Medium"
                })
                continue

            if vulnerable(res, payload):
                results.append({
                    "url": action,
                    "payload": payload,
                    "vulnerability": "SQL Injection Detected",
                    "description": f"Potential SQL injection detected using payload: {payload}",
                    "severity_score": "High"
                })
            else:
                results.append({
                    "url": action,
                    "payload": payload,
                    "vulnerability": "No Vulnerability Detected",
                    "description": "No immediate evidence of SQL injection for this payload.",
                    "severity_score": "Low"
                })

    return results

def generate_report(results, report_path=REPORT_FILE):
    """Create a basic HTML report file."""
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("<!doctype html><html><head><meta charset='utf-8'><title>SQLi Report</title>")
        f.write("<style>")
        f.write("body{font-family:Arial,Helvetica,sans-serif;padding:20px} .high{background:#ffd6d6;padding:10px;border-left:5px solid #e53935} .med{background:#fff2cc;padding:10px;border-left:5px solid #f39c12} .low{background:#e6ffed;padding:10px;border-left:5px solid #2ecc71} ul{list-style:none;padding:0}")
        f.write("</style></head><body>")
        f.write(f"<h1>SQL Injection Scan Report</h1><p>Generated: {now}</p>")
        f.write("<ul>")
        for r in results:
            sev = r.get("severity_score", "Low")
            cls = "low"
            if sev == "High":
                cls = "high"
            elif sev == "Medium":
                cls = "med"
            f.write(f"<li class='{cls}'><strong>{r.get('vulnerability')}</strong> — {r.get('url')}<br>")
            f.write(f"<em>{r.get('description')}</em><br>")
            f.write(f"Payload: <code>{(r.get('payload') or '')}</code><br>")
            f.write(f"Severity: {sev}</li><hr>")
        f.write("</ul></body></html>")
    return report_path

# --- Routes ---
@app.route("/", methods=["GET"])
def index():
    # Serve the frontend HTML
    return send_from_directory(os.path.join(BASE_DIR, "static"), "index.html")

@app.route("/", methods=["POST"])
def scan_url():
    content = request.get_json() or {}
    url = content.get("url")
    if not url:
        return jsonify({"message": "URL is required"}), 400

    results = sql_injection_scan(url)
    # generate report file so /download_report can serve it
    generate_report(results)
    return jsonify({"results": results})

@app.route("/download_report", methods=["GET"])
def download_report():
    if not os.path.exists(REPORT_FILE):
        return jsonify({"message": "No report available. Please run a scan first."}), 404
    return send_file(REPORT_FILE, as_attachment=True)

if __name__ == "__main__":
    # DEV only: debug True. Turn off for production.
    app.run(host="127.0.0.1", port=5000, debug=True)
